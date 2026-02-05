#!/usr/bin/env python3
"""
SecureHeadersScan - Enterprise-Grade HTTP Security Header Scanner
-----------------------------------------------------------------
Complete implementation with all edge cases handled
"""

import sys
import os
import time
import signal
import socket
import json
import csv
import concurrent.futures
import random
import ssl
import threading
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from datetime import datetime
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
)
from rich.logging import RichHandler
from rich.traceback import install as install_rich_traceback
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    wait_random,
    retry_if_exception_type,
    before_sleep_log,
)

# Install rich traceback
install_rich_traceback()

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)
logger = logging.getLogger(__name__)
# Reduce urllib3 logging
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

console = Console()

# Global shutdown flag
SHUTDOWN_REQUESTED = False

class OutputFormat(Enum):
    CONSOLE = "console"
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"

@dataclass
class SecurityHeader:
    """Data class for security header information"""
    name: str
    description: str
    recommendation: str
    severity: str  # low, medium, high, critical
    reference: str
    category: str  # xss, clickjacking, transport, etc.

# Comprehensive security headers database
SECURITY_HEADERS: Dict[str, SecurityHeader] = {
    "Content-Security-Policy": SecurityHeader(
        name="Content-Security-Policy",
        description="Prevents XSS, data injection, and malicious script execution",
        recommendation="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
        severity="critical",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        category="xss"
    ),
    "Strict-Transport-Security": SecurityHeader(
        name="Strict-Transport-Security",
        description="Forces HTTPS and prevents protocol downgrade attacks",
        recommendation="max-age=31536000; includeSubDomains; preload",
        severity="critical",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        category="transport"
    ),
    "X-Frame-Options": SecurityHeader(
        name="X-Frame-Options",
        description="Protects against clickjacking attacks",
        recommendation="DENY",
        severity="high",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        category="clickjacking"
    ),
    "X-Content-Type-Options": SecurityHeader(
        name="X-Content-Type-Options",
        description="Prevents MIME-sniffing attacks",
        recommendation="nosniff",
        severity="medium",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        category="mime_sniffing"
    ),
    "Referrer-Policy": SecurityHeader(
        name="Referrer-Policy",
        description="Controls Referer header information leakage",
        recommendation="strict-origin-when-cross-origin",
        severity="medium",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        category="information_leakage"
    ),
    "Permissions-Policy": SecurityHeader(
        name="Permissions-Policy",
        description="Restricts access to sensitive browser features",
        recommendation="geolocation=(), camera=(), microphone=(), payment=(), usb=()",
        severity="medium",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        category="feature_policy"
    ),
    "Cache-Control": SecurityHeader(
        name="Cache-Control",
        description="Prevents caching of sensitive data",
        recommendation="no-store, no-cache, must-revalidate",
        severity="low",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
        category="caching"
    ),
    "Pragma": SecurityHeader(
        name="Pragma",
        description="Backward compatibility cache control",
        recommendation="no-cache",
        severity="low",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma",
        category="caching"
    ),
    "Cross-Origin-Opener-Policy": SecurityHeader(
        name="Cross-Origin-Opener-Policy",
        description="Prevents cross-origin window attacks",
        recommendation="same-origin",
        severity="high",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        category="cross_origin"
    ),
    "Cross-Origin-Embedder-Policy": SecurityHeader(
        name="Cross-Origin-Embedder-Policy",
        description="Protects against cross-origin data leaks",
        recommendation="require-corp",
        severity="medium",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
        category="cross_origin"
    ),
    "Cross-Origin-Resource-Policy": SecurityHeader(
        name="Cross-Origin-Resource-Policy",
        description="Controls cross-origin resource access",
        recommendation="same-origin",
        severity="medium",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
        category="cross_origin"
    ),
    "X-XSS-Protection": SecurityHeader(
        name="X-XSS-Protection",
        description="Enables XSS filtering in older browsers",
        recommendation="1; mode=block",
        severity="low",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
        category="xss"
    ),
}

@dataclass
class ScanResult:
    """Data class for scan results"""
    url: str
    status_code: int
    headers: Dict[str, str]
    missing_headers: List[str]
    present_headers: List[str]
    scan_time: float
    error: Optional[str] = None
    redirect_chain: List[str] = None
    final_url: Optional[str] = None
    ip_address: Optional[str] = None
    server: Optional[str] = None
    timestamp: str = None
    retries_used: int = 0
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        if self.redirect_chain is None:
            self.redirect_chain = []

# Signal handler for graceful shutdown
def signal_handler(signum, frame):
    """Handle interrupt signals gracefully"""
    global SHUTDOWN_REQUESTED
    SHUTDOWN_REQUESTED = True
    console.print("\n[yellow]⚠️  Shutdown requested. Finishing current operation...[/yellow]")
    raise KeyboardInterrupt("Shutdown requested by user")

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def build_robust_session() -> requests.Session:
    """
    Build a robust HTTP session with intelligent retry and connection handling
    """
    session = requests.Session()
    
    # Intelligent retry strategy
    retry_strategy = Retry(
        total=2,
        backoff_factor=1.0,
        status_forcelist=[408, 429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        respect_retry_after_header=True,
    )
    
    # Custom adapter with connection pooling
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=20,
        pool_maxsize=20,
        pool_block=False,
    )
    
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    # Set headers
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    
    return session

def validate_and_normalize_url(url: str) -> Optional[str]:
    """
    Validate and normalize URL
    """
    if not url or not isinstance(url, str):
        return None
    
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    try:
        parsed = urlparse(url)
        
        if not parsed.netloc:
            return None
        
        # Normalize URL
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return normalized
    except Exception:
        return None

@retry(
    retry=retry_if_exception_type((
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
        socket.timeout,
    )),
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    before_sleep=lambda retry_state: logger.warning(
        f"Retry {retry_state.attempt_number} for {retry_state.args[0]}"
    ),
)
def scan_single_url(url: str) -> ScanResult:
    """
    Scan a single URL for security headers
    """
    global SHUTDOWN_REQUESTED
    
    if SHUTDOWN_REQUESTED:
        raise KeyboardInterrupt("Shutdown requested")
    
    start_time = time.perf_counter()
    retries_used = 0
    
    try:
        # Create session
        session = build_robust_session()
        
        # Add small random delay
        time.sleep(random.uniform(0.1, 0.5))
        
        # Try HEAD first
        try:
            response = session.head(
                url,
                allow_redirects=True,
                verify=True,
                timeout=(5, 15),
                stream=False
            )
            
            if response.status_code >= 400:
                raise requests.RequestException(f"HEAD returned {response.status_code}")
                
        except (requests.RequestException, requests.Timeout):
            # Fall back to GET
            response = session.get(
                url,
                allow_redirects=True,
                verify=True,
                timeout=(10, 30),
                stream=False
            )
        
        # Process response
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        # Analyze security headers
        missing_headers = []
        present_headers = []
        
        for header_name in SECURITY_HEADERS.keys():
            header_lower = header_name.lower()
            if header_lower in headers_lower:
                present_headers.append(header_name)
            else:
                missing_headers.append(header_name)
        
        # Get server information
        server_info = response.headers.get('Server', '')
        
        # Get IP address
        ip_address = None
        try:
            domain = urlparse(url).netloc
            ip_address = socket.gethostbyname(domain)
        except (socket.gaierror, socket.error):
            pass
        
        # Build redirect chain
        redirect_chain = []
        if hasattr(response, 'history') and response.history:
            redirect_chain = [resp.url for resp in response.history]
        
        scan_time = time.perf_counter() - start_time
        
        return ScanResult(
            url=url,
            status_code=response.status_code,
            headers=dict(response.headers),
            missing_headers=missing_headers,
            present_headers=present_headers,
            scan_time=scan_time,
            redirect_chain=redirect_chain,
            final_url=response.url,
            ip_address=ip_address,
            server=server_info,
            retries_used=retries_used
        )
        
    except socket.gaierror as e:
        scan_time = time.perf_counter() - start_time
        return ScanResult(
            url=url,
            status_code=0,
            headers={},
            missing_headers=list(SECURITY_HEADERS.keys()),
            present_headers=[],
            scan_time=scan_time,
            error=f"DNS resolution failed: {str(e)}",
            retries_used=retries_used
        )
        
    except requests.exceptions.SSLError as e:
        scan_time = time.perf_counter() - start_time
        return ScanResult(
            url=url,
            status_code=0,
            headers={},
            missing_headers=list(SECURITY_HEADERS.keys()),
            present_headers=[],
            scan_time=scan_time,
            error=f"SSL error: {str(e)}",
            retries_used=retries_used
        )
        
    except requests.exceptions.ConnectionError as e:
        scan_time = time.perf_counter() - start_time
        return ScanResult(
            url=url,
            status_code=0,
            headers={},
            missing_headers=list(SECURITY_HEADERS.keys()),
            present_headers=[],
            scan_time=scan_time,
            error=f"Connection failed: {str(e)}",
            retries_used=retries_used
        )
        
    except requests.exceptions.Timeout as e:
        scan_time = time.perf_counter() - start_time
        return ScanResult(
            url=url,
            status_code=0,
            headers={},
            missing_headers=list(SECURITY_HEADERS.keys()),
            present_headers=[],
            scan_time=scan_time,
            error=f"Timeout: {str(e)}",
            retries_used=retries_used
        )
        
    except KeyboardInterrupt:
        raise
        
    except Exception as e:
        scan_time = time.perf_counter() - start_time
        logger.error(f"Unexpected error scanning {url}: {e}", exc_info=True)
        return ScanResult(
            url=url,
            status_code=0,
            headers={},
            missing_headers=list(SECURITY_HEADERS.keys()),
            present_headers=[],
            scan_time=scan_time,
            error=f"Unexpected error: {str(e)}",
            retries_used=retries_used
        )

def scan_multiple_urls(urls: List[str], max_workers: int = 5) -> List[ScanResult]:
    """
    Scan multiple URLs concurrently
    """
    global SHUTDOWN_REQUESTED
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=50),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        refresh_per_second=10,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {len(urls)} URL(s)...[/cyan]",
            total=len(urls)
        )
        
        # Use ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(max_workers, len(urls)),
            thread_name_prefix="scanner"
        ) as executor:
            # Submit all tasks
            future_to_url = {}
            for url in urls:
                if SHUTDOWN_REQUESTED:
                    break
                
                future = executor.submit(scan_single_url, url)
                future_to_url[future] = url
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_url):
                if SHUTDOWN_REQUESTED:
                    for f in future_to_url:
                        f.cancel()
                    console.print("\n[yellow]⚠️  Scan interrupted[/yellow]")
                    break
                
                url = future_to_url[future]
                try:
                    result = future.result(timeout=60)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    results.append(ScanResult(
                        url=url,
                        status_code=0,
                        headers={},
                        missing_headers=list(SECURITY_HEADERS.keys()),
                        present_headers=[],
                        scan_time=0,
                        error="Worker timeout (60s)",
                        retries_used=0
                    ))
                except Exception as e:
                    results.append(ScanResult(
                        url=url,
                        status_code=0,
                        headers={},
                        missing_headers=list(SECURITY_HEADERS.keys()),
                        present_headers=[],
                        scan_time=0,
                        error=f"Processing error: {str(e)}",
                        retries_used=0
                    ))
                
                progress.update(task, advance=1)
    
    return results

def display_result(result: ScanResult, show_all: bool = False):
    """
    Display scan result in console
    """
    if result.error:
        console.print(Panel.fit(
            f"[bold red]Error Scanning:[/bold red] {result.url}\n"
            f"[yellow]Error:[/yellow] {result.error}",
            title="Scan Failed",
            border_style="red",
        ))
        return
    
    # Summary panel
    summary_panel = Panel.fit(
        f"[bold]Target:[/bold] {result.url}\n"
        f"[bold]Final URL:[/bold] {result.final_url or result.url}\n"
        f"[bold]Status Code:[/bold] {result.status_code}\n"
        f"[bold]Server:[/bold] {result.server or 'Not disclosed'}\n"
        f"[bold]IP Address:[/bold] {result.ip_address or 'Unknown'}\n"
        f"[bold red]Missing Headers:[/bold red] {len(result.missing_headers)}/{len(SECURITY_HEADERS)}\n"
        f"[bold green]Scan Time:[/bold green] {result.scan_time:.3f}s\n"
        f"[bold]Retries Used:[/bold] {result.retries_used}",
        title="Scan Summary",
        border_style="blue",
    )
    
    console.print(summary_panel)
    
    # Security headers table
    table = Table(
        title="HTTP Security Headers Analysis",
        show_lines=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Header", style="cyan", no_wrap=True, ratio=1)
    table.add_column("Status", justify="center", ratio=1)
    table.add_column("Severity", justify="center", ratio=1)
    table.add_column("Value", style="yellow", no_wrap=False, ratio=2)
    table.add_column("Description", style="white", no_wrap=False, ratio=3)
    
    # Sort headers by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_headers = sorted(
        SECURITY_HEADERS.items(),
        key=lambda x: severity_order.get(x[1].severity, 4)
    )
    
    for header_name, header_info in sorted_headers:
        if header_name in result.present_headers:
            status = "[green]✓ PRESENT[/green]"
            value = result.headers.get(header_name, "")
            if len(value) > 100:
                value = value[:97] + "..."
        else:
            status = "[red]✗ MISSING[/red]"
            value = f"[yellow]{header_info.recommendation}[/yellow]"
        
        # Color code severity
        severity_color = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green"
        }.get(header_info.severity, "white")
        
        severity = f"[{severity_color}]{header_info.severity.upper()}[/{severity_color}]"
        
        table.add_row(
            header_name,
            status,
            severity,
            value,
            header_info.description
        )
    
    console.print(table)
    
    # Show all headers if requested
    if show_all and result.headers:
        console.print("\n[bold]All HTTP Headers:[/bold]")
        headers_table = Table(show_header=True, header_style="bold cyan")
        headers_table.add_column("Header")
        headers_table.add_column("Value")
        
        for header, value in sorted(result.headers.items()):
            if len(value) > 100:
                value = value[:97] + "..."
            headers_table.add_row(header, value)
        
        console.print(headers_table)

def export_results(results: List[ScanResult], format: OutputFormat, filename: str):
    """
    Export scan results to file
    """
    try:
        if format == OutputFormat.JSON:
            with open(filename, 'w') as f:
                json.dump([asdict(r) for r in results], f, indent=2, default=str)
            console.print(f"[green]✓ Results exported to {filename}[/green]")
            
        elif format == OutputFormat.CSV:
            if results:
                fieldnames = list(asdict(results[0]).keys())
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for result in results:
                        writer.writerow(asdict(result))
                console.print(f"[green]✓ Results exported to {filename}[/green]")
                
        elif format == OutputFormat.HTML:
            html_content = generate_html_report(results)
            with open(filename, 'w') as f:
                f.write(html_content)
            console.print(f"[green]✓ HTML report generated: {filename}[/green]")
            
        elif format == OutputFormat.MARKDOWN:
            markdown_content = generate_markdown_report(results)
            with open(filename, 'w') as f:
                f.write(markdown_content)
            console.print(f"[green]✓ Markdown report generated: {filename}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error exporting results: {e}[/red]")

def generate_html_report(results: List[ScanResult]) -> str:
    """Generate HTML report"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Headers Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #4CAF50; color: white; }}
        .present {{ color: green; }}
        .missing {{ color: red; }}
        .error {{ background-color: #ffebee; padding: 10px; border-radius: 5px; margin: 10px 0; }}
        .footer {{ margin-top: 30px; text-align: center; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Headers Scan Report</h1>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Total URLs Scanned:</strong> {len(results)}</p>
"""
    
    for result in results:
        if result.error:
            html += f"""
        <div class="error">
            <h3>{result.url}</h3>
            <p><strong>Error:</strong> {result.error}</p>
        </div>
"""
        else:
            html += f"""
        <h2>{result.url}</h2>
        <p><strong>Status Code:</strong> {result.status_code} | 
           <strong>Scan Time:</strong> {result.scan_time:.3f}s | 
           <strong>Missing Headers:</strong> {len(result.missing_headers)}/{len(SECURITY_HEADERS)}</p>
        
        <table>
            <thead>
                <tr>
                    <th>Header</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Value</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for header_name, header_info in SECURITY_HEADERS.items():
                if header_name in result.present_headers:
                    status = '<span class="present">✓ PRESENT</span>'
                    value = result.headers.get(header_name, "")
                    if len(value) > 100:
                        value = value[:97] + "..."
                else:
                    status = '<span class="missing">✗ MISSING</span>'
                    value = header_info.recommendation
                
                html += f"""
                <tr>
                    <td><strong>{header_name}</strong></td>
                    <td>{status}</td>
                    <td>{header_info.severity.upper()}</td>
                    <td><code>{value}</code></td>
                </tr>
"""
            
            html += """
            </tbody>
        </table>
        <hr>
"""
    
    html += f"""
        <div class="footer">
            <p>Generated by SecureHeadersScan</p>
            <p>Report generated on {timestamp}</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html

def generate_markdown_report(results: List[ScanResult]) -> str:
    """Generate Markdown report"""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    markdown = f"""# Security Headers Scan Report

**Generated:** {timestamp}  
**Total URLs Scanned:** {len(results)}

---
"""
    
    for result in results:
        if result.error:
            markdown += f"""
## ❌ {result.url}

**Error:** {result.error}

---
"""
        else:
            markdown += f"""
## ✅ {result.url}

**Status Code:** {result.status_code}  
**Scan Time:** {result.scan_time:.3f}s  
**Missing Headers:** {len(result.missing_headers)}/{len(SECURITY_HEADERS)}

| Header | Status | Severity | Value |
|--------|--------|----------|-------|
"""
            
            for header_name, header_info in SECURITY_HEADERS.items():
                if header_name in result.present_headers:
                    status = "✅ PRESENT"
                    value = result.headers.get(header_name, "")
                    if len(value) > 100:
                        value = value[:97] + "..."
                else:
                    status = "❌ MISSING"
                    value = header_info.recommendation
                
                markdown += f"| **{header_name}** | {status} | **{header_info.severity.upper()}** | `{value}` |\n"
            
            markdown += "\n---\n"
    
    markdown += f"""
*Report generated by SecureHeadersScan on {timestamp}*
"""
    
    return markdown

def parse_input_file(filename: str) -> List[str]:
    """
    Parse input file containing URLs
    """
    urls = []
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    normalized = validate_and_normalize_url(line)
                    if normalized:
                        urls.append(normalized)
    except FileNotFoundError:
        console.print(f"[red]Error: File '{filename}' not found[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        sys.exit(1)
    
    return urls

def main():
    """Main entry point"""
    global SHUTDOWN_REQUESTED
    
    try:
        # Display banner
        console.print(Panel.fit(
            "[bold cyan]SecureHeadersScan v2.0[/bold cyan]\n"
            "Robust HTTP Security Header Scanner\n\n"
            "[green]✓ Graceful shutdown (Ctrl+C)[/green]\n"
            "[green]✓ Progress tracking[/green]\n"
            "[green]✓ Multiple export formats[/green]\n\n"
            "[yellow]Press Ctrl+C at any time for graceful shutdown[/yellow]",
            border_style="green",
            padding=(1, 2),
        ))
        
        # Parse command line arguments
        import argparse
        
        parser = argparse.ArgumentParser(
            description="Scan HTTP security headers",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s -f urls.txt
  %(prog)s url1 url2 url3
  %(prog)s -f urls.txt -o results.json --format json
            """
        )
        
        # Input options
        parser.add_argument(
            "urls",
            nargs="*",
            help="URL(s) to scan"
        )
        parser.add_argument(
            "-f", "--file",
            help="File containing list of URLs"
        )
        
        # Performance options
        parser.add_argument(
            "-w", "--workers",
            type=int,
            default=5,
            help="Maximum concurrent workers (default: 5)"
        )
        parser.add_argument(
            "-t", "--timeout",
            type=int,
            default=30,
            help="Request timeout in seconds (default: 30)"
        )
        
        # Output options
        parser.add_argument(
            "-o", "--output",
            help="Output filename"
        )
        parser.add_argument(
            "--format",
            choices=[fmt.value for fmt in OutputFormat],
            default="console",
            help="Output format (default: console)"
        )
        parser.add_argument(
            "--show-all",
            action="store_true",
            help="Show all HTTP headers"
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose logging"
        )
        
        args = parser.parse_args()
        
        # Set logging level
        if args.verbose:
            logging.getLogger().setLevel(logging.INFO)
            console.print("[yellow]Verbose mode enabled[/yellow]\n")
        
        # Collect URLs
        all_urls = []
        
        if args.file:
            file_urls = parse_input_file(args.file)
            all_urls.extend(file_urls)
            console.print(f"[green]Loaded {len(file_urls)} URLs from file[/green]")
        
        # Add command line URLs
        for url in args.urls:
            normalized = validate_and_normalize_url(url)
            if normalized:
                all_urls.append(normalized)
            else:
                console.print(f"[yellow]Warning: Invalid URL skipped: {url}[/yellow]")
        
        # If no URLs provided, ask interactively
        if not all_urls:
            console.print("\n[bold]Interactive Mode[/bold]")
            console.print("=" * 50)
            
            while True:
                url_input = console.input("\n[yellow]Enter target URL (or 'quit' to exit): [/yellow]").strip()
                
                if url_input.lower() in ['quit', 'exit', 'q']:
                    console.print("[yellow]Goodbye![/yellow]")
                    sys.exit(0)
                
                if not url_input:
                    console.print("[red]Please enter a URL[/red]")
                    continue
                
                normalized = validate_and_normalize_url(url_input)
                if not normalized:
                    console.print("[red]Invalid URL format. Please include http:// or https://[/red]")
                    continue
                
                all_urls.append(normalized)
                break
        
        # Remove duplicates
        seen = set()
        unique_urls = []
        for url in all_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        console.print(f"\n[green]Found {len(unique_urls)} unique URL(s) to scan[/green]")
        
        if len(unique_urls) == 0:
            console.print("[red]No valid URLs to scan[/red]")
            sys.exit(1)
        
        # Display configuration
        config_panel = Panel.fit(
            f"[bold]Scan Configuration:[/bold]\n"
            f"• URLs: {len(unique_urls)}\n"
            f"• Workers: {args.workers}\n"
            f"• Timeout: {args.timeout}s\n"
            f"• Output Format: {args.format}\n"
            f"• Show All Headers: {args.show_all}",
            border_style="cyan",
            padding=(1, 2)
        )
        console.print(config_panel)
        
        # Perform scan
        console.print("\n[yellow]Starting scan... Press Ctrl+C to stop gracefully[/yellow]\n")
        
        results = []
        
        if len(unique_urls) == 1:
            # Single URL scan
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
                refresh_per_second=10,
            ) as progress:
                task = progress.add_task(
                    f"[cyan]Scanning {unique_urls[0]}...[/cyan]",
                    total=1
                )
                
                try:
                    result = scan_single_url(unique_urls[0])
                    results.append(result)
                    progress.update(task, advance=1)
                except KeyboardInterrupt:
                    console.print("\n[yellow]Scan interrupted[/yellow]")
                    sys.exit(0)
                except Exception as e:
                    console.print(f"[red]Scan failed: {e}[/red]")
                    sys.exit(1)
        else:
            # Multiple URLs scan
            results = scan_multiple_urls(unique_urls, max_workers=args.workers)
        
        # Display results
        console.print(f"\n{'='*60}")
        console.print(f"[bold green]SCAN COMPLETE - {len(results)} URL(S) ANALYZED[/bold green]")
        console.print(f"{'='*60}\n")
        
        successful = 0
        failed = 0
        
        for i, result in enumerate(results, 1):
            if len(results) > 1:
                console.print(f"\n[bold cyan]{'='*50}[/bold cyan]")
                console.print(f"[bold cyan]RESULT {i}/{len(results)}[/bold cyan]")
                console.print(f"[bold cyan]{'='*50}[/bold cyan]\n")
            
            display_result(result, args.show_all)
            
            if result.error:
                failed += 1
            else:
                successful += 1
        
        # Summary
        console.print(f"\n{'='*60}")
        console.print("[bold]Summary:[/bold]")
        console.print(f"  [green]Successful: {successful}[/green]")
        console.print(f"  [red]Failed: {failed}[/red]")
        console.print(f"  [yellow]Total time: {sum(r.scan_time for r in results):.2f}s[/yellow]")
        console.print(f"{'='*60}")
        
        # Export results if requested
        if args.output and results:
            try:
                format_enum = OutputFormat(args.format)
                export_results(results, format_enum, args.output)
            except ValueError as e:
                console.print(f"[red]Invalid format: {e}[/red]")
            except Exception as e:
                console.print(f"[red]Error exporting results: {e}[/red]")
        
        console.print(f"\n[green]✓ All operations completed successfully![/green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown requested. Exiting gracefully...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        logger.exception("Main execution failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
