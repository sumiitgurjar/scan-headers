#!/usr/bin/env python3
# ============================================================================
#  Security Headers Scanner (SHS-Scan)
#  Professional HTTP security header analysis tool
#  Version: 2.0.1
# ============================================================================

import sys
import os
import time
import signal
import socket
import json
import csv
import random
import ssl
import threading
import subprocess
import logging
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone
import concurrent.futures

# ============================================================================
# Dependency Management
# ============================================================================

class DependencyManager:
    """Professional dependency management for SHS-Scan"""
    
    REQUIRED_PACKAGES = {
        'requests': 'requests>=2.31.0',
        'urllib3': 'urllib3>=2.0.0',
        'rich': 'rich>=13.0.0',
        'tenacity': 'tenacity>=8.0.0'
    }
    
    @staticmethod
    def check_package(module_name: str) -> bool:
        """Check if a package is installed"""
        try:
            __import__(module_name)
            return True
        except ImportError:
            return False
    
    @staticmethod
    def install_package(package_spec: str, quiet: bool = True) -> bool:
        """Install a package using pip"""
        try:
            cmd = [sys.executable, "-m", "pip", "install"]
            if quiet:
                cmd.append("-q")
            cmd.append(package_spec)
            
            subprocess.check_call(
                cmd,
                stdout=subprocess.DEVNULL if quiet else None,
                stderr=subprocess.DEVNULL if quiet else None
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    @staticmethod
    def update_package(package_name: str, quiet: bool = True) -> bool:
        """Update a package to latest version"""
        try:
            cmd = [sys.executable, "-m", "pip", "install", "--upgrade"]
            if quiet:
                cmd.append("-q")
            cmd.append(package_name)
            
            subprocess.check_call(
                cmd,
                stdout=subprocess.DEVNULL if quiet else None,
                stderr=subprocess.DEVNULL if quiet else None
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    @classmethod
    def check_dependencies(cls, auto_install: bool = True, show_progress: bool = False) -> bool:
        """
        Check and optionally install missing dependencies
        Returns True if all dependencies are satisfied
        """
        missing = []
        
        # Check which packages are missing
        for module_name in cls.REQUIRED_PACKAGES.keys():
            if not cls.check_package(module_name):
                missing.append(module_name)
        
        if not missing:
            return True
        
        if not auto_install:
            print(f"[!] Missing dependencies: {', '.join(missing)}")
            print(f"[!] Install with: pip install {' '.join(cls.REQUIRED_PACKAGES.values())}")
            return False
        
        # Install missing packages
        if show_progress:
            print(f"[*] Installing {len(missing)} missing dependencies...")
        
        for module_name in missing:
            package_spec = cls.REQUIRED_PACKAGES[module_name]
            
            if show_progress:
                print(f"[*] Installing {package_spec}...", end=" ", flush=True)
            
            if cls.install_package(package_spec, quiet=not show_progress):
                if show_progress:
                    print("✓")
            else:
                if show_progress:
                    print("✗")
                print(f"[!] Failed to install {package_spec}")
                return False
        
        return True
    
    @classmethod
    def update_dependencies(cls, quiet: bool = True) -> Dict[str, bool]:
        """
        Update all dependencies to latest versions
        Returns dict of package_name: success_status
        """
        results = {}
        
        if not quiet:
            print("[*] Updating dependencies...")
        
        for module_name, package_spec in cls.REQUIRED_PACKAGES.items():
            package_name = package_spec.split('>=')[0]
            
            if not quiet:
                print(f"[*] Updating {package_name}...", end=" ", flush=True)
            
            success = cls.update_package(package_name, quiet=quiet)
            results[package_name] = success
            
            if not quiet:
                print("✓" if success else "✗")
        
        return results


# ============================================================================
# Bootstrap Process
# ============================================================================

def bootstrap():
    """Bootstrap the application with dependency checks"""
    
    # Print banner first
    banner = r"""
     (\_/)
     ( •_•)
    / >🍪   Security Headers Scan v2.0
    """
    print(banner)
    print("SHS-Scan: Security Headers Scanner")
    #print("=" * 60)
    
    # Check for --update-deps flag
    update_deps = any(arg in ("--update-deps", "-U") for arg in sys.argv)
    
    # Check and install dependencies
    if not DependencyManager.check_dependencies(auto_install=True, show_progress=True):
        print("[!] Failed to satisfy dependencies")
        sys.exit(1)
    
    # Update dependencies if requested
    if update_deps:
        print("\n[*] Updating dependencies to latest versions...")
        results = DependencyManager.update_dependencies(quiet=False)
        
        failed = [pkg for pkg, status in results.items() if not status]
        if failed:
            print(f"[!] Failed to update: {', '.join(failed)}")
        else:
            print("[✓] All dependencies updated successfully")
    
    print("=" * 60)
    print()


# Run bootstrap
bootstrap()

# ============================================================================
# Import Third-Party Dependencies
# ============================================================================

import requests
import urllib3
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
    retry_if_exception_type,
)

# ============================================================================
# Configuration
# ============================================================================

# Install rich traceback handler
install_rich_traceback()

# Suppress SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)
logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.WARNING)

console = Console()

# Global state
SHUTDOWN_REQUESTED = False
FOLLOW_REDIRECTS = True
DNS_CACHE = {}
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 30

# ============================================================================
# Data Structures
# ============================================================================

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


# ============================================================================
# Security Headers Database
# ============================================================================

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

DEPRECATED_HEADERS = {
    "X-Frame-Options": "Deprecated: Use Content-Security-Policy frame-ancestors instead.",
    "X-XSS-Protection": "Deprecated: Use Content-Security-Policy instead.",
    "Public-Key-Pins": "Deprecated: Use Certificate Transparency instead.",
    "Expect-CT": "Deprecated: No longer recommended by MDN.",
}

BEST_PRACTICE_CHECKS = [
    {
        "name": "Strict-Transport-Security",
        "required": True,
        "check": lambda v: v and "max-age=" in v and "includeSubDomains" in v and "preload" in v,
        "recommendation": "Set Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
    },
    {
        "name": "Content-Security-Policy",
        "required": True,
        "check": lambda v: v and "default-src" in v and "'self'" in v,
        "recommendation": "Set Content-Security-Policy: default-src 'self'"
    },
    {
        "name": "X-Content-Type-Options",
        "required": True,
        "check": lambda v: v and v.strip().lower() == "nosniff",
        "recommendation": "Set X-Content-Type-Options: nosniff"
    },
    {
        "name": "Referrer-Policy",
        "required": False,
        "check": lambda v: v and v.strip().lower() in ["origin-when-cross-origin", "strict-origin-when-cross-origin", "no-referrer", "same-origin"],
        "recommendation": "Set Referrer-Policy: origin-when-cross-origin or stricter"
    },
    {
        "name": "Cache-Control",
        "required": False,
        "check": lambda v: v and "no-store" in v,
        "recommendation": "Set Cache-Control: no-store for sensitive endpoints"
    },
    {
        "name": "Permissions-Policy",
        "required": False,
        "check": lambda v: v and ("microphone=()" in v or "camera=()" in v or "geolocation=()" in v),
        "recommendation": "Set Permissions-Policy: microphone=(), camera=(), geolocation=()"
    },
    {
        "name": "Access-Control-Allow-Origin",
        "required": False,
        "check": lambda v: v and v.strip() != "*",
        "recommendation": "Avoid Access-Control-Allow-Origin: * (use specific origins)"
    },
    {
        "name": "Clear-Site-Data",
        "required": False,
        "check": lambda v: v and "*" in v,
        "recommendation": "Set Clear-Site-Data: * for logout endpoints"
    },
]

SECURITY_HEADER_NAMES: List[str] = list(SECURITY_HEADERS.keys())
SECURITY_HEADER_LOWER_SET: Set[str] = {h.lower() for h in SECURITY_HEADER_NAMES}

# ============================================================================
# Core Functions
# ============================================================================

def validate_and_normalize_url(url: str) -> Optional[str]:
    """Validate and normalize URL"""
    if not url or not isinstance(url, str):
        return None
    
    url = url.strip()
    
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    try:
        parsed = urlparse(url)
        
        if not parsed.netloc:
            return None
        
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


def build_robust_session() -> requests.Session:
    """Build a robust HTTP session with intelligent retry and connection handling"""
    session = requests.Session()
    retry_strategy = Retry(
        total=0,
        backoff_factor=1.0,
        status_forcelist=[408, 429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=20,
        pool_maxsize=20,
        pool_block=False,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    return session


@retry(
    retry=retry_if_exception_type((
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
        socket.timeout,
    )),
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=1, min=2, max=10),
)
def scan_single_url(url: str) -> ScanResult:
    """Scan a single URL for security headers"""
    global SHUTDOWN_REQUESTED, FOLLOW_REDIRECTS, DNS_CACHE
    
    if SHUTDOWN_REQUESTED:
        raise KeyboardInterrupt("Shutdown requested")
    
    start_time = time.perf_counter()
    retries_used = 0
    
    try:
        session = build_robust_session()
        
        time.sleep(random.uniform(0.1, 0.5))
        
        response = session.get(
            url,
            allow_redirects=FOLLOW_REDIRECTS,
            verify=False,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            stream=False
        )
        
        all_responses = []
        if hasattr(response, 'history'):
            all_responses.extend(response.history)
        all_responses.append(response)
        
        final_response = response
        
        headers_lower = {k.lower(): v for k, v in final_response.headers.items()}
        
        present_headers = [h for h in SECURITY_HEADER_NAMES if h.lower() in headers_lower]
        missing_headers = [h for h in SECURITY_HEADER_NAMES if h not in present_headers]
        
        server_info = final_response.headers.get('Server', '')
        
        ip_address = None
        try:
            domain = urlparse(final_response.url).netloc
            if domain in DNS_CACHE:
                ip_address = DNS_CACHE[domain]
            else:
                try:
                    ip_address = socket.gethostbyname(domain)
                    DNS_CACHE[domain] = ip_address
                except (socket.gaierror, socket.error):
                    ip_address = None
        except Exception:
            ip_address = None
        
        redirect_chain = [resp.url for resp in all_responses]
        
        scan_time = time.perf_counter() - start_time
        
        return ScanResult(
            url=url,
            status_code=final_response.status_code,
            headers=dict(final_response.headers),
            missing_headers=missing_headers,
            present_headers=present_headers,
            scan_time=scan_time,
            redirect_chain=redirect_chain,
            final_url=final_response.url,
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
    """Scan multiple URLs concurrently"""
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
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(max_workers, len(urls)),
            thread_name_prefix="shs-scanner"
        ) as executor:
            future_to_url = {}
            for url in urls:
                if SHUTDOWN_REQUESTED:
                    break
                
                future = executor.submit(scan_single_url, url)
                future_to_url[future] = url
            
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


def display_result(result: ScanResult, show_all: bool = False, remove_headers: Set[str] = None):
    """Display scan result in console"""
    if remove_headers is None:
        remove_headers = set()
    
    if result.error:
        console.print(Panel.fit(
            f"Error Scanning: {result.url}\n"
            f"Error: {result.error}",
            title="Scan Failed",
            border_style="red",
        ))
        return

    summary_panel = Panel.fit(
        f"Target: {result.url}\n"
        f"Final URL: {result.final_url or result.url}\n"
        f"Status Code: {result.status_code}\n"
        f"Server: {result.server or 'Not disclosed'}\n"
        f"IP Address: {result.ip_address or 'Unknown'}\n"
        f"Scan Time: {result.scan_time:.3f}s\n"
        f"Retries Used: {result.retries_used}",
        title="Scan Summary",
        border_style="cyan",
    )
    console.print(summary_panel)
    console.print(f"[red]Missing Headers: {len(result.missing_headers)}/{len(SECURITY_HEADERS)}[/red]")

    table = Table(
        title="HTTP Security Headers Analysis",
        show_lines=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Header", style="cyan", no_wrap=True, ratio=1)
    table.add_column("Status", justify="center", ratio=1)
    table.add_column("Description", no_wrap=False, ratio=2)
    table.add_column("Recommendation", no_wrap=False, ratio=2)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_headers = sorted(
        SECURITY_HEADERS.items(),
        key=lambda x: severity_order.get(x[1].severity, 4)
    )

    for header_name, header_info in sorted_headers:
        if header_name.lower() in remove_headers:
            continue
        
        is_present = header_name in result.present_headers
        recommendation_text = ""
        
        if header_name in DEPRECATED_HEADERS:
            if header_name == "X-Frame-Options":
                recommendation_text = "[yellow]DEPRECATED[/yellow]: Use Content-Security-Policy frame-ancestors directive instead. Set: Content-Security-Policy: frame-ancestors 'self'"
            elif header_name == "X-XSS-Protection":
                recommendation_text = "[yellow]DEPRECATED[/yellow]: Use Content-Security-Policy instead. Set: Content-Security-Policy: default-src 'self'; script-src 'self'"
            elif header_name == "Public-Key-Pins":
                recommendation_text = "[yellow]DEPRECATED[/yellow]: Use Certificate Transparency logs instead"
            elif header_name == "Expect-CT":
                recommendation_text = "[yellow]DEPRECATED[/yellow]: Remove this header. Use certificate transparency instead"
            else:
                recommendation_text = f"[yellow]DEPRECATED[/yellow]: {DEPRECATED_HEADERS[header_name]}"
        else:
            best_practice_check = None
            for check in BEST_PRACTICE_CHECKS:
                if check["name"] == header_name:
                    best_practice_check = check
                    break
            
            v = result.headers.get(header_name, None)
            
            if best_practice_check:
                if not v and best_practice_check["required"]:
                    recommendation_text = f"[red]REQUIRED[/red]: {best_practice_check['recommendation']}"
                elif v and not best_practice_check["check"](v):
                    recommendation_text = f"[yellow]WEAK CONFIG[/yellow]: {best_practice_check['recommendation']}"
                elif is_present:
                    recommendation_text = f"[green]OK[/green]: {v[:70]}..." if len(v) > 70 else f"[green]OK[/green]: {v}"
                else:
                    recommendation_text = f"[yellow]NOT SET[/yellow]: {best_practice_check['recommendation']}"
            else:
                if is_present:
                    v_val = result.headers.get(header_name, "")
                    recommendation_text = f"[green]OK[/green]: {v_val[:70]}..." if len(v_val) > 70 else f"[green]OK[/green]: {v_val}"
                else:
                    recommendation_text = f"[yellow]NOT SET[/yellow]: {header_info.recommendation}"
        
        status_cell = "[green]✓ PRESENT[/green]" if is_present else "[red]✗ MISSING[/red]"
        
        table.add_row(
            f"[cyan]{header_name}[/cyan]",
            status_cell,
            header_info.description,
            recommendation_text
        )
    
    console.print(table)

    if show_all and result.headers:
        console.print("\n[bold cyan]All HTTP Headers:[/bold cyan]")
        headers_table = Table(show_header=True, header_style="bold cyan")
        headers_table.add_column("Header")
        headers_table.add_column("Value")
        for header, value in sorted(result.headers.items()):
            if len(value) > 100:
                value = value[:97] + "..."
            headers_table.add_row(header, value)
        console.print(headers_table)


def export_results(results: List[ScanResult], format: OutputFormat, filename: str):
    """Export scan results to file"""
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
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Headers Scan Report - SHS-Scan</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; font-weight: 600; }}
        .present {{ color: #27ae60; font-weight: 600; }}
        .missing {{ color: #e74c3c; font-weight: 600; }}
        .error {{ background-color: #ffebee; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #e74c3c; }}
        .footer {{ margin-top: 40px; text-align: center; color: #7f8c8d; font-size: 0.9em; padding-top: 20px; border-top: 1px solid #ecf0f1; }}
        .meta {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Headers Scan Report</h1>
        <div class="meta">
            <p><strong>Generated:</strong> {timestamp}</p>
            <p><strong>Total URLs Scanned:</strong> {len(results)}</p>
            <p><strong>Tool:</strong> SHS-Scan v2.0</p>
        </div>
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
        <h2>📋 {result.url}</h2>
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
            <p><strong>Generated by SHS-Scan - Security Headers Scanner</strong></p>
            <p>Report generated on {timestamp}</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


def generate_markdown_report(results: List[ScanResult]) -> str:
    """Generate Markdown report"""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    markdown = f"""# 🔒 Security Headers Scan Report

**Generated:** {timestamp}  
**Total URLs Scanned:** {len(results)}  
**Tool:** SHS-Scan v2.0

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
---

*Generated by SHS-Scan - Security Headers Scanner on {timestamp}*
"""
    
    return markdown


def parse_input_file(filename: str) -> List[str]:
    """Parse input file containing URLs"""
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
    global SHUTDOWN_REQUESTED, FOLLOW_REDIRECTS, READ_TIMEOUT, CONNECT_TIMEOUT
    
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description="SHS-Scan - Security Headers Scanner v2.0",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s -f urls.txt
  %(prog)s url1 url2 url3
  %(prog)s -f urls.txt -o report.json --format json
  %(prog)s --update-deps https://example.com
            """
        )
        
        parser.add_argument(
            "--update-deps", "-U",
            action="store_true",
            help="Update dependencies to latest versions"
        )
        
        parser.add_argument(
            "urls",
            nargs="*",
            help="URL(s) to scan"
        )
        parser.add_argument(
            "-f", "--file",
            help="File containing list of URLs"
        )
        
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
        parser.add_argument(
            "--connect-timeout",
            type=int,
            default=5,
            help="TCP connect timeout in seconds (default: 5)"
        )
        
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
        parser.add_argument(
            "--no-follow-redirects",
            dest="follow_redirects",
            action="store_false",
            help="Do not follow HTTP redirects",
        )
        parser.add_argument(
            "--remove-header",
            type=str,
            default="",
            help="Comma-separated list of headers to exclude from analysis"
        )
        
        args = parser.parse_args()
        
        if args.verbose:
            logging.getLogger().setLevel(logging.INFO)
            console.print("[cyan]Verbose mode enabled[/cyan]\n")

        FOLLOW_REDIRECTS = bool(getattr(args, 'follow_redirects', True))
        if not FOLLOW_REDIRECTS:
            console.print("[yellow]Redirect following disabled[/yellow]\n")
        
        READ_TIMEOUT = int(args.timeout)
        CONNECT_TIMEOUT = int(getattr(args, 'connect_timeout', CONNECT_TIMEOUT))
        console.print(f"[cyan]Timeouts - Connect: {CONNECT_TIMEOUT}s, Read: {READ_TIMEOUT}s[/cyan]\n")
        
        all_urls = []
        
        if args.file:
            file_urls = parse_input_file(args.file)
            all_urls.extend(file_urls)
            console.print(f"[cyan]Loaded {len(file_urls)} URLs from file[/cyan]")
        
        for url in args.urls:
            normalized = validate_and_normalize_url(url)
            if normalized:
                all_urls.append(normalized)
            else:
                console.print(f"[yellow]Warning: Invalid URL skipped: {url}[/yellow]")
        
        if not all_urls:
            console.print("\n[bold cyan]Interactive Mode[/bold cyan]")
            #console.print("=" * 60)
            
            while True:
                url_input = console.input("\nEnter target URL (or 'quit' to exit): ").strip()
                
                if url_input.lower() in ['quit', 'exit', 'q']:
                    console.print("[cyan]Goodbye![/cyan]")
                    sys.exit(0)
                
                if not url_input:
                    console.print("[yellow]Please enter a URL[/yellow]")
                    continue
                
                normalized = validate_and_normalize_url(url_input)
                if not normalized:
                    console.print("[yellow]Invalid URL format. Please include http:// or https://[/yellow]")
                    continue
                
                all_urls.append(normalized)
                break
        
        seen = set()
        unique_urls = []
        for url in all_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        if len(unique_urls) == 0:
            console.print("[red]No valid URLs to scan[/red]")
            sys.exit(1)
        
        console.print("\n[bold green]Starting Security Headers Scan[/bold green]\n")
        
        results = []
        
        if len(unique_urls) == 1:
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
            results = scan_multiple_urls(unique_urls, max_workers=args.workers)
        
        successful = 0
        failed = 0
        
        remove_headers = set()
        if args.remove_header:
            remove_headers = {h.strip().lower() for h in args.remove_header.split(',') if h.strip()}
        
        for i, result in enumerate(results, 1):
            if len(results) > 1:
                console.print(f"\n{'='*60}")
                console.print(f"[bold cyan]RESULT {i}/{len(results)}[/bold cyan]")
                console.print(f"{'='*60}\n")
            display_result(result, args.show_all, remove_headers)
            if result.error:
                failed += 1
            else:
                successful += 1
        
        console.print(f"\n{'='*60}")
        console.print("[bold cyan]Summary:[/bold cyan]")
        console.print(f"    [green]✓[/green] Successful: {successful}")
        if failed > 0:
            console.print(f"    [red]✗[/red] Failed: {failed}")
        console.print(f"    Total time: {sum(r.scan_time for r in results):.2f}s")
        console.print(f"{'='*60}")
        
        if args.output and results:
            try:
                format_enum = OutputFormat(args.format)
                export_results(results, format_enum, args.output)
            except ValueError as e:
                console.print(f"[red]Invalid format: {e}[/red]")
            except Exception as e:
                console.print(f"[red]Error exporting results: {e}[/red]")
        
        console.print(f"\n[green]✓[/green] All operations completed successfully!\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutdown requested...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        logger.exception("Main execution failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
