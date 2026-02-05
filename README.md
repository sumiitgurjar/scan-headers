**SecureHeadersScan**

A Python Script to scan websites for HTTP security headers c.

**Installation**

**Prerequisites**

- Python 3.8 or higher
- pip (Python package manager)

**Install Dependencies**

```
pip install requests rich tenacity

```

**Download the Script**

```
curl -O https://raw.githubusercontent.com/sumiitgurjar/scan-headers/refs/heads/main/security_header_scan.py
chmod +x security_header_scan.py

```

**Basic Usage**

**Scan a Single Website**

```
python3 security_header_scan.py <https://example.com>

```

**Scan Multiple Websites**

```
python3 security_header_scan.py <https://example.com> <https://google.com> <https://github.com>

```

**Scan Websites from a File**

```
python3 security_header_scan.py -f urls.txt

```

**File Format for URLs**

Create a file (`urls.txt`) with one URL per line:

```
<https://example.com>
<https://google.com>
<https://github.com>

```

**Advanced Options**

**Control Number of Concurrent Scans**

```
python3 security_header_scan.py -f urls.txt -w 5

```

**Set Request Timeout**

```
python3 security_header_scan.py <https://example.com> -t 60

```

**Save Results to File**

```
# Save as JSON
python3 security_header_scan.py <https://example.com> -o results.json --format json

# Save as CSV
python3 security_header_scan.py -f urls.txt -o results.csv --format csv

# Save as HTML report
python3 security_header_scan.py -f urls.txt -o report.html --format html

```

**Show All Headers**

```
python3 security_header_scan.py <https://example.com> --show-all

```

**Enable Detailed Logging**

```
python3 security_header_scan.py <https://example.com> --verbose

```

**Examples**

1. **Basic scan:**

```
python3 security_header_scan.py <https://example.com>

```

1. **Batch scan with 10 workers:**

```
python3 security_header_scan.py -f urls.txt -w 10

```

**Stopping the Scan**

Press `Ctrl+C` at any time to stop.

**Common Issues**

**Connection Errors**

If you get connection errors, try:

- Increasing timeout: `t 60`
- Reducing workers: `w 2`
- Checking if the site is accessible from browser

**SSL Errors**

The tool verifies SSL certificates by default. If you encounter SSL errors, ensure:

- Your system certificates are up to date
- The website has a valid SSL certificate

**Slow Responses**

Some websites may respond slowly. Use `-t 60` to increase timeout.

**Output Formats**

**Console (Default)**

Color-coded table output showing present/missing headers.

**JSON**

```
[
  {
    "url": "<https://example.com>",
    "status_code": 200,
    "headers": {...},
    "missing_headers": [...],
    "present_headers": [...],
    "scan_time": 1.234
  }
]

```

**Quick Start Commands**

```
# Install and run basic scan
pip install requests rich tenacity
python3 security_header_scan.py <https://example.com>

# Install and run batch scan
pip install requests rich tenacity
python3 security_header_scan.py -f urls.txt

# Install and run with all options
pip install requests rich tenacity
python3 security_header_scan.py -f urls.txt -w 10 -o results.json --format json --verbose

```

**Notes**

- Use responsibly and only scan websites you own or have permission to test.
- Results are for informational purposes only
