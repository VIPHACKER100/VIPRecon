# VIPRecon Usage Guide

Developed by **viphacker100 (Aryan Ahirwar)**

This guide provides detailed instructions and examples for using VIPRecon effectively.

## Installation

```bash
# Clone the repository
git clone https://github.com/youruser/VIPRecon.git
cd VIPRecon

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Basic Scanning

Run a full scan with default settings:

```bash
python main.py -t https://example.com
```

## Advanced Options

### 1. Specific Modules

Run only the technology fingerprinting and subdomain discovery:

```bash
python main.py -t example.com -m fingerprint,subdomain_enum
```

Available modules:

- `basic_info`
- `fingerprint`
- `subdomain_enum`
- `waf_detect`
- `api_discovery`
- `vuln_scan`
- `cors_check`
- `js_analysis`
- `security_headers`
- `port_scan` (New)
- `dir_brute` (New)

### 2. Checkpoint & Resume (New)

VIPRecon saves progress automatically. If a scan is stopped, you can resume it from the last completed module:

```bash
# Resume by specifying the target
python main.py -t viphacker100.com --resume viphacker100.com
```

### 3. Rate Limiting

Control how fast VIPRecon sends requests (default is 1.0):

```bash
# Slow scan (0.5 requests per second)
python main.py -t example.com --rate-limit 0.5
```

### 3. Using a Proxy

Useful for debugging or routing through Burp Suite/ZAP:

```bash
python main.py -t example.com --proxy http://127.0.0.1:8080 --no-verify-ssl
```

### 4. Interactive Mode

Explore findings after the scan completes:

```bash
python main.py -t example.com --interactive
```

### 5. Authentication

Scan authenticated areas of a web application:

```bash
# Bearer Token
python main.py -t example.com --auth-type bearer --auth-token YOUR_TOKEN

# Cookies
python main.py -t example.com --auth-type cookie --auth-cookie "session=123; user=admin"
```

## Output & Reporting

By default, reports are saved in the `./output` directory.

- **JSON**: Machine-readable format for integration with other tools.
- **HTML**: Human-readable report with charts and detailed findings.

Specify custom output directory:

```bash
python main.py -t example.com -o ./my_project_results
```

## Troubleshooting

- **Large Output**: Use `-v` to see detailed debug logs.
- **SSL Errors**: Use `--no-verify-ssl` if testing internal sites with self-signed certificates.
- **Slow Discovery**: Increase the `--timeout` value if the server is slow to respond.

---

**Legal Disclaimer**: Unauthorized scanning of computer systems is illegal. Always obtain proper authorization before testing any target.
