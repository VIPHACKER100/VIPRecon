# VIPRecon Usage Guide

Developed by **viphacker100 (Aryan Ahirwar)**

**Version**: 1.0.1

This guide provides detailed instructions and examples for using VIPRecon effectively.

## What's New in v1.0.1

- Improved checkpoint/resume reliability
- Enhanced rate limiting with proper token bucket algorithm
- Better path traversal detection
- All unit tests passing (15/15)
- Enhanced error handling and type safety

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

- `basic_info` - HTTP headers, WHOIS, DNS, and SSL certificate information
- `fingerprint` - Technology and framework detection
- `subdomain_enum` - Subdomain discovery via DNS brute-force and certificate transparency
- `waf_detect` - Web Application Firewall identification
- `api_discovery` - API endpoint discovery from JavaScript and page analysis
- `vuln_scan` - Vulnerability scanning (XSS, SQLi, Open Redirects)
- `cors_check` - CORS misconfiguration detection
- `js_analysis` - JavaScript analysis for secrets and endpoints
- `security_headers` - Security headers audit
- `port_scan` - Network port scanning
- `dir_brute` - Directory and file brute-forcing

### 2. Checkpoint & Resume

VIPRecon automatically saves progress after each module completes. Checkpoints are stored in JSON format in the output directory.

```bash
# Resume by specifying the target
python main.py -t viphacker100.com --resume viphacker100.com

# Resume from a specific checkpoint file
python main.py -t example.com --resume ./output/checkpoint_example.com.json
```

**How it works:**
- Checkpoint created after each successfully completed module
- Stores all findings, metadata, and module progress
- Automatically cleans up checkpoint on successful completion
- Resume from any interruption (network issues, crashes, user cancel)

### 3. Rate Limiting

Control request frequency to avoid overwhelming target servers (default is 1.0 req/s):

```bash
# Slow scan (0.5 requests per second)
python main.py -t example.com --rate-limit 0.5

# Fast scan (10 requests per second) - use with caution
python main.py -t example.com --rate-limit 10
```

**Note**: Uses token bucket algorithm for smooth rate limiting with burst capability.

### 4. Using a Proxy

Useful for debugging or routing through Burp Suite/ZAP:

```bash
python main.py -t example.com --proxy http://127.0.0.1:8080 --no-verify-ssl
```

### 5. Interactive Mode

Explore findings after the scan completes with an interactive shell:

```bash
python main.py -t example.com --interactive
```

**Features:**
- Query scan results with custom filters
- Export specific findings
- Compare with previous scans
- Generate custom reports on-demand

### 6. Authentication

Scan authenticated areas of a web application:

```bash
# Bearer Token
python main.py -t example.com --auth-type bearer --auth-token YOUR_TOKEN

# Basic Authentication
python main.py -t example.com --auth-type basic --auth-username admin --auth-password secret

# Cookies
python main.py -t example.com --auth-type cookie --auth-cookie "session=123; user=admin"
```

### 7. Notifications

Get notified when scans complete via webhooks:

```bash
# Slack notification
python main.py -t example.com --webhook https://hooks.slack.com/services/xxx --webhook-service slack

# Discord notification
python main.py -t example.com --webhook https://discord.com/api/webhooks/xxx --webhook-service discord
```

### 8. Comparing Scans

Compare two scan results to identify changes:

```bash
python main.py --diff report1.json,report2.json
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

### Common Issues

**SSL Certificate Errors**
```bash
# Disable SSL verification for internal sites with self-signed certificates
python main.py -t example.com --no-verify-ssl
```

**Slow Server Response**
```bash
# Increase timeout for slow-responding servers
python main.py -t example.com --timeout 60
```

**Verbose Logging**
```bash
# Enable debug logging for troubleshooting
python main.py -t example.com -v
```

**Connection Issues**
```bash
# Use a proxy for debugging (e.g., Burp Suite, OWASP ZAP)
python main.py -t example.com --proxy http://127.0.0.1:8080
```

**Resume Interrupted Scans**
```bash
# If a scan was interrupted, resume from checkpoint
python main.py -t example.com --resume example.com
```

### Performance Tips

- Use `--rate-limit` to avoid overwhelming the target server
- For large scopes, consider running modules individually
- Use `-o` to specify a custom output directory for organization
- Enable checkpoints for long-running scans

## Best Practices

1. **Always obtain proper authorization** before scanning any target
2. **Start with a slow rate limit** on production systems
3. **Use checkpoints** for critical long-running scans
4. **Review findings manually** - automated tools can produce false positives
5. **Keep the tool updated** for the latest security checks

---

**Legal Disclaimer**: Unauthorized scanning of computer systems is illegal. Always obtain proper authorization before testing any target.
