# <p align="center"><img src="assets/logo.svg" alt="VIPRecon Logo" width="400"><br>VIPRecon - Professional Web Reconnaissance Tool</p>

Developed by **viphacker100 (Aryan Ahirwar)**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

A comprehensive web application reconnaissance and security testing tool designed for ethical security professionals. VIPRecon provides automated scanning capabilities to identify technologies, vulnerabilities, and security misconfigurations in web applications.

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool is designed for **authorized security testing only**. Unauthorized access to computer systems is illegal. Users must:

- Have explicit written permission to test target systems
- Comply with all applicable laws and regulations
- Use this tool responsibly and ethically
- Not use this tool for malicious purposes

The developers assume no liability for misuse of this tool.

## 🚀 Features

VIPRecon includes 16 major reconnaissance and security testing modules:

### Reconnaissance Modules

1. **Basic Information Gathering** - HTTP headers, WHOIS, DNS records, SSL certificate info
2. **Advanced Fingerprinting** - Technology detection (CMS, frameworks, libraries, servers)
3. **Subdomain Enumeration** - DNS brute-force, certificate transparency, search engine discovery
4. **WAF Detection** - Identify web application firewalls (Cloudflare, AWS WAF, etc.)
5. **API Endpoint Discovery** - Find REST APIs, GraphQL endpoints, Swagger/OpenAPI specs

### 🛡️ Security Testing

- **Port Scanner**: identifies open services and potential entry points.
- **Directory Discovery**: Brute-forces common paths to find hidden files and panels.
- **Vulnerability Scanner**: XSS, SQLi, Open Redirects, Path Traversal.
- **CORS Checker**: Misconfiguration detection.
- **JS Analyzer**: Sensitive data extraction (API keys, endpoints).
- **Security Headers**: Audit of security configurations.

### 🚀 Advanced Features

- **Checkpoint & Resume**: Mission-critical resilience; resume any scan exactly where it left off.
- **Webhooks**: Notify completion to Slack or Discord.
- **Diff Tool**: Compare scan results over time.
- **Interactive Shell**: Post-scan result exploration.

## 📋 Requirements

- Python 3.8 or higher
- pip (Python package manager)
- Internet connection (for external lookups)

## 🔧 Installation

### Quick Install

```bash
# Clone the repository
git clone https://VIPHACKER100/viprecon.git
cd viprecon

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Docker Installation

```bash
# Build Docker image
docker build -t viprecon .

# Run with Docker
docker run -v $(pwd)/output:/app/output viprecon -t https://example.com
```

## 🎯 Quick Start

### Basic Scan

```bash
# Full scan with reports
python main.py -t https://example.com -o ./results -f both
```

This will:

- Run all modules against the target
- Generate both JSON and HTML reports
- Save results to `./output/` directory

### Scan Specific Modules

```bash
python main.py -t example.com -m fingerprint,subdomain_enum,vuln_scan
```

### Custom Rate Limit

```bash
python main.py -t example.com --rate-limit 0.5
```

### Using a Proxy

```bash
python main.py -t example.com --proxy http://127.0.0.1:8080
```

### Checkpoint & Resume Usage

VIPRecon automatically saves progress. If a scan is interrupted, you can resume it:

```bash
# Resume using the target domain
python main.py -t example.com --resume example.com

# Resume using a specific checkpoint file
python main.py -t example.com --resume ./output/checkpoint_example.com.json
```

### Notification and Diff Usage

```bash
# Enable Slack notifications
python main.py -t example.com --webhook SLACK_URL --webhook-service slack

# Compare two previous scan results
python main.py --diff results/scan1.json,results/scan2.json

# Interactive mode
python main.py -t example.com --interactive
```

## 📖 Usage

### Command-Line Options

```
usage: main.py [-h] -t TARGET [-m MODULES] [-o OUTPUT] [-f FORMAT] [-v]
               [--rate-limit RATE_LIMIT] [--timeout TIMEOUT] [--interactive]
               [--proxy PROXY] [--user-agent USER_AGENT] [--wordlist WORDLIST]

VIPRecon - Web Application Reconnaissance Tool

required arguments:
  -t, --target TARGET          Target URL or domain

optional arguments:
  -h, --help                   Show this help message and exit
  -m, --modules MODULES        Comma-separated list of modules to run
                               (default: all)
  -o, --output OUTPUT          Output directory (default: ./output)
  -f, --format FORMAT          Output format: json, html, both (default: both)
  -v, --verbose                Enable verbose logging
  --rate-limit RATE_LIMIT      Requests per second (default: 1)
  --timeout TIMEOUT            Request timeout in seconds (default: 30)
  --interactive                Launch interactive mode after scan
  --proxy PROXY                Proxy URL (e.g., http://127.0.0.1:8080)
  --user-agent USER_AGENT      Custom User-Agent string
  --wordlist WORDLIST          Path to custom wordlist
```

### Available Modules

- `basic_info` - Basic information gathering
- `fingerprint` - Technology fingerprinting
- `subdomain_enum` - Subdomain enumeration
- `waf_detect` - WAF detection
- `api_discovery` - API endpoint discovery
- `vuln_scan` - Vulnerability scanning
- `cors_check` - CORS misconfiguration check
- `js_analysis` - JavaScript analysis
- `security_headers` - Security headers audit
- `port_scan` - Network port scanning
- `dir_brute` - Directory discovery

## 📊 Output Formats

### JSON Report

Machine-readable format for integration with other tools:

```json
{
  "scan_metadata": {
    "target": "https://example.com",
    "start_time": "2026-02-12T12:00:00",
    "duration_seconds": 45.2
  },
  "technologies": [...],
  "vulnerabilities": [...],
  "subdomains": [...]
}
```

### HTML Report

Professional, human-readable report with:

- Executive summary
- Vulnerability breakdown by severity
- Technology stack visualization
- Detailed findings with remediation advice

## ⚙️ Configuration

Edit `config/default_config.yaml` to customize:

- HTTP client settings (timeout, retries, user-agent)
- Rate limiting parameters
- Module-specific settings
- Output preferences
- Logging configuration

Example configuration:

```yaml
http:
  timeout: 30
  max_retries: 3
  user_agent: "VIPRecon/1.0"

rate_limit:
  requests_per_second: 1.0

modules:
  vulnerability_scanner:
    check_xss: true
    check_sqli: true
```

## 🔐 Authentication

VIPRecon supports scanning authenticated sections:

```bash
# Basic Authentication
python -m src.main -t example.com --auth-type basic --auth-username user --auth-password pass

# Bearer Token
python -m src.main -t example.com --auth-type bearer --auth-token YOUR_TOKEN

# Cookie Authentication
python -m src.main -t example.com --auth-type cookie --auth-cookie "session=abc123"
```

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/core/test_http_client.py
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Lead Developer**: viphacker100 (Aryan Ahirwar)
- Built with Python and asyncio for high performance
- Uses industry-standard security testing methodologies
- Inspired by tools like Nmap, Nikto, and OWASP ZAP

## 📧 Contact

For questions, issues, or feature requests:

- Open an issue on GitHub
- Reach out to **viphacker100 (Aryan Ahirwar)**
- Email: <viphacker.100.org@gmail.com>

## 🗺️ Roadmap

Planned features for future releases:

- Machine learning-based anomaly detection
- GraphQL security testing
- WebSocket vulnerability scanning
- CI/CD pipeline integration
- Centralized dashboard for multiple scans
- Compliance reporting (OWASP Top 10, PCI DSS)

---

**Remember:** Always obtain proper authorization before testing any system you don't own!

