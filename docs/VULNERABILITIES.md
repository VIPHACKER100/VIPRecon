# VIPRecon Vulnerability Reference

**Version**: 1.0.1

This document describes the security vulnerabilities scanned by VIPRecon, their potential impact, and detection methods.

## Severity Levels

VIPRecon categorizes findings using the following severity scale:

- **CRITICAL**: Immediate risk of system compromise or data breach. Requires immediate attention.
- **HIGH**: Significant security weakness that could lead to compromise. Should be fixed promptly.
- **MEDIUM**: Moderate risk issues that should be addressed in the next maintenance cycle.
- **LOW**: Minor issues with limited impact. Fix when convenient.
- **INFO**: Informational findings that don't pose direct security risks but provide useful context.

## 1. Cross-Site Scripting (XSS)

**Severity**: HIGH to CRITICAL

- **Detection Module**: `vuln_scanner.py`
- **Method**: 
  - Reflective payload testing in URL parameters
  - Testing various contexts (HTML, JavaScript, URL, CSS)
  - Payloads: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `javascript:alert(1)`
- **Impact**: 
  - Attacker can execute arbitrary JavaScript in the victim's browser
  - Session theft via cookie access
  - Keylogging and credential harvesting
  - Site defacement
  - Phishing attacks using the trusted domain
- **Remediation**: 
  - Implement context-appropriate output encoding (HTML, JavaScript, URL, CSS)
  - Use Content Security Policy (CSP) headers
  - Implement input validation and sanitization
  - Use modern frameworks that auto-escape output (React, Vue, Angular)
  - Enable XSS protection headers (X-XSS-Protection)

## 2. SQL Injection (SQLi)

**Severity**: CRITICAL

- **Detection Module**: `vuln_scanner.py`
- **Method**: 
  - Injecting SQL-specific characters (`'`, `"`, `;`, `--`, `/*`)
  - Error-based detection (database error messages)
  - Time-based blind SQLi detection
  - Boolean-based blind SQLi detection
  - Common payloads: `1' OR '1'='1`, `1; DROP TABLE users--`, `" OR ""="`
- **Impact**: 
  - Unauthorized access to entire database
  - Data exfiltration (customer data, passwords, financial records)
  - Data modification or deletion
  - Authentication bypass
  - Server compromise (via xp_cmdshell, UDFs)
  - Complete system takeover in severe cases
- **Remediation**: 
  - Use parameterized queries/prepared statements exclusively
  - Use ORM frameworks that handle SQL safely
  - Input validation using allow-lists
  - Apply principle of least privilege to database accounts
  - Enable database query logging and monitoring
  - Regular security audits and penetration testing

## 3. CORS Misconfiguration

**Severity**: HIGH

- **Detection Module**: `cors_checker.py`
- **Method**: 
  - Testing `Origin` header reflections
  - Checking wildcard origins (`*`)
  - Testing credential inclusion with reflected origins
  - Null origin testing
  - Subdomain trust exploitation
- **Impact**: 
  - Allows malicious websites to read sensitive data from the target domain
  - Session hijacking on behalf of authenticated users
  - API key theft
  - Bypass of same-origin policy protections
  - Cross-origin data theft
- **Remediation**: 
  - Set explicit `Access-Control-Allow-Origin` values (never use wildcards with credentials)
  - Avoid `Access-Control-Allow-Credentials: true` with reflected origins
  - Validate origins against strict allow-lists
  - Implement proper Vary: Origin headers
  - Regular CORS policy audits
  - Use Content Security Policy as additional defense

## 4. Path Traversal / Local File Inclusion (LFI)

**Severity**: HIGH to CRITICAL

- **Detection Module**: `vuln_scanner.py`
- **Method**: 
  - Injecting `../` sequences (`../../../etc/passwd`)
  - URL encoding variants (`%2e%2e%2f`, `%252e%252e%252f`)
  - Null byte injection (older systems)
  - Double encoding attempts
  - Unicode normalization bypasses
  - Target files: `/etc/passwd`, `C:\Windows\win.ini`, `WEB-INF/web.xml`
- **Impact**: 
  - Disclosure of sensitive system files
  - Application source code exposure
  - Configuration file access (database credentials, API keys)
  - Log file access
  - Remote code execution (when combined with file upload)
- **Remediation**: 
  - Sanitize user-provided file paths (remove `../`, `..\`)
  - Use strict allow-lists for accessible files
  - Store files outside web root
  - Use chroot jails or containerization
  - Implement Web Application Firewall (WAF) rules
  - Canonicalize paths before validation

## 5. Security Header Audit

**Severity**: MEDIUM to HIGH

- **Detection Module**: `security_headers.py`
- **Headers Audited**:

| Header | Purpose | Risk if Missing |
|--------|---------|-----------------|
| **Strict-Transport-Security (HSTS)** | Forces HTTPS connections | SSL stripping attacks, man-in-the-middle |
| **Content-Security-Policy (CSP)** | Controls resource loading | XSS attacks, data injection |
| **X-Frame-Options** | Prevents clickjacking | UI redressing, clickjacking attacks |
| **X-Content-Type-Options** | Prevents MIME-sniffing | Drive-by downloads, content spoofing |
| **Referrer-Policy** | Controls referrer information | Information leakage, privacy violations |
| **X-XSS-Protection** | Legacy XSS filter (deprecated) | Limited protection in older browsers |
| **Permissions-Policy** | Controls browser features | Unauthorized camera/mic access, geolocation |

- **Impact**: 
  - Missing headers leave users vulnerable to various web-based attacks
  - Reduced defense-in-depth
  - Compliance violations (PCI DSS, HIPAA, etc.)
- **Remediation**: 
  - Implement all security headers with appropriate values
  - Use automated tools to verify headers regularly
  - Test with securityheaders.com or Mozilla Observatory
  - Keep CSP policies strict but functional

## 6. JavaScript Sensitive Data Leak

**Severity**: MEDIUM to HIGH

- **Detection Module**: `js_analyzer.py`
- **Method**: 
  - Regex-based scanning of client-side JS files
  - API key patterns (AWS, Google, Stripe, etc.)
  - Internal endpoint discovery
  - Hardcoded credentials detection
  - Source map analysis
  - Comment analysis for sensitive information
  - Patterns detected:
    - AWS Access Keys: `AKIA[0-9A-Z]{16}`
    - API Keys: `api[_-]?key`, `apikey`
    - Passwords: `password`, `passwd`, `pwd`
    - Secrets: `secret`, `token`, `private`
    - Internal endpoints: `/api/internal`, `/admin`
- **Impact**: 
  - Exposure of infrastructure secrets
  - Unauthorized API access
  - Cloud resource compromise
  - Internal system enumeration
  - Privilege escalation
  - Data breach facilitation
- **Remediation**: 
  - Never store secrets in client-side code
  - Use environment variables for server-side secrets
  - Implement secret managers (HashiCorp Vault, AWS Secrets Manager)
  - Regular code audits for hardcoded credentials
  - Use tools like git-secrets or truffleHog in CI/CD
  - Remove sensitive comments before deployment
  - Disable source maps in production

## 7. Open Redirects

**Severity**: MEDIUM

- **Detection Module**: `vuln_scanner.py`
- **Method**: 
  - Injecting external URLs into redirect parameters (`?redirect=`, `?url=`, `?next=`)
  - Protocol-relative URLs (`//evil.com`)
  - JavaScript redirects (`javascript:`)
  - Data URIs (`data:text/html`)
  - Common parameter names: `redirect`, `url`, `next`, `return`, `dest`, `destination`
- **Impact**: 
  - Facilitates phishing attacks
  - Credential harvesting via fake login pages
  - Malware distribution using trusted domain
  - Social engineering attacks
  - OAuth token theft
- **Remediation**: 
  - Use relative URLs for redirects exclusively
  - Validate redirect targets against strict allow-lists
  - Implement redirect tokens/signed URLs
  - User confirmation for external redirects
  - Display full destination URL to users
  - Use intermediate warning pages for external links

## 8. Insecure Direct Object References (IDOR)

**Severity**: HIGH to CRITICAL

- **Detection Module**: `api_discovery.py` + `vuln_scanner.py`
- **Method**: 
  - Testing sequential ID access (`/api/users/1`, `/api/users/2`)
  - GUID/UUID prediction attempts
  - Parameter tampering in API requests
  - Mass assignment vulnerability detection
- **Impact**: 
  - Unauthorized access to other users' data
  - Privilege escalation
  - Data modification/deletion
  - Account takeover
  - Horizontal and vertical privilege abuse
- **Remediation**: 
  - Implement proper access controls on every request
  - Use indirect object references (mapping tables)
  - Validate user permissions server-side
  - Avoid exposing database IDs in URLs
  - Implement rate limiting on sensitive endpoints
  - Use UUIDs instead of sequential IDs

## 9. Information Disclosure

**Severity**: LOW to MEDIUM

- **Detection Module**: `basic_info.py`, `fingerprinting.py`
- **Method**: 
  - Server version disclosure in headers
  - Stack traces in error pages
  - Debug information leakage
  - Robots.txt and sitemap.xml analysis
  - Technology fingerprinting
  - Directory listing detection
- **Impact**: 
  - Aids attackers in reconnaissance
  - Reveals vulnerable software versions
  - Exposes internal architecture
  - Provides attack surface information
- **Remediation**: 
  - Remove server version banners
  - Custom error pages without debug info
  - Disable directory listings
  - Minimize information in headers
  - Regular security assessments

## Vulnerability Remediation Priority

When addressing findings, prioritize based on:

1. **Immediate (24-48 hours)**: CRITICAL vulnerabilities in production
2. **Short-term (1-2 weeks)**: HIGH severity issues
3. **Medium-term (1 month)**: MEDIUM severity issues
4. **Long-term (next release)**: LOW severity and informational findings

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
