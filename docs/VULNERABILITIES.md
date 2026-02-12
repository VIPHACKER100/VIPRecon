# VIPRecon Vulnerability Reference

This document describes the security vulnerabilities scanned by VIPRecon, their potential impact, and detection methods.

## 1. Cross-Site Scripting (XSS)
- **Detection Module**: `vuln_scanner.py`
- **Method**: Reflective payload testing in URL parameters.
- **Impact**: Attacker can execute arbitrary JavaScript in the victim's browser, leading to session theft or site defacement.
- **Remediation**: Implement output encoding and use Content Security Policy (CSP) headers.

## 2. SQL Injection (SQLi)
- **Detection Module**: `vuln_scanner.py`
- **Method**: Injecting SQL-specific characters (`'`, `"`, `;`) and observing error messages in the response.
- **Impact**: Unauthorized access to database data, modification, or deletion of sensitive information.
- **Remediation**: Use parameterized queries and prepared statements.

## 3. CORS Misconfiguration
- **Detection Module**: `cors_checker.py`
- **Method**: Testing `Origin` header reflections and credential inclusion.
- **Impact**: Allows malicious websites to read sensitive data from the target domain on behalf of a logged-in user.
- **Remediation**: Set explicit `Access-Control-Allow-Origin` values and avoid `Access-Control-Allow-Credentials: true` with wildcards.

## 4. Path Traversal
- **Detection Module**: `vuln_scanner.py`
- **Method**: Injecting `../` sequences to attempt reading system files like `/etc/passwd` or `C:\Windows\win.ini`.
- **Impact**: Disclosure of sensitive system files and application source code.
- **Remediation**: Sanitize user-provided file paths and use allow-lists.

## 5. Security Header Audit
- **Detection Module**: `security_headers.py`
- **Headers Audited**:
    - **HSTS**: Force HTTPS.
    - **CSP**: Prevent XSS and data injection.
    - **X-Frame-Options**: Prevent Clickjacking.
    - **X-Content-Type-Options**: Prevent MIME-sniffing.
    - **Referrer-Policy**: Control referrer information leak.
- **Impact**: Missing headers leave users vulnerable to various web-based attacks.

## 6. JavaScript Sensitive Data Leak
- **Detection Module**: `js_analyzer.py`
- **Method**: Regex-based scanning of client-side JS files for API keys, AWS credentials, and private endpoints.
- **Impact**: Exposure of infrastructure secrets and internal API structures.
- **Remediation**: Never store secrets in client-side code; use environment variables or secret managers on the server side.

## 7. Open Redirects
- **Detection Module**: `vuln_scanner.py`
- **Method**: Injecting external URLs into redirect parameters.
- **Impact**: Facilitates phishing attacks by making a malicious link look like it belongs to a trusted domain.
- **Remediation**: Use relative URLs for redirects or validate the target against an allow-list.
