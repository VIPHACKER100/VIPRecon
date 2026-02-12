"""
Vulnerability scanner module for VIPRecon.
Performs basic security testing for common web vulnerabilities.
"""

import asyncio
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from src.core.models import Vulnerability, SeverityLevel, Endpoint, ScanTarget
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class VulnerabilityScanner:
    """Scans for common web application vulnerabilities."""
    
    # XSS test payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
        "'-alert(1)-'",
        "\"><img src=x onerror=alert(1)>",
    ]
    
    # SQL injection test payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' /*",
        "admin'--",
        "1' ORDER BY 1--",
        "' UNION SELECT NULL--",
    ]
    
    # Directory traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
    ]
    
    # Open redirect payloads
    OPEN_REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
    ]
    
    def __init__(self, http_client: AsyncHTTPClient, config: Dict[str, bool] = None):
        """
        Initialize vulnerability scanner.
        
        Args:
            http_client: HTTP client for making requests.
            config: Configuration dict for enabling/disabling checks.
        """
        self.http_client = http_client
        self.config = config or {
            'check_xss': True,
            'check_sqli': True,
            'check_open_redirect': True,
            'check_directory_traversal': True,
        }
    
    async def scan(self, target: ScanTarget, endpoints: List[Endpoint]) -> List[Vulnerability]:
        """
        Scan target for vulnerabilities.
        
        Args:
            target: Target to scan.
            endpoints: List of endpoints to test.
        
        Returns:
            List of discovered vulnerabilities.
        """
        logger.info(f"Starting vulnerability scan for {target.domain}")
        
        vulnerabilities = []
        
        try:
            # Prepare test URLs
            test_urls = self._prepare_test_urls(target.url, endpoints)
            
            # Run different vulnerability checks
            tasks = []
            
            if self.config.get('check_xss'):
                tasks.append(self._scan_xss(test_urls))
            
            if self.config.get('check_sqli'):
                tasks.append(self._scan_sqli(test_urls))
            
            if self.config.get('check_open_redirect'):
                tasks.append(self._scan_open_redirect(test_urls))
            
            if self.config.get('check_directory_traversal'):
                tasks.append(self._scan_directory_traversal(test_urls))
            
            # Execute all checks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            for result in results:
                if isinstance(result, list):
                    vulnerabilities.extend(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Vulnerability check failed: {str(result)}")
            
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Vulnerability scanning failed: {str(e)}")
            raise ModuleException("vuln_scan", f"Failed to scan for vulnerabilities: {str(e)}")
    
    def _prepare_test_urls(self, base_url: str, endpoints: List[Endpoint]) -> List[str]:
        """
        Prepare URLs for testing.
        
        Args:
            base_url: Base URL of the target.
            endpoints: List of discovered endpoints.
        
        Returns:
            List of URLs to test.
        """
        test_urls = [base_url]
        
        # Add discovered endpoints
        for endpoint in endpoints[:10]:  # Limit to first 10 to avoid too many requests
            url = urljoin(base_url, endpoint.path)
            test_urls.append(url)
        
        # Add common vulnerable parameters
        common_params = ['id', 'page', 'search', 'q', 'url', 'redirect', 'file', 'path']
        for param in common_params:
            test_url = f"{base_url}?{param}=test"
            test_urls.append(test_url)
        
        return list(set(test_urls))  # Remove duplicates
    
    async def _scan_xss(self, urls: List[str]) -> List[Vulnerability]:
        """
        Scan for Cross-Site Scripting (XSS) vulnerabilities.
        
        Args:
            urls: List of URLs to test.
        
        Returns:
            List of XSS vulnerabilities found.
        """
        logger.debug("Scanning for XSS vulnerabilities")
        vulnerabilities = []
        
        for url in urls:
            for payload in self.XSS_PAYLOADS:
                try:
                    vuln = await self._check_xss(url, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break  # Found XSS, no need to test more payloads for this URL
                except Exception as e:
                    logger.debug(f"XSS check failed for {url}: {str(e)}")
        
        return vulnerabilities
    
    async def _check_xss(self, url: str, payload: str) -> Optional[Vulnerability]:
        """
        Check a single URL for XSS vulnerability.
        
        Args:
            url: URL to test.
            payload: XSS payload to inject.
        
        Returns:
            Vulnerability object if found, None otherwise.
        """
        # Parse URL and inject payload into parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # No parameters, try adding one
            test_url = f"{url}?test={payload}"
            param_name = "test"
        else:
            # Inject into first parameter
            param_name = list(params.keys())[0]
            params[param_name] = [payload]
            query_string = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
        
        try:
            response = await self.http_client.get(test_url)
            
            # Check if payload is reflected unescaped in response
            if self._verify_xss(response.body, payload):
                logger.warning(f"XSS vulnerability found: {url}")
                return Vulnerability(
                    type="Cross-Site Scripting (XSS)",
                    severity=SeverityLevel.HIGH,
                    description=f"Reflected XSS vulnerability found in parameter '{param_name}'",
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    proof=f"Payload reflected in response without proper encoding",
                    remediation="Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers."
                )
        except Exception:
            pass
        
        return None
    
    def _verify_xss(self, response_body: str, payload: str) -> bool:
        """
        Verify if XSS payload is reflected unescaped.
        
        Args:
            response_body: HTTP response body.
            payload: Injected payload.
        
        Returns:
            True if vulnerable, False otherwise.
        """
        # Check if payload appears unescaped in response
        if payload in response_body:
            # Additional check: ensure it's not properly encoded
            encoded_variants = [
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                payload.replace('<', '\\u003c').replace('>', '\\u003e'),
            ]
            
            for encoded in encoded_variants:
                if encoded in response_body:
                    return False  # Properly encoded, not vulnerable
            
            return True  # Payload appears unescaped
        
        return False
    
    async def _scan_sqli(self, urls: List[str]) -> List[Vulnerability]:
        """
        Scan for SQL Injection vulnerabilities.
        
        Args:
            urls: List of URLs to test.
        
        Returns:
            List of SQLi vulnerabilities found.
        """
        logger.debug("Scanning for SQL injection vulnerabilities")
        vulnerabilities = []
        
        for url in urls:
            for payload in self.SQLI_PAYLOADS:
                try:
                    vuln = await self._check_sqli(url, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
                except Exception as e:
                    logger.debug(f"SQLi check failed for {url}: {str(e)}")
        
        return vulnerabilities
    
    async def _check_sqli(self, url: str, payload: str) -> Optional[Vulnerability]:
        """
        Check a single URL for SQL injection vulnerability.
        
        Args:
            url: URL to test.
            payload: SQLi payload to inject.
        
        Returns:
            Vulnerability object if found, None otherwise.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            test_url = f"{url}?id={payload}"
            param_name = "id"
        else:
            param_name = list(params.keys())[0]
            params[param_name] = [payload]
            query_string = urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
        
        try:
            response = await self.http_client.get(test_url)
            
            # Check for SQL error messages
            if self._verify_sqli(response.body):
                logger.warning(f"SQL injection vulnerability found: {url}")
                return Vulnerability(
                    type="SQL Injection",
                    severity=SeverityLevel.CRITICAL,
                    description=f"SQL injection vulnerability found in parameter '{param_name}'",
                    url=url,
                    parameter=param_name,
                    payload=payload,
                    proof="SQL error messages detected in response",
                    remediation="Use parameterized queries or prepared statements. Implement input validation and least privilege database access."
                )
        except Exception:
            pass
        
        return None
    
    def _verify_sqli(self, response_body: str) -> bool:
        """
        Verify if response contains SQL error messages.
        
        Args:
            response_body: HTTP response body.
        
        Returns:
            True if SQL errors detected, False otherwise.
        """
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "mysql error",
            "ora-",
            "postgresql",
            "sqlite_",
            "sqlserver",
            "syntax error",
            "unclosed quotation mark",
            "quoted string not properly terminated",
        ]
        
        response_lower = response_body.lower()
        return any(error in response_lower for error in sql_errors)
    
    async def _scan_open_redirect(self, urls: List[str]) -> List[Vulnerability]:
        """
        Scan for open redirect vulnerabilities.
        
        Args:
            urls: List of URLs to test.
        
        Returns:
            List of open redirect vulnerabilities found.
        """
        logger.debug("Scanning for open redirect vulnerabilities")
        vulnerabilities = []
        
        for url in urls:
            for payload in self.OPEN_REDIRECT_PAYLOADS:
                try:
                    vuln = await self._check_open_redirect(url, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
                except Exception as e:
                    logger.debug(f"Open redirect check failed for {url}: {str(e)}")
        
        return vulnerabilities
    
    async def _check_open_redirect(self, url: str, payload: str) -> Optional[Vulnerability]:
        """
        Check for open redirect vulnerability.
        
        Args:
            url: URL to test.
            payload: Redirect payload.
        
        Returns:
            Vulnerability object if found, None otherwise.
        """
        # Common redirect parameters
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'goto']
        
        for param in redirect_params:
            test_url = f"{url}?{param}={payload}"
            
            try:
                response = await self.http_client.get(test_url, allow_redirects=False)
                
                # Check if redirecting to our payload
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('location', '')
                    if 'evil.com' in location.lower():
                        logger.warning(f"Open redirect vulnerability found: {url}")
                        return Vulnerability(
                            type="Open Redirect",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Open redirect vulnerability found in parameter '{param}'",
                            url=url,
                            parameter=param,
                            payload=payload,
                            proof=f"Redirects to external domain: {location}",
                            remediation="Validate redirect URLs against a whitelist. Use relative URLs when possible."
                        )
            except Exception:
                pass
        
        return None
    
    async def _scan_directory_traversal(self, urls: List[str]) -> List[Vulnerability]:
        """
        Scan for directory traversal vulnerabilities.
        
        Args:
            urls: List of URLs to test.
        
        Returns:
            List of directory traversal vulnerabilities found.
        """
        logger.debug("Scanning for directory traversal vulnerabilities")
        vulnerabilities = []
        
        for url in urls:
            for payload in self.PATH_TRAVERSAL_PAYLOADS:
                try:
                    vuln = await self._check_directory_traversal(url, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        break
                except Exception as e:
                    logger.debug(f"Directory traversal check failed for {url}: {str(e)}")
        
        return vulnerabilities
    
    async def _check_directory_traversal(self, url: str, payload: str) -> Optional[Vulnerability]:
        """
        Check for directory traversal vulnerability.
        
        Args:
            url: URL to test.
            payload: Path traversal payload.
        
        Returns:
            Vulnerability object if found, None otherwise.
        """
        # Common file parameters
        file_params = ['file', 'path', 'page', 'document', 'folder', 'include']
        
        for param in file_params:
            test_url = f"{url}?{param}={payload}"
            
            try:
                response = await self.http_client.get(test_url)
                
                # Check for sensitive file contents
                if self._verify_directory_traversal(response.body):
                    logger.warning(f"Directory traversal vulnerability found: {url}")
                    return Vulnerability(
                        type="Directory Traversal",
                        severity=SeverityLevel.HIGH,
                        description=f"Directory traversal vulnerability found in parameter '{param}'",
                        url=url,
                        parameter=param,
                        payload=payload,
                        proof="Sensitive file contents detected in response",
                        remediation="Validate and sanitize file paths. Use a whitelist of allowed files. Implement proper access controls."
                    )
            except Exception:
                pass
        
        return None
    
    def _verify_directory_traversal(self, response_body: str) -> bool:
        """
        Verify if response contains sensitive file contents.
        
        Args:
            response_body: HTTP response body.
        
        Returns:
            True if sensitive files detected, False otherwise.
        """
        # Signatures of sensitive files
        signatures = [
            "root:",  # /etc/passwd
            "[extensions]",  # win.ini
            "for 16-bit app support",  # win.ini
            "[fonts]",  # win.ini
        ]
        
        return any(sig in response_body for sig in signatures)
