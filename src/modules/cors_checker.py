"""
CORS (Cross-Origin Resource Sharing) misconfiguration checker for VIPRecon.
Tests for insecure CORS policies that could lead to data theft.
"""

from typing import List, Optional, Dict
from src.core.models import Vulnerability, SeverityLevel, ScanTarget
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CORSChecker:
    """Checks for CORS misconfigurations."""
    
    # Test origins to check
    TEST_ORIGINS = [
        "https://evil.com",
        "http://evil.com",
        "null",
        "https://attacker.com",
    ]
    
    def __init__(self, http_client: AsyncHTTPClient):
        """
        Initialize CORS checker.
        
        Args:
            http_client: HTTP client for making requests.
        """
        self.http_client = http_client
    
    async def check(self, target: ScanTarget) -> List[Vulnerability]:
        """
        Check target for CORS misconfigurations.
        
        Args:
            target: Target to check.
        
        Returns:
            List of CORS vulnerabilities found.
        """
        logger.info(f"Checking CORS configuration for {target.domain}")
        
        vulnerabilities = []
        
        try:
            # Test different CORS scenarios
            vuln = await self._test_wildcard_origin(target.url)
            if vuln:
                vulnerabilities.append(vuln)
            
            vuln = await self._test_null_origin(target.url)
            if vuln:
                vulnerabilities.append(vuln)
            
            vuln = await self._test_arbitrary_origin(target.url)
            if vuln:
                vulnerabilities.append(vuln)
            
            vuln = await self._test_credentials_with_wildcard(target.url)
            if vuln:
                vulnerabilities.append(vuln)
            
            logger.info(f"Found {len(vulnerabilities)} CORS issues")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"CORS checking failed: {str(e)}")
            raise ModuleException("cors_check", f"Failed to check CORS: {str(e)}")
    
    async def _test_wildcard_origin(self, url: str) -> Optional[Vulnerability]:
        """
        Test if server responds with wildcard ACAO header.
        
        Args:
            url: URL to test.
        
        Returns:
            Vulnerability if found, None otherwise.
        """
        try:
            headers = {'Origin': 'https://evil.com'}
            response = await self.http_client.get(url, headers=headers)
            
            acao = response.headers.get('access-control-allow-origin', '')
            
            if acao == '*':
                logger.warning(f"Wildcard CORS policy detected: {url}")
                return Vulnerability(
                    type="CORS Misconfiguration - Wildcard Origin",
                    severity=SeverityLevel.MEDIUM,
                    description="Server allows requests from any origin using wildcard (*)",
                    url=url,
                    proof=f"Access-Control-Allow-Origin: {acao}",
                    remediation="Specify allowed origins explicitly instead of using wildcard. Implement origin validation."
                )
        except Exception as e:
            logger.debug(f"Wildcard origin test failed: {str(e)}")
        
        return None
    
    async def _test_null_origin(self, url: str) -> Optional[Vulnerability]:
        """
        Test if server accepts null origin.
        
        Args:
            url: URL to test.
        
        Returns:
            Vulnerability if found, None otherwise.
        """
        try:
            headers = {'Origin': 'null'}
            response = await self.http_client.get(url, headers=headers)
            
            acao = response.headers.get('access-control-allow-origin', '')
            acac = response.headers.get('access-control-allow-credentials', '')
            
            if acao == 'null':
                severity = SeverityLevel.HIGH if acac.lower() == 'true' else SeverityLevel.MEDIUM
                
                logger.warning(f"Null origin accepted: {url}")
                return Vulnerability(
                    type="CORS Misconfiguration - Null Origin",
                    severity=severity,
                    description="Server accepts requests from null origin, which can be exploited via sandboxed iframes",
                    url=url,
                    proof=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                    remediation="Do not allow null origin. Implement proper origin validation."
                )
        except Exception as e:
            logger.debug(f"Null origin test failed: {str(e)}")
        
        return None
    
    async def _test_arbitrary_origin(self, url: str) -> Optional[Vulnerability]:
        """
        Test if server reflects arbitrary origin.
        
        Args:
            url: URL to test.
        
        Returns:
            Vulnerability if found, None otherwise.
        """
        vulnerabilities = []
        
        for test_origin in self.TEST_ORIGINS:
            if test_origin == 'null':
                continue  # Already tested separately
            
            try:
                headers = {'Origin': test_origin}
                response = await self.http_client.get(url, headers=headers)
                
                acao = response.headers.get('access-control-allow-origin', '')
                acac = response.headers.get('access-control-allow-credentials', '')
                
                # Check if our origin is reflected
                if acao.lower() == test_origin.lower():
                    # Critical if credentials are allowed
                    if acac.lower() == 'true':
                        logger.warning(f"Critical CORS misconfiguration: {url}")
                        return Vulnerability(
                            type="CORS Misconfiguration - Arbitrary Origin with Credentials",
                            severity=SeverityLevel.CRITICAL,
                            description=f"Server reflects arbitrary origin ({test_origin}) and allows credentials, enabling cross-origin data theft",
                            url=url,
                            proof=f"Origin: {test_origin} → Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                            remediation="Implement strict origin validation with a whitelist. Do not reflect arbitrary origins when credentials are allowed."
                        )
                    else:
                        logger.warning(f"CORS misconfiguration detected: {url}")
                        return Vulnerability(
                            type="CORS Misconfiguration - Arbitrary Origin",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Server reflects arbitrary origin ({test_origin}) without proper validation",
                            url=url,
                            proof=f"Origin: {test_origin} → Access-Control-Allow-Origin: {acao}",
                            remediation="Implement strict origin validation with a whitelist of allowed origins."
                        )
            
            except Exception as e:
                logger.debug(f"Arbitrary origin test failed for {test_origin}: {str(e)}")
        
        return None
    
    async def _test_credentials_with_wildcard(self, url: str) -> Optional[Vulnerability]:
        """
        Test for the invalid combination of wildcard origin with credentials.
        
        Args:
            url: URL to test.
        
        Returns:
            Vulnerability if found, None otherwise.
        """
        try:
            headers = {'Origin': 'https://evil.com'}
            response = await self.http_client.get(url, headers=headers)
            
            acao = response.headers.get('access-control-allow-origin', '')
            acac = response.headers.get('access-control-allow-credentials', '')
            
            # This is actually invalid per spec, but some browsers might allow it
            if acao == '*' and acac.lower() == 'true':
                logger.warning(f"Invalid CORS configuration: {url}")
                return Vulnerability(
                    type="CORS Misconfiguration - Wildcard with Credentials",
                    severity=SeverityLevel.HIGH,
                    description="Server uses wildcard origin with credentials enabled (invalid per CORS spec)",
                    url=url,
                    proof=f"Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                    remediation="This configuration is invalid. Use specific origins instead of wildcard when credentials are needed."
                )
        except Exception as e:
            logger.debug(f"Credentials with wildcard test failed: {str(e)}")
        
        return None
    
    def _analyze_cors_headers(self, headers: Dict[str, str], sent_origin: str) -> Dict[str, str]:
        """
        Analyze CORS-related headers from response.
        
        Args:
            headers: Response headers.
            sent_origin: Origin that was sent in request.
        
        Returns:
            Dictionary with CORS header analysis.
        """
        return {
            'access_control_allow_origin': headers.get('access-control-allow-origin', 'Not set'),
            'access_control_allow_credentials': headers.get('access-control-allow-credentials', 'Not set'),
            'access_control_allow_methods': headers.get('access-control-allow-methods', 'Not set'),
            'access_control_allow_headers': headers.get('access-control-allow-headers', 'Not set'),
            'access_control_max_age': headers.get('access-control-max-age', 'Not set'),
            'sent_origin': sent_origin,
        }
