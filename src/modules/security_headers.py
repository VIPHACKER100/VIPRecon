"""
Security headers checker module for VIPRecon.
Audits HTTP security headers and identifies missing or misconfigured headers.
"""

from typing import List, Dict
from src.core.models import SecurityHeader, SeverityLevel, HTTPResponse, ScanTarget
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityHeaderChecker:
    """Checks for presence and proper configuration of security headers."""
    
    # Security headers to check
    SECURITY_HEADERS = {
        'strict-transport-security': {
            'name': 'Strict-Transport-Security (HSTS)',
            'severity_if_missing': SeverityLevel.MEDIUM,
            'recommendation': 'Add Strict-Transport-Security header with max-age of at least 31536000 (1 year) and includeSubDomains directive.',
            'good_values': ['max-age=31536000', 'includeSubDomains'],
        },
        'content-security-policy': {
            'name': 'Content-Security-Policy (CSP)',
            'severity_if_missing': SeverityLevel.LOW,
            'recommendation': 'Implement a Content-Security-Policy header to prevent XSS and data injection attacks.',
            'bad_values': ['unsafe-inline', 'unsafe-eval'],
        },
        'x-frame-options': {
            'name': 'X-Frame-Options',
            'severity_if_missing': SeverityLevel.MEDIUM,
            'recommendation': 'Add X-Frame-Options header with value DENY or SAMEORIGIN to prevent clickjacking.',
            'good_values': ['DENY', 'SAMEORIGIN'],
        },
        'x-content-type-options': {
            'name': 'X-Content-Type-Options',
            'severity_if_missing': SeverityLevel.LOW,
            'recommendation': 'Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.',
            'good_values': ['nosniff'],
        },
        'referrer-policy': {
            'name': 'Referrer-Policy',
            'severity_if_missing': SeverityLevel.LOW,
            'recommendation': 'Add Referrer-Policy header to control referrer information. Recommended: no-referrer or strict-origin-when-cross-origin.',
            'good_values': ['no-referrer', 'strict-origin-when-cross-origin', 'same-origin'],
        },
        'permissions-policy': {
            'name': 'Permissions-Policy',
            'severity_if_missing': SeverityLevel.INFO,
            'recommendation': 'Consider adding Permissions-Policy header to control browser features and APIs.',
        },
        'x-xss-protection': {
            'name': 'X-XSS-Protection',
            'severity_if_missing': SeverityLevel.INFO,
            'recommendation': 'Add X-XSS-Protection: 1; mode=block (note: deprecated in favor of CSP, but still useful for older browsers).',
            'good_values': ['1; mode=block'],
        },
    }
    
    def __init__(self, http_client: AsyncHTTPClient):
        """
        Initialize security header checker.
        
        Args:
            http_client: HTTP client for making requests.
        """
        self.http_client = http_client
    
    async def check(self, target: ScanTarget) -> List[SecurityHeader]:
        """
        Check security headers for the target.
        
        Args:
            target: Target to check.
        
        Returns:
            List of security header check results.
        """
        logger.info(f"Checking security headers for {target.domain}")
        
        try:
            # Fetch the target page
            response = await self.http_client.get(target.url)
            
            # Check each security header
            results = []
            
            for header_key, header_info in self.SECURITY_HEADERS.items():
                result = self._check_header(response, header_key, header_info)
                results.append(result)
            
            # Count missing headers
            missing_count = sum(1 for r in results if not r.present)
            logger.info(f"Security headers check complete: {missing_count} headers missing")
            
            return results
            
        except Exception as e:
            logger.error(f"Security headers check failed: {str(e)}")
            raise ModuleException("security_headers", f"Failed to check security headers: {str(e)}")
    
    def _check_header(
        self,
        response: HTTPResponse,
        header_key: str,
        header_info: Dict
    ) -> SecurityHeader:
        """
        Check a single security header.
        
        Args:
            response: HTTP response to check.
            header_key: Header key to check (lowercase).
            header_info: Information about the header.
        
        Returns:
            SecurityHeader object with check result.
        """
        header_value = response.headers.get(header_key)
        present = header_value is not None
        
        if present:
            # Header is present, check if it's properly configured
            severity, recommendation = self._analyze_header_value(
                header_key,
                header_value,
                header_info
            )
        else:
            # Header is missing
            severity = header_info['severity_if_missing']
            recommendation = header_info['recommendation']
        
        return SecurityHeader(
            header_name=header_info['name'],
            present=present,
            value=header_value,
            severity=severity,
            recommendation=recommendation if not present or severity != SeverityLevel.INFO else None
        )
    
    def _analyze_header_value(
        self,
        header_key: str,
        header_value: str,
        header_info: Dict
    ) -> tuple:
        """
        Analyze header value for proper configuration.
        
        Args:
            header_key: Header key.
            header_value: Header value.
            header_info: Header information.
        
        Returns:
            Tuple of (severity, recommendation).
        """
        header_value_lower = header_value.lower()
        
        # Check for bad values
        if 'bad_values' in header_info:
            for bad_value in header_info['bad_values']:
                if bad_value.lower() in header_value_lower:
                    return (
                        SeverityLevel.MEDIUM,
                        f"Header contains insecure directive '{bad_value}'. {header_info['recommendation']}"
                    )
        
        # Check for good values
        if 'good_values' in header_info:
            has_good_value = any(
                good_value.lower() in header_value_lower
                for good_value in header_info['good_values']
            )
            
            if not has_good_value:
                return (
                    SeverityLevel.LOW,
                    f"Header present but may not be optimally configured. {header_info['recommendation']}"
                )
        
        # Specific checks for certain headers
        if header_key == 'strict-transport-security':
            return self._check_hsts(header_value)
        elif header_key == 'content-security-policy':
            return self._check_csp(header_value)
        
        # Header is present and looks good
        return (SeverityLevel.INFO, None)
    
    def _check_hsts(self, value: str) -> tuple:
        """
        Check HSTS header configuration.
        
        Args:
            value: HSTS header value.
        
        Returns:
            Tuple of (severity, recommendation).
        """
        value_lower = value.lower()
        
        # Extract max-age
        import re
        max_age_match = re.search(r'max-age=(\d+)', value_lower)
        
        if not max_age_match:
            return (
                SeverityLevel.MEDIUM,
                "HSTS header missing max-age directive."
            )
        
        max_age = int(max_age_match.group(1))
        
        # Check if max-age is sufficient (at least 6 months)
        if max_age < 15768000:  # 6 months in seconds
            return (
                SeverityLevel.LOW,
                f"HSTS max-age is {max_age} seconds. Recommended: at least 31536000 (1 year)."
            )
        
        # Check for includeSubDomains
        if 'includesubdomains' not in value_lower:
            return (
                SeverityLevel.LOW,
                "HSTS header should include 'includeSubDomains' directive for better security."
            )
        
        return (SeverityLevel.INFO, None)
    
    def _check_csp(self, value: str) -> tuple:
        """
        Check CSP header configuration.
        
        Args:
            value: CSP header value.
        
        Returns:
            Tuple of (severity, recommendation).
        """
        value_lower = value.lower()
        
        issues = []
        
        # Check for unsafe directives
        if 'unsafe-inline' in value_lower:
            issues.append("'unsafe-inline' allows inline scripts, reducing XSS protection")
        
        if 'unsafe-eval' in value_lower:
            issues.append("'unsafe-eval' allows eval(), reducing XSS protection")
        
        # Check for wildcard sources
        if "'*'" in value or " * " in value:
            issues.append("Wildcard (*) source allows loading from any origin")
        
        if issues:
            return (
                SeverityLevel.MEDIUM,
                "CSP has potential issues: " + "; ".join(issues)
            )
        
        # Check if CSP is too permissive
        if 'default-src' not in value_lower and 'script-src' not in value_lower:
            return (
                SeverityLevel.LOW,
                "CSP should define at least 'default-src' or 'script-src' directive."
            )
        
        return (SeverityLevel.INFO, None)
