"""
WAF (Web Application Firewall) detection module for VIPRecon.
Identifies the presence and type of WAF protecting the target.
"""

import json
from pathlib import Path
from typing import Optional, Dict, List, Any
from src.core.models import ScanTarget, HTTPResponse
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class WAFDetector:
    """Detects Web Application Firewalls protecting the target."""
    
    # Test payloads designed to trigger WAF responses
    TEST_PAYLOADS = [
        "?id=1' OR '1'='1",  # SQL injection
        "?q=<script>alert(1)</script>",  # XSS
        "?file=../../../etc/passwd",  # Path traversal
        "?cmd=;cat /etc/passwd",  # Command injection
        "?search=<img src=x onerror=alert(1)>",  # XSS variant
    ]
    
    def __init__(self, http_client: AsyncHTTPClient):
        """
        Initialize WAF detector.
        
        Args:
            http_client: HTTP client for making requests.
        """
        self.http_client = http_client
        self.signatures = self._load_signatures()
        logger.debug(f"Loaded {len(self.signatures)} WAF signatures")
    
    def _load_signatures(self) -> Dict:
        """
        Load WAF signatures from JSON file.
        
        Returns:
            Dictionary of WAF signatures.
        """
        try:
            sig_path = Path(__file__).parent.parent.parent / "config" / "waf_signatures.json"
            with open(sig_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load WAF signatures: {str(e)}")
            return {}
    
    async def detect(self, target: ScanTarget) -> Optional[Dict[str, Any]]:
        """
        Detect if a WAF is protecting the target.
        
        Args:
            target: Target to check for WAF.
        
        Returns:
            Dictionary with WAF information if detected, None otherwise.
        """
        logger.info(f"Detecting WAF for {target.domain}")
        
        try:
            # Send malicious payloads and collect responses
            responses = await self._send_malicious_payloads(target.url)
            
            if not responses:
                logger.warning("No responses received from WAF detection payloads")
                return None
            
            # Analyze responses for WAF signatures
            waf_name = self._analyze_responses(responses)
            
            if waf_name:
                logger.info(f"WAF detected: {waf_name}")
                return {
                    'detected': True,
                    'name': waf_name,
                    'confidence': 'high',
                    'evidence': self._get_evidence(responses, waf_name)
                }
            else:
                # Check if responses suggest a WAF even if we can't identify it
                if self._check_response_codes(responses):
                    logger.info("Generic WAF behavior detected")
                    return {
                        'detected': True,
                        'name': 'Unknown WAF',
                        'confidence': 'medium',
                        'evidence': 'Suspicious response patterns detected'
                    }
            
            logger.info("No WAF detected")
            return None
            
        except Exception as e:
            logger.error(f"WAF detection failed: {str(e)}")
            raise ModuleException("waf_detect", f"Failed to detect WAF: {str(e)}")
    
    async def _send_malicious_payloads(self, base_url: str) -> List[HTTPResponse]:
        """
        Send test payloads to trigger WAF responses.
        
        Args:
            base_url: Base URL to test.
        
        Returns:
            List of HTTP responses.
        """
        responses = []
        
        for payload in self.TEST_PAYLOADS:
            try:
                url = f"{base_url}{payload}"
                response = await self.http_client.get(url, allow_redirects=False)
                responses.append(response)
                logger.debug(f"Payload response: {response.status_code}")
            except Exception as e:
                logger.debug(f"Payload request failed: {str(e)}")
                # Continue with other payloads
        
        return responses
    
    def _analyze_responses(self, responses: List[HTTPResponse]) -> Optional[str]:
        """
        Analyze responses to identify specific WAF.
        
        Args:
            responses: List of HTTP responses to analyze.
        
        Returns:
            Name of detected WAF or None.
        """
        # Score each WAF based on matching signatures
        waf_scores = {waf_name: 0 for waf_name in self.signatures.keys()}
        
        for response in responses:
            for waf_name, signature in self.signatures.items():
                # Check headers
                if 'headers' in signature:
                    if self._check_headers(response, signature['headers']):
                        waf_scores[waf_name] += 3
                
                # Check cookies
                if 'cookies' in signature:
                    if self._check_cookies(response, signature['cookies']):
                        waf_scores[waf_name] += 3
                
                # Check response text
                if 'response_text' in signature:
                    if self._check_response_text(response, signature['response_text']):
                        waf_scores[waf_name] += 2
                
                # Check status codes
                if 'status_codes' in signature:
                    if response.status_code in signature['status_codes']:
                        waf_scores[waf_name] += 1
        
        # Return WAF with highest score if above threshold
        max_score = max(waf_scores.values())
        if max_score >= 3:  # Require at least 3 points for positive detection
            detected_waf = max(waf_scores, key=waf_scores.get)
            return detected_waf.replace('_', ' ').title()
        
        return None
    
    def _check_headers(self, response: HTTPResponse, header_patterns: List[str]) -> bool:
        """
        Check if response headers match WAF signatures.
        
        Args:
            response: HTTP response to check.
            header_patterns: List of header patterns to match.
        
        Returns:
            True if any pattern matches.
        """
        for pattern in header_patterns:
            pattern_lower = pattern.lower()
            
            # Check if pattern is in any header name or value
            for header_name, header_value in response.headers.items():
                if pattern_lower in header_name.lower() or pattern_lower in header_value.lower():
                    return True
        
        return False
    
    def _check_cookies(self, response: HTTPResponse, cookie_patterns: List[str]) -> bool:
        """
        Check if response cookies match WAF signatures.
        
        Args:
            response: HTTP response to check.
            cookie_patterns: List of cookie patterns to match.
        
        Returns:
            True if any pattern matches.
        """
        set_cookie = response.headers.get('set-cookie', '').lower()
        
        for pattern in cookie_patterns:
            if pattern.lower() in set_cookie:
                return True
        
        return False
    
    def _check_response_text(self, response: HTTPResponse, text_patterns: List[str]) -> bool:
        """
        Check if response body contains WAF signatures.
        
        Args:
            response: HTTP response to check.
            text_patterns: List of text patterns to match.
        
        Returns:
            True if any pattern matches.
        """
        body_lower = response.body.lower()
        
        for pattern in text_patterns:
            if pattern.lower() in body_lower:
                return True
        
        return False
    
    def _check_response_codes(self, responses: List[HTTPResponse]) -> bool:
        """
        Check if response codes suggest WAF presence.
        
        Args:
            responses: List of HTTP responses.
        
        Returns:
            True if patterns suggest WAF.
        """
        # Count blocking responses (403, 406, 503)
        blocking_codes = [403, 406, 503]
        blocked_count = sum(1 for r in responses if r.status_code in blocking_codes)
        
        # If most payloads were blocked, likely a WAF
        return blocked_count >= len(responses) * 0.6
    
    def _get_evidence(self, responses: List[HTTPResponse], waf_name: str) -> str:
        """
        Get evidence string for WAF detection.
        
        Args:
            responses: List of HTTP responses.
            waf_name: Name of detected WAF.
        
        Returns:
            Evidence description string.
        """
        evidence_parts = []
        
        # Get signature for this WAF
        waf_key = waf_name.lower().replace(' ', '-')
        signature = self.signatures.get(waf_key, {})
        
        # Check what matched
        for response in responses:
            if 'headers' in signature:
                for header in signature['headers']:
                    if header.lower() in str(response.headers).lower():
                        evidence_parts.append(f"Header: {header}")
                        break
            
            if 'cookies' in signature:
                for cookie in signature['cookies']:
                    if cookie.lower() in response.headers.get('set-cookie', '').lower():
                        evidence_parts.append(f"Cookie: {cookie}")
                        break
        
        return ", ".join(set(evidence_parts)) if evidence_parts else "Pattern matching"
