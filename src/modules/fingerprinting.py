"""
Technology fingerprinting module for VIPRecon.
Detects web technologies, frameworks, CMS, and libraries.
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Set
from bs4 import BeautifulSoup
from src.core.models import Technology, HTTPResponse, ScanTarget
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class TechnologyFingerprinter:
    """Identifies technologies used by the target web application."""
    
    def __init__(self):
        """Initialize the fingerprinter with technology signatures."""
        self.signatures = self._load_signatures()
        logger.debug(f"Loaded {len(self.signatures)} technology signatures")
    
    def _load_signatures(self) -> Dict:
        """
        Load technology signatures from JSON file.
        
        Returns:
            Dictionary of technology signatures.
        """
        try:
            sig_path = Path(__file__).parent.parent.parent / "config" / "fingerprints.json"
            with open(sig_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load fingerprints: {str(e)}")
            return {}
    
    async def fingerprint(
        self,
        target: ScanTarget,
        response: HTTPResponse
    ) -> List[Technology]:
        """
        Fingerprint technologies from HTTP response.
        
        Args:
            target: Scan target.
            response: HTTP response to analyze.
        
        Returns:
            List of detected technologies.
        """
        logger.info(f"Fingerprinting technologies for {target.domain}")
        
        detected_techs: Dict[str, Set[str]] = {}  # tech_name -> set of indicators
        
        try:
            # Parse HTML
            soup = BeautifulSoup(response.body, 'lxml')
            
            # Check each technology signature
            for tech_name, signature in self.signatures.items():
                indicators = set()
                
                # Check headers
                if 'headers' in signature:
                    header_indicators = self._check_headers(response.headers, signature['headers'])
                    indicators.update(header_indicators)
                
                # Check meta tags
                if 'meta' in signature:
                    meta_indicators = self._check_meta_tags(soup, signature['meta'])
                    indicators.update(meta_indicators)
                
                # Check cookies
                if 'cookies' in signature:
                    cookie_indicators = self._check_cookies(response.headers, signature['cookies'])
                    indicators.update(cookie_indicators)
                
                # Check scripts
                if 'scripts' in signature:
                    script_indicators = self._check_scripts(soup, signature['scripts'])
                    indicators.update(script_indicators)
                
                # Check HTML patterns
                if 'html_patterns' in signature:
                    html_indicators = self._check_html_patterns(response.body, signature['html_patterns'])
                    indicators.update(html_indicators)
                
                # If any indicators found, add technology
                if indicators:
                    detected_techs[tech_name] = indicators
            
            # Convert to Technology objects
            technologies = []
            for tech_name, indicators in detected_techs.items():
                signature = self.signatures[tech_name]
                
                tech = Technology(
                    name=tech_name.replace('_', ' ').title(),
                    category=signature.get('category', 'Unknown'),
                    confidence=self._calculate_confidence(indicators),
                    indicators=list(indicators)
                )
                technologies.append(tech)
            
            logger.info(f"Detected {len(technologies)} technologies")
            return sorted(technologies, key=lambda t: t.confidence, reverse=True)
            
        except Exception as e:
            logger.error(f"Fingerprinting failed: {str(e)}")
            raise ModuleException("fingerprinting", f"Failed to fingerprint technologies: {str(e)}")
    
    def _check_headers(self, headers: Dict[str, str], patterns: List[str]) -> Set[str]:
        """
        Check HTTP headers for technology indicators.
        
        Args:
            headers: HTTP headers dictionary.
            patterns: List of header patterns to match.
        
        Returns:
            Set of matched indicators.
        """
        indicators = set()
        
        for pattern in patterns:
            # Pattern format: "Header-Name: value" or just "Header-Name"
            if ':' in pattern:
                header_name, expected_value = pattern.split(':', 1)
                header_name = header_name.strip().lower()
                expected_value = expected_value.strip().lower()
                
                actual_value = headers.get(header_name, '').lower()
                if expected_value in actual_value:
                    indicators.add(f"Header: {pattern}")
            else:
                # Just check if header exists
                if pattern.lower() in headers:
                    indicators.add(f"Header: {pattern}")
        
        return indicators
    
    def _check_meta_tags(self, soup: BeautifulSoup, patterns: List[str]) -> Set[str]:
        """
        Check HTML meta tags for technology indicators.
        
        Args:
            soup: BeautifulSoup parsed HTML.
            patterns: List of meta tag patterns to match.
        
        Returns:
            Set of matched indicators.
        """
        indicators = set()
        
        meta_tags = soup.find_all('meta')
        
        for pattern in patterns:
            # Pattern format: "name:value" or "property:value"
            if ':' in pattern:
                attr_name, expected_value = pattern.split(':', 1)
                expected_value = expected_value.lower()
                
                for meta in meta_tags:
                    content = meta.get('content', '').lower()
                    name = meta.get('name', '').lower()
                    
                    if attr_name.lower() in name and expected_value in content:
                        indicators.add(f"Meta: {pattern}")
        
        return indicators
    
    def _check_cookies(self, headers: Dict[str, str], patterns: List[str]) -> Set[str]:
        """
        Check cookies for technology indicators.
        
        Args:
            headers: HTTP headers dictionary.
            patterns: List of cookie patterns to match.
        
        Returns:
            Set of matched indicators.
        """
        indicators = set()
        
        # Get Set-Cookie headers
        cookies = headers.get('set-cookie', '')
        
        for pattern in patterns:
            if pattern.lower() in cookies.lower():
                indicators.add(f"Cookie: {pattern}")
        
        return indicators
    
    def _check_scripts(self, soup: BeautifulSoup, patterns: List[str]) -> Set[str]:
        """
        Check script tags for technology indicators.
        
        Args:
            soup: BeautifulSoup parsed HTML.
            patterns: List of script patterns to match.
        
        Returns:
            Set of matched indicators.
        """
        indicators = set()
        
        script_tags = soup.find_all('script', src=True)
        
        for script in script_tags:
            src = script.get('src', '').lower()
            
            for pattern in patterns:
                if pattern.lower() in src:
                    indicators.add(f"Script: {pattern}")
        
        return indicators
    
    def _check_html_patterns(self, html: str, patterns: List[str]) -> Set[str]:
        """
        Check HTML content for technology indicators using regex.
        
        Args:
            html: Raw HTML content.
            patterns: List of patterns to search for.
        
        Returns:
            Set of matched indicators.
        """
        indicators = set()
        
        html_lower = html.lower()
        
        for pattern in patterns:
            if pattern.lower() in html_lower:
                indicators.add(f"HTML: {pattern}")
        
        return indicators
    
    def _calculate_confidence(self, indicators: Set[str]) -> float:
        """
        Calculate confidence score based on number of indicators.
        
        Args:
            indicators: Set of matched indicators.
        
        Returns:
            Confidence score (0-100).
        """
        # More indicators = higher confidence
        # 1 indicator = 40%, 2 = 60%, 3 = 80%, 4+ = 95%
        indicator_count = len(indicators)
        
        if indicator_count == 0:
            return 0.0
        elif indicator_count == 1:
            return 40.0
        elif indicator_count == 2:
            return 60.0
        elif indicator_count == 3:
            return 80.0
        else:
            return 95.0
