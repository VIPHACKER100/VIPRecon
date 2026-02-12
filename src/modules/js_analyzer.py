"""
JavaScript analyzer module for VIPRecon.
Extracts sensitive information, API endpoints, and secrets from JavaScript files.
"""

import re
from typing import List, Dict, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from src.core.models import JavaScriptFinding, ScanTarget
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class JavaScriptAnalyzer:
    """Analyzes JavaScript files for sensitive information and endpoints."""
    
    # Regex patterns for sensitive data
    PATTERNS = {
        'api_keys': [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'["\']?apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        ],
        'aws_keys': [
            r'AKIA[0-9A-Z]{16}',
            r'["\']?aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
            r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']',
        ],
        'google_api': [
            r'AIza[0-9A-Za-z\-_]{35}',
        ],
        'slack_tokens': [
            r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}',
        ],
        'github_tokens': [
            r'ghp_[a-zA-Z0-9]{36}',
            r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
        ],
        'private_keys': [
            r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        ],
        'passwords': [
            r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            r'["\']?passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
        ],
        'emails': [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        'endpoints': [
            r'["\']/(api|v\d+|graphql|rest)[^"\']*["\']',
            r'https?://[^"\']+',
        ],
        'subdomains': [
            r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}',
        ],
    }
    
    def __init__(self, http_client: AsyncHTTPClient, max_js_files: int = 50):
        """
        Initialize JavaScript analyzer.
        
        Args:
            http_client: HTTP client for downloading JS files.
            max_js_files: Maximum number of JS files to analyze.
        """
        self.http_client = http_client
        self.max_js_files = max_js_files
    
    async def analyze(self, target: ScanTarget, html_content: str) -> List[JavaScriptFinding]:
        """
        Analyze JavaScript files from the target.
        
        Args:
            target: Target to analyze.
            html_content: HTML content from the main page.
        
        Returns:
            List of JavaScript findings.
        """
        logger.info(f"Analyzing JavaScript files for {target.domain}")
        
        findings = []
        
        try:
            # Extract JavaScript URLs from HTML
            js_urls = await self._extract_js_urls(html_content, target.url)
            
            logger.info(f"Found {len(js_urls)} JavaScript files to analyze")
            
            # Limit number of files to analyze
            js_urls = js_urls[:self.max_js_files]
            
            # Analyze each JavaScript file
            for js_url in js_urls:
                try:
                    finding = await self._analyze_js_file(js_url)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    logger.debug(f"Failed to analyze {js_url}: {str(e)}")
            
            logger.info(f"Completed JavaScript analysis, {len(findings)} files analyzed")
            return findings
            
        except Exception as e:
            logger.error(f"JavaScript analysis failed: {str(e)}")
            raise ModuleException("js_analysis", f"Failed to analyze JavaScript: {str(e)}")
    
    async def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """
        Extract JavaScript file URLs from HTML.
        
        Args:
            html: HTML content.
            base_url: Base URL for resolving relative URLs.
        
        Returns:
            List of JavaScript file URLs.
        """
        js_urls = set()
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Find all script tags with src attribute
            script_tags = soup.find_all('script', src=True)
            
            for script in script_tags:
                src = script.get('src')
                if src:
                    # Resolve relative URLs
                    full_url = urljoin(base_url, src)
                    
                    # Only include .js files or URLs without extension
                    if full_url.endswith('.js') or '?' in full_url or '.js?' in full_url:
                        js_urls.add(full_url)
            
            logger.debug(f"Extracted {len(js_urls)} JavaScript URLs from HTML")
        
        except Exception as e:
            logger.warning(f"Failed to extract JS URLs: {str(e)}")
        
        return list(js_urls)
    
    async def _analyze_js_file(self, url: str) -> JavaScriptFinding:
        """
        Analyze a single JavaScript file.
        
        Args:
            url: URL of the JavaScript file.
        
        Returns:
            JavaScriptFinding object with analysis results.
        """
        logger.debug(f"Analyzing JavaScript file: {url}")
        
        # Download JavaScript file
        js_content = await self._download_js_file(url)
        
        if not js_content:
            return None
        
        # Extract various information
        finding = JavaScriptFinding(
            file_url=url,
            endpoints=self._extract_endpoints(js_content),
            api_keys=self._extract_api_keys(js_content),
            subdomains=self._extract_subdomains(js_content),
            comments=self._extract_comments(js_content),
            sensitive_data=self._find_sensitive_data(js_content)
        )
        
        # Log findings
        if finding.api_keys:
            logger.warning(f"Found {len(finding.api_keys)} potential API keys in {url}")
        if finding.sensitive_data:
            logger.warning(f"Found {len(finding.sensitive_data)} sensitive data items in {url}")
        
        return finding
    
    async def _download_js_file(self, url: str) -> str:
        """
        Download JavaScript file content.
        
        Args:
            url: URL of the JavaScript file.
        
        Returns:
            JavaScript file content.
        """
        try:
            response = await self.http_client.get(url)
            return response.body
        except Exception as e:
            logger.debug(f"Failed to download {url}: {str(e)}")
            return ""
    
    def _extract_endpoints(self, js_content: str) -> List[str]:
        """
        Extract API endpoints from JavaScript code.
        
        Args:
            js_content: JavaScript code.
        
        Returns:
            List of discovered endpoints.
        """
        endpoints = set()
        
        for pattern in self.PATTERNS['endpoints']:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Clean up the match
                endpoint = match.strip('"\'')
                if endpoint and len(endpoint) > 1:
                    endpoints.add(endpoint)
        
        return list(endpoints)[:50]  # Limit to 50 endpoints
    
    def _extract_api_keys(self, js_content: str) -> List[Dict[str, str]]:
        """
        Extract potential API keys from JavaScript code.
        
        Args:
            js_content: JavaScript code.
        
        Returns:
            List of dictionaries with key type and value.
        """
        api_keys = []
        
        # Check for various API key patterns
        for key_type, patterns in self.PATTERNS.items():
            if key_type in ['api_keys', 'aws_keys', 'google_api', 'slack_tokens', 'github_tokens']:
                for pattern in patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0] if match else ''
                        
                        if match and len(match) > 10:
                            api_keys.append({
                                'type': key_type,
                                'value': match[:50] + '...' if len(match) > 50 else match  # Truncate for safety
                            })
        
        return api_keys[:20]  # Limit to 20 keys
    
    def _extract_subdomains(self, js_content: str) -> List[str]:
        """
        Extract subdomains from JavaScript code.
        
        Args:
            js_content: JavaScript code.
        
        Returns:
            List of discovered subdomains.
        """
        subdomains = set()
        
        for pattern in self.PATTERNS['subdomains']:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    # Extract the domain part
                    url = match[0] if match else ''
                else:
                    url = match
                
                # Parse and extract domain
                try:
                    parsed = urlparse(url if url.startswith('http') else f'https://{url}')
                    if parsed.hostname:
                        subdomains.add(parsed.hostname)
                except Exception:
                    pass
        
        return list(subdomains)[:30]  # Limit to 30 subdomains
    
    def _extract_comments(self, js_content: str) -> List[str]:
        """
        Extract comments from JavaScript code.
        
        Args:
            js_content: JavaScript code.
        
        Returns:
            List of comments.
        """
        comments = []
        
        # Single-line comments
        single_line = re.findall(r'//\s*(.+)', js_content)
        comments.extend(single_line)
        
        # Multi-line comments
        multi_line = re.findall(r'/\*\s*(.*?)\s*\*/', js_content, re.DOTALL)
        comments.extend(multi_line)
        
        # Filter out empty and very short comments
        comments = [c.strip() for c in comments if c.strip() and len(c.strip()) > 5]
        
        return comments[:50]  # Limit to 50 comments
    
    def _find_sensitive_data(self, js_content: str) -> List[Dict[str, str]]:
        """
        Find sensitive data like passwords, private keys, emails.
        
        Args:
            js_content: JavaScript code.
        
        Returns:
            List of dictionaries with data type and value.
        """
        sensitive_data = []
        
        # Check for passwords
        for pattern in self.PATTERNS['passwords']:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ''
                
                if match and len(match) > 3:
                    sensitive_data.append({
                        'type': 'password',
                        'value': '***REDACTED***'  # Don't expose actual passwords
                    })
        
        # Check for private keys
        for pattern in self.PATTERNS['private_keys']:
            if re.search(pattern, js_content):
                sensitive_data.append({
                    'type': 'private_key',
                    'value': 'Private key found in JavaScript'
                })
        
        # Check for emails
        for pattern in self.PATTERNS['emails']:
            matches = re.findall(pattern, js_content)
            for match in matches:
                sensitive_data.append({
                    'type': 'email',
                    'value': match
                })
        
        return sensitive_data[:30]  # Limit to 30 items
