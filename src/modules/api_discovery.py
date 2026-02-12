"""
API endpoint discovery module for VIPRecon.
Discovers REST APIs, GraphQL endpoints, and API documentation.
"""

import re
import json
from pathlib import Path
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from src.core.models import Endpoint, ScanTarget, HTTPResponse
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class APIDiscoverer:
    """Discovers API endpoints and documentation."""
    
    def __init__(self, http_client: AsyncHTTPClient):
        """
        Initialize API discoverer.
        
        Args:
            http_client: HTTP client for making requests.
        """
        self.http_client = http_client
        self.api_paths = self._load_api_paths()
    
    def _load_api_paths(self) -> List[str]:
        """
        Load common API paths from wordlist.
        
        Returns:
            List of API paths to check.
        """
        try:
            wordlist_path = Path(__file__).parent.parent.parent / "config" / "wordlists" / "api_paths.txt"
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                paths = [line.strip() for line in f if line.strip()]
            logger.debug(f"Loaded {len(paths)} API paths from wordlist")
            return paths
        except Exception as e:
            logger.warning(f"Failed to load API paths: {str(e)}")
            return ['/api', '/api/v1', '/graphql', '/swagger.json', '/openapi.json']
    
    async def discover(self, target: ScanTarget, html_content: str) -> List[Endpoint]:
        """
        Discover API endpoints for the target.
        
        Args:
            target: Target to discover APIs for.
            html_content: HTML content from the main page.
        
        Returns:
            List of discovered endpoints.
        """
        logger.info(f"Discovering API endpoints for {target.domain}")
        
        discovered_endpoints: Set[str] = set()
        
        try:
            # Method 1: Fuzz common API paths
            fuzzing_endpoints = await self._fuzz_common_paths(target.url)
            discovered_endpoints.update(fuzzing_endpoints)
            
            # Method 2: Extract from HTML
            html_endpoints = self._extract_from_html(html_content, target.url)
            discovered_endpoints.update(html_endpoints)
            
            # Method 3: Check for API documentation
            doc_endpoints = await self._check_api_documentation(target.url)
            discovered_endpoints.update(doc_endpoints)
            
            # Convert to Endpoint objects
            endpoints = []
            for endpoint_url in discovered_endpoints:
                endpoint = Endpoint(
                    path=self._extract_path(endpoint_url),
                    method='GET',  # Default, would need further testing to determine
                    source='api_discovery',
                    status_code=None
                )
                endpoints.append(endpoint)
            
            logger.info(f"Discovered {len(endpoints)} API endpoints")
            return endpoints
            
        except Exception as e:
            logger.error(f"API discovery failed: {str(e)}")
            raise ModuleException("api_discovery", f"Failed to discover APIs: {str(e)}")
    
    async def _fuzz_common_paths(self, base_url: str) -> Set[str]:
        """
        Fuzz common API paths to find endpoints.
        
        Args:
            base_url: Base URL to test.
        
        Returns:
            Set of discovered endpoint URLs.
        """
        logger.debug("Fuzzing common API paths")
        
        discovered = set()
        
        for path in self.api_paths:
            try:
                url = urljoin(base_url, path)
                endpoint = await self._validate_endpoint(url)
                
                if endpoint:
                    discovered.add(url)
                    logger.debug(f"Found API endpoint: {url}")
            
            except Exception as e:
                logger.debug(f"Failed to check {path}: {str(e)}")
        
        return discovered
    
    async def _validate_endpoint(self, url: str) -> Optional[str]:
        """
        Validate if a URL is an active endpoint.
        
        Args:
            url: URL to validate.
        
        Returns:
            URL if valid, None otherwise.
        """
        try:
            response = await self.http_client.get(url, allow_redirects=False)
            
            # Consider 200, 401, 403 as valid (endpoint exists)
            if response.status_code in [200, 401, 403, 405]:
                return url
            
            return None
            
        except Exception:
            return None
    
    def _extract_from_html(self, html: str, base_url: str) -> Set[str]:
        """
        Extract API endpoints from HTML content.
        
        Args:
            html: HTML content to parse.
            base_url: Base URL for resolving relative URLs.
        
        Returns:
            Set of discovered endpoint URLs.
        """
        logger.debug("Extracting API endpoints from HTML")
        
        discovered = set()
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract from inline scripts
            scripts = soup.find_all('script', string=True)
            for script in scripts:
                script_content = script.string
                if script_content:
                    endpoints = self._extract_from_javascript(script_content)
                    discovered.update(endpoints)
            
            # Extract from data attributes
            elements_with_api = soup.find_all(attrs={'data-api': True})
            for element in elements_with_api:
                api_url = element.get('data-api')
                if api_url:
                    full_url = urljoin(base_url, api_url)
                    discovered.add(full_url)
            
            # Look for AJAX calls in onclick attributes
            elements_with_onclick = soup.find_all(attrs={'onclick': True})
            for element in elements_with_onclick:
                onclick = element.get('onclick', '')
                urls = re.findall(r'["\']([^"\']*(?:api|graphql)[^"\']*)["\']', onclick)
                for url in urls:
                    full_url = urljoin(base_url, url)
                    discovered.add(full_url)
        
        except Exception as e:
            logger.warning(f"Failed to extract from HTML: {str(e)}")
        
        return discovered
    
    def _extract_from_javascript(self, js_content: str) -> Set[str]:
        """
        Extract API endpoints from JavaScript code.
        
        Args:
            js_content: JavaScript code to analyze.
        
        Returns:
            Set of discovered endpoint paths.
        """
        discovered = set()
        
        # Regex patterns for API endpoints
        patterns = [
            r'["\']/(api|v\d+|graphql|rest)[^"\']*["\']',  # API paths
            r'fetch\(["\']([^"\']+)["\']',  # fetch() calls
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',  # axios calls
            r'\.get\(["\']([^"\']+)["\']',  # .get() calls
            r'\.post\(["\']([^"\']+)["\']',  # .post() calls
            r'url:\s*["\']([^"\']+)["\']',  # url: property
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # match might be a tuple if pattern has multiple groups
                if isinstance(match, tuple):
                    match = match[0] if match else ''
                
                if match and ('api' in match.lower() or 'graphql' in match.lower() or match.startswith('/v')):
                    discovered.add(match)
        
        return discovered
    
    async def _check_api_documentation(self, base_url: str) -> Set[str]:
        """
        Check for API documentation endpoints (Swagger, OpenAPI, etc.).
        
        Args:
            base_url: Base URL to check.
        
        Returns:
            Set of discovered endpoints from documentation.
        """
        logger.debug("Checking for API documentation")
        
        discovered = set()
        
        # Common documentation paths
        doc_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/swagger-ui.html',
            '/api-docs',
            '/api/docs',
            '/openapi.json',
            '/openapi.yaml',
            '/api/swagger.json',
            '/api/openapi.json',
            '/docs',
            '/redoc',
        ]
        
        for path in doc_paths:
            try:
                url = urljoin(base_url, path)
                response = await self.http_client.get(url)
                
                if response.status_code == 200:
                    logger.info(f"Found API documentation: {url}")
                    
                    # Try to parse OpenAPI/Swagger spec
                    if path.endswith('.json'):
                        try:
                            spec = json.loads(response.body)
                            endpoints = self._parse_openapi_spec(spec, base_url)
                            discovered.update(endpoints)
                        except json.JSONDecodeError:
                            pass
            
            except Exception:
                pass
        
        return discovered
    
    def _parse_openapi_spec(self, spec: Dict[str, Any], base_url: str) -> Set[str]:
        """
        Parse OpenAPI/Swagger specification to extract endpoints.
        
        Args:
            spec: OpenAPI/Swagger specification dictionary.
            base_url: Base URL for the API.
        
        Returns:
            Set of endpoint URLs.
        """
        discovered = set()
        
        try:
            # Get base path
            base_path = spec.get('basePath', '')
            
            # Extract paths
            paths = spec.get('paths', {})
            for path in paths.keys():
                full_path = base_path + path
                full_url = urljoin(base_url, full_path)
                discovered.add(full_url)
                logger.debug(f"Found endpoint from spec: {full_path}")
        
        except Exception as e:
            logger.warning(f"Failed to parse OpenAPI spec: {str(e)}")
        
        return discovered
    
    def _extract_path(self, url: str) -> str:
        """
        Extract path from URL.
        
        Args:
            url: Full URL.
        
        Returns:
            Path component.
        """
        parsed = urlparse(url)
        return parsed.path or '/'
