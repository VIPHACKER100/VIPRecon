"""
Async HTTP client wrapper for VIPRecon tool.
Provides centralized HTTP operations with error handling and retry logic.
"""

import aiohttp
import asyncio
import time
from typing import Dict, Optional, Any
from src.core.exceptions import NetworkException, TimeoutException
from src.core.models import HTTPResponse
from src.core.rate_limiter import RateLimiter
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AsyncHTTPClient:
    """
    Asynchronous HTTP client with retry logic and error handling.
    """
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        user_agent: str = "VIPRecon/1.0",
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        rate_limiter: Optional[RateLimiter] = None
    ):
        """
        Initialize HTTP client.
        
        Args:
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts.
            user_agent: User-Agent header value.
            verify_ssl: Whether to verify SSL certificates.
            proxy: Optional proxy URL (e.g., "http://127.0.0.1:8080").
            rate_limiter: Optional rate limiter instance.
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.rate_limiter = rate_limiter
        
        # Session will be created when needed
        self._session: Optional[aiohttp.ClientSession] = None
        
        logger.debug(f"HTTP client initialized: timeout={timeout}s, retries={max_retries}")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """
        Get or create aiohttp session.
        """
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                ssl=self.verify_ssl,
                limit=100,
                limit_per_host=10
            )
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent}
            )
        
        return self._session
    
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True
    ) -> HTTPResponse:
        """Perform HTTP GET request."""
        return await self._request('GET', url, headers=headers, params=params, allow_redirects=allow_redirects)
    
    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> HTTPResponse:
        """Perform HTTP POST request."""
        return await self._request('POST', url, data=data, json=json, headers=headers)
    
    async def head(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True
    ) -> HTTPResponse:
        """Perform HTTP HEAD request."""
        return await self._request('HEAD', url, headers=headers, allow_redirects=allow_redirects)
    
    async def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> HTTPResponse:
        """
        Internal method to perform HTTP request with retry logic.
        """
        # Apply rate limiting if configured
        if self.rate_limiter:
            await self.rate_limiter.acquire()
        
        session = await self._get_session()
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                
                # Add proxy if configured
                if self.proxy:
                    kwargs['proxy'] = self.proxy
                
                async with session.request(method, url, **kwargs) as response:
                    response_time = time.time() - start_time
                    
                    # Read response body
                    try:
                        body = await response.text()
                    except Exception:
                        # If text decoding fails, try bytes
                        body_bytes = await response.read()
                        body = body_bytes.decode('utf-8', errors='ignore')
                    
                    # Create HTTPResponse object
                    http_response = HTTPResponse(
                        status_code=response.status,
                        headers=dict(response.headers),
                        body=body,
                        response_time=response_time,
                        url=str(response.url)
                    )
                    
                    logger.debug(f"{method} {url} -> {response.status} ({response_time:.2f}s)")
                    
                    return http_response
            
            except asyncio.TimeoutError as e:
                last_exception = e
                logger.warning(f"Timeout on {method} {url} (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                
            except aiohttp.ClientError as e:
                last_exception = e
                logger.warning(f"Network error on {method} {url}: {str(e)} (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
            
            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error on {method} {url}: {str(e)}")
                break
        
        # All retries failed
        if isinstance(last_exception, asyncio.TimeoutError):
            raise TimeoutException(f"Request to {url} timed out after {self.max_retries} attempts")
        else:
            raise NetworkException(f"Request to {url} failed: {str(last_exception)}")
    
    async def close(self) -> None:
        """Close the HTTP session and cleanup resources."""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("HTTP client session closed")
    
    async def __aenter__(self):
        """Context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.close()
