"""
Rate limiter for controlling request frequency.
Prevents overwhelming target servers and triggering defensive measures.
"""

import asyncio
import time
from typing import Optional
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter for controlling request frequency.
    """
    
    def __init__(self, requests_per_second: float = 1.0, burst_limit: Optional[int] = None):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum number of requests per second.
            burst_limit: Maximum burst size (default: 5x requests_per_second).
        """
        self.requests_per_second = requests_per_second
        self.burst_limit = burst_limit or int(requests_per_second)
        self.tokens = self.burst_limit
        self.last_update = time.time()
        self.lock = asyncio.Lock()
        
        logger.debug(f"Rate limiter initialized: {requests_per_second} req/s, burst: {self.burst_limit}")
    
    def _add_new_tokens(self) -> None:
        """Add new tokens based on elapsed time."""
        current_time = time.time()
        elapsed = current_time - self.last_update
        new_tokens = elapsed * self.requests_per_second
        self.tokens = min(self.burst_limit, self.tokens + new_tokens)
        self.last_update = current_time
    
    async def acquire(self) -> None:
        """
        Acquire permission to make a request.
        Blocks if rate limit would be exceeded.
        """
        async with self.lock:
            # Add new tokens based on elapsed time
            self._add_new_tokens()
            
            # Wait until we have a token available
            while self.tokens < 1:
                # Calculate wait time for one token
                wait_time = 1.0 / self.requests_per_second
                logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
                self._add_new_tokens()
            
            # Consume a token
            self.tokens -= 1
    
    def get_current_rate(self) -> float:
        """
        Get current request rate.
        
        Returns:
            Current requests per second.
        """
        return self.requests_per_second
    
    async def __aenter__(self):
        """Context manager entry."""
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        pass
