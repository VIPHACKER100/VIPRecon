"""
Rate limiter for controlling request frequency.
Prevents overwhelming target servers and triggering defensive measures.
"""

import asyncio
import time
from collections import deque
from typing import Optional
from src.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimiter:
    """
    Token bucket rate limiter for controlling request frequency.
    """
    
    def __init__(self, requests_per_second: float = 1.0, burst_size: Optional[int] = None):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum number of requests per second.
            burst_size: Maximum burst size (default: 5x requests_per_second).
        """
        self.requests_per_second = requests_per_second
        self.interval = 1.0 / requests_per_second  # Time between requests
        self.burst_size = burst_size or max(5, int(requests_per_second * 5))
        
        # Track request timestamps
        self.request_times = deque(maxlen=self.burst_size)
        self.lock = asyncio.Lock()
        
        logger.debug(f"Rate limiter initialized: {requests_per_second} req/s, burst: {self.burst_size}")
    
    async def acquire(self) -> None:
        """
        Acquire permission to make a request.
        Blocks if rate limit would be exceeded.
        """
        async with self.lock:
            current_time = time.time()
            
            # Clean up old request times
            self._cleanup_old_requests(current_time)
            
            # Check if we need to wait
            if len(self.request_times) >= self.burst_size:
                # Calculate wait time
                oldest_request = self.request_times[0]
                time_window = 1.0  # 1 second window
                wait_time = time_window - (current_time - oldest_request)
                
                if wait_time > 0:
                    logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                    await asyncio.sleep(wait_time)
                    current_time = time.time()
                    self._cleanup_old_requests(current_time)
            
            # Check if we need to wait for interval
            if self.request_times:
                last_request = self.request_times[-1]
                time_since_last = current_time - last_request
                
                if time_since_last < self.interval:
                    wait_time = self.interval - time_since_last
                    logger.debug(f"Waiting {wait_time:.2f}s for rate limit interval")
                    await asyncio.sleep(wait_time)
                    current_time = time.time()
            
            # Record this request
            self.request_times.append(current_time)
    
    def _cleanup_old_requests(self, current_time: float) -> None:
        """
        Remove request timestamps older than 1 second.
        
        Args:
            current_time: Current timestamp.
        """
        while self.request_times and (current_time - self.request_times[0]) > 1.0:
            self.request_times.popleft()
    
    def get_current_rate(self) -> float:
        """
        Get current request rate.
        
        Returns:
            Current requests per second.
        """
        if len(self.request_times) < 2:
            return 0.0
        
        time_span = self.request_times[-1] - self.request_times[0]
        if time_span == 0:
            return 0.0
        
        return len(self.request_times) / time_span
    
    async def __aenter__(self):
        """Context manager entry."""
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        pass
