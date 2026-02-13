"""
Tests for the RateLimiter component.
"""

import pytest
import asyncio
import time
from src.core.rate_limiter import RateLimiter

@pytest.mark.asyncio
async def test_rate_limiter_init():
    """Test initialization of RateLimiter."""
    limiter = RateLimiter(requests_per_second=10, burst_limit=20)
    assert limiter.requests_per_second == 10
    assert limiter.burst_limit == 20
    assert limiter.tokens == 20

@pytest.mark.asyncio
async def test_rate_limiter_consumption():
    """Test token consumption."""
    limiter = RateLimiter(requests_per_second=100)
    
    # Take 10 tokens
    for _ in range(10):
        async with limiter:
            pass
            
    assert limiter.tokens <= 95  # Should have ~90 or slightly more after refill (with tolerance for timing)

@pytest.mark.asyncio
async def test_rate_limiter_refill():
    """Test that tokens are refilled over time."""
    limiter = RateLimiter(requests_per_second=10, burst_limit=10)
    
    # Consume all tokens
    limiter.tokens = 0
    
    # Wait 0.5 seconds, should refill 5 tokens
    await asyncio.sleep(0.5)
    
    # We call _add_new_tokens internally when acquiring, 
    # but for testing we can check if tokens increased
    async with limiter:
        pass
        
    assert limiter.tokens > 0
    assert limiter.tokens <= 5

@pytest.mark.asyncio
async def test_rate_limiter_blocking():
    """Test that the limiter eventually blocks/slows down."""
    limit = 50
    limiter = RateLimiter(requests_per_second=limit, burst_limit=limit)
    
    start_time = time.time()
    
    # Consume more than the limit
    for _ in range(limit + 5):
        async with limiter:
            pass
            
    end_time = time.time()
    duration = end_time - start_time
    
    # If it works, it should take at least (5/50) = 0.1 seconds for the extra tokens
    assert duration >= 0.05  # Approximate
