"""
Shared pytest fixtures for VIPRecon tests.
"""

import pytest
import asyncio
from typing import Dict, Any
from src.core.rate_limiter import RateLimiter
from src.core.http_client import AsyncHTTPClient

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def mock_config() -> Dict[str, Any]:
    """Provide a mock configuration dictionary."""
    return {
        'rate_limit': 100,  # High limit for tests
        'http': {
            'timeout': 5,
            'max_retries': 1
        },
        'user_agent': 'VIPRecon-Test/1.0',
        'proxy': None,
        'no_verify_ssl': True
    }

@pytest.fixture
async def rate_limiter():
    """Provide a RateLimiter instance."""
    return RateLimiter(requests_per_second=100)

@pytest.fixture
async def http_client(rate_limiter):
    """Provide an AsyncHTTPClient instance."""
    client = AsyncHTTPClient(
        rate_limiter=rate_limiter,
        timeout=5,
        max_retries=1
    )
    yield client
    await client.close()
