"""
Tests for the WAFDetector module using mocked HTTP responses.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from src.modules.waf_detector import WAFDetector
from src.core.models import ScanTarget, HTTPResponse

@pytest.fixture
def mock_http_client():
    """Provide a mocked HTTP client."""
    client = MagicMock()
    client.get = AsyncMock()
    return client

@pytest.mark.asyncio
async def test_waf_detection_cloudflare(mock_http_client):
    """Test detection of Cloudflare WAF."""
    target = ScanTarget(url="https://example.com", domain="example.com")
    
    # Mock Cloudflare response
    mock_response = HTTPResponse(
        status_code=403,
        headers={'server': 'cloudflare', 'cf-ray': '123456789'},
        body="Attention Required! | Cloudflare",
        response_time=0.1,
        url="https://example.com/?id=1' OR '1'='1"
    )
    mock_http_client.get.return_value = mock_response
    
    detector = WAFDetector(mock_http_client)
    result = await detector.detect(target)
    
    assert result is not None
    assert result['detected'] is True
    assert "Cloudflare" in result['name']
    assert result['confidence'] == 'high'

@pytest.mark.asyncio
async def test_waf_no_detection(mock_http_client):
    """Test behavior when no WAF is detected."""
    target = ScanTarget(url="https://example.com", domain="example.com")
    
    # Mock normal response (200 OK)
    mock_response = HTTPResponse(
        status_code=200,
        headers={'server': 'Apache'},
        body="Welcome home",
        response_time=0.1,
        url="https://example.com/"
    )
    mock_http_client.get.return_value = mock_response
    
    detector = WAFDetector(mock_http_client)
    result = await detector.detect(target)
    
    assert result is None
