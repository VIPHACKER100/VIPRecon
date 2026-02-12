"""
Tests for the TargetValidator component.
"""

import pytest
from src.utils.validators import TargetValidator
from src.core.models import ScanTarget
from src.core.exceptions import ValidationException

def test_validator_valid_urls():
    """Test validation of valid URLs."""
    validator = TargetValidator()
    
    targets = [
        "https://example.com",
        "http://test.local:8080",
        "example.com",
        "127.0.0.1",
        "sub.domain.tld/path?query=1"
    ]
    
    for t in targets:
        result = validator.parse_target(t)
        assert isinstance(result, ScanTarget)
        assert result.domain in t or result.ip in t

def test_validator_invalid_inputs():
    """Test validation of invalid inputs."""
    validator = TargetValidator()
    
    invalid = [
        "",
        "   ",
        "!!!invalid!!!",
        "ftp://not-supported.com",
        "javascript:alert(1)"
    ]
    
    for i in invalid:
        with pytest.raises(ValidationException):
            validator.parse_target(i)

def test_validator_sanitization():
    """Test path traversal and character sanitization."""
    validator = TargetValidator()
    
    # Payload in URL should be caught or sanitized in the domain part
    with pytest.raises(ValidationException):
        validator.parse_target("example.com/../../etc/passwd")

def test_validator_parsing_details():
    """Test specific parsing logic for ports and protocols."""
    validator = TargetValidator()
    
    # Port parsing
    target = validator.parse_target("example.com:8443")
    assert target.port == 8443
    
    # Protocol parsing
    target = validator.parse_target("http://example.com")
    assert target.protocol == "http"
    assert target.port == 80  # Default for http
    
    target = validator.parse_target("https://example.com")
    assert target.protocol == "https"
    assert target.port == 443  # Default for https
