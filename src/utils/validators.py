"""
Input validation utilities for VIPRecon tool.
Ensures safe handling of user inputs and prevents injection attacks.
"""

import re
import validators
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Tuple, Any
from src.core.exceptions import ValidationException
from src.core.models import ScanTarget


def validate_url(url: str) -> bool:
    """
    Validate if a string is a valid URL.
    """
    try:
        return validators.url(url) is True
    except Exception:
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name.
    """
    try:
        return validators.domain(domain) is True
    except Exception:
        return False


def validate_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IPv4 or IPv6 address.
    """
    try:
        return validators.ipv4(ip) is True or validators.ipv6(ip) is True
    except Exception:
        return False


def sanitize_input(user_input: str) -> str:
    """
    Sanitize user input by removing potentially dangerous characters.
    """
    if not user_input:
        return ""
    # Remove null bytes
    sanitized = user_input.replace('\x00', '')
    # Remove control characters except newline and tab
    sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\n\t')
    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()
    return sanitized


class TargetValidator:
    """Validator and parser for scan targets."""
    
    def parse_target(self, target_url: str) -> ScanTarget:
        """
        Parse a target URL or domain into a ScanTarget object.
        
        Args:
            target_url: Target URL or domain string.
        
        Returns:
            ScanTarget object.
        
        Raises:
            ValidationException: If target is invalid.
        """
        # Sanitize input
        target_url = sanitize_input(target_url)
        
        if not target_url:
            raise ValidationException("Target URL cannot be empty")
        
        # Check for path traversal attempts (but not in protocol)
        url_without_protocol = target_url
        if '://' in target_url:
            url_without_protocol = target_url.split('://', 1)[1]
        
        dangerous_patterns = ['..', '\\', '%2e%2e']
        for pattern in dangerous_patterns:
            if pattern in url_without_protocol.lower():
                raise ValidationException(f"Path traversal attempt detected: {target_url}")
            
        # Add protocol if missing
        original_input = target_url
        if not target_url.startswith(('http://', 'https://')):
            target_url = f'https://{target_url}'
        
        # Parse URL
        try:
            parsed = urlparse(target_url)
        except Exception as e:
            raise ValidationException(f"Failed to parse URL {target_url}: {str(e)}")
            
        # Extract components
        protocol = parsed.scheme or 'https'
        domain = parsed.hostname
        
        if not domain:
            # Maybe it was just a domain name with a port but no protocol?
            # urlparse("example.com:8080") -> scheme='example.com', path='8080'
            # Let's try again with the original input if it didn't have protocol
            if not original_input.startswith(('http://', 'https://')):
                # Try prepending https again if it failed
                pass
            raise ValidationException(f"Could not extract domain from target: {original_input}")
            
        # Validate domain/IP
        if not validate_domain(domain) and not validate_ip(domain):
            raise ValidationException(f"Invalid domain or IP address: {domain}")
            
        # Determine port
        port = parsed.port
        if not port:
            port = 443 if protocol == 'https' else 80
            
        if not validate_port(port):
            raise ValidationException(f"Invalid port number: {port}")
            
        return ScanTarget(
            url=target_url,
            domain=domain,
            ip=None,  # Will be resolved later
            port=port,
            protocol=protocol
        )


def parse_target(target: str) -> Dict[str, Any]:
    """
    Parse a target URL or domain into components (for legacy support).
    """
    validator = TargetValidator()
    scan_target = validator.parse_target(target)
    return {
        'protocol': scan_target.protocol,
        'domain': scan_target.domain,
        'port': scan_target.port,
        'path': urlparse(scan_target.url).path or '/',
        'full_url': scan_target.url
    }


def validate_port(port: int) -> bool:
    """
    Validate if a port number is valid.
    """
    return 1 <= port <= 65535


def is_safe_filename(filename: str) -> bool:
    """
    Check if a filename is safe (no path traversal attempts).
    """
    if not filename:
        return False
        
    # Check for path traversal patterns
    dangerous_patterns = ['..', '/', '\\', '\x00']
    for pattern in dangerous_patterns:
        if pattern in filename:
            return False
            
    # Check for absolute paths
    if filename.startswith(('/', '\\')) or (len(filename) > 1 and filename[1] == ':'):
        return False
        
    return True


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from a URL.
    """
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def normalize_url(url: str) -> str:
    """
    Normalize a URL to a standard format.
    """
    if not url:
        return ""
        
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = f'https://{url}'
    
    # Parse and reconstruct
    try:
        parsed = urlparse(url)
        
        # Remove default ports
        port = parsed.port
        if (parsed.scheme == 'https' and port == 443) or (parsed.scheme == 'http' and port == 80):
            port = None
        
        # Reconstruct URL
        netloc = parsed.hostname or ""
        if port:
            netloc = f'{netloc}:{port}'
        
        normalized = f'{parsed.scheme}://{netloc}{parsed.path}'
        if parsed.query:
            normalized += f'?{parsed.query}'
        
        return normalized
    except Exception:
        return url


def is_valid_http_method(method: str) -> bool:
    """
    Check if an HTTP method is valid.
    """
    if not method:
        return False
    valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
    return method.upper() in valid_methods
