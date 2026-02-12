"""
Custom exception classes for VIPRecon tool.
Provides granular error handling across the application.
"""


class ReconException(Exception):
    """Base exception for all VIPRecon errors."""
    pass


class NetworkException(ReconException):
    """Raised when network-related errors occur."""
    pass


class ValidationException(ReconException):
    """Raised when input validation fails."""
    pass


class TimeoutException(ReconException):
    """Raised when a request or operation times out."""
    pass


class AuthenticationException(ReconException):
    """Raised when authentication fails."""
    pass


class RateLimitException(ReconException):
    """Raised when rate limit is exceeded."""
    pass


class ConfigurationError(ReconException):
    """Raised when configuration is invalid or missing."""
    pass


class ModuleException(ReconException):
    """Raised when a scanning module encounters an error."""
    
    def __init__(self, module_name: str, message: str):
        self.module_name = module_name
        super().__init__(f"[{module_name}] {message}")


class ParsingException(ReconException):
    """Raised when parsing HTML, JSON, or other content fails."""
    pass
