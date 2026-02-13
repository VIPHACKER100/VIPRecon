# VIPRecon Developer Guide

**Version**: 1.0.1

Welcome to the VIPRecon developer documentation! This guide explains the project architecture, core components, and how to add your own scanning modules.

## Recent Changes (v1.0.1)

- **RateLimiter**: Rewritten with proper token bucket algorithm
- **Type Safety**: Enhanced type annotations across all modules
- **Error Handling**: Improved null checks and exception handling
- **Testing**: All 15 unit tests now passing
- **Path Traversal**: Enhanced detection in URL validation

## Architecture Overview

VIPRecon is built on an asynchronous architecture using `asyncio` and `aiohttp` for high-performance concurrent scanning.

```
viprecon/
├── main.py                     # Entry point
├── src/
│   ├── cli/                    # Command-line interface
│   │   ├── argument_parser.py  # CLI argument parsing
│   │   ├── progress.py         # Progress tracking & display
│   │   ├── output_formatter.py # Console output formatting
│   │   └── interactive.py      # Interactive shell
│   ├── core/                   # Core infrastructure
│   │   ├── orchestrator.py     # Scan coordination & module management
│   │   ├── http_client.py      # Async HTTP client with retries
│   │   ├── rate_limiter.py     # Token bucket rate limiting
│   │   ├── models.py           # Data models (dataclasses)
│   │   └── exceptions.py       # Custom exception classes
│   ├── modules/                # Scanning modules
│   │   ├── basic_info.py       # Basic reconnaissance
│   │   ├── fingerprinting.py   # Technology detection
│   │   ├── subdomain_enum.py   # Subdomain discovery
│   │   ├── waf_detector.py     # WAF identification
│   │   ├── api_discovery.py    # API endpoint discovery
│   │   ├── vuln_scanner.py     # Vulnerability scanning
│   │   ├── cors_checker.py     # CORS misconfiguration checks
│   │   ├── js_analyzer.py      # JavaScript analysis
│   │   ├── security_headers.py # Security header audit
│   │   ├── port_scanner.py     # Network port scanning
│   │   └── directory_brute.py  # Directory brute-forcing
│   ├── reports/                # Report generation
│   │   ├── report_manager.py   # Report coordination
│   │   ├── json_report.py      # JSON report generation
│   │   ├── html_report.py      # HTML report generation
│   │   └── templates/          # HTML templates
│   └── utils/                  # Utilities
│       ├── validators.py       # Input validation
│       ├── config_loader.py    # Configuration management
│       ├── logger.py           # Logging setup
│       ├── notifications.py    # Webhook notifications
│       └── diff_engine.py      # Scan comparison
├── tests/                      # Unit tests
├── config/                     # Configuration files
└── docs/                       # Documentation
```

## Core Components

### 1. `AsyncHTTPClient` (`src/core/http_client.py`)
Centralized HTTP client for all network requests.

**Features:**
- **Automatic Rate Limiting**: Integrated with `RateLimiter`
- **Retry Logic**: Configurable exponential backoff for transient failures
- **Proxy Support**: Easy routing through tools like Burp Suite
- **Connection Pooling**: Efficient connection reuse via `aiohttp`
- **SSL Control**: Optional SSL verification bypass

**Usage:**
```python
async with AsyncHTTPClient(rate_limiter=limiter) as client:
    response = await client.get("https://example.com")
```

### 2. `RateLimiter` (`src/core/rate_limiter.py`)
Token bucket rate limiter for controlling request frequency.

**Features:**
- **Token Bucket Algorithm**: Smooth rate limiting with burst capability
- **Async Context Manager**: Easy integration with `async with`
- **Configurable**: `requests_per_second` and `burst_limit` parameters

**Usage:**
```python
limiter = RateLimiter(requests_per_second=10, burst_limit=20)
async with limiter:
    # Make request
    pass
```

### 3. `ScanOrchestrator` (`src/core/orchestrator.py`)
Manages the lifecycle of a scan, coordinating all modules.

**Responsibilities:**
- Initializes shared HTTP client and rate limiter
- Executes modules sequentially
- Handles checkpoint creation and resumption
- Manages scan metadata and results
- Provides error handling and recovery

### 4. `ScanResult` & Models (`src/core/models.py`)
Type-safe dataclasses for structured data.

**Key Models:**
- `ScanTarget`: Target URL/domain information
- `ScanResult`: Complete scan findings container
- `Vulnerability`: Security issue with severity
- `Technology`: Detected technology/stack
- `Subdomain`, `Endpoint`, `SecurityHeader`: Specific findings

### 5. Exception Handling (`src/core/exceptions.py`)
Custom exception hierarchy for granular error handling:

- `ReconException`: Base exception
- `NetworkException`: Network-related errors
- `ValidationException`: Input validation failures
- `TimeoutException`: Request timeouts
- `ModuleException`: Module-specific errors

## Adding a New Module

Adding a module is a 4-step process:

### Step 1: Create the Module File
Create a new file in `src/modules/your_module.py`. Follow the existing patterns:

```python
"""
Description of your module.
"""

from typing import List, Any
from src.core.models import ScanTarget, ScanResult, Vulnerability
from src.core.http_client import AsyncHTTPClient
from src.core.exceptions import ModuleException
from src.utils.logger import get_logger

logger = get_logger(__name__)


class YourNewModule:
    """Brief description of the module."""
    
    def __init__(self, http_client: AsyncHTTPClient):
        """
        Initialize the module.
        
        Args:
            http_client: HTTP client for making requests.
        """
        self.http_client = http_client
    
    async def scan(self, target: ScanTarget) -> List[Vulnerability]:
        """
        Perform scanning logic.
        
        Args:
            target: Target to scan.
            
        Returns:
            List of findings.
        """
        logger.info(f"Starting your module scan for {target.domain}")
        
        try:
            # Your scanning logic here
            findings = []
            
            # Example: Make HTTP request
            response = await self.http_client.get(target.url)
            
            # Process response
            # ...
            
            return findings
            
        except Exception as e:
            logger.error(f"Your module failed: {str(e)}")
            raise ModuleException("your_module", f"Scan failed: {str(e)}")
```

### Step 2: Register in Orchestrator
Open `src/core/orchestrator.py`:

1. **Import your module** at the top:
```python
from src.modules.your_module import YourNewModule
```

2. **Add a private method** to execute your module:
```python
async def _run_your_module(self, target: ScanTarget, result: ScanResult) -> None:
    """Run your new module."""
    if self.http_client is None:
        raise ReconException("HTTP client not initialized")
    
    scanner = YourNewModule(self.http_client)
    findings = await scanner.scan(target)
    result.your_findings = findings  # Add to ScanResult
```

3. **Register in available_modules** in `__init__`:
```python
self.available_modules = {
    # ... existing modules ...
    'your_module': self._run_your_module,
}
```

### Step 3: Update Argument Parser
Open `src/cli/argument_parser.py` and add your module to the valid modules set:

```python
valid_modules = {
    # ... existing modules ...
    'your_module',
}
```

Also update the help text for the `--modules` argument.

### Step 4: Update Models (if needed)
If your module produces new types of findings, update `src/core/models.py`:

```python
@dataclass
class ScanResult:
    # ... existing fields ...
    your_findings: List[YourFinding] = field(default_factory=list)
```

And create a new dataclass for your finding type:

```python
@dataclass
class YourFinding:
    """Represents a finding from your module."""
    name: str
    severity: SeverityLevel
    description: str
    # ... other fields ...
```

## Testing Your Changes

VIPRecon uses `pytest` for testing. All tests must pass before submitting changes.

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_your_module.py -v

# Run specific test
pytest tests/test_your_module.py::test_function_name -v
```

### Writing Tests

Create a new test file in `tests/` matching your module name:

```python
"""
Tests for your_module.
"""

import pytest
from src.modules.your_module import YourNewModule
from src.core.models import ScanTarget

@pytest.mark.asyncio
async def test_your_module_basic():
    """Test basic functionality."""
    # Setup
    target = ScanTarget(url="https://example.com", domain="example.com")
    
    # Execute
    module = YourNewModule(http_client)
    results = await module.scan(target)
    
    # Assert
    assert len(results) >= 0
    # Add more specific assertions
```

### Test Guidelines

- Use `@pytest.mark.asyncio` for async tests
- Mock external HTTP calls to avoid network dependencies
- Test both success and failure cases
- Test edge cases (empty input, invalid input, etc.)
- Maintain >80% code coverage for new modules

## Code Quality

### Type Hints
Use type hints for all function signatures:

```python
def function_name(param: str) -> int:
    """Function description."""
    return len(param)
```

### Docstrings
Use Google-style docstrings:

```python
def scan(self, target: ScanTarget) -> List[Vulnerability]:
    """
    Scan the target for vulnerabilities.
    
    Args:
        target: Target to scan.
        
    Returns:
        List of discovered vulnerabilities.
        
    Raises:
        ModuleException: If scanning fails.
    """
```

### Error Handling

Always use the custom exception hierarchy:

```python
from src.core.exceptions import ModuleException

try:
    # Risky operation
    result = await self.http_client.get(url)
except Exception as e:
    logger.error(f"Operation failed: {str(e)}")
    raise ModuleException("module_name", f"Failed: {str(e)}")
```

### Logging

Use the centralized logger:

```python
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Different log levels
logger.debug("Detailed debug info")
logger.info("General information")
logger.warning("Warning message")
logger.error("Error message")
```

## Configuration

Default configuration is stored in `config/default_config.yaml`. Module-specific settings should be added here:

```yaml
modules:
  your_module:
    setting_name: value
    another_setting: value
```

Access configuration in your module:

```python
setting = self.config.get('modules', {}).get('your_module', {}).get('setting_name', default_value)
```

## Submitting Changes

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/your-feature`
3. **Make** your changes with tests
4. **Run** all tests: `pytest tests/`
5. **Commit** with clear messages: `git commit -m "Add: your feature description"`
6. **Push** to your fork: `git push origin feature/your-feature`
7. **Open** a Pull Request

### Commit Message Format

```
Type: Brief description

Detailed explanation of what changed and why.

- Bullet points for specific changes
- Reference issues: Fixes #123
```

Types: `Add`, `Fix`, `Update`, `Remove`, `Refactor`, `Docs`, `Test`

## Debugging Tips

### Enable Debug Logging

```python
# In your code
logger.setLevel(logging.DEBUG)

# Or via CLI
python main.py -t example.com -v
```

### Using a Proxy

Route traffic through Burp Suite or OWASP ZAP:

```bash
python main.py -t example.com --proxy http://127.0.0.1:8080
```

### Interactive Debugging

Use Python debugger in async context:

```python
import pdb; pdb.set_trace()
```

Or use `breakpoint()` in Python 3.7+.

### Checkpoint Debugging

Inspect checkpoint files to understand scan state:

```bash
cat output/checkpoint_example.com.json | python -m json.tool
```

## Architecture Patterns

### Async/Await Pattern

All I/O operations should be async:

```python
async def fetch_data(self, url: str) -> str:
    async with self.http_client.get(url) as response:
        return await response.text()
```

### Module Result Pattern

Modules should return structured data:

```python
async def scan(self, target: ScanTarget) -> List[Vulnerability]:
    vulnerabilities = []
    
    # Discover issues
    if self._is_vulnerable(response):
        vuln = Vulnerability(
            type="Vuln Type",
            severity=SeverityLevel.HIGH,
            description="Description",
            url=target.url,
            remediation="How to fix"
        )
        vulnerabilities.append(vuln)
    
    return vulnerabilities
```

### Rate Limiting Pattern

Always use rate limiting for HTTP requests:

```python
async def make_request(self, url: str) -> HTTPResponse:
    async with self.rate_limiter:
        return await self.http_client.get(url)
```
