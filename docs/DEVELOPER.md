# VIPRecon Developer Guide

Welcome to the VIPRecon developer documentation! This guide explains the project architecture, core components, and how to add your own scanning modules.

## Architecture Overview

VIPRecon is built on an asynchronous architecture using `asyncio` and `aiohttp`.

```
main.py
  └── cli/                      # Interface handling
  └── core/                     # Orchestration & Infrastructure
      └── orchestrator.py       # Main glue connecting modules
      └── http_client.py        # Shared client with rate limiting
  └── modules/                  # Specialized scanning logic
  └── reports/                  # Data visualization
```

## Core Components

### 1. `AsyncHTTPClient`
All network requests should pass through the `AsyncHTTPClient` found in `src/core/http_client.py`.
- **Automatic Rate Limiting**: Uses the token bucket algorithm.
- **Retries**: Configurable retry logic for transient failures.
- **Proxy Support**: Easy routing through tools like Burp Suite.

### 2. `ScanResult` & `models.py`
Data is passed between modules using type-safe dataclasses. Always use the predefined models in `src/core/models.py`.

### 3. `ScanOrchestrator`
The orchestrator manages the lifecycle of a scan. It initializes the shared client and executes modules sequentially (or concurrently where appropriate).

## Adding a New Module

Adding a module is a 3-step process:

### Step 1: Create the Module File
Create a new file in `src/modules/your_module.py`. Inherit logic from existing patterns:

```python
class MyNewModule:
    def __init__(self, http_client):
        self.http_client = http_client

    async def run(self, target: ScanTarget) -> List[Vulnerability]:
        # Your logic here
        pass
```

### Step 2: Register in Orchestrator
Open `src/core/orchestrator.py`:
1. Import your module.
2. Add a private method `_run_your_module` to the `ScanOrchestrator` class.
3. Add it to the `self.available_modules` dictionary in `__init__`.

### Step 3: Update Argument Parser
If you want the module to be selectable via the CLI, update `src/cli/argument_parser.py` valid modules set.

## Testing Your Changes
We use `pytest`. Always add a test file in the `tests/` directory matching your module name.

```bash
# Run all tests
pytest tests/
```

## Styling & Linting
- Follow PEP 8.
- Use type hints for all function signatures.
- Document classes and methods with Google-style docstrings.
