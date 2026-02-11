# PolicyEngine Python Integration Tests

This directory contains Python-based integration and end-to-end tests for the Manetu PolicyEngine.

## Overview

While the PolicyEngine is written in Go, this Python test suite provides:

- **Integration Testing**: Test the HTTP and gRPC APIs from a client perspective
- **End-to-End Testing**: Validate complete policy evaluation workflows
- **PolicyDomain Validation**: Test PolicyDomain configurations
- **Cross-Language Testing**: Ensure APIs work correctly from non-Go clients

## Quick Start

### Setup

```bash
# Option 1: Use the test runner script (recommended)
./scripts/run-tests.sh

# Option 2: Manual setup
python3 -m venv .venv-test
source .venv-test/bin/activate
pip install -r requirements-test.txt
pytest
```

### Running Tests

```bash
# Run all tests (excluding integration tests by default)
./scripts/run-tests.sh

# Run smoke tests only
./scripts/run-tests.sh --smoke

# Run integration tests (requires MPE server)
./scripts/run-tests.sh --integration

# Run with coverage report
./scripts/run-tests.sh --coverage

# Run specific test file
pytest tests/test_sample.py

# Run specific test
pytest tests/test_sample.py::TestPolicyEngineCLI::test_mpe_version

# Run tests matching a keyword
pytest -k "policy"
```

## Test Organization

Tests are organized using pytest markers:

- `@pytest.mark.unit` - Fast unit tests, no external dependencies
- `@pytest.mark.integration` - Integration tests requiring MPE server
- `@pytest.mark.smoke` - Quick smoke tests for basic functionality
- `@pytest.mark.api` - HTTP API tests
- `@pytest.mark.grpc` - gRPC service tests
- `@pytest.mark.policy` - PolicyDomain validation tests
- `@pytest.mark.slow` - Tests that take significant time

### Run tests by marker

```bash
pytest -m unit          # Only unit tests
pytest -m smoke         # Only smoke tests
pytest -m "not slow"    # Skip slow tests
```

## Project Structure

```
tests/
├── __init__.py           # Package initialization
├── conftest.py           # Shared fixtures and configuration
├── test_sample.py        # Sample tests demonstrating patterns
├── README.md             # This file
└── [your test files]     # Add your tests here

pytest.ini                # Pytest configuration
requirements-test.txt     # Python test dependencies
scripts/run-tests.sh      # Test runner script
```

## Writing Tests

### Example Test

```python
import pytest

@pytest.mark.integration
def test_authorization_flow(mpe_server, sample_principal):
    """Test a complete authorization flow."""
    import requests

    # Make authorization request
    response = requests.post(
        f"{mpe_server}/v1/authorize",
        json={
            "principal": sample_principal,
            "action": "read",
            "resource": {"id": "doc-123", "type": "document"}
        }
    )

    # Assert response
    assert response.status_code == 200
    assert response.json()["allow"] is True
```

### Available Fixtures

See `conftest.py` for all available fixtures:

- `project_root` - Path to project root directory
- `testdata_dir` - Path to testdata directory
- `mpe_binary` - Path to built mpe CLI binary
- `mpe_server` - Running MPE server instance (starts/stops automatically)
- `sample_policy_domain` - Path to sample PolicyDomain YAML
- `sample_principal` - Sample principal for authorization tests
- `sample_resource` - Sample resource for authorization tests

## Best Practices

1. **Use markers** - Tag tests appropriately (unit, integration, smoke, etc.)
2. **Use fixtures** - Leverage shared fixtures in conftest.py
3. **Keep tests focused** - One test should test one thing
4. **Clean up resources** - Use fixtures for setup/teardown
5. **Skip when appropriate** - Use `@pytest.mark.skip()` for tests requiring specific setup

## CI/CD Integration

To integrate with CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Run Python Integration Tests
  run: |
    ./scripts/run-tests.sh --coverage
```

## Environment Variables

- `MPE_TEST_PORT` - Port for test server (default: 9090)
- `MPE_TEST_TIMEOUT` - Test timeout in seconds (default: 30)

## Troubleshooting

### Tests failing to start MPE server

Make sure the mpe binary is built:
```bash
make build
```

### Import errors

Activate the virtual environment:
```bash
source .venv-test/bin/activate
pip install -r requirements-test.txt
```

### Port already in use

Set a different port:
```bash
export MPE_TEST_PORT=9091
pytest
```

## Next Steps

This is a starting point! Expand this test suite by:

1. Adding HTTP API integration tests
2. Adding gRPC service tests
3. Testing different PolicyDomain configurations
4. Adding performance/load tests
5. Testing error cases and edge conditions
