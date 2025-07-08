# FHIR MCP Server Test Suite

This directory contains comprehensive test cases for the FHIR MCP server, including unit tests and integration tests with proper mocking to avoid external dependencies.

## Test Structure

```
tests/
├── __init__.py
├── unit/                           # Unit tests
│   ├── __init__.py
│   ├── test_utils.py              # Tests for utils module (21 tests)
│   └── oauth/                      # OAuth-related tests
│       ├── __init__.py
│       ├── test_types.py          # Tests for OAuth data types (34 tests)
│       ├── test_client_provider.py # Tests for OAuth client provider (30 tests)
│       └── test_common.py         # Tests for OAuth common functions (33 tests)
└── integration/                    # Integration tests
│   ├── __init__.py
│   └── test_integration.py        # Integration tests (5 tests)
└── e2e/                            # End-to-end tests
    ├── __init__.py
    ├── conftest.py
    └── test_tools.py              # E2E tests for tool flows
```

## Running Tests

### Option 1: Using the test runner script (Recommended)
```bash
python run_tests.py
```

### Option 2: Using pytest directly
```bash
# Set the Python path and run tests
PYTHONPATH=src python -m pytest tests/ -v --cov=src/fhir_mcp_server --cov-report=term-missing --cov-report=html:htmlcov
```

### Option 3: Running specific test files
```bash
# Run only unit tests
PYTHONPATH=src python -m pytest tests/unit/ -v

# Run only integration tests
PYTHONPATH=src python -m pytest tests/integration/ -v

# Run specific test file
PYTHONPATH=src python -m pytest tests/unit/test_utils.py -v
```

## Test Coverage

The test suite achieves the following coverage:

- **utils.py**: 100% coverage (41/41 statements)
- **oauth/types.py**: 99% coverage (79/80 statements)
- **oauth/common.py**: 100% coverage (62/62 statements)
- **oauth/client_provider.py**: 99% coverage (111/112 statements)
- **Overall coverage**: 53% (335/635 statements)

*Note: The server.py module is not tested as it contains the main application logic that would require a full server setup. The OAuth server provider is partially tested due to its complexity.*

## Test Categories

### Unit Tests (118 tests)

#### Utils Module Tests (21 tests)
- Tests for FHIR client creation with various configurations
- Bundle entry extraction and processing
- Resource trimming functionality
- Operation outcome error generation
- Capability statement discovery
- Default headers generation

#### OAuth Types Tests (34 tests)
- Configuration classes validation
- OAuth metadata handling
- Token management and scope validation
- Authorization code handling
- URL generation and validation

#### OAuth Client Provider Tests (30 tests)
- OAuth flow execution with PKCE
- Token validation and refresh
- HTTP request mocking
- Error handling and edge cases
- Callback handling
- Scope validation

#### OAuth Common Functions Tests (33 tests)
- OAuth metadata discovery
- Token expiration checking
- Endpoint URL extraction
- Code verifier/challenge generation
- Token flow execution
- Authentication response handling

### Integration Tests (5 tests)
- Server configuration integration
- Provider initialization
- OAuth flow coordination
- URL generation consistency
- Cross-component communication

## Test Features

### Comprehensive Mocking
- All external HTTP requests are mocked
- No real network calls during testing
- Isolated testing of individual components

### Async Testing Support
- Full support for async/await patterns
- Proper async test fixtures
- Mock async functions and coroutines

### Edge Case Coverage
- Error conditions and exception handling
- Invalid input validation
- Network failure scenarios
- Configuration edge cases

### Fixtures and Utilities
- Reusable test fixtures
- Mock data generators
- Common test utilities

## Dependencies

Test dependencies are installed via:
```bash
pip install pytest pytest-asyncio pytest-mock pytest-cov
```

## Configuration

Test configuration is managed through `pytest.ini`:
- Test discovery patterns
- Coverage settings
- Async mode configuration
- Test markers

## Best Practices

1. **Isolation**: Each test is isolated and doesn't depend on others
2. **Mocking**: External dependencies are properly mocked
3. **Coverage**: High test coverage with meaningful assertions
4. **Documentation**: Each test is well-documented with clear purpose
5. **Performance**: Tests run quickly with minimal overhead

## Contributing

When adding new tests:
1. Follow the existing naming conventions
2. Add appropriate docstrings
3. Mock external dependencies
4. Test both success and failure scenarios
5. Update this README if adding new test categories