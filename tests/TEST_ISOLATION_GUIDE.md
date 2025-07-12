# Test Isolation Guide for Infrastructure Management System

## Overview

This guide explains the comprehensive test isolation system that prevents all external API calls during testing. The system ensures that tests run locally without making real network requests to external services like WHOIS, DNS, HTTP endpoints, or certificate authorities.

## Features

### Complete Network Isolation
- **WHOIS Queries**: All `whois.whois()` calls are mocked
- **DNS Lookups**: All `dns.resolver.resolve()` calls are mocked
- **HTTP Requests**: All `requests.get/post/put/delete` calls are mocked
- **SSL/TLS Connections**: All socket and SSL operations are mocked
- **Certificate Transparency**: All CT log queries are mocked
- **Subprocess Calls**: All external command executions are mocked

### Automatic Application
- **ALL Tests**: Network isolation is applied to ALL tests by default
- **No Configuration Required**: Tests automatically use isolated environment
- **Consistent Mock Data**: All tests get consistent, realistic mock responses

## Architecture

### Core Components

1. **`tests/test_isolation.py`**: Core isolation module with mock classes
2. **`tests/conftest.py`**: Pytest configuration with auto-applied fixtures
3. **`pytest.ini`**: Pytest configuration file
4. **Mock Classes**: Realistic mock objects for all external services

### Mock Classes

#### MockWhoisResult
```python
class MockWhoisResult:
    def __init__(self, domain: str = "example.com"):
        self.domain = domain
        self.registrar = "Test Registrar Ltd"
        self.registrant_name = "Test Owner"
        self.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        self.expiration_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.status = ["active", "clientTransferProhibited"]
        self.name_servers = ["ns1.example.com", "ns2.example.com"]
```

#### MockDNSAnswer
```python
class MockDNSAnswer:
    def __init__(self, address: str = "1.2.3.4", ttl: int = 300):
        self.address = address
        self.ttl = ttl
        self.target = address
        self.preference = 10  # For MX records
        self.exchange = "mail.example.com"  # For MX records
```

#### MockHTTPResponse
```python
class MockHTTPResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None, text: str = ""):
        self.status_code = status_code
        self.text = text or "Mock HTTP Response"
        self.json_data = json_data or []
        
    def json(self):
        return self.json_data
```

## Usage

### Basic Test Writing

Tests automatically use network isolation - no special configuration needed:

```python
def test_domain_scanner(domain_scanner, mock_session):
    """Test domain scanning - automatically isolated"""
    domain_info = domain_scanner.scan_domain('example.com', mock_session)
    
    # This will use mock data, not real WHOIS/DNS
    assert domain_info.registrar == "Test Registrar Ltd"
    assert domain_info.domain_name == "example.com"
```

### Using Fixtures

Several fixtures are available for common mock objects:

```python
def test_with_fixtures(mock_whois_result, mock_dns_answer, mock_http_response):
    """Test using pre-configured mock fixtures"""
    assert mock_whois_result.registrar == "Test Registrar Ltd"
    assert mock_dns_answer.address == "1.2.3.4"
    assert mock_http_response.status_code == 200
```

### Custom Mock Data

Create custom mock data for specific test scenarios:

```python
def test_custom_mock_data():
    """Test with custom mock data"""
    from tests.test_isolation import create_mock_whois_result
    
    custom_whois = create_mock_whois_result(
        domain="custom.com",
        registrar="Custom Registrar",
        creation_date=datetime(2010, 1, 1)
    )
    
    assert custom_whois.registrar == "Custom Registrar"
    assert custom_whois.domain == "custom.com"
```

### Manual Isolation Control

For advanced scenarios, you can manually control isolation:

```python
from tests.test_isolation import isolated_test, NetworkIsolationManager

@isolated_test
def test_manually_isolated():
    """Test with manual isolation decorator"""
    # This test is explicitly isolated
    pass

def test_with_context_manager():
    """Test using context manager"""
    with NetworkIsolationManager() as isolation:
        # Network calls are isolated within this block
        pass
```

## Configuration

### Pytest Configuration

The `pytest.ini` file configures the testing environment:

```ini
[tool:pytest]
# Automatically applies network isolation to ALL tests
testpaths = tests
python_files = test_*.py

# Timeout configuration to prevent hanging tests
timeout = 30
timeout_method = thread

# Environment variables
env =
    PYTHONPATH = .
    TESTING = 1
    PYTEST_CURRENT_TEST = 1
```

### Auto-Applied Fixtures

The `conftest.py` file automatically applies network isolation:

```python
@pytest.fixture(autouse=True)
def prevent_all_network_calls(request):
    """Auto-applied fixture that prevents ALL network calls for ALL tests"""
    _isolation_manager.start()
    yield
    _isolation_manager.stop()
```

## Verification

### Testing the Isolation

Verify that isolation is working correctly:

```python
def test_no_real_network_calls(domain_scanner, mock_session):
    """Verify no real network calls are made"""
    # Even with a real domain, should not make real calls
    domain_info = domain_scanner.scan_domain('google.com', mock_session)
    
    # Should have mock data, not real Google data
    assert domain_info.registrar == "Test Registrar Ltd"
```

### Consistency Checks

Verify that mock data is consistent:

```python
def test_consistent_mock_data(domain_scanner, mock_session):
    """Verify mock data is consistent across calls"""
    domain_info1 = domain_scanner.scan_domain('test1.com', mock_session)
    domain_info2 = domain_scanner.scan_domain('test2.com', mock_session)
    
    # Mock registrar should be consistent
    assert domain_info1.registrar == domain_info2.registrar
```

## Running Tests

### Basic Test Execution

```bash
# Run all tests with network isolation
pytest

# Run specific test file
pytest tests/unit/test_domain_scanner.py

# Run with verbose output
pytest -v

# Run with logging
pytest --log-cli-level=INFO
```

### Test Debugging

```bash
# Run single test with full output
pytest tests/unit/test_domain_scanner.py::test_scan_domain_basic -v -s

# Run with pdb debugger
pytest --pdb tests/unit/test_domain_scanner.py::test_scan_domain_basic
```

## Best Practices

### 1. Trust the Isolation

Don't add manual patches for external services - the isolation system handles everything:

```python
# ❌ Don't do this
@patch('requests.get')
def test_something(mock_get):
    mock_get.return_value = Mock()
    # Test code

# ✅ Do this instead
def test_something():
    # Network isolation is automatic
    result = make_http_request()
    assert result.status_code == 200
```

### 2. Use Realistic Test Data

Use domain names and data that reflect real-world scenarios:

```python
def test_domain_analysis():
    """Test with realistic domain names"""
    test_domains = [
        'example.com',
        'test.internal.company.com',
        'api.service.example.org'
    ]
    
    for domain in test_domains:
        result = analyze_domain(domain)
        assert result.is_valid
```

### 3. Test Error Conditions

Test how your code handles various error scenarios:

```python
def test_error_handling():
    """Test error handling with invalid inputs"""
    error_cases = [
        "",  # Empty string
        "invalid..domain",  # Invalid format
        "a" * 300,  # Too long
    ]
    
    for domain in error_cases:
        result = scan_domain(domain)
        # Should handle errors gracefully
        assert result.error is not None or result.is_valid == False
```

### 4. Performance Testing

Tests run faster with network isolation:

```python
def test_performance():
    """Test performance without network delays"""
    import time
    
    start = time.time()
    result = scan_multiple_domains(['test1.com', 'test2.com', 'test3.com'])
    duration = time.time() - start
    
    # Should complete quickly without real network calls
    assert duration < 1.0
    assert len(result) == 3
```

## Troubleshooting

### Common Issues

1. **Tests still making network calls**: Check that isolation is active
2. **Unexpected mock data**: Verify mock configuration
3. **Import errors**: Ensure test isolation module is properly imported

### Debugging Isolation

Check if isolation is active:

```python
def test_isolation_debug():
    """Debug isolation status"""
    from tests.test_isolation import _isolation_manager
    assert _isolation_manager.active == True
```

### Mock Data Verification

Verify mock responses:

```python
def test_mock_verification():
    """Verify mock data is being used"""
    import whois
    result = whois.whois('example.com')
    assert result.registrar == "Test Registrar Ltd"
```

## Migration Guide

### From Manual Mocking

If you have existing tests with manual mocking:

```python
# Before: Manual mocking
@patch('requests.get')
@patch('whois.whois')
def test_old_style(mock_whois, mock_requests):
    mock_whois.return_value = MockWhoisResult()
    mock_requests.return_value = MockHTTPResponse()
    # Test code

# After: Automatic isolation
def test_new_style():
    # Network isolation is automatic
    # Test code - same functionality, less boilerplate
```

### Updating Existing Tests

1. Remove manual `@patch` decorators for network calls
2. Remove manual mock setup for external services
3. Use provided fixtures for common mock objects
4. Test that isolation is working correctly

## Benefits

### For Development

- **Faster Tests**: No network delays
- **Reliable Tests**: No external service dependencies
- **Consistent Results**: Same mock data every run
- **Offline Development**: Tests work without internet

### For CI/CD

- **No External Dependencies**: CI doesn't need internet access
- **Predictable Performance**: Consistent test execution times
- **No Rate Limiting**: Tests don't hit external API limits
- **Cost Reduction**: No charges for external API calls

### For Security

- **No Data Leakage**: No real queries to external services
- **Isolated Environment**: Tests can't affect production services
- **Safe Testing**: Test with sensitive data without external exposure

## Conclusion

The test isolation system provides comprehensive protection against external API calls while maintaining realistic test scenarios. By automatically mocking all network operations, it ensures that tests run quickly, reliably, and consistently without depending on external services.

All tests are automatically isolated - no configuration required. Just write your tests normally, and the isolation system handles the rest.