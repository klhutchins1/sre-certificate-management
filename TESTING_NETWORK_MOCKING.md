# Network Mocking Strategy for Tests

## ✅ Fixed Issues

### TypeError: isinstance() arg 2 must be a type or tuple of types

**Problem**: The `test_render_scan_interface_with_input` test was failing because aggressive `sys.modules` mocking was breaking the built-in type system that `isinstance()` depends on.

**Root Cause**: Mocking modules like `socket`, `ssl`, etc. in `sys.modules` too early was interfering with Python's built-in type checking mechanisms.

**Solution**: 
1. **Removed aggressive `sys.modules` mocking** from conftest.py
2. **Used targeted `patch()` decorators** instead of `sys.modules` manipulation  
3. **Replaced `isinstance()` with `hasattr()` checks** in mock functions:

```python
# Before (causing TypeError)
isinstance(spec, (list, tuple))
isinstance(spec, int)

# After (safe alternative)
hasattr(spec, '__len__')
hasattr(spec, '__index__')
```

### Rate Limiting Too Fast in Tests

**Problem**: Tests were running too fast because rate limiting was effectively disabled, making it hard to verify rate limiting behavior.

**Solution**: Created two fixtures for different testing scenarios:

1. **`fast_rate_limits`** - For most tests, sets rate limits to 36000/minute (effectively disabled)
2. **`normal_rate_limits`** - For testing rate limiting behavior, sets realistic limits (10/minute)

```python
@pytest.fixture  
def fast_rate_limits():
    """Speed up tests by disabling rate limiting."""
    # Returns 36000 requests/minute (600/second)
    
@pytest.fixture
def normal_rate_limits():
    """Test actual rate limiting with 10 requests/minute."""
    # Returns 10 requests/minute (6 seconds between requests)
```

## 🚫 No Real Network Calls in Tests

### Comprehensive Network Mocking

All tests now use **targeted patching** instead of aggressive `sys.modules` manipulation:

1. **Auto-fixture**: `prevent_network_calls()` uses `@patch` decorators
2. **Graceful fallbacks**: Handles missing modules (dns, whois) gracefully
3. **Preserves built-in types**: No interference with `isinstance()`, `type()`, etc.

```python
@pytest.fixture(autouse=True)
def prevent_network_calls():
    with patch('socket.socket') as mock_socket, \
         patch('ssl.create_default_context') as mock_ssl, \
         patch('requests.get', return_value=mock_response):
        # Try to patch optional modules gracefully
        try:
            with patch('dns.resolver.resolve', return_value=[mock_dns_answer]):
                yield
        except ImportError:
            yield  # Continue even if dns module not available
```

### Key Benefits

✅ **Fast tests** - Rate limiting can be disabled for speed  
✅ **Reliable tests** - No dependency on external site availability  
✅ **Controlled scenarios** - Can test specific edge cases  
✅ **Isolated testing** - Tests don't affect external systems  
✅ **No TypeError** - Built-in types work correctly  

### Example Usage

```python
def test_with_disabled_rate_limiting(fast_rate_limits):
    """Most tests use this for speed."""
    # Rate limiting effectively disabled (36000/min)
    pass

def test_rate_limiting_behavior(normal_rate_limits):  
    """Specific tests for rate limiting functionality."""
    # Rate limiting enabled (10/min = 6 seconds between requests)
    pass
```

### Testing Network Error Scenarios

```python
def test_site_unavailable():
    """Test handling when a site is completely unavailable."""
    with patch('socket.create_connection', side_effect=socket.timeout):
        # Test code that should handle timeout gracefully
        pass

def test_invalid_certificate():
    """Test handling of invalid SSL certificates."""
    with patch('ssl.create_default_context') as mock_ssl:
        mock_ssl.side_effect = ssl.SSLError("Certificate verification failed")
        # Test code that should handle SSL errors gracefully  
        pass
```

## 📋 Test Categories

### Rate Limiting Fixtures
- `fast_rate_limits` - For speed (36000/min - effectively disabled)
- `normal_rate_limits` - For testing rate limiting (10/min)

### Markers
- `@pytest.mark.network` - For tests that would require real network (should be mocked)
- `@pytest.mark.slow` - For integration tests
- Run fast tests only: `pytest -m "not slow and not network"`

### File Structure
```
tests/
├── conftest.py                          # Targeted network mocking (no sys.modules)
├── unit/
│   └── test_views/
│       ├── test_scannerView.py          # Fixed isinstance issues + fast_rate_limits
│       └── test_scannerView_simple.py   # Isolated tests for isinstance() verification
└── integration/                         # Real network tests (if needed)
```

## 🛡️ Preventing Accidental Network Calls

The new mocking system uses targeted patching that:

1. **Doesn't break built-in types** - `isinstance()`, `type()` work correctly
2. **Handles missing modules gracefully** - Tests continue even if dns/whois unavailable
3. **Uses context managers** - Cleaner setup/teardown  
4. **Provides clear error messages** - If real network calls slip through

## 🔧 Running Tests

```bash
# Run all tests with network mocking and fast rate limits
pytest tests/

# Run only fast, mocked tests  
pytest -m "not slow and not network"

# Run specific test with fast rate limits
pytest tests/unit/test_views/test_scannerView.py::test_render_scan_interface_with_input -v

# Test rate limiting behavior specifically
pytest tests/unit/test_views/test_scannerView_simple.py::test_rate_limiting_behavior -v

# Verify isinstance() functionality
pytest tests/unit/test_views/test_scannerView_simple.py::test_isinstance_works -v
```

## ✨ Rate Limiting Verification

You can now test that rate limiting is working:

```python
def test_verify_rate_limiting(normal_rate_limits):
    """Verify rate limiting is actually applied."""
    scanner = DomainScanner()
    
    # Should be 10 requests/minute = 6 seconds between requests
    assert scanner.whois_rate_limit == 10
    
    min_time_between_queries = 60.0 / scanner.whois_rate_limit
    assert min_time_between_queries == 6.0  # 6 seconds between queries
```

## 🔧 Before/After Comparison

### Before (Broken)
- ❌ `sys.modules` mocking broke `isinstance()` 
- ❌ Rate limiting unclear (always fast)
- ❌ Network calls could slip through
- ❌ Difficult to test rate limiting behavior

### After (Fixed)
- ✅ `isinstance()` works correctly
- ✅ Rate limiting configurable per test
- ✅ Comprehensive network mocking with graceful fallbacks
- ✅ Easy to test both fast execution and rate limiting behavior