# Comprehensive Testing Strategy

**Document Version:** 1.0  
**Date:** 2025-01-27  
**Status:** Active

---

## Executive Summary

This document outlines the comprehensive testing strategy for the Certificate Management System. The goal is to achieve full test coverage, ensure tests catch problems, maintain tests as code evolves, and establish a clear process for adding tests with new features.

---

## Testing Philosophy

### Core Principles

1. **Full Coverage**: Aim for 100% coverage of business logic, with exceptions only for:
   - Trivial getters/setters (covered by integration tests)
   - Error handling that's tested through integration tests
   - UI rendering code (tested via view tests)

2. **Test-Driven Development**: When adding new features:
   - Write tests first (TDD) when possible
   - At minimum, write tests alongside feature code
   - Never merge features without tests

3. **Test Independence**: 
   - Tests must not depend on each other
   - Tests must be isolated (network isolation enforced)
   - Tests must be repeatable

4. **Test Maintainability**:
   - Tests should be easy to update when code changes
   - Tests should clearly indicate what's being tested
   - Tests should use meaningful assertions

5. **Regression Prevention**:
   - Tests must catch breaking changes
   - Update tests when refactoring (tests should guide refactoring)
   - Run tests before every commit

---

## Test Structure

### Test Organization

```
tests/
├── conftest.py              # Global fixtures and network isolation
├── test_isolation.py        # Network isolation system
├── unit/                    # Unit tests (isolated, fast)
│   ├── conftest.py         # Unit-specific fixtures
│   ├── test_services/      # Service layer tests
│   ├── test_utils/          # Utility function tests
│   ├── test_models/         # Model tests
│   ├── test_scanner/        # Scanner tests
│   └── test_views/          # View tests
└── integration/            # Integration tests (future)
```

### Test Categories

1. **Unit Tests** (`tests/unit/`):
   - Test individual functions/methods in isolation
   - Mock all external dependencies
   - Fast execution (< 100ms per test)
   - Cover edge cases and error paths

2. **Integration Tests** (planned):
   - Test component interactions
   - Use real database (test database)
   - Test full workflows

---

## Coverage Goals

### Current Coverage Gaps Identified

#### Services Needing Tests:
- [ ] `DashboardService` - Dashboard metrics and hierarchy
- [ ] `SearchService` - Search functionality
- [ ] `HistoryService` - History retrieval and tracking
- [ ] `HostService` - Host CRUD operations
- [ ] `DomainService` - Domain CRUD and hierarchy
- [ ] `ApplicationService` - Application management
- [ ] `ViewDataService` - View data aggregation
- [ ] `BaseService` - Base service utilities
- [x] `CertificateService` - Partial coverage exists
- [x] `CertificateExportService` - Covered in `test_certificate_export_service.py`
- [x] `ScanService` - Partial coverage in `test_scan_controls.py`
- [x] `SettingsService` - Partial coverage in settings tests

#### Utilities Needing Tests:
- [ ] `domain_validation.py` - Domain validation logic
- [ ] `dns_records.py` - DNS record fetching and processing
- [ ] `ignore_list.py` - Ignore list matching
- [x] `certificate_deduplication.py` - Covered
- [x] `proxy_detection.py` - Partial coverage

#### Components Needing Tests:
- [ ] `components/deletion_dialog.py` - Deletion dialog
- [ ] `components/metrics_row.py` - Metrics display
- [ ] `components/page_header.py` - Page header

#### Core Modules:
- [ ] `monitoring.py` - Monitoring utilities
- [ ] `notifications.py` - Notification system
- [ ] `compatibility.py` - Compatibility layer

---

## Testing Guidelines

### When Adding New Features

1. **Before Writing Code**:
   - Identify what needs to be tested
   - Write test cases for:
     - Happy path
     - Edge cases
     - Error cases
     - Boundary conditions

2. **While Writing Code**:
   - Write tests alongside implementation
   - Ensure tests pass
   - Refactor if tests reveal design issues

3. **After Writing Code**:
   - Run full test suite
   - Check coverage report
   - Document any coverage exceptions
   - Update this document if needed

### Test File Naming

- Test files: `test_<module_name>.py`
- Test classes: `Test<ClassName>`
- Test functions: `test_<functionality_description>`

Example:
```python
# File: test_dashboard_service.py
class TestDashboardService:
    def test_get_dashboard_metrics():
        ...
    def test_get_certificate_timeline():
        ...
```

### Test Structure Template

```python
"""
Tests for <module_name> module.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from infra_mgmt.services.<ServiceName> import ServiceName

class TestServiceName:
    """Test suite for ServiceName."""
    
    @pytest.fixture
    def service(self):
        """Create service instance for testing."""
        return ServiceName()
    
    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock()
        return session
    
    def test_happy_path(self, service, mock_session):
        """Test normal operation."""
        # Arrange
        # Act
        # Assert
        
    def test_edge_case(self, service, mock_session):
        """Test edge case handling."""
        # ...
        
    def test_error_handling(self, service, mock_session):
        """Test error scenarios."""
        # ...
```

---

## Running Tests

### Basic Commands

```bash
# Activate virtual environment
venv\Scripts\activate

# Run all tests
pytest

# Run with coverage
pytest --cov=infra_mgmt --cov-report=html --cov-report=term

# Run specific test file
pytest tests/unit/test_dashboard_service.py

# Run specific test
pytest tests/unit/test_dashboard_service.py::TestDashboardService::test_get_dashboard_metrics

# Run tests in verbose mode
pytest -v

# Run tests and show print statements
pytest -s
```

### Coverage Requirements

- **Minimum Coverage**: 80% for new code
- **Target Coverage**: 90%+ for critical modules
- **Coverage Report**: Run before every PR
- **Coverage Exclusions**: Document in `.coveragerc`

---

## Network Isolation

All tests run with network isolation by default (configured in `tests/conftest.py`). This ensures:
- No real external API calls
- Fast, predictable tests
- No test failures due to network issues

**Important**: Never disable network isolation for unit tests. If you need real network calls, create an integration test.

---

## Test Data Management

### Fixtures

Use pytest fixtures for test data:
- Session fixtures: Create database sessions
- Model fixtures: Create test models
- Service fixtures: Create service instances

### Test Data Location

- In-memory SQLite databases for unit tests
- Test data files in `tests/data/` if needed
- Mock data generated in fixtures

---

## Common Patterns

### Testing Services

```python
def test_service_method(self, service, mock_session):
    # Mock session queries
    mock_session.query.return_value.filter.return_value.first.return_value = mock_obj
    
    # Call service method
    result = service.method(mock_session, args)
    
    # Assert results
    assert result['success'] is True
    assert 'data' in result
```

### Testing Utilities

```python
def test_utility_function():
    # Test with various inputs
    assert utility_function('valid_input') == expected_output
    assert utility_function('invalid_input') is None
    assert utility_function('') == default_value
```

### Testing Error Handling

```python
def test_service_error_handling(self, service, mock_session):
    # Simulate database error
    mock_session.commit.side_effect = SQLAlchemyError("DB Error")
    
    # Call service method
    result = service.method(mock_session, args)
    
    # Assert error handling
    assert result['success'] is False
    assert 'error' in result
    mock_session.rollback.assert_called_once()
```

---

## Continuous Integration

### Pre-commit Checklist

- [ ] All tests pass: `pytest`
- [ ] Coverage is acceptable: `pytest --cov`
- [ ] No linting errors
- [ ] No deprecation warnings
- [ ] Tests are fast (< 30 seconds for full suite)

### PR Requirements

- [ ] New features have tests
- [ ] Coverage report attached
- [ ] Tests pass in CI
- [ ] Documentation updated if needed

---

## Test Maintenance

### When Refactoring Code

1. **Update Tests First**: Tests should guide refactoring
2. **Keep Tests Passing**: Refactor tests alongside code
3. **Improve Tests**: If tests are hard to update, improve them
4. **Don't Delete Tests**: Even if functionality changes

### When Tests Fail

1. **Don't Ignore**: Fix tests or fix code
2. **Investigate**: Understand why test failed
3. **Fix Root Cause**: Don't just make test pass
4. **Update Documentation**: If behavior changed

---

## Known Test Issues

### Currently Broken Tests

None known at this time.

### Slow Tests

None identified. All tests should run in < 100ms individually.

---

## Future Improvements

1. **Integration Tests**: Add integration test suite
2. **Performance Tests**: Add performance benchmarks
3. **E2E Tests**: Add end-to-end tests for critical workflows
4. **Mutation Testing**: Consider mutation testing for critical paths
5. **Property-Based Testing**: Use hypothesis for data validation

---

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [coverage.py documentation](https://coverage.readthedocs.io/)
- [unittest.mock documentation](https://docs.python.org/3/library/unittest.mock.html)

---

## Review and Updates

This document should be reviewed:
- When adding new test categories
- When changing testing philosophy
- When coverage goals change
- Quarterly for accuracy

**Last Updated**: 2025-01-27


