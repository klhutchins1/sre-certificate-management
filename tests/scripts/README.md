# Manual Test Scripts

This directory contains standalone validation and test scripts that can be run manually for debugging, validation, or performance testing. These are not part of the automated pytest test suite.

## Scripts

### Migration & Compatibility

- **`test_migration.py`** - Validates database migration scripts work correctly
- **`test_compatibility_verification.py`** - Verifies Windows Python 3.8 compatibility fixes

### Performance Testing

- **`test_cache_performance.py`** - Demonstrates cache performance improvements
- **`test_optimizations.py`** - Validates performance optimizations (lazy loading, memory usage, etc.)

### Deduplication Validation

- **`test_enhanced_proxy_deduplication.py`** - Validates enhanced proxy certificate deduplication
- **`test_enhanced_deduplication_validation.py`** - Comprehensive deduplication validation
- **`test_enhanced_deduplication_simple_validation.py`** - Simple deduplication validation
- **`test_deduplicator_debug.py`** - Debug script for deduplicator logic

### Feature Validation

- **`test_san_scanning_fix.py`** - Validates SAN scanning functionality

## Usage

These scripts can be run directly:

```bash
# Run a specific validation script
python tests/scripts/test_migration.py

# Run compatibility verification
python tests/scripts/test_compatibility_verification.py

# Run performance tests
python tests/scripts/test_cache_performance.py
```

## Note

These scripts are for manual validation and debugging. For automated testing, use the pytest test suite in the `tests/unit/` directory.

