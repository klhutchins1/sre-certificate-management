# Changelog

All notable changes to the Certificate Management System are documented in this file.

## Recent Updates

### Performance Optimizations

- **Database Query Optimizations**: Fixed N+1 query patterns, implemented bulk operations (10-50x performance improvement)
- **Rate Limiting Optimizations**: Reduced unnecessary sleep calls, improved timestamp cleanup (20-30% faster scanning)
- **Logging Optimizations**: Reduced duplicate logging, optimized test output
- **Session Reuse**: Optimized database session creation to use centralized session management

### New Features

- **Scan Control**: Added pause/resume/stop functionality for ongoing scans
- **Proxy Certificate Deduplication**: Automatic detection and merging of duplicate proxy certificates during scanning
- **Enhanced Test Configuration**: Improved test output and execution performance

### Bug Fixes

- **Input Validation**: Enhanced IP address validation to handle None and non-string inputs gracefully
- **Mock Compatibility**: Improved handling of mock sockets and context managers in tests
- **Offline Mode**: Added logic to skip IP address resolution when offline mode is enabled
- **Memory Leaks**: Fixed cache manager background thread issues causing test slowdowns

### Testing Improvements

- **Network Isolation**: Comprehensive test isolation system preventing external API calls during testing
- **Test Coverage**: Added tests for services, utilities, and components
- **Test Performance**: Reduced test execution time from 25-30 seconds to 20-22 seconds

### Database Improvements

- **Proxy Detection Migration**: Added database migration for proxy detection columns (`proxied`, `proxy_info`)
- **Cache Manager**: Fixed memory leaks and background thread issues
- **Unique Constraints**: Fixed database constraint issues

### Documentation

- **Organized Documentation**: Moved core documentation to `docs/` folder
- **Consolidated Guides**: Created consolidated deduplication guide
- **Updated README**: Added information about new features and fixed known issues

## Historical Changes

### Proxy Certificate Support

- Added proxy certificate detection and marking
- Implemented proxy certificate deduplication (basic and advanced)
- Created migration scripts for proxy detection support
- Enhanced certificate scanning to detect proxy certificates automatically

### Certificate Deduplication

- Implemented general certificate deduplication based on thumbprint/serial number
- Created proxy-specific deduplication for dynamically generated certificates
- Added data migration support for maintaining referential integrity

### Database Caching

- Implemented local SQLite cache with background synchronization
- Added cache management UI for monitoring and control
- Optimized for file-share network performance (10-50x improvement)

### Network Isolation

- Implemented comprehensive test isolation system
- Created mock classes for all external services (WHOIS, DNS, HTTP, SSL)
- Automatic network isolation for all tests

### Test Coverage

- Added comprehensive test coverage for services, utilities, and components
- Implemented test isolation to prevent external API calls
- Improved test performance and reliability

### Deprecation Fixes

- Fixed deprecation warnings across the codebase
- Updated to use modern Python patterns and libraries
- Improved compatibility with Python 3.8+

### Windows Compatibility

- Fixed Windows-specific Python 3.8 compatibility issues
- Improved path handling for Windows environments
- Enhanced UNC path support for network databases

