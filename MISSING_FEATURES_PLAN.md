# Missing Features Implementation Plan
## Certificate Management System

**Document Version:** 1.0  
**Date:** 2025-01-27  
**Status:** Planning Phase

---

## Executive Summary

This document outlines a comprehensive plan for implementing missing features identified through evaluation of the Certificate Management System codebase, documentation, and known issues. Features are categorized by priority and complexity to facilitate planning and resource allocation.

---

## Table of Contents

1. [Feature Categories](#feature-categories)
2. [High Priority Features](#high-priority-features)
3. [Medium Priority Features](#medium-priority-features)
4. [Low Priority Features](#low-priority-features)
5. [Documentation Updates](#documentation-updates)
6. [Implementation Roadmap](#implementation-roadmap)

---

## Feature Categories

### Status Legend
- ✅ **Implemented** - Feature exists and works
- ⚠️ **Partially Implemented** - Feature exists but incomplete or needs enhancement
- ❌ **Missing** - Feature does not exist
- 📝 **Documentation Issue** - Feature exists but incorrectly documented

---

## High Priority Features

### 1. Advanced Certificate Validation ❌
**Priority:** High  
**Complexity:** Medium-High  
**Status:** Missing

**Current State:**
- Basic chain validation exists via `_validate_cert_chain()` in `certificate_scanner.py`
- Validation checks expiration, weak algorithms, and required fields
- Chain validation uses system trust store

**Missing Components:**
- **OCSP (Online Certificate Status Protocol) checking**
  - Implement OCSP request/response handling
  - Check certificate revocation status in real-time
  - Cache OCSP responses with appropriate TTL
  - Handle OCSP stapling when available
  
- **CRL (Certificate Revocation List) checking**
  - Download and parse CRL files from certificate authority
  - Check certificate serial against CRL entries
  - Handle CRL distribution point URLs
  - Cache CRLs with proper expiration handling
  
- **Revocation status tracking**
  - Store revocation status in database
  - Track revocation date and reason
  - Alert on revoked certificates
  - Historical revocation tracking

**Implementation Tasks:**
1. Add OCSP checking module (`infra_mgmt/utils/ocsp_checker.py`)
   - Implement OCSP request builder
   - Handle OCSP response parsing
   - Error handling and fallback mechanisms
   
2. Add CRL checking module (`infra_mgmt/utils/crl_checker.py`)
   - CRL download and caching
   - CRL parsing (DER/X509 format)
   - Serial number lookup
   
3. Enhance Certificate model
   - Add `revocation_status` field (enum: None, Valid, Revoked, Unknown)
   - Add `revocation_date` field
   - Add `revocation_reason` field
   - Add `ocsp_response_cached_until` field
   
4. Database migration for new fields
   - Migration script similar to proxy detection migration
   - Add indexes for revocation status queries
   
5. Update certificate scanner
   - Integrate OCSP checking after certificate retrieval
   - Integrate CRL checking as fallback
   - Update CertificateInfo class
   
6. UI enhancements
   - Display revocation status in certificate view
   - Warning badges for revoked certificates
   - Revocation status filter in certificate list
   
7. Configuration options
   - Enable/disable OCSP checking
   - Enable/disable CRL checking
   - OCSP timeout settings
   - CRL cache TTL settings

**Estimated Effort:** 3-4 weeks  
**Dependencies:** None

---

### 2. Scan Certificates from Associated Bindings ❌
**Priority:** High  
**Complexity:** Medium  
**Status:** Missing

**Current State:**
- Scanning exists for manual host/domain input
- `CertificateBinding` model tracks certificate deployments
- `get_certificates_for_domain()` retrieves certificates from bindings
- No UI/functionality to scan based on existing bindings

**Missing Components:**
- Button/feature to scan all hosts from a certificate's bindings
- Bulk scan functionality from certificate detail page
- Scan scheduling for certificate bindings
- Progress tracking for binding scans

**Implementation Tasks:**
1. Enhance CertificateService
   - Add `get_certificate_bindings_for_scan()` method
   - Return list of scan targets (host:port) from bindings
   - Filter bindings by last_seen date (optional)
   
2. Add scanning from bindings to ScannerView
   - Add "Scan from Bindings" button in certificate detail view
   - Multi-select for bindings to scan
   - Option to scan all or selected bindings
   
3. Enhance ScanService
   - Add `scan_certificate_bindings(certificate_id, binding_ids=None)` method
   - Handle batch scanning of bindings
   - Progress updates for binding scans
   
4. Add to CertificatesView
   - "Scan Associated Hosts" button in certificate details
   - Display binding scan results
   - Track last scan time per binding

**Estimated Effort:** 1-2 weeks  
**Dependencies:** None

---

### 3. Recursive Domain Deletion ⚠️
**Priority:** High  
**Complexity:** Low-Medium  
**Status:** Partially Implemented (marked as not fully implemented in README)

**Current State:**
- `DomainService.delete_domain_by_id()` exists
- Domain model has parent/child relationships
- No recursive deletion logic implemented

**Missing Components:**
- Recursive deletion of child domains
- Cascade deletion handling
- Warning/confirmation UI for recursive deletion
- Transaction-safe deletion with rollback

**Implementation Tasks:**
1. Enhance DomainService
   - Add `delete_domain_recursive()` method
   - Recursively find all child domains
   - Delete children before parent
   - Handle foreign key constraints
   
2. Database schema review
   - Ensure cascade rules are properly configured
   - Verify no orphaned records after deletion
   
3. UI enhancements in DomainsView
   - Checkbox option: "Also delete child domains"
   - Confirmation dialog showing affected domains
   - List of domains that will be deleted
   
4. Error handling
   - Rollback on failure
   - Clear error messages for constraint violations

**Estimated Effort:** 1 week  
**Dependencies:** None

---

### 4. Offline Mode Detection During Scan ❌
**Priority:** High  
**Complexity:** Low  
**Status:** Missing

**Current State:**
- `config.yaml` has `scanning.offline_mode` setting
- WhoIS module may not respect offline mode (documented issue)
- No automatic detection of offline state

**Missing Components:**
- Automatic offline mode detection
- Network connectivity checks
- Graceful degradation when offline
- UI indicator for offline mode

**Implementation Tasks:**
1. Add network detection utility (`infra_mgmt/utils/network_detection.py`)
   - Check DNS resolution capability
   - Check internet connectivity (ping/test endpoint)
   - Detect proxy availability
   
2. Enhance scanner initialization
   - Auto-detect offline state at startup
   - Update config automatically or warn user
   - Periodic re-check for connectivity
   
3. Update WhoIS module
   - Respect offline_mode flag
   - Skip WhoIS queries when offline
   - Log when WhoIS skipped due to offline mode
   
4. UI enhancements
   - Display offline mode status indicator
   - Option to manually toggle offline mode
   - Warning when attempting online operations while offline

**Estimated Effort:** 1 week  
**Dependencies:** None

---

## Medium Priority Features

### 5. Enhanced Search - Full-Text Search ❌
**Priority:** Medium  
**Complexity:** Medium  
**Status:** Missing (basic ILIKE search exists)

**Current State:**
- `SearchService.perform_search()` uses SQLAlchemy ILIKE queries
- Search works on certificates, hosts, IPs
- Filtering by status and platform available
- No full-text indexing or advanced search features

**Missing Components:**
- Full-text search index (SQLite FTS5)
- Multi-field weighted search
- Search result ranking
- Search history
- Advanced search filters (date ranges, multiple criteria)

**Implementation Tasks:**
1. Add FTS5 virtual tables
   - Create FTS5 index for certificates
   - Create FTS5 index for hosts
   - Create FTS5 index for domains
   - Maintain index synchronization
   
2. Enhance SearchService
   - Implement full-text search queries
   - Add search result ranking/scoring
   - Support boolean operators (AND, OR, NOT)
   - Phrase search support
   
3. UI enhancements in SearchView
   - Advanced search panel
   - Date range filters
   - Multiple field filters
   - Search history dropdown
   - Saved searches feature
   
4. Configuration
   - Enable/disable full-text search
   - Search result limit settings
   - Relevance threshold

**Estimated Effort:** 2-3 weeks  
**Dependencies:** SQLite 3.9+ (FTS5 support)

---

### 6. Bulk Actions UI ❌
**Priority:** Medium  
**Complexity:** Low-Medium  
**Status:** Missing (backend code exists)

**Current State:**
- `OptimizedDatabaseService.bulk_update_certificates()` exists
- No UI for bulk operations
- Individual actions available per item

**Missing Components:**
- Multi-select checkboxes in certificate/host tables
- Bulk action menu
- Bulk delete, bulk tag, bulk update
- Confirmation dialogs for bulk operations

**Implementation Tasks:**
1. Enhance AG Grid configuration
   - Add row selection (checkbox column)
   - Multi-select functionality
   - Select all/none options
   
2. Add bulk action UI components
   - Bulk action toolbar
   - Action buttons (Delete, Tag, Update, Export)
   - Selection counter display
   
3. Implement bulk operations in services
   - Bulk delete service method
   - Bulk update service method
   - Bulk tag/untag service method
   - Transaction safety for bulk operations
   
4. Add to CertificatesView and HostsView
   - Integrate bulk action toolbar
   - Confirmation dialogs
   - Progress indicators for bulk operations

**Estimated Effort:** 2 weeks  
**Dependencies:** None

---

### 7. Domain Registration/Expiration Tracking ❌
**Priority:** Medium  
**Complexity:** Medium  
**Status:** Missing

**Current State:**
- Domain model exists with basic fields
- DNS record tracking exists
- No registration or expiration tracking

**Missing Components:**
- Domain registration date tracking
- Domain expiration date tracking
- Registration renewal alerts
- Registrar information tracking
- Ownership monitoring

**Implementation Tasks:**
1. Enhance Domain model
   - Add `registration_date` field
   - Add `expiration_date` field
   - Add `registrar` field
   - Add `registrar_contact` field
   - Add `auto_renew` boolean field
   
2. Enhance WhoIS integration
   - Extract registration dates from WhoIS
   - Extract expiration dates from WhoIS
   - Extract registrar information
   - Update domain records on scan
   
3. Database migration
   - Add new fields to domains table
   - Migration script
   
4. UI enhancements in DomainsView
   - Display registration/expiration dates
   - Expiration warnings (similar to certificates)
   - Registrar information display
   - Filter by expiration date
   
5. Alert system integration
   - Domain expiration alerts
   - Registration renewal reminders
   - Configuration for alert thresholds

**Estimated Effort:** 2 weeks  
**Dependencies:** WhoIS integration

---

### 8. Database Caching for Non-UNC Paths ❌
**Priority:** Medium  
**Complexity:** Low  
**Status:** Missing (only works for network paths)

**Current State:**
- Cache manager exists and works for UNC/network paths
- Local path databases don't use caching
- Performance optimization missing for local files

**Missing Components:**
- Cache detection for local database paths
- Performance monitoring for local databases
- Optional caching for local paths (for performance)
- Configuration to enable caching per path pattern

**Implementation Tasks:**
1. Enhance cache manager
   - Detect database path type (UNC vs local)
   - Option to enable cache for local paths
   - Performance comparison logic
   - Automatic cache enablement for slow local paths
   
2. Configuration options
   - `database.enable_cache_local` setting
   - `database.cache_local_threshold_ms` setting
   - Automatic detection toggle
   
3. Performance monitoring
   - Track read/write times for local paths
   - Suggest caching if performance is poor
   - Cache statistics display

**Estimated Effort:** 1 week  
**Dependencies:** None

---

## Low Priority Features

### 9. Multi-Instance Support ❌
**Priority:** Low (for current scale)  
**Complexity:** High  
**Status:** Missing

**Current State:**
- Single-instance deployment
- SQLite database (not ideal for concurrent writes)
- No locking mechanisms
- No conflict resolution

**Missing Components:**
- Database locking (file-level or application-level)
- Concurrent access handling
- Conflict detection and resolution
- Multi-instance coordination
- Connection pooling improvements

**Implementation Tasks:**
1. Database locking mechanism
   - File-based locking for SQLite
   - Lock timeout handling
   - Deadlock detection
   
2. Conflict resolution
   - Timestamp-based conflict resolution
   - Last-write-wins strategy
   - Merge conflict detection
   - User notification of conflicts
   
3. Connection management
   - Connection pooling improvements
   - Connection timeout handling
   - Retry logic for locked databases
   
4. Configuration
   - Lock timeout settings
   - Conflict resolution strategy
   - Multi-instance awareness flag

**Estimated Effort:** 4-6 weeks  
**Dependencies:** None (but SQLite limitations may require PostgreSQL migration for full support)

**Note:** This may not be necessary if current single-instance deployment meets needs.

---

### 10. Security Enhancements - RBAC ❌
**Priority:** Low (trusted environment)  
**Complexity:** High  
**Status:** Missing

**Current State:**
- No authentication/authorization
- Assumes trusted environment
- No user management
- No role-based access

**Missing Components:**
- User authentication system
- Role-based access control (RBAC)
- Permission management
- Audit logging for security events
- Session management

**Implementation Tasks:**
1. User management system
   - User model and database tables
   - User registration/login
   - Password hashing (bcrypt)
   - Session management (Streamlit session + DB)
   
2. RBAC system
   - Role model (Admin, User, Viewer, etc.)
   - Permission model
   - Role-permission mapping
   - Resource-level permissions
   
3. Authentication integration
   - Streamlit authentication wrapper
   - Protected route decorator
   - Login/logout UI
   
4. Audit logging
   - Security event logging
   - User action tracking
   - Access attempt logging
   - Audit log viewer
   
5. UI enhancements
   - User management page (admin only)
   - Role assignment UI
   - Permission management UI
   - Audit log viewer

**Estimated Effort:** 6-8 weeks  
**Dependencies:** None

**Note:** May not be necessary if system remains in trusted environment.

---

### 11. Audit Trail and Versioning ❌
**Priority:** Low  
**Complexity:** Medium-High  
**Status:** Missing

**Current State:**
- History tracking exists for certificates
- Scan history tracked
- No comprehensive audit trail
- No data versioning

**Missing Components:**
- Comprehensive audit log table
- Change tracking for all entities
- Data versioning/history
- Rollback capability
- Audit log viewer

**Implementation Tasks:**
1. Audit log model
   - Generic audit log table
   - Entity type and ID tracking
   - Change type (Create, Update, Delete)
   - Before/after values (JSON)
   - User/timestamp tracking
   
2. Audit logging service
   - Automatic logging on model changes
   - SQLAlchemy event listeners
   - Change diff generation
   
3. Versioning system
   - Entity version table
   - Snapshot on each change
   - Version comparison UI
   
4. Rollback functionality
   - Rollback to previous version
   - Selective field rollback
   - Rollback confirmation
   
5. UI enhancements
   - Audit log viewer
   - Version history display
   - Diff viewer
   - Rollback UI

**Estimated Effort:** 4-5 weeks  
**Dependencies:** None

---

### 12. Transaction-Safe Imports with Rollback ❌
**Priority:** Low  
**Complexity:** Medium  
**Status:** Missing

**Current State:**
- Import functionality exists (CSV imports)
- No transaction safety
- No rollback on partial failures
- No import validation

**Missing Components:**
- Transaction-wrapped imports
- Validation before import
- Partial rollback on errors
- Import progress tracking
- Error reporting

**Implementation Tasks:**
1. Import service enhancement
   - Wrap imports in transactions
   - Validation before commit
   - Rollback on validation failure
   - Partial success handling
   
2. Validation framework
   - Schema validation
   - Data validation rules
   - Duplicate detection
   - Referential integrity checks
   
3. Import UI enhancements
   - Progress tracking
   - Validation feedback
   - Error reporting
   - Partial import results

**Estimated Effort:** 2-3 weeks  
**Dependencies:** None

---

## Documentation Updates

### Issues Found

1. **Pause/Stop Scan Functionality** 📝
   - **Issue:** README states "No pause/stop for ongoing scans"
   - **Reality:** Pause/stop functionality exists in `ScanManager` and `ScanService`
   - **Action:** Update README to reflect actual functionality
   - **Files to update:**
     - `README.md` (line 139)
     - Document pause/stop usage in scanner section

2. **Scan from Bindings** 📝
   - **Issue:** Listed as planned feature but no clear documentation of what it means
   - **Action:** Clarify requirement and document implementation plan

3. **Feature Status** 📝
   - **Issue:** Some features listed as "planned" may be partially implemented
   - **Action:** Audit all features and update status accurately

### Documentation Tasks

1. Update README.md
   - Fix pause/stop scan documentation
   - Clarify scan from bindings feature
   - Update feature status checklist
   - Add new features to planned section

2. Update DESIGN.md
   - Add new features to planned enhancements
   - Update known limitations
   - Document new models/fields

3. Update functional_spec.md
   - Add detailed specs for new features
   - Update checklist with accurate status

4. Create feature-specific documentation
   - OCSP/CRL validation guide
   - Bulk actions user guide
   - Full-text search guide
   - Security features guide (if implemented)

---

## Implementation Roadmap

### Phase 1: Critical Fixes (Weeks 1-2)
1. ✅ Recursive Domain Deletion
2. ✅ Offline Mode Detection
3. ✅ Documentation Updates (pause/stop scan)

### Phase 2: High-Value Features (Weeks 3-8)
1. ✅ Scan from Bindings
2. ✅ Advanced Certificate Validation (OCSP/CRL)
   - Week 3-4: OCSP implementation
   - Week 5-6: CRL implementation
   - Week 7-8: Integration and testing

### Phase 3: Enhanced Usability (Weeks 9-14)
1. ✅ Full-Text Search
2. ✅ Bulk Actions UI
3. ✅ Domain Registration Tracking

### Phase 4: Performance & Infrastructure (Weeks 15-16)
1. ✅ Database Caching for Non-UNC Paths

### Phase 5: Advanced Features (Optional, Weeks 17+)
1. ⚠️ Multi-Instance Support (if needed)
2. ⚠️ Security Enhancements (if needed)
3. ⚠️ Audit Trail (if needed)
4. ⚠️ Transaction-Safe Imports (if needed)

---

## Risk Assessment

### High Risk Features
- **Multi-Instance Support:** High complexity, may require database migration
- **Security Enhancements:** Significant architectural changes
- **OCSP/CRL Validation:** External dependencies, network reliability

### Medium Risk Features
- **Full-Text Search:** Requires SQLite FTS5, schema changes
- **Audit Trail:** Performance implications for large datasets

### Low Risk Features
- **Bulk Actions:** Well-understood pattern, existing backend code
- **Scan from Bindings:** Extends existing functionality
- **Recursive Deletion:** Straightforward implementation

---

## Success Criteria

### High Priority Features
- [ ] OCSP checking works for 90%+ of certificates
- [ ] CRL checking works as fallback
- [ ] Scan from bindings processes all bindings successfully
- [ ] Recursive deletion handles all child domains correctly
- [ ] Offline mode automatically detected and respected

### Medium Priority Features
- [ ] Full-text search is 10x faster than current search for large datasets
- [ ] Bulk actions handle 100+ items without performance issues
- [ ] Domain expiration tracking accurate to 95%+

---

## Notes

1. **Prioritization:** Focus on High Priority features first
2. **Testing:** Each feature must have comprehensive unit and integration tests
3. **Documentation:** Update documentation in parallel with implementation
4. **Migration:** All database changes require migration scripts
5. **Backward Compatibility:** Maintain compatibility with existing data

---

## Approval and Sign-off

**Document Status:** Ready for Review  
**Next Steps:**
1. Review this plan with stakeholders
2. Prioritize features based on business needs
3. Allocate resources and timeline
4. Begin Phase 1 implementation

---

*This document should be reviewed and updated as features are implemented and priorities change.*

