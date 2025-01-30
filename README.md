# Certificate Management System

A comprehensive web-based system for tracking and managing SSL/TLS certificates across various infrastructure components.

## Installation

### Standard Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/SRE-CertificateManagement.git
cd SRE-CertificateManagement
```

2. Create and activate a virtual environment:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install requirements:

```bash
pip install -r requirements.txt
```

4. Run the application:

```bash
streamlit run run.py
```

### Offline Installation

1. On a machine with internet access:

```bash
# Create requirements folder
mkdir requirements_offline
cd requirements_offline

# Download all required packages
pip download -r requirements.txt

# Copy the following to a zip/USB:
# - requirements_offline folder
# - All project files
```

2. On the offline machine:

```bash
# Extract/copy files
# Create and activate virtual environment as above

# Install from downloaded files
pip install --no-index --find-links requirements_offline -r requirements.txt
```

## Usage Guide

### Scanning Certificates

1. Navigate to "Scan" in the sidebar
2. Enter hostnames (one per line)
3. Click "Start Scan"
4. View results and any errors

### Viewing Certificates

1. Go to "Certificates" page
2. View list of all certificates
3. Select a certificate to see:
   - Subject Alternative Names (SANs)
   - Associated hosts
   - Detailed certificate information

### Managing Hosts

1. Access "Hosts" page
2. View hosts by IP address
3. Select an IP to see:
   - Associated hostnames
   - Certificates using this IP

### Dashboard

- View total certificates and hosts
- See certificates expiring soon
- Timeline of certificate validity periods

## Features

### Certificate Management

- [x] View list of all SSL/TLS certificates
- [x] Display detailed certificate information:
  - Serial number
  - Thumbprint
  - Expiration date
  - Issuer
  - Subject
  - Subject Alternative Names (SAN)
  - Key usage
  - Algorithm
- [x] Track certificate status (active, expired, pending renewal)
- [x] Store replacement dates and associated ticket numbers
- [x] Track certificate hosting platform:
  - F5
  - Akamai
  - Cloudflare
  - Windows Server (IIS)
  - Connection certificates

### Export Features

- [x] CSV Export:
  - Certificate list exports
  - Host list exports
  - Custom field selection
- [x] PDF Export:
  - Detailed certificate reports
  - Host inventory reports
  - Customizable templates
- [x] Timeline Visualization:
  - Certificate validity timeline
  - Interactive charts
  - Export to image format

### Data Synchronization

- [ ] Environment-Specific Scanning:
  - VDI Mode: Internal server and F5 certificate scanning
  - Desktop Mode: External and F5 certificate scanning
  - Mode auto-detection based on network access
- [ ] Database Export/Import:
  - Export scanned data as portable database files
  - Merge databases from different environments
  - Conflict resolution for duplicate entries
  - Automatic backup before merge operations
- [ ] Incremental Updates:
  - Track scan origin and timestamp
  - Only sync new or modified entries
  - Preserve local modifications
  - Conflict detection and resolution
- [ ] Data Validation:
  - Verify data integrity during import
  - Validate certificate chains across environments
  - Check for expired or revoked certificates
  - Report conflicts and inconsistencies

### Infrastructure Mapping

- [x] Associate certificates with:
  - IP addresses
  - Hostnames
  - DNS entries
- [x] View all DNS/Hostnames using a specific certificate
- [x] View certificate history for specific IP addresses

### Scanning & Monitoring

- [x] Scan DNS/Hostnames for current certificate information
- [x] Automatically scan and track all DNS names in certificate SAN
- [x] Auto-associate discovered hostnames with certificates
- [x] Track last scan date
- [x] Alert on approaching expiration dates
- [x] Verify certificate chain validity

### Historical Tracking

- [x] Certificate deployment history
- [x] Previous certificates per IP/hostname
- [x] Changes in certificate assignments
- [x] Scan history

### User Interface

- [x] Web-based interface
- [x] Certificate list view with filtering and sorting
- [x] Detailed certificate view
- [x] Infrastructure view
- [x] Scanning interface
- [x] Historical data visualization
- [x] Search functionality
- [x] Settings management interface

### Configuration Management

- [x] YAML-based configuration file
- [x] Multiple configuration locations support
  - Local directory
  - User home directory
  - System-wide configuration
- [x] Environment variable override support
- [x] Web interface for settings management
- [x] Configurable scanning profiles
  - Internal scanning settings
  - External scanning settings
  - Rate limiting and delays
- [x] Alert thresholds configuration
- [x] Export settings management
- [x] Automated backup system
  - Database backups
  - Configuration backups
  - Backup manifests

### Available Settings

#### Database and Backup Settings

- `paths.database`: Path to the SQLite database file
  - Default: `data/certificates.db`
  - Can be relative or absolute path
- `paths.backups`: Directory for storing backups
  - Default: `data/backups`
  - Used for database and settings backups

#### Scanning Profiles

##### Internal Scanning

- `scanning.internal.rate_limit`: Maximum requests per minute
  - Default: 10
  - Adjust based on network capacity
- `scanning.internal.delay`: Delay between requests (seconds)
  - Default: 2
  - Higher values reduce network load
- `scanning.internal.domains`: List of internal domains
  - Used to identify internal scanning targets
  - One domain per line in settings interface

##### External Scanning

- `scanning.external.rate_limit`: Maximum requests per minute
  - Default: 5
  - Lower than internal to respect external services
- `scanning.external.delay`: Delay between requests (seconds)
  - Default: 5
  - Higher than internal to avoid triggering rate limits
- `scanning.external.domains`: List of external domains
  - Used to identify external scanning targets
  - One domain per line in settings interface

#### Alert Configuration

##### Certificate Expiry Warnings

- `alerts.expiry_warnings`: List of warning thresholds
  - Info level: 90 days before expiry
  - Warning level: 30 days before expiry
  - Critical level: 7 days before expiry
- `alerts.failed_scans.consecutive_failures`: Number of failed scans before alerting
  - Default: 3
  - Helps avoid false positives
- `alerts.persistence_file`: Location of alert state storage
  - Default: `data/alerts.json`
  - Tracks acknowledged/unacknowledged alerts

## Implementation

### Technology Stack

- Python 3.x
- Streamlit for UI
- SQLite database
- PyYAML for configuration
- Certificate scanning libraries:
  - ssl
  - OpenSSL
  - cryptography
  - socket

### Core Components

- Certificate Scanner: Python-based scanning engine
  - Based on existing getCertificates.py
  - Enhanced with SAN processing
  - Modular design for UI integration
- Database Layer: SQLite with SQLAlchemy
- Web Interface: Streamlit dashboard
- Settings Management: YAML-based configuration
- Report Generator: PDF/CSV export functionality

### Pending Features

#### Data Synchronization Implementation

- [ ] Environment Detection and Configuration:
  - Network connectivity checks
  - Environment-specific scanning profiles
  - Automatic mode switching
  - Configuration persistence

- [ ] Database Operations:
  - SQLite database file compression
  - Incremental database dumps
  - Three-way merge algorithm
  - Transaction-safe imports

- [ ] User Interface:
  - Environment status indicator
  - Manual sync trigger option
  - Sync history and logs
  - Conflict resolution interface
  - Progress tracking for long operations

- [ ] Data Integrity:
  - Checksums for exported data
  - Version tracking for records
  - Audit logging of sync operations
  - Rollback capabilities

#### Advanced Certificate Validation

- [ ] Complete certificate chain validation
- [ ] Root certificate verification
- [ ] Intermediate certificate tracking
- [ ] Certificate revocation checking
- [ ] OCSP stapling support

#### Enhanced Search Capabilities

- [ ] Full-text search across all fields
- [ ] Advanced filtering and sorting
- [ ] Saved search profiles
- [ ] Bulk actions on search results
- [ ] Export search results

#### Settings Management Interface

- [ ] Web-based configuration editor
- [ ] Profile management system
- [ ] Rate limit configuration
- [ ] Custom scanning profiles
- [ ] Configuration validation

#### Automated Backup System

- [ ] Scheduled automatic backups
- [ ] Backup verification
- [ ] Restore testing

## Development Approach

### Phase 1: Core Features

1. Port/adapt existing scanning code
2. Setup SQLite database schema
3. Create basic Streamlit interface

### Phase 2: Infrastructure Integration

1. Scanning functionality
2. Platform integration
3. Assignment management

### Phase 3: Advanced Features

1. Historical tracking
2. Advanced reporting
3. Search capabilities

### Phase 4: Enhancement

1. Performance optimization
2. Additional integrations
3. Advanced certificate validation
4. History page does not need Scan Trends
5. Scan button color should be green
6. Scan button should be disabled when scanning is in progress
7. Scan results should be organized better
8. When scanning is in progress, the site should show a loading spinner sooner and stay present longer
9. History page should show correct host instead of unknown host.
10. Hosts page should be using ag-grid
11. Hosts page should use color for valid and invalid certificates
12. Dashboard data graph should be sized correctly when there are a lot of certificates.
13. Need a Change planning page, to help build change tickets.
