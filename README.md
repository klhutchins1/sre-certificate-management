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
# Method 1: Using custom runner (recommended)
python run_custom.py

# Method 2: Using streamlit directly (alternative)
streamlit run run.py
```

The application will be available at http://localhost:8501 by default.

### Troubleshooting

If you encounter port conflicts, you can modify the port in `run_custom.py` by changing the `--server.port` value.

To see detailed logs of the application startup:

1. Run the application using the custom runner
2. Check the `streamlit_runner.log` file in the application directory
3. The log file contains detailed information about the startup process and any errors

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
2. View hosts in interactive AG Grid table with:
   - Sortable columns
   - Built-in filtering
   - Real-time search
   - Color-coded status indicators
3. Select a host to see:
   - Detailed host information
   - Associated certificates
   - Certificate status and details
4. Features:
   - Modern, responsive grid interface
   - Advanced filtering capabilities
   - Quick access to certificate details
   - Color-coded status indicators
   - Efficient data handling

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

- [x] Web-based interface with modern AG Grid tables
- [x] Certificate list view with advanced filtering and sorting
- [x] Host management with interactive grid interface
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

- [ ] Bulk actions on search results


#### Settings Management Interface

- [ ] Web-based configuration editor
- [ ] Rate limit configuration
- [ ] Configuration validation

#### Automated Backup System

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
2. Advanced certificate validation
3. History page does not need Scan Trends
4. Scan button color should be green
5. Scan button should be disabled when scanning is in progress
6. Scan results should be organized better
7. When scanning is in progress, the site should show a loading spinner sooner and stay present longer
8. History page should show correct host instead of unknown host.
9.  Hosts page should be using ag-grid
10. Hosts page should use color for valid and invalid certificates
11. Dashboard data graph should be sized correctly when there are a lot of certificates.
12. Need a Change planning page, to help build change tickets.

## Planned Features

### Certificate Authority Management

- [ ] Track CA certificates separately from end-entity certificates
- [ ] Display CA information in Certificates view
- [ ] Track CA certificate chain relationships
- [ ] Monitor CA certificate expiration
- [ ] Validate certificate chains against known CAs
- [ ] Import trusted CA certificates from system store

### Multi-Instance Support

- [ ] Enable multiple application instances to run simultaneously
- [ ] Implement proper database locking mechanisms
- [ ] Handle concurrent database access
- [ ] Add instance identification and status tracking
- [ ] Provide conflict resolution for concurrent updates

### JWT Certificate Management

- [ ] Scan for JWT certificates on RDS servers using PowerShell
- [ ] Define standardized JWT certificate format
- [ ] Import JWT certificates from scan results
- [ ] Track JWT-specific certificate usage
- [ ] Monitor JWT certificate expiration
- [ ] Validate JWT certificate signatures

### Enhanced Scanning Features

- [ ] Maintain historical certificate data when scans fail
  - Preserve existing certificate data if new scan fails
  - Keep last successful scan data for each IP/domain
  - Track scan source (instance/environment) for each result
  - Implement scan result confidence scoring
- [ ] Implement partial update mechanism for scan results
  - Update only changed certificate data
  - Keep existing data when scan access is denied
  - Merge partial scan results from different sources
  - Handle network connectivity issues gracefully
- [ ] Track scan success/failure history
  - Log scan attempts from each instance
  - Record scan environment details
  - Track access permissions per instance
  - Monitor scan reliability per source
- [ ] Add scan result confidence levels
  - Calculate confidence score based on scan source
  - Consider historical scan success rate
  - Factor in network conditions
  - Weight results by instance reliability
- [ ] Provide manual override for scan results
  - Allow manual data preservation
  - Support administrator data validation
  - Enable source-specific overrides
  - Track override history
- [ ] Compare scan results with previous data
  - Detect significant changes
  - Alert on unexpected data loss
  - Validate scan result consistency
  - Maintain scan result audit trail
- [ ] Cross-instance scan coordination
  - Coordinate scanning between instances
  - Share scan results across environments
  - Resolve conflicting scan data
  - Optimize scanning efficiency

### Domain Management

- [ ] Track domain registration expiration
- [ ] Monitor domain ownership
- [ ] Alertand warning on approaching domain expiration
- [ ] Track domain-certificate relationships
- [ ] Support for wildcard domain tracking

### Data Resilience

- [ ] Implement robust database locking
- [ ] Add transaction rollback support
- [ ] Maintain audit trail of changes
- [ ] Implement data versioning
- [ ] Add conflict resolution mechanisms

These planned features will enhance the system's capabilities in:

- Certificate Authority tracking and validation
- Multi-instance deployment support
- JWT certificate management
- Scan result persistence
- Domain lifecycle management
- Data integrity and resilience
- create CSR
  