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

#### Export Settings
##### PDF Export Configuration
- `exports.pdf.template`: HTML template for PDF reports
  - Default: `reports/template.html`
  - Customizable for branding
- `exports.pdf.logo`: Logo image for reports
  - Default: `reports/logo.png`
  - Company logo or branding image

##### CSV Export Configuration
- `exports.csv.delimiter`: Character used to separate values
  - Default: `,`
  - Can be changed for regional preferences
- `exports.csv.encoding`: Character encoding for files
  - Default: `utf-8`
  - Change if needed for special characters

#### Configuration File Locations
1. Environment variable: `CERT_SCANNER_CONFIG`
   - Highest priority
   - Set to full path of config file
2. Local directory: `config.yaml`
   - Project directory
   - Good for development
3. User home: `~/.cert_scanner/config.yaml`
   - Per-user settings
   - `%USERPROFILE%\.cert_scanner\config.yaml` on Windows
4. System-wide: `/etc/cert_scanner/config.yaml`
   - Shared settings
   - Not typically used on Windows

#### Backup System
The application includes an automated backup system accessible through the Settings interface:

##### Creating Backups
- Click the "Create New Backup" button in Settings
- Automatically backs up:
  - Database file
  - Configuration file
  - Creates a manifest file
- Creates safety backup before restore operations

##### Restoring Backups
- Select a backup from the dropdown list
- Shows timestamp for each available backup
- Confirms before restoring
- Creates safety backup of current state
- Automatically restores:
  - Configuration settings
  - Database (if included in backup)
- Requires application restart after restore

##### Backup Contents
- Database backup: `certificates_YYYYMMDD_HHMMSS.db`
- Config backup: `config_YYYYMMDD_HHMMSS.yaml`
- Manifest: `backup_YYYYMMDD_HHMMSS.json`
  - Contains backup metadata
  - Timestamps
  - File locations
  - Creation details

##### Backup Location
- Stored in directory specified by `paths.backups`
- Default: `data/backups`
- Can be customized in settings
- Maintains backup history

##### Best Practices
- Create regular backups before major changes
- Store backups in a secure location
- Keep multiple backup versions
- Verify backup integrity periodically
- Test restore functionality in development
- Document any custom configurations
- Keep backup directory organized

### Configuration Troubleshooting

#### Common Issues and Solutions

##### Database Connection Issues
- **Issue**: Database file not found
  - Check if the `paths.database` path is correct
  - Ensure the directory exists and has write permissions
  - Use absolute paths if running from different directories
  - Default location is created automatically if not exists

##### Scanning Problems
- **Issue**: Scans too aggressive/triggering security alerts
  - Increase `scanning.internal.delay` and decrease `rate_limit`
  - Split domains between internal/external profiles
  - Use smaller batch sizes for scanning

- **Issue**: Scans too slow
  - Adjust rate limits based on network capacity
  - Decrease delays if network allows
  - Consider parallel scanning for internal networks

##### Alert Configuration
- **Issue**: Missing alerts
  - Verify alert thresholds are properly set
  - Check if `alerts.persistence_file` is writable
  - Ensure expiry warning days are in descending order

- **Issue**: Too many alerts
  - Increase `alerts.failed_scans.consecutive_failures`
  - Adjust expiry warning thresholds
  - Group similar alerts together

##### Export Issues
- **Issue**: PDF generation fails
  - Verify template path in `exports.pdf.template`
  - Check if logo file exists at `exports.pdf.logo`
  - Ensure directories have write permissions

- **Issue**: CSV encoding problems
  - Try different `exports.csv.encoding` values:
    - `utf-8-sig` for Excel compatibility
    - `latin1` for legacy systems
    - `ascii` for basic compatibility

#### Best Practices
1. **Backup Configuration**
   - Keep a backup of working configuration
   - Document any custom changes
   - Use version control for config files

2. **Path Management**
   - Use absolute paths in production
   - Keep all paths under project directory
   - Create missing directories automatically

3. **Security Considerations**
   - Don't store sensitive data in config
   - Use appropriate file permissions
   - Keep backups in secure location

4. **Performance Tuning**
   - Start with conservative rate limits
   - Monitor network impact
   - Adjust based on actual usage

#### Environment-Specific Settings
- **Development**:
  ```yaml
  scanning:
    internal:
      rate_limit: 20
      delay: 1
  ```

- **Production**:
  ```yaml
  scanning:
    internal:
      rate_limit: 10
      delay: 2
    external:
      rate_limit: 5
      delay: 5
  ```

- **High Security**:
  ```yaml
  scanning:
    internal:
      rate_limit: 5
      delay: 5
    external:
      rate_limit: 2
      delay: 10
  ```

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
- Alert System: Email/notification integration
- Report Generator: PDF/CSV export functionality

## Development Approach

### Existing Code Integration
- Adapt getCertificates.py scanning functionality:
  - Extract core scanning logic
  - Add SAN processing
  - Implement async scanning for UI responsiveness
  - Add database integration
- Enhance error handling and logging
- Add certificate metadata extraction
- Implement periodic scanning capability

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
2. Alerting system
3. Advanced reporting

### Phase 4: Enhancement
1. Performance optimization
2. Additional integrations
3. Advanced search capabilities 

## Similar Existing Solutions

### Commercial Solutions
- CertificateTools.com
  - Enterprise focused
  - Expensive licensing
  - More features than needed
- KeyManager Plus
  - Enterprise grade
  - Complex deployment
  - Extensive feature set

### Open Source Alternatives
- XCA
  - Desktop only
  - Limited scanning
  - No automation
- Let's Encrypt Certificate Manager
  - Limited to LE certificates
  - No external scanning

### Why Build Custom
- Specific requirements for scanning and tracking
- Need for simple, focused functionality
- Cost-effective solution
- Integration with existing tools and processes 

## Current Status

### Implemented Features
- ✅ Certificate scanning and storage
- ✅ IP address and hostname tracking
- ✅ Certificate details view with SANs
- ✅ Host management by IP address
- ✅ Basic dashboard with metrics
- ✅ Certificate timeline visualization
- ✅ Settings management interface
- ✅ Configurable scanning profiles 

### Under Development
- 🚧 History tracking
- 🚧 Search functionality
- 🚧 Advanced filtering
- 🚧 Export capabilities

### Planned Features
- 📋 Certificate chain validation
- 📋 Automated scanning
- 📋 Email notifications
- �� Custom reporting 