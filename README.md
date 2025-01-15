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

## Implementation

### Technology Stack
- Python 3.x
- Streamlit for UI
- SQLite database
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