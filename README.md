# Certificate Management System

A comprehensive web-based system for tracking and managing SSL/TLS certificates across various infrastructure components.

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