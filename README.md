# Certificate Management System

## 1. Overview

A comprehensive web-based system for tracking and managing SSL/TLS certificates across infrastructure components. Features include certificate/host/domain tracking, scanning, reporting, configuration, and backup.

---

## 2. Features

### Core Features

- **Certificate Tracking:** View, search, filter, and track SSL/TLS certificates, including status, associations, and history.
- **Host & Domain Tracking:** Inventory, types, IPs, DNS, and associations.
- **Infrastructure Mapping:** Visualize relationships between certificates, hosts, and domains.
- **Scanning & Monitoring:** Internal/external scans, SANs, scan history, alerts, and certificate chain validation.
- **Export & Reporting:** CSV/PDF exports, customizable templates, timeline/charts.
- **Configuration & Backup:** YAML-based config, web editor, multi-location, env overrides, automated/manual backup/restore.
- **User Interface:** Modern web UI with AG Grid, advanced filtering, responsive design.
- **Error Handling:** Custom exceptions, logging, and robust error management.
- **Testing:** Unit/integration tests, edge case coverage, test data for backup/restore.

### Planned & Upcoming Features

- **Data Synchronization:** Environment-specific scanning, database export/import, incremental updates, conflict resolution.
- **Advanced Validation:** Complete certificate chain validation, revocation checking, OCSP stapling.
- **Enhanced Search:** Full-text search, advanced filtering, bulk actions.
- **Multi-Instance Support:** Database locking, concurrent access, conflict resolution.
- **Security Enhancements:** Role-based access, audit logging, secret management.
- **Domain Management:** Registration/expiration tracking, ownership monitoring, wildcard support.
- **Data Resilience:** Locking, rollback, audit trail, versioning.
- **Scanning:** Scan certificates from associated bindings.

---

## 3. Installation

### Standard Installation

```bash
git clone https://github.com/klhutchins1/SRE-CertificateManagement.git
cd SRE-CertificateManagement
  # Optional: Create and activate a virtual environment for Python
  # python -m venv venv
  # venv\Scripts\activate

pip install -r requirements.txt
python run_custom.py

# or
source venv/bin/activate  # Linux/Mac
pip install -r requirements.txt
python run_custom.py  # or: streamlit run run.py
```

App runs at <http://localhost:8501>.

### Offline Installation

- Download requirements on an online machine, copy to `requirements_offline`, then:

```bash
pip install --no-index --find-links requirements_offline -r requirements.txt
```

### Troubleshooting

- Change port in `run_custom.py` if needed.
- Check `streamlit_runner.log` for startup errors.

---

## 4. Usage Guide

- **Scanning Certificates:** Use the "Scan" sidebar, enter hostnames, start scan, view results/errors.
  - Scan domains you want to track registrar and certificate Info.
  - ![Scan](https://github.com/klhutchins1/sre-certificate-management/blob/main/images/Screenshot-Scanner.png "Scan")
- **Viewing Certificates:** "Certificates" page for list/detail, SANs, associations.
  - ![Certificate](https://github.com/klhutchins1/sre-certificate-management/blob/main/images/Screenshot-Certificate.png "Certificate")
- **Managing Hosts:** "Hosts" page with AG Grid, filtering, status indicators, details.
  - ![Host](https://github.com/klhutchins1/sre-certificate-management/blob/main/images/Screenshot-Host.png "Host")
- **Dashboard:** Overview of certificates, expiring soon, timeline.
  - ![Dashboard](https://github.com/klhutchins1/sre-certificate-management/blob/main/images/Screenshot-Dashboard.png "Dashboard")
- **Domain:** Overview of Domain and DNS information
  - ![Domain](https://github.com/klhutchins1/sre-certificate-management/blob/main/images/Screenshot-Domain.png "Domain")
- **History** Previosly scanned Certificates and scans
  - ![History](https://github.com/klhutchins1/sre-certificate-management/blob/main/images/Screenshot-History.png "History")
  
---

## 5. Configuration

- **Database:** `paths.database` (default: `data/certificates.db`)
- **Backups:** `paths.backups` (default: `data/backups`)
- **Scanning Profiles:** Internal/external rate limits, delays, domains.
- **Alerts:** Expiry warnings, failed scan thresholds, alert state file.
- **Environment Overrides:** Supported via environment variables.
- **Web Editor:** UI for settings management.

---

## 6. Architecture & Technology

- **Stack:** Python 3.x, Streamlit, SQLite, PyYAML, cryptography libraries.
- **Core Components:** Scanner, database layer (SQLAlchemy), web interface, settings manager, report generator.
- **Data Flow:** Scanning → Database → UI/Export/Alerts.
- **Control Flow:** User actions in UI trigger scans, updates, exports, and configuration changes.

---

## 7. Testing

- **Coverage:** Unit/integration tests for all core features.
- **How to Run:**

```bash
pytest
```

- **Edge Cases:** Backup/restore, error scenarios, validation.

---

## 8. Development & Contribution

- **Phases:** Core features → Integration → Advanced features → Enhancements.
- **How to Contribute:** Submit pull requests, follow code style guidelines, add/maintain tests and documentation.
- **Roadmap:** See "Planned & Upcoming Features" above.

---

## 9. Known Issues & Limitations

- Recursive domain deletion not fully implemented.
- WhoIS module may not respect offline mode.
- No pause/stop for ongoing scans.
- Some environment labeling and dashboard aggregation issues.

---

## 10. Appendix

- **Glossary:** (Add as needed)
- **References:** (Add as needed)
- **Links:** (Add as needed)
  