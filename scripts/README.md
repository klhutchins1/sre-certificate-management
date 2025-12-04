# Scripts Directory

This directory contains utility scripts organized by category.

## Directory Structure

- **`migrations/`** - Database migration scripts
- **`diagnostics/`** - Diagnostic and analysis scripts
- **`deduplication/`** - Certificate deduplication scripts
- **`_common.py`** - Common utilities for all scripts (config loading, path resolution)

## Usage

All scripts can be run from the project root directory. They automatically locate `config.yaml` in the project root.

### Migration Scripts

```bash
# Add proxy detection columns
python scripts/migrations/migrate_proxy_detection.py

# Add revocation status columns
python scripts/migrations/migrate_revocation_status.py

# Migrate remote database
python scripts/migrations/migrate_remote_database.py --db-path \\\\server\\share\\certificates.db
```

### Diagnostic Scripts

```bash
# Diagnose proxy certificates
python scripts/diagnostics/diagnose_proxy_certificates.py

# Find certificate duplicates
python scripts/diagnostics/find_certificate_duplicates.py

# Examine certificates in detail
python scripts/diagnostics/examine_certificates.py
```

### Deduplication Scripts

```bash
# Basic proxy certificate deduplication
python scripts/deduplication/proxy_certificate_deduplication.py --dry-run

# Advanced proxy certificate deduplication (recommended)
python scripts/deduplication/proxy_certificate_deduplication_advanced.py --dry-run

# General certificate deduplication
python scripts/deduplication/general_certificate_deduplication.py --dry-run
```

## Common Utilities

The `_common.py` module provides shared functionality:

- `find_project_root()` - Locates the project root directory
- `load_config()` - Loads configuration from `config.yaml`
- `get_database_path_from_config()` - Gets database path from config

All scripts use these utilities to ensure they work correctly regardless of their location in the directory structure.

## Configuration

All scripts read configuration from `config.yaml` in the project root. The database path is typically specified in `config.yaml` under `paths.database`, but can also be overridden with command-line arguments.

## Notes

- Scripts automatically handle relative paths and find the project root
- Database paths from config.yaml are resolved relative to the project root
- All scripts include fallback logic if `_common.py` is not available

