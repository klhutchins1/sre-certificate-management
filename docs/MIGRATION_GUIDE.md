# Database Migration Guide: Adding Proxy Detection Support

## Overview

This guide helps you migrate your existing database to add proxy detection support. The migration adds two new columns to the `certificates` table:

- `proxied` (BOOLEAN) - Indicates if a certificate was detected as a proxy/MITM certificate
- `proxy_info` (TEXT) - Stores detailed information about why the certificate was flagged as proxied

## Quick Start

### Option 1: Automatic Migration (Recommended)

Use the automatic migration launcher:

```bash
python run_with_migration.py
```

This will automatically check if migration is needed and run it before starting your application.

### Option 2: Manual Migration

Run the migration script directly:

```bash
python scripts/migrations/migrate_proxy_detection.py
```

### Option 3: Verify Migration Only

Check if migration has already been applied:

```bash
python scripts/migrations/migrate_proxy_detection.py --verify-only
```

## Migration Scripts

### 1. `migrate_proxy_detection.py`

The main migration script with the following features:

- **Automatic backup** of your database before migration
- **Safe migration** that only adds missing columns
- **Verification** of migration success
- **Detailed logging** of the migration process
- **Command-line options** for customization

#### Usage Examples:

```bash
# Basic migration (uses default database path)
python scripts/migrations/migrate_proxy_detection.py

# Specify custom database path
python scripts/migrations/migrate_proxy_detection.py --db-path /path/to/your/certificates.db

# Verify migration without making changes
python scripts/migrations/migrate_proxy_detection.py --verify-only

# Skip backup (not recommended)
python scripts/migrations/migrate_proxy_detection.py --no-backup
```

### 2. `run_with_migration.py`

Application launcher that automatically handles migration:

```bash
python run_with_migration.py
```

This script:
- Checks if migration is needed
- Runs migration automatically if required
- Starts your main application
- Provides clear error messages if migration fails

### 3. `test_migration.py`

Test script to verify migration works correctly:

```bash
python test_migration.py
```

This creates a test database, runs the migration, and verifies everything works correctly.

## Migration Process

### What the Migration Does

1. **Creates a backup** of your existing database
2. **Checks current schema** to see what columns exist
3. **Adds missing columns**:
   - `proxied` (BOOLEAN, default: FALSE)
   - `proxy_info` (TEXT, nullable)
4. **Verifies the migration** was successful
5. **Preserves all existing data**

### Safety Features

- **Non-destructive**: Only adds columns, never removes or modifies existing data
- **Automatic backup**: Creates timestamped backup before making changes
- **Verification**: Checks that migration was successful
- **Idempotent**: Safe to run multiple times (won't duplicate columns)

### Example Migration Output

```
============================================================
🔧 Proxy Detection Database Migration Tool
============================================================
Database path: /path/to/data/certificates.db
Verify only: False
Skip backup: False
============================================================
✅ Database backed up to: /path/to/data/certificates.db.backup.1703123456
🔧 Starting proxy detection migration for database: /path/to/data/certificates.db
✅ Found 'certificates' table
📋 Current columns: id, serial_number, thumbprint, common_name, valid_from, valid_until, issuer, subject, san, key_usage, signature_algorithm, chain_valid, sans_scanned, created_at, updated_at, notes, version
➕ Adding 'proxied' column...
✅ Added 'proxied' column
➕ Adding 'proxy_info' column...
✅ Added 'proxy_info' column
✅ Migration verification successful
📋 Updated columns: id, serial_number, thumbprint, common_name, valid_from, valid_until, issuer, subject, san, key_usage, signature_algorithm, chain_valid, sans_scanned, created_at, updated_at, notes, version, proxied, proxy_info
📊 Database contains 1250 existing certificates
💾 Changes committed to database

============================================================
✅ Migration completed successfully!
============================================================

🔍 Verifying migration...
🔍 Migration Verification:
   proxied column: ✅
   proxy_info column: ✅
✅ Migration verification successful!

🎉 Your database is now ready for proxy detection!

Next steps:
1. Restart your application
2. The proxy detection features will now work
3. New certificates will be checked for proxy indicators
4. Existing certificates will remain unchanged
```

## Database Schema Changes

### Before Migration

```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY,
    serial_number TEXT UNIQUE NOT NULL,
    thumbprint TEXT UNIQUE NOT NULL,
    common_name TEXT,
    valid_from DATETIME NOT NULL,
    valid_until DATETIME NOT NULL,
    issuer TEXT,
    subject TEXT,
    san TEXT,
    key_usage TEXT,
    signature_algorithm TEXT,
    chain_valid BOOLEAN DEFAULT 0,
    sans_scanned BOOLEAN DEFAULT 0,
    created_at DATETIME,
    updated_at DATETIME,
    notes TEXT,
    version INTEGER
);
```

### After Migration

```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY,
    serial_number TEXT UNIQUE NOT NULL,
    thumbprint TEXT UNIQUE NOT NULL,
    common_name TEXT,
    valid_from DATETIME NOT NULL,
    valid_until DATETIME NOT NULL,
    issuer TEXT,
    subject TEXT,
    san TEXT,
    key_usage TEXT,
    signature_algorithm TEXT,
    chain_valid BOOLEAN DEFAULT 0,
    sans_scanned BOOLEAN DEFAULT 0,
    created_at DATETIME,
    updated_at DATETIME,
    notes TEXT,
    version INTEGER,
    proxied BOOLEAN DEFAULT 0,           -- NEW: Proxy detection flag
    proxy_info TEXT                      -- NEW: Proxy detection details
);
```

## Troubleshooting

### Common Issues

#### 1. "Database file not found"

**Error:**
```
❌ Error: Database file not found at data/certificates.db
```

**Solution:**
- Check the database path is correct
- Use `--db-path` to specify the correct path:
  ```bash
  python migrate_proxy_detection.py --db-path /correct/path/to/certificates.db
  ```

#### 2. "certificates table not found"

**Error:**
```
❌ Error: 'certificates' table not found in database
```

**Solution:**
- This means your database doesn't have the certificates table
- The application will create it automatically when you first run it
- No migration is needed for new databases

#### 3. "Permission denied"

**Error:**
```
❌ Error during migration: [Errno 13] Permission denied
```

**Solution:**
- Check file permissions on the database file
- Ensure you have write access to the database directory
- Try running with appropriate permissions

#### 4. Migration verification fails

**Error:**
```
❌ Migration verification failed!
```

**Solution:**
- Check the database backup was created
- Restore from backup if needed
- Run migration again
- Contact support if the issue persists

### Restoring from Backup

If something goes wrong, you can restore from the automatic backup:

```bash
# Find your backup file
ls -la data/certificates.db.backup.*

# Restore from backup (replace TIMESTAMP with actual timestamp)
cp data/certificates.db.backup.TIMESTAMP data/certificates.db
```

## Post-Migration

### What Happens After Migration

1. **Existing certificates** remain unchanged (all have `proxied=FALSE` and `proxy_info=NULL`)
2. **New certificates** will be checked for proxy indicators
3. **Proxy detection features** are now available in your application

### Verifying the Migration

You can verify the migration worked by checking the database:

```sql
-- Check that columns exist
PRAGMA table_info(certificates);

-- Check existing certificates (should all be proxied=FALSE)
SELECT COUNT(*) as total_certificates,
       SUM(CASE WHEN proxied = 1 THEN 1 ELSE 0 END) as proxy_certificates
FROM certificates;
```

### Testing Proxy Detection

After migration, you can test proxy detection by:

1. **Scanning a known proxy certificate** (if you have one)
2. **Checking the database** for the new columns
3. **Verifying proxy detection** works in the application

## Configuration

### Proxy Detection Settings

After migration, you can configure proxy detection in your `config.yaml`:

```yaml
proxy_detection:
  enabled: true
  ca_fingerprints: []
  ca_subjects: 
    - "Corporate Proxy CA"
    - "BlueCoat ProxySG CA"
  ca_serials: []
  bypass_patterns:
    - "*.github.com"
    - "*.googleapis.com"
  bypass_external: false
```

### Application Integration

The migration integrates seamlessly with your existing application:

- **No code changes required** - the new columns are automatically used
- **Backward compatible** - existing code continues to work
- **Enhanced functionality** - proxy detection features are now available

## Support

If you encounter issues with the migration:

1. **Check the troubleshooting section** above
2. **Run the test script** to verify the migration process
3. **Check the logs** for detailed error messages
4. **Restore from backup** if needed
5. **Contact support** with the error details

## Files Created

- `scripts/migrations/migrate_proxy_detection.py` - Main migration script
- `run_with_migration.py` - Application launcher with migration
- `tests/scripts/test_migration.py` - Migration test script
- `docs/MIGRATION_GUIDE.md` - This documentation

## Summary

The migration process is designed to be:

- **Safe**: Non-destructive with automatic backups
- **Simple**: One-command migration
- **Verifiable**: Built-in verification and testing
- **Automatic**: Can be integrated into application startup

Follow the Quick Start section above to migrate your database and start using proxy detection features.
