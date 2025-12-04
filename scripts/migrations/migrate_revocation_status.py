#!/usr/bin/env python3
"""
Database Migration Script: Add Revocation Status Columns

This script migrates an existing database to add revocation status support.
It adds revocation-related columns to the certificates table for OCSP/CRL checking.

Usage:
    python migrate_revocation_status.py [--db-path PATH_TO_DATABASE] [--no-backup]
    
Example:
    python migrate_revocation_status.py --db-path data/certificates.db
"""

import argparse
import sqlite3
import sys
import os
import yaml
from pathlib import Path

# Add scripts directory to path to import common utilities
# _common.py is in scripts/, so we need to add scripts/ directory to path
scripts_dir = Path(__file__).parent.parent  # scripts/ directory
sys.path.insert(0, str(scripts_dir))
try:
    from _common import find_project_root, load_config, get_database_path_from_config
except ImportError:
    # Fallback if _common.py not available
    def find_project_root():
        """Find the project root directory (where config.yaml is located)."""
        current = Path(__file__).resolve()
        # Script is in scripts/migrations/, so go up 3 levels to reach project root
        project_root = current.parent.parent.parent
        return project_root
    
    def load_config():
        """Load configuration from config.yaml file."""
        project_root = find_project_root()
        config_path = project_root / 'config.yaml'
        if not config_path.exists():
            print(f"⚠️  Warning: config.yaml not found at {config_path}")
            return None
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config
        except Exception as e:
            print(f"⚠️  Warning: Could not load config.yaml: {e}")
            return None
    
    def get_database_path_from_config():
        """Get database path from config.yaml file."""
        config = load_config()
        if config and 'paths' in config and 'database' in config['paths']:
            db_path = config['paths']['database']
            if not os.path.isabs(db_path):
                project_root = find_project_root()
                db_path = os.path.join(project_root, db_path)
            return db_path
        return None

def check_database_exists(db_path):
    """Check if the database file exists."""
    if not os.path.exists(db_path):
        print(f"❌ Error: Database file not found at {db_path}")
        return False
    return True

def check_table_exists(cursor, table_name):
    """Check if a table exists in the database."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cursor.fetchone() is not None

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table."""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def backup_database(db_path):
    """Create a backup of the database before migration."""
    backup_path = f"{db_path}.backup.{int(__import__('time').time())}"
    try:
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"✅ Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"⚠️  Warning: Could not create backup: {e}")
        return None

def migrate_revocation_status_columns(db_path, skip_backup=False):
    """
    Migrate the database to add revocation status columns.
    
    Args:
        db_path (str): Path to the SQLite database file
        skip_backup (bool): If True, skip backup creation
        
    Returns:
        bool: True if migration successful, False otherwise
    """
    print(f"🔧 Starting revocation status migration for database: {db_path}")
    
    # Check if database exists
    if not check_database_exists(db_path):
        return False
    
    # Create backup
    if not skip_backup:
        backup_path = backup_database(db_path)
        if not backup_path:
            print("⚠️  Warning: Backup creation failed, but continuing...")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if certificates table exists
        if not check_table_exists(cursor, 'certificates'):
            print("❌ Error: 'certificates' table not found in database")
            print("   The application will create this table automatically when first run.")
            return False
        
        print("✅ Found 'certificates' table")
        
        # Get current columns
        cursor.execute("PRAGMA table_info(certificates)")
        current_columns = [row[1] for row in cursor.fetchall()]
        print(f"📋 Current columns: {', '.join(current_columns)}")
        
        # Columns to add
        columns_to_add = [
            ('revocation_status', 'TEXT'),
            ('revocation_date', 'DATETIME'),
            ('revocation_reason', 'TEXT'),
            ('revocation_check_method', 'TEXT'),
            ('revocation_last_checked', 'DATETIME'),
            ('ocsp_response_cached_until', 'DATETIME'),
        ]
        
        # Add missing columns
        added_columns = []
        for column_name, column_type in columns_to_add:
            if not check_column_exists(cursor, 'certificates', column_name):
                print(f"➕ Adding '{column_name}' column...")
                try:
                    cursor.execute(f"ALTER TABLE certificates ADD COLUMN {column_name} {column_type}")
                    added_columns.append(column_name)
                    print(f"✅ Added '{column_name}' column")
                except Exception as e:
                    print(f"❌ Error adding '{column_name}' column: {e}")
                    conn.rollback()
                    return False
            else:
                print(f"⏭️  Column '{column_name}' already exists, skipping")
        
        if not added_columns:
            print("ℹ️  All revocation status columns already exist. Migration not needed.")
            return True
        
        # Commit changes
        conn.commit()
        print("💾 Changes committed to database")
        
        # Verify migration
        print("\n🔍 Verifying migration...")
        cursor.execute("PRAGMA table_info(certificates)")
        updated_columns = [row[1] for row in cursor.fetchall()]
        print(f"📋 Updated columns: {', '.join(updated_columns)}")
        
        # Verify all columns exist
        all_present = all(
            check_column_exists(cursor, 'certificates', col[0])
            for col in columns_to_add
        )
        
        if all_present:
            print("✅ Migration verification successful")
        else:
            print("❌ Migration verification failed - some columns missing")
            return False
        
        # Get certificate count
        cursor.execute("SELECT COUNT(*) FROM certificates")
        cert_count = cursor.fetchone()[0]
        print(f"📊 Database contains {cert_count} existing certificates")
        print("   All certificates will have revocation_status = NULL (not checked)")
        print("   Use the certificate scanner to check revocation status")
        
        conn.close()
        
        print("\n============================================================")
        print("✅ Migration completed successfully!")
        print("============================================================")
        
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error during migration: {e}")
        if 'conn' in locals():
            conn.rollback()
        return False
    except Exception as e:
        print(f"❌ Unexpected error during migration: {e}")
        if 'conn' in locals():
            conn.rollback()
        return False

def verify_migration(db_path):
    """Verify that migration has been applied."""
    if not check_database_exists(db_path):
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        if not check_table_exists(cursor, 'certificates'):
            print("❌ 'certificates' table not found")
            return False
        
        required_columns = [
            'revocation_status',
            'revocation_date',
            'revocation_reason',
            'revocation_check_method',
            'revocation_last_checked',
            'ocsp_response_cached_until',
        ]
        
        all_present = all(
            check_column_exists(cursor, 'certificates', col)
            for col in required_columns
        )
        
        conn.close()
        
        if all_present:
            print("✅ Migration verification: All revocation status columns present")
            return True
        else:
            print("❌ Migration verification: Some columns missing")
            missing = [col for col in required_columns 
                      if not check_column_exists(cursor, 'certificates', col)]
            print(f"   Missing columns: {', '.join(missing)}")
            return False
            
    except Exception as e:
        print(f"❌ Error during verification: {e}")
        return False

def main():
    """Main entry point for the migration script."""
    parser = argparse.ArgumentParser(
        description='Migrate database to add revocation status columns'
    )
    parser.add_argument(
        '--db-path',
        type=str,
        help='Path to the SQLite database file'
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip database backup (not recommended)'
    )
    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify migration, do not perform migration'
    )
    
    args = parser.parse_args()
    
    # Determine database path
    if args.db_path:
        db_path = args.db_path
    else:
        db_path = get_database_path_from_config()
        if not db_path:
            db_path = 'data/certificates.db'
    
    print("=" * 60)
    print("🔧 Revocation Status Database Migration Tool")
    print("=" * 60)
    print(f"Database path: {db_path}")
    print(f"Verify only: {args.verify_only}")
    print(f"Skip backup: {args.no_backup}")
    print("=" * 60)
    print()
    
    if args.verify_only:
        if verify_migration(db_path):
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Perform migration
    success = migrate_revocation_status_columns(db_path, skip_backup=args.no_backup)
    
    if success:
        print("\n🎉 Your database is now ready for revocation status checking!")
        print("\nNext steps:")
        print("1. Restart your application")
        print("2. The OCSP/CRL checking features will now work")
        print("3. New certificates will be checked for revocation status")
        print("4. Existing certificates will have revocation_status = NULL until checked")
        sys.exit(0)
    else:
        print("\n❌ Migration failed. Please check the errors above.")
        sys.exit(1)

if __name__ == '__main__':
    main()


