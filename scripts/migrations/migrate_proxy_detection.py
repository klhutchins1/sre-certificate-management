#!/usr/bin/env python3
"""
Database Migration Script: Add Proxy Detection Columns

This script migrates an existing database to add proxy detection support.
It adds the 'proxied' and 'proxy_info' columns to the certificates table.

Usage:
    python migrate_proxy_detection.py [--db-path PATH_TO_DATABASE]
    
Example:
    python migrate_proxy_detection.py --db-path data/certificates.db
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
    cursor.execute("PRAGMA table_info(?)", (table_name,))
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

def migrate_proxy_detection_columns(db_path):
    """
    Migrate the database to add proxy detection columns.
    
    Args:
        db_path (str): Path to the SQLite database file
        
    Returns:
        bool: True if migration successful, False otherwise
    """
    print(f"🔧 Starting proxy detection migration for database: {db_path}")
    
    # Check if database exists
    if not check_database_exists(db_path):
        return False
    
    # Create backup
    backup_path = backup_database(db_path)
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if certificates table exists
        if not check_table_exists(cursor, 'certificates'):
            print("❌ Error: 'certificates' table not found in database")
            return False
        
        print("✅ Found 'certificates' table")
        
        # Check current columns
        cursor.execute("PRAGMA table_info(certificates)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        print(f"📋 Current columns: {', '.join(existing_columns)}")
        
        # Add proxied column if it doesn't exist
        if 'proxied' not in existing_columns:
            print("➕ Adding 'proxied' column...")
            cursor.execute("ALTER TABLE certificates ADD COLUMN proxied BOOLEAN DEFAULT 0")
            print("✅ Added 'proxied' column")
        else:
            print("ℹ️  'proxied' column already exists")
        
        # Add proxy_info column if it doesn't exist
        if 'proxy_info' not in existing_columns:
            print("➕ Adding 'proxy_info' column...")
            cursor.execute("ALTER TABLE certificates ADD COLUMN proxy_info TEXT")
            print("✅ Added 'proxy_info' column")
        else:
            print("ℹ️  'proxy_info' column already exists")
        
        # Verify the migration
        cursor.execute("PRAGMA table_info(certificates)")
        updated_columns = [row[1] for row in cursor.fetchall()]
        
        # Check if both columns are now present
        if 'proxied' in updated_columns and 'proxy_info' in updated_columns:
            print("✅ Migration verification successful")
            
            # Show final column list
            print(f"📋 Updated columns: {', '.join(updated_columns)}")
            
            # Count existing certificates
            cursor.execute("SELECT COUNT(*) FROM certificates")
            cert_count = cursor.fetchone()[0]
            print(f"📊 Database contains {cert_count} existing certificates")
            
            # Commit changes
            conn.commit()
            print("💾 Changes committed to database")
            
            return True
        else:
            print("❌ Error: Migration verification failed")
            return False
            
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        if backup_path and os.path.exists(backup_path):
            print(f"🔄 You can restore from backup: {backup_path}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def verify_migration(db_path):
    """Verify that the migration was successful."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns exist
        cursor.execute("PRAGMA table_info(certificates)")
        columns = [row[1] for row in cursor.fetchall()]
        
        has_proxied = 'proxied' in columns
        has_proxy_info = 'proxy_info' in columns
        
        print("\n🔍 Migration Verification:")
        print(f"   proxied column: {'✅' if has_proxied else '❌'}")
        print(f"   proxy_info column: {'✅' if has_proxy_info else '❌'}")
        
        if has_proxied and has_proxy_info:
            print("✅ Migration verification successful!")
            return True
        else:
            print("❌ Migration verification failed!")
            return False
            
    except Exception as e:
        print(f"❌ Error during verification: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def main():
    """Main function to handle command line arguments and run migration."""
    parser = argparse.ArgumentParser(
        description="Migrate database to add proxy detection columns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python migrate_proxy_detection.py
  python migrate_proxy_detection.py --db-path data/certificates.db
  python migrate_proxy_detection.py --verify-only --db-path data/certificates.db
        """
    )
    
    parser.add_argument(
        '--db-path',
        type=str,
        help='Path to the SQLite database file (default: from config.yaml)'
    )
    
    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify the migration, do not perform migration'
    )
    
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip database backup (not recommended)'
    )
    
    args = parser.parse_args()
    
    # Get database path from config or command line
    if args.db_path:
        db_path = Path(args.db_path).resolve()
        print(f"ℹ️  Using database path from command line: {db_path}")
    else:
        db_path = get_database_path_from_config()
        if db_path:
            db_path = Path(db_path).resolve()
            print(f"ℹ️  Using database path from config.yaml: {db_path}")
        else:
            print("❌ Error: No database path specified and not found in config.yaml")
            print("Please specify --db-path or ensure config.yaml contains paths.database")
            sys.exit(1)
    
    print("=" * 60)
    print("🔧 Proxy Detection Database Migration Tool")
    print("=" * 60)
    print(f"Database path: {db_path}")
    print(f"Verify only: {args.verify_only}")
    print(f"Skip backup: {args.no_backup}")
    print("=" * 60)
    
    if args.verify_only:
        success = verify_migration(str(db_path))
        sys.exit(0 if success else 1)
    
    # Perform migration
    success = migrate_proxy_detection_columns(str(db_path))
    
    if success:
        print("\n" + "=" * 60)
        print("✅ Migration completed successfully!")
        print("=" * 60)
        
        # Verify migration
        print("\n🔍 Verifying migration...")
        verify_success = verify_migration(str(db_path))
        
        if verify_success:
            print("\n🎉 Your database is now ready for proxy detection!")
            print("\nNext steps:")
            print("1. Restart your application")
            print("2. The proxy detection features will now work")
            print("3. New certificates will be checked for proxy indicators")
            print("4. Existing certificates will remain unchanged")
        else:
            print("\n⚠️  Migration completed but verification failed")
            print("Please check the database manually")
            
        sys.exit(0)
    else:
        print("\n" + "=" * 60)
        print("❌ Migration failed!")
        print("=" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main()
