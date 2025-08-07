#!/usr/bin/env python3
"""
Application launcher with automatic database migration.

This script automatically migrates the database to add proxy detection columns
before starting the main application.
"""

import sys
import os
import yaml
from pathlib import Path

def load_config():
    """Load configuration from config.yaml file."""
    config_path = 'config.yaml'
    if not os.path.exists(config_path):
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
        # Handle relative paths
        if not os.path.isabs(db_path):
            db_path = os.path.join(os.getcwd(), db_path)
        return db_path
    return None

def run_migration():
    """Run the database migration if needed."""
    try:
        from migrate_proxy_detection import migrate_proxy_detection_columns, verify_migration
        
        # Get database path from config
        db_path = get_database_path_from_config()
        if not db_path:
            print("❌ Error: Could not determine database path from config.yaml")
            print("Please ensure config.yaml contains paths.database")
            return False
        
        print(f"ℹ️  Using database path from config.yaml: {db_path}")
        
        # Check if database exists
        if not os.path.exists(db_path):
            print(f"ℹ️  Database not found at {db_path}, will be created by application")
            return True
        
        # Check if migration is needed
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if proxy columns already exist
        cursor.execute("PRAGMA table_info(certificates)")
        columns = [row[1] for row in cursor.fetchall()]
        conn.close()
        
        has_proxied = 'proxied' in columns
        has_proxy_info = 'proxy_info' in columns
        
        if has_proxied and has_proxy_info:
            print("✅ Database already has proxy detection columns")
            return True
        
        print("🔧 Database migration needed for proxy detection...")
        
        # Run migration
        success = migrate_proxy_detection_columns(db_path)
        
        if success:
            print("✅ Database migration completed successfully")
            return True
        else:
            print("❌ Database migration failed")
            return False
            
    except Exception as e:
        print(f"⚠️  Migration check failed: {e}")
        print("Continuing with application startup...")
        return True

def main():
    """Main function to run migration and start application."""
    print("🚀 Starting application with automatic database migration...")
    
    # Run migration
    migration_success = run_migration()
    
    if not migration_success:
        print("❌ Failed to migrate database. Please run migration manually:")
        print("   python migrate_proxy_detection.py")
        sys.exit(1)
    
    # Start the main application
    print("🎯 Starting main application...")
    
    # Import and run the main application
    try:
        from infra_mgmt.app import main as app_main
        app_main()
    except ImportError:
        # Fallback to run.py if app.py doesn't exist
        try:
            from run import main as run_main
            run_main()
        except ImportError:
            print("❌ Could not find main application entry point")
            print("Please run the application manually:")
            print("   python run.py")
            sys.exit(1)

if __name__ == "__main__":
    main()
