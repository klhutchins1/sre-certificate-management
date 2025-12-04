#!/usr/bin/env python3
"""
Database migration script to add proxy override fields to the Certificate model.

This migration adds the following fields to the certificates table:
- real_serial_number: Real serial number when certificate is behind proxy
- real_thumbprint: Real thumbprint when certificate is behind proxy  
- real_issuer: Real issuer information when certificate is behind proxy
- real_subject: Real subject information when certificate is behind proxy
- real_valid_from: Real valid from date when certificate is behind proxy
- real_valid_until: Real valid until date when certificate is behind proxy
- override_notes: Notes about the override
- override_created_at: When the override was created

Usage:
    python migrate_proxy_override_fields.py
"""

import sys
import os
from sqlalchemy import create_engine, text
from datetime import datetime

# Add the project root to the path (3 levels up from scripts/migrations/)
# Script is in scripts/migrations/, so go up 3 levels to reach project root
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from infra_mgmt.db.engine import get_engine
from infra_mgmt.settings import settings

def run_migration():
    """Run the migration to add proxy override fields."""
    print("Starting migration: Adding proxy override fields to certificates table...")
    
    try:
        # Get database path from settings
        db_path = settings.get('paths.database', 'data/certificates.db')
        print(f"Using database path: {db_path}")
        
        # Ensure the database file exists
        import os
        if not os.path.exists(db_path):
            print(f"Database file does not exist at: {db_path}")
            return False
        
        # Get database engine
        engine = get_engine(db_path)
        
        with engine.connect() as conn:
            # Start transaction
            trans = conn.begin()
            
            try:
                # Check if columns already exist
                result = conn.execute(text("""
                    SELECT COUNT(*) as count 
                    FROM pragma_table_info('certificates') 
                    WHERE name IN ('real_serial_number', 'real_thumbprint', 'real_issuer', 'real_subject', 
                                  'real_valid_from', 'real_valid_until', 'override_notes', 'override_created_at')
                """))
                
                existing_columns = result.fetchone()[0]
                
                if existing_columns == 8:
                    print("Migration already completed - all proxy override fields exist.")
                    trans.rollback()
                    return True
                elif existing_columns > 0:
                    print(f"Warning: {existing_columns} proxy override fields already exist. This may indicate a partial migration.")
                
                # Add the new columns
                migration_sql = """
                    ALTER TABLE certificates ADD COLUMN real_serial_number TEXT;
                    ALTER TABLE certificates ADD COLUMN real_thumbprint TEXT;
                    ALTER TABLE certificates ADD COLUMN real_issuer TEXT;
                    ALTER TABLE certificates ADD COLUMN real_subject TEXT;
                    ALTER TABLE certificates ADD COLUMN real_valid_from DATETIME;
                    ALTER TABLE certificates ADD COLUMN real_valid_until DATETIME;
                    ALTER TABLE certificates ADD COLUMN override_notes TEXT;
                    ALTER TABLE certificates ADD COLUMN override_created_at DATETIME;
                """
                
                # Execute each ALTER TABLE statement
                for statement in migration_sql.strip().split(';'):
                    if statement.strip():
                        print(f"Executing: {statement.strip()}")
                        conn.execute(text(statement))
                
                # Commit the transaction
                trans.commit()
                print("Migration completed successfully!")
                
                # Verify the migration
                result = conn.execute(text("""
                    SELECT COUNT(*) as count 
                    FROM pragma_table_info('certificates') 
                    WHERE name IN ('real_serial_number', 'real_thumbprint', 'real_issuer', 'real_subject', 
                                  'real_valid_from', 'real_valid_until', 'override_notes', 'override_created_at')
                """))
                
                column_count = result.fetchone()[0]
                if column_count == 8:
                    print("Verification successful: All 8 proxy override fields added.")
                else:
                    print(f"Warning: Expected 8 columns, found {column_count}")
                
                return True
                
            except Exception as e:
                print(f"Error during migration: {e}")
                trans.rollback()
                return False
                
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        return False

if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
