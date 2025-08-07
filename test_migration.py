#!/usr/bin/env python3
"""
Test script to verify proxy detection migration works correctly.
"""

import sqlite3
import tempfile
import os
import sys
from pathlib import Path

# Add the project root to the path so we can import the migration function
sys.path.insert(0, str(Path(__file__).parent))

def create_test_database():
    """Create a test database with the old schema (without proxy columns)."""
    # Create a temporary database
    temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    temp_db.close()
    
    conn = sqlite3.connect(temp_db.name)
    cursor = conn.cursor()
    
    # Create certificates table with old schema (without proxy columns)
    cursor.execute("""
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
        )
    """)
    
    # Insert some test data
    cursor.execute("""
        INSERT INTO certificates (
            serial_number, thumbprint, common_name, valid_from, valid_until,
            issuer, subject, chain_valid, created_at, updated_at
        ) VALUES (
            'test123', 'abc456', 'example.com', 
            '2024-01-01 00:00:00', '2025-01-01 00:00:00',
            '{"commonName": "Test CA"}', '{"commonName": "example.com"}',
            1, '2024-01-01 00:00:00', '2024-01-01 00:00:00'
        )
    """)
    
    conn.commit()
    conn.close()
    
    return temp_db.name

def test_migration():
    """Test the migration process."""
    print("🧪 Testing proxy detection migration...")
    
    # Create test database
    test_db_path = create_test_database()
    print(f"✅ Created test database: {test_db_path}")
    
    try:
        # Import and run migration
        from migrate_proxy_detection import migrate_proxy_detection_columns, verify_migration
        
        # Run migration
        print("\n🔧 Running migration...")
        success = migrate_proxy_detection_columns(test_db_path)
        
        if not success:
            print("❌ Migration failed!")
            return False
        
        # Verify migration
        print("\n🔍 Verifying migration...")
        verify_success = verify_migration(test_db_path)
        
        if not verify_success:
            print("❌ Verification failed!")
            return False
        
        # Test that we can query the new columns
        conn = sqlite3.connect(test_db_path)
        cursor = conn.cursor()
        
        # Check that the columns exist and have default values
        cursor.execute("SELECT proxied, proxy_info FROM certificates LIMIT 1")
        result = cursor.fetchone()
        
        if result is None:
            print("❌ No data found in certificates table!")
            return False
        
        proxied, proxy_info = result
        
        # proxied should be 0 (False) by default
        if proxied != 0:
            print(f"❌ Expected proxied=0, got {proxied}")
            return False
        
        # proxy_info should be None by default
        if proxy_info is not None:
            print(f"❌ Expected proxy_info=None, got {proxy_info}")
            return False
        
        print("✅ Default values are correct")
        
        # Test inserting a record with proxy detection data
        cursor.execute("""
            INSERT INTO certificates (
                serial_number, thumbprint, common_name, valid_from, valid_until,
                issuer, subject, chain_valid, created_at, updated_at,
                proxied, proxy_info
            ) VALUES (
                'proxy123', 'def789', 'proxy.example.com', 
                '2024-01-01 00:00:00', '2025-01-01 00:00:00',
                '{"commonName": "Corporate Proxy CA"}', '{"commonName": "proxy.example.com"}',
                1, '2024-01-01 00:00:00', '2024-01-01 00:00:00',
                1, 'Detected as proxy certificate: Matched proxy CA subject'
            )
        """)
        
        conn.commit()
        
        # Verify the new record
        cursor.execute("SELECT proxied, proxy_info FROM certificates WHERE serial_number = 'proxy123'")
        result = cursor.fetchone()
        
        if result is None:
            print("❌ Could not find inserted proxy certificate!")
            return False
        
        proxied, proxy_info = result
        
        if proxied != 1:
            print(f"❌ Expected proxied=1, got {proxied}")
            return False
        
        if not proxy_info or 'proxy certificate' not in proxy_info:
            print(f"❌ Expected proxy_info to contain 'proxy certificate', got {proxy_info}")
            return False
        
        print("✅ Proxy certificate insertion works correctly")
        
        conn.close()
        
        print("\n🎉 All migration tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        return False
    finally:
        # Clean up test database
        try:
            os.unlink(test_db_path)
            print(f"🧹 Cleaned up test database: {test_db_path}")
        except:
            pass

if __name__ == "__main__":
    success = test_migration()
    sys.exit(0 if success else 1)
