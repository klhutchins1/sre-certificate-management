from datetime import datetime, timedelta
import gc
import json
import os
import shutil
import tempfile
import time
from unittest.mock import patch
import pytest
from sqlalchemy import inspect
from sqlalchemy.orm import Session
from infra_mgmt.db.engine import init_database
from infra_mgmt.db.health import check_database
from .test_helpers import cleanup_temp_dir

from infra_mgmt.db.schema import reset_database
from infra_mgmt.models import Base, Certificate
# ... (add other necessary imports and fixtures)
# Paste the relevant test functions here from test_db.py 
def test_check_database():
    """Test checking database existence and initialization"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_check.db")

    try:
        # Mock the settings to return our test database path
        with patch('infra_mgmt.db.health.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Ensure the file does not exist before the first check
            if os.path.exists(db_path):
                os.remove(db_path)

            # Database should not exist initially
            if os.path.exists(db_path):
                print(f"[DEBUG] File exists before check: {db_path}")
            else:
                print(f"[DEBUG] File does not exist before check: {db_path}")
            assert check_database() is False

            # Create database
            engine = init_database(db_path)
            
            # Database should exist now
            assert check_database() is True
            
            # Cleanup
            engine.dispose()
    finally:
        shutil.rmtree(temp_dir)
def test_check_database_corrupted():
    """Test database check with corrupted database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "corrupted.db")
    
    try:
        # Create a corrupted database file
        with open(db_path, 'wb') as f:
            f.write(b'not a sqlite db')
            f.flush()
            os.fsync(f.fileno())
        print(f"[DEBUG] Corrupted file size: {os.path.getsize(db_path)}")
        with open(db_path, 'rb') as f:
            print(f"[DEBUG] Corrupted file header: {f.read(16)}")
        
        # Mock settings to return corrupted database path
        with patch('infra_mgmt.db.health.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Check should return False for corrupted database
            assert check_database() is False
    
    finally:
        cleanup_temp_dir(temp_dir)
def test_check_database_valid():
    """Test database check with valid database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "valid.db")
    
    try:
        # Create a valid database
        engine = init_database(db_path)
        engine.dispose()
        
        # Mock settings to return valid database path
        with patch('infra_mgmt.db.health.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Check should return True for valid database
            assert check_database() is True
    
    finally:
        cleanup_temp_dir(temp_dir)
def test_database_validation():
    """Test database validation and corruption handling."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    try:
        # Initialize database
        engine = init_database(db_path)
        
        # Mock settings to return our test database path
        with patch('infra_mgmt.db.health.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Add some test data
            session = Session(engine)
            cert = Certificate(
                serial_number="test123",
                thumbprint="test456",
                common_name="test.com",
                valid_from=datetime.now(),
                valid_until=datetime.now() + timedelta(days=365),
                issuer=json.dumps({"CN": "Test CA"}),
                subject=json.dumps({"CN": "test.com"}),
                san=json.dumps(["test.com"]),
                chain_valid=True,
                sans_scanned=True
            )
            session.add(cert)
            session.commit()
            session.close()
            
            # Check if database is valid
            assert check_database(), "Database should be valid after initialization"
            
            # Close engine before corrupting the database
            engine.dispose()
            
            # Corrupt the database
            with open(db_path, 'wb') as f:
                f.write(b'not a sqlite db')
                f.flush()
                os.fsync(f.fileno())
            time.sleep(0.1)
            print(f"[DEBUG] Corrupted file size: {os.path.getsize(db_path)}")
            with open(db_path, 'rb') as f:
                print(f"[DEBUG] Corrupted file header: {f.read(16)}")
            
            # Check if database is invalid
            assert not check_database(), "Database should be invalid after corruption"
            
            # Remove the corrupted database file
            os.remove(db_path)
            
            # Reset the database
            engine = init_database(db_path)
            reset_database(engine)
            
            # Check if database is valid again
            assert check_database(), "Database should be valid after reset"
            
    finally:
        # Clean up
        if 'session' in locals():
            session.close()
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_database_corruption_detection():
    """Test database corruption detection and handling."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "corruption_test.db")
    
    try:
        # Create a valid database
        engine = init_database(db_path)
        engine.dispose()
        
        # Force garbage collection and wait for file handles to be released
        gc.collect()
        time.sleep(0.1)
        
        # Corrupt the database file
        with open(db_path, 'wb') as f:
            f.write(b'not a sqlite db')
            f.flush()
            os.fsync(f.fileno())
        time.sleep(0.1)
        print(f"[DEBUG] Corrupted file size: {os.path.getsize(db_path)}")
        with open(db_path, 'rb') as f:
            print(f"[DEBUG] Corrupted file header: {f.read(16)}")
        
        # Mock settings to return our test database path
        with patch('infra_mgmt.db.health.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Verify corruption is detected
            assert not check_database()
            
            # Remove the corrupted file
            os.remove(db_path)
            
            # Force garbage collection and wait for file handles to be released
            gc.collect()
            time.sleep(0.1)
            
            # Attempt to initialize should create new database
            engine = init_database(db_path)
            assert engine is not None
            
            # Verify database is now valid
            assert check_database()
            
            # Verify tables were recreated
            with engine.connect() as conn:
                inspector = inspect(engine)
                required_tables = set(Base.metadata.tables.keys())
                existing_tables = set(inspector.get_table_names())
                assert required_tables.issubset(existing_tables)
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)
