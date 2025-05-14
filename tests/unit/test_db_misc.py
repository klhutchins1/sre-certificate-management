from datetime import datetime, timedelta
import gc
import os
import shutil
import stat
import tempfile
import time
from unittest.mock import patch
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from infra_mgmt.backup import _backup_database_file, _restore_database_file
from infra_mgmt.constants import ENV_PRODUCTION, HOST_TYPE_SERVER
from infra_mgmt.db.session import get_session
from .test_helpers import cleanup_temp_dir

from infra_mgmt.db.engine import init_database
from infra_mgmt.db.health import check_database
from infra_mgmt.db.schema import reset_database
from infra_mgmt.models import Certificate, Host
from infra_mgmt.utils.SessionManager import SessionManager
# ... (add other necessary imports and fixtures)
# Paste the relevant test functions here from test_db.py 
def test_reset_database():
    
    """Test resetting the database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_reset.db")

    try:
        engine = init_database(db_path)

        # Add some test data
        session = get_session(engine)
        # Add test data here
        session.commit()
        session.close()

        # Reset database
        assert reset_database(engine) is True

        # Verify tables are empty
        inspector = inspect(engine)
        for table_name in inspector.get_table_names():
            with engine.connect() as connection:  # Use a connection to execute the query
                result = connection.execute(text(f"SELECT COUNT(*) FROM {table_name}"))  # Use text() for SQL
                assert result.scalar() == 0  # Ensure the table is empty
    finally:
        if 'engine' in locals():
            engine.dispose()
        shutil.rmtree(temp_dir)
def test_restore_database_with_active_connections():
    """Test database restore when there are active connections"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "source.db")
    backup_dir = os.path.join(temp_dir, "backups")
    os.makedirs(backup_dir)
    
    try:
        # Create and initialize source database
        engine = init_database(db_path)
        
        # Add some initial data
        with SessionManager(engine) as session:
            host = Host(
                name="original",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
        
        # Create backup
        backup_path = _backup_database_file(engine, backup_dir)
        
        # Modify original database
        with SessionManager(engine) as session:
            host = Host(
                name="modified",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
        
        # Create an active connection
        active_session = Session(engine)
        
        try:
            # Restore should succeed even with active connection
            assert _restore_database_file(backup_path, engine) is True
            
            # Verify database was restored to original state
            with SessionManager(engine) as session:
                hosts = session.query(Host).all()
                assert len(hosts) == 1
                assert hosts[0].name == "original"
        
        finally:
            active_session.close()
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_reset_database_with_active_connections():
    """Test database reset with active connections"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_reset.db")
    
    try:
        # Create and initialize database
        engine = init_database(db_path)
        
        # Add some test data
        with SessionManager(engine) as session:
            host = Host(
                name="test-reset",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
        
        # Create an active connection
        active_session = Session(engine)
        
        try:
            # Reset should succeed even with active connection
            assert reset_database(engine) is True
            
            # Verify database was reset
            with SessionManager(engine) as session:
                assert session.query(Host).count() == 0
        
        finally:
            active_session.close()
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)


def test_database_operation_errors():
    """Test error handling in database operations."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "error_test.db")
    
    try:
        # Initialize database
        engine = init_database(db_path)
        
        # Test invalid JSON in certificate fields
        session = get_session(engine)
        assert session is not None, "Failed to create session"
        
        cert = Certificate(
            serial_number="test123",
            thumbprint="test_thumbprint",
            common_name="test.com",
            valid_from=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(days=30),
            issuer='invalid json',
            subject='invalid json',
            san='invalid json',
            chain_valid=True,
            sans_scanned=True
        )
        
        # Verify invalid JSON is handled gracefully
        session.add(cert)
        session.commit()
        
        # Verify data is stored as-is
        result = session.query(Certificate).first()
        assert result._issuer == 'invalid json'
        assert result._subject == 'invalid json'
        assert result._san == '["invalid json"]'
        
        # Test concurrent access
        session2 = get_session(engine)
        assert session2 is not None, "Failed to create second session"
        
        # Start a transaction in session2
        session2.execute(text("BEGIN IMMEDIATE"))
        session2.query(Certificate).first()
        
        # Attempt to modify in first session
        with pytest.raises(Exception) as exc_info:
            cert = session.query(Certificate).first()
            cert.common_name = 'new.com'
            session.commit()
        assert "database is locked" in str(exc_info.value).lower()
        
        # Clean up
        session2.rollback()
        session2.close()
        session.close()
        
    finally:
        # Clean up
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_database_file_permissions():
    """Test database file permission handling."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "permission_test.db")
    
    try:
        # Create database with initial permissions
        engine = init_database(db_path)
        engine.dispose()
        
        # Force garbage collection and wait for file handles to be released
        gc.collect()
        time.sleep(0.1)
        
        # Remove write permissions
        current_mode = os.stat(db_path).st_mode
        os.chmod(db_path, current_mode & ~stat.S_IWRITE)
        
        # Mock settings to return our test database path
        with patch('infra_mgmt.db.health.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Attempt to initialize should handle permission error
            with pytest.raises(Exception) as exc_info:
                init_database(db_path)
            assert "No write permission for database file" in str(exc_info.value)
            
            # Restore write permissions
            os.chmod(db_path, current_mode | stat.S_IWRITE)
            
            # Force garbage collection and wait for file handles to be released
            gc.collect()
            time.sleep(0.1)
            
            # Attempt to initialize should succeed
            engine = init_database(db_path)
            assert engine is not None
            
            # Verify database is valid
            assert check_database()
            
            # Clean up engine before final check
            engine.dispose()
            gc.collect()
            time.sleep(0.1)
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_cleanup_temp_dir_error_handling():
    """Test cleanup_temp_dir error handling"""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create some files and remove read permission from one
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test data")
        
        # Remove read permission
        current_mode = os.stat(test_file).st_mode
        os.chmod(test_file, current_mode & ~stat.S_IREAD)
        
        # Cleanup should handle permission errors gracefully
        cleanup_temp_dir(temp_dir)
        
        # Directory should still be removed despite permission error
        assert not os.path.exists(temp_dir)
    
    except Exception:
        # Restore permissions for cleanup if test fails
        if os.path.exists(test_file):
            os.chmod(test_file, current_mode | stat.S_IREAD)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

