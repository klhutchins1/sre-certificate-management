from datetime import datetime, timedelta
import gc
import json
import os
import shutil
import sqlite3
import tempfile
import time
from unittest.mock import MagicMock, patch
import pytest
from infra_mgmt.backup import _backup_database_file, _restore_database_file, create_backup, restore_backup, list_backups, restore_database, backup_database
from infra_mgmt.constants import ENV_PRODUCTION, HOST_TYPE_SERVER
from infra_mgmt.db.engine import init_database
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from infra_mgmt.db.schema import reset_database
from infra_mgmt.models import Base, Certificate, Host
from infra_mgmt.utils.SessionManager import SessionManager
from .test_helpers import cleanup_temp_dir
import stat
import logging
from infra_mgmt.exceptions import DatabaseError, BackupError
# ... (add other necessary imports and fixtures)
# Paste the relevant test functions here from test_db.py 

def test_backup_and_restore_database():
    """Test database backup and restore functionality"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_backup.db")
    backup_dir = os.path.join(temp_dir, "backups")
    engine = None
    
    try:
        # Create backup directory first
        os.makedirs(backup_dir, exist_ok=True)
        
        # Create and initialize database
        engine = init_database(db_path)
        
        # Add some test data
        with Session(engine) as session:
            cert = Certificate(
                serial_number="backup_test",
                thumbprint="backup123",
                common_name="backup.com",
                valid_from=datetime.now(),
                valid_until=datetime.now(),
                issuer="Test CA",
                subject="CN=backup.com",
                san="backup.com"
            )
            session.add(cert)
            session.commit()
        
        # Create backup
        backup_path = _backup_database_file(engine, backup_dir)
        assert os.path.exists(backup_path)
        
        # Modify original database
        reset_database(engine)
        
        # Verify database is empty
        with Session(engine) as session:
            assert session.query(Certificate).count() == 0
        
        # Restore from backup
        assert _restore_database_file(backup_path, engine) is True
        
        # Verify restored data
        with Session(engine) as session:
            restored_cert = session.query(Certificate).filter_by(serial_number="backup_test").first()
            assert restored_cert is not None
            assert restored_cert.thumbprint == "backup123"
    
    finally:
        if engine:
            engine.dispose()
        Session.close_all()
        
        # Add a delay and force garbage collection
        time.sleep(0.2)
        gc.collect()
        
        if os.path.exists(temp_dir):
            for retry in range(3):
                try:
                    shutil.rmtree(temp_dir)
                    break
                except PermissionError:
                    if retry < 2:
                        time.sleep(0.5 * (retry + 1))
                    else:
                        logger.warning(f"Could not delete temporary directory after {retry + 1} attempts: {temp_dir}")


def test_backup_database_failure():
    """Test backup_database when the backup directory cannot be created"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    # Create a temporary directory and then remove it to simulate a failure
    temp_dir = tempfile.mkdtemp()
    shutil.rmtree(temp_dir)  # Remove the directory to ensure it cannot be created

    with pytest.raises(Exception) as exc_info:
        backup_database(engine, temp_dir)

    # Verify the error message without logging it
    assert "Failed to create database backup" in str(exc_info.value)

    # Cleanup
    Base.metadata.drop_all(engine)
    engine.dispose()

def test_restore_database_failure():
    """Test restore_database when the backup file does not exist"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with pytest.raises(DatabaseError) as exc_info:
        restore_database("/invalid/backup/path", engine)

    # Verify the error message without logging it
    assert "unable to open database file" in str(exc_info.value)

    # Cleanup
    Base.metadata.drop_all(engine)
    engine.dispose()

def test_backup_database_with_data():
    """Test database backup with actual data"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "source.db")
    backup_dir = os.path.join(temp_dir, "backups")
    os.makedirs(backup_dir)
    
    try:
        # Create and initialize source database
        engine = init_database(db_path)
        
        # Add some test data
        with SessionManager(engine) as session:
            host = Host(
                name="backup-test",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
        
        # Create backup
        backup_path = backup_database(engine, backup_dir)
        assert os.path.exists(backup_path)
        
        # Verify backup is a valid database
        backup_engine = create_engine(f"sqlite:///{backup_path}")
        with SessionManager(backup_engine) as session:
            hosts = session.query(Host).all()
            assert len(hosts) == 1
            assert hosts[0].name == "backup-test"
        
        backup_engine.dispose()
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_backup_database_no_permission():
    """Test backup database when backup directory has no write permission"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "source.db")
    backup_dir = os.path.join(temp_dir, "backups")
    os.makedirs(backup_dir)
    
    try:
        # Create source database
        engine = init_database(db_path)
        
        # Remove write permissions from backup directory
        current_mode = os.stat(backup_dir).st_mode
        os.chmod(backup_dir, current_mode & ~stat.S_IWRITE)
        
        # Mock os.access to simulate no write permission
        def mock_access(path, mode):
            if str(path) == str(backup_dir) and mode == os.W_OK:
                return False
            return True
        
        # Attempt backup with mocked permissions
        with patch('os.access', side_effect=mock_access):
            with pytest.raises(BackupError) as exc_info:
                backup_database(engine, backup_dir)
            assert "No write permission for backup directory" in str(exc_info.value)
    
    finally:
        # Restore permissions for cleanup
        os.chmod(backup_dir, current_mode | stat.S_IWRITE)
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_backup_restore_complex_scenarios():
    """Test backup and restore operations with complex scenarios."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "backup_test.db")
    backup_dir = os.path.join(temp_dir, "backups")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        
        # Add some test data
        with Session(engine) as session:
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
        
        # Test backup with non-existent directory
        nonexistent_dir = os.path.join(temp_dir, "nonexistent")
        backup_path = backup_database(engine, nonexistent_dir)
        assert os.path.exists(backup_path)
        
        # Test backup with unwritable directory
        if os.name != 'nt':  # Skip on Windows
            os.chmod(backup_dir, 0o444)  # Read-only
            with pytest.raises(Exception) as exc_info:
                backup_database(engine, backup_dir)
            assert "No write permission" in str(exc_info.value)
            os.chmod(backup_dir, 0o777)  # Restore permissions
        
        # Test restore with locked database
        with sqlite3.connect(db_path) as conn:
            conn.execute("BEGIN EXCLUSIVE")
            with pytest.raises(DatabaseError) as exc_info:
                restore_database(backup_path, engine)
            assert "database is locked" in str(exc_info.value).lower()
        
        # Test restore with invalid backup file
        with open(backup_path, 'w') as f:
            f.write("invalid data")
        with pytest.raises(DatabaseError) as exc_info:
            restore_database(backup_path, engine)
        assert "file is not a database" in str(exc_info.value)
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_backup_restore_edge_cases():
    """Test backup and restore operations with edge cases."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "backup_test.db")
    backup_dir = os.path.join(temp_dir, "backups")

    try:
        # Create initial database
        engine = init_database(db_path)

        # Test backup with non-existent source
        with patch('os.path.exists', return_value=False):
            with pytest.raises(BackupError) as exc_info:
                backup_database(engine, backup_dir)
            assert "Source database does not exist" in str(exc_info.value)

        # Test backup with unwritable directory
        if os.name != 'nt':  # Skip on Windows
            os.makedirs(backup_dir)
            os.chmod(backup_dir, 0o444)  # Read-only
            with pytest.raises(Exception) as exc_info:
                backup_database(engine, backup_dir)
            assert "No write permission" in str(exc_info.value)
            os.chmod(backup_dir, 0o777)  # Restore permissions

        # Test backup with file creation error
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with pytest.raises(Exception) as exc_info:
                backup_database(engine, backup_dir)
            assert "Failed to create backup file" in str(exc_info.value)

        # Test restore with non-existent backup
        with pytest.raises(DatabaseError) as exc_info:
            restore_database("nonexistent.db", engine)
        assert "unable to open database file" in str(exc_info.value)

        # Test restore with invalid backup
        invalid_backup = os.path.join(backup_dir, "invalid.db")
        with open(invalid_backup, 'w') as f:
            f.write("invalid data")

        with pytest.raises(DatabaseError) as exc_info:
            restore_database(invalid_backup, engine)
        assert "file is not a database" in str(exc_info.value)

        # Test restore with locked database
        with patch('sqlite3.connect') as mock_connect:
            mock_connect.side_effect = sqlite3.OperationalError("database is locked")
            with pytest.raises(DatabaseError) as exc_info:
                restore_database(invalid_backup, engine)
            assert "Database is locked" in str(exc_info.value)

    finally:
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to clean up temporary directory {temp_dir}: {e}")

def test_backup_database_verification_error():
    """Test backup_database with verification error."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    backup_dir = os.path.join(temp_dir, "backups")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        
        # Mock create_engine to raise error during verification
        mock_engine = MagicMock()
        mock_connection = MagicMock()
        mock_connection.__enter__.return_value = mock_connection
        mock_connection.__exit__.return_value = None
        mock_engine.connect.return_value = mock_connection
        mock_connection.execute.side_effect = Exception("Verification error")
        
        # Patch the correct create_engine used in backup.py
        with patch('infra_mgmt.backup.create_engine', return_value=mock_engine):
            with patch('os.path.exists', return_value=True):
                with patch('os.access', return_value=True):
                    with patch('shutil.copy2'):
                        with pytest.raises(BackupError) as exc_info:
                            backup_database(engine, backup_dir)
                        assert "Failed to verify backup" in str(exc_info.value)
        
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_database_backup_with_large_data():
    """Test database backup with large amounts of data"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "large_data.db")
    backup_dir = os.path.join(temp_dir, "backups")
    os.makedirs(backup_dir)
    
    try:
        engine = init_database(db_path)
        
        # Add large amount of test data
        with SessionManager(engine) as session:
            for i in range(1000):
                host = Host(
                    name=f"host-{i}",
                    host_type=HOST_TYPE_SERVER,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                session.add(host)
            session.commit()
        
        # Create backup
        backup_path = backup_database(engine, backup_dir)
        assert os.path.exists(backup_path)
        
        # Verify backup integrity
        backup_engine = create_engine(f"sqlite:///{backup_path}")
        with SessionManager(backup_engine) as session:
            count = session.query(Host).count()
            assert count == 1000
        
        backup_engine.dispose()
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)
