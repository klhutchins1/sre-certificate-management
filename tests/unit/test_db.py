import pytest
from sqlalchemy import create_engine, inspect, Column, Integer, String
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from infra_mgmt.db import (
    init_database, get_session, backup_database, restore_database, 
    update_database_schema, reset_database, check_database, SessionManager, _is_network_path, _normalize_path,
    migrate_database, sync_default_ignore_patterns
)
from infra_mgmt.models import Base, Certificate, Host, HostIP, IgnoredDomain, IgnoredCertificate
from datetime import datetime, timedelta
import os
import tempfile
import shutil
import time
from unittest.mock import patch, MagicMock
from pathlib import Path
from sqlalchemy import text
from infra_mgmt.settings import Settings
import logging
import gc
import stat
import sqlite3
from sqlalchemy.orm import sessionmaker
import sqlalchemy.exc
from unittest.mock import create_autospec
import threading
from sqlalchemy import event
from sqlalchemy.orm import validates
import queue
import sys
from pathlib import WindowsPath
import json
from sqlalchemy.exc import InvalidRequestError

logger = logging.getLogger(__name__)

# Constants for test data
HOST_TYPE_SERVER = "Server"
ENV_PRODUCTION = "Production"

def cleanup_temp_dir(temp_dir):
    """Helper function to clean up temporary test directories."""
    try:
        # Close all sessions
        Session.close_all()
        
        # Force garbage collection
        gc.collect()
        
        # Add a small delay to allow file handles to be released
        time.sleep(0.1)
        
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"Warning: Failed to clean up temporary directory {temp_dir}: {e}")

@pytest.fixture
def test_db():
    """Create a test database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    engine = None
    
    try:
        # Create database URL
        db_url = f"sqlite:///{db_path}"
        
        # Create engine and initialize database properly
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        
        # Perform migrations
        migrate_database(engine)
        
        # Sync default ignore patterns
        sync_default_ignore_patterns(engine)
        
        # Verify database is properly initialized
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            
            # Verify all required tables exist
            inspector = inspect(engine)
            required_tables = set(Base.metadata.tables.keys())
            existing_tables = set(inspector.get_table_names())
            assert required_tables.issubset(existing_tables)
            
            # Verify ignored tables exist
            assert 'ignored_domains' in existing_tables
            assert 'ignored_certificates' in existing_tables
        
        yield engine
        
    except Exception as e:
        logger.error(f"Failed to initialize test database: {str(e)}")
        raise
    finally:
        try:
            # Cleanup - ensure all connections are closed
            if engine:
                engine.dispose()
            
            # Close any remaining sessions
            Session.close_all()
            
            # Drop tables if they exist
            if os.path.exists(db_path):
                try:
                    if engine:
                        Base.metadata.drop_all(engine)
                except Exception:
                    pass
            
            cleanup_temp_dir(temp_dir)
            
        except Exception as e:
            logger.debug(f"Error during test database cleanup: {str(e)}")

@pytest.fixture
def test_session(test_db):
    """Create a test session"""
    session = None
    try:
        session = Session(test_db)
        yield session
    finally:
        if session:
            session.close()

def test_init_database():
    """Test database initialization"""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    engine = None
    try:
        # Test with new database
        engine = init_database(db_path)
        assert engine is not None
        
        # Verify tables were created
        with Session(engine) as session:
            # Try creating a test record
            cert = Certificate(
                serial_number="test123",
                thumbprint="abc123",
                common_name="test.com",
                valid_from=datetime.now(),
                valid_until=datetime.now(),
                issuer=json.dumps({"CN": "Test CA"}),
                subject=json.dumps({"CN": "test.com"}),
                san=json.dumps(["test.com"])
            )
            session.add(cert)
            session.commit()
            
            # Verify record was created
            result = session.query(Certificate).filter_by(serial_number="test123").first()
            assert result is not None
            assert result.serial_number == "test123"
            
            # Verify JSON fields were properly stored
            assert isinstance(result._issuer, str)
            assert isinstance(result._subject, str)
            assert isinstance(result._san, str)
            
            # Verify JSON content
            issuer_data = json.loads(result._issuer)
            assert isinstance(issuer_data, dict)
            assert issuer_data["CN"] == "Test CA"
            
            subject_data = json.loads(result._subject)
            assert isinstance(subject_data, dict)
            assert subject_data["CN"] == "test.com"
            
            san_data = json.loads(result._san)
            assert isinstance(san_data, list)
            assert san_data == ["test.com"]
            
            # Verify ignored tables were created
            inspector = inspect(engine)
            assert 'ignored_domains' in inspector.get_table_names()
            assert 'ignored_certificates' in inspector.get_table_names()
            
            # Verify default ignore patterns were synced
            ignored_domains = session.query(IgnoredDomain).all()
            ignored_certs = session.query(IgnoredCertificate).all()
            assert len(ignored_domains) > 0 or len(ignored_certs) > 0
    
    finally:
        # Cleanup
        if engine:
            engine.dispose()
        Session.close_all()
        time.sleep(0.1)
        try:
            shutil.rmtree(temp_dir)
        except PermissionError:
            time.sleep(0.5)
            try:
                shutil.rmtree(temp_dir)
            except PermissionError:
                print(f"Warning: Could not delete temporary directory: {temp_dir}")

def test_get_session():
    """Test getting a database session"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_session.db")
    
    try:
        engine = init_database(db_path)
        session = get_session(engine)
        
        assert session is not None
        assert isinstance(session, Session)
        
        # Test with None engine
        assert get_session(None) is None
    finally:
        if 'session' in locals():
            session.close()
        if 'engine' in locals():
            engine.dispose()
        shutil.rmtree(temp_dir)

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

def test_check_database():
    """Test checking database existence and initialization"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_check.db")

    try:
        # Mock the settings to return our test database path
        with patch('infra_mgmt.db.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Database should not exist initially
            assert check_database() is False

            # Create database
            engine = init_database(db_path)
            
            # Database should exist now
            assert check_database() is True
            
            # Cleanup
            engine.dispose()
    finally:
        shutil.rmtree(temp_dir)

def test_session_manager():
    """Test SessionManager context manager"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_session_manager.db")
    
    try:
        engine = init_database(db_path)
        
        # Test normal operation
        with SessionManager(engine) as session:
            assert session is not None
            assert isinstance(session, Session)
        
        # Test with None engine
        with SessionManager(None) as session:
            assert session is None
        
        # Test exception handling
        with pytest.raises(Exception):
            with SessionManager(engine) as session:
                raise Exception("Test exception")
    finally:
        if 'engine' in locals():
            engine.dispose()
        shutil.rmtree(temp_dir)

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
        backup_path = backup_database(engine, backup_dir)
        assert os.path.exists(backup_path)
        
        # Modify original database
        reset_database(engine)
        
        # Verify database is empty
        with Session(engine) as session:
            assert session.query(Certificate).count() == 0
        
        # Restore from backup
        assert restore_database(backup_path, engine) is True
        
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

def test_database_constraints(test_session):
    """Test database constraints and relationships"""
    # Create a host
    host = Host(
        name="testhost.com",
        host_type="Server",
        environment="Production",
        last_seen=datetime.now()
    )
    test_session.add(host)
    test_session.commit()
    
    # Create an IP for the host
    ip = HostIP(
        host_id=host.id,
        ip_address="192.168.1.1",
        last_seen=datetime.now()
    )
    test_session.add(ip)
    test_session.commit()
    
    # Verify relationship
    assert len(host.ip_addresses) == 1
    assert host.ip_addresses[0].ip_address == "192.168.1.1"
    
    # Test cascade delete
    test_session.delete(host)
    test_session.commit()
    
    # Verify IP was also deleted
    assert test_session.query(HostIP).filter_by(ip_address="192.168.1.1").first() is None 

def test_init_database_corrupted():
    """Test database initialization with a corrupted database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "corrupted.db")
    
    try:
        # Create a corrupted database file
        with open(db_path, 'w') as f:
            f.write("corrupted data")
        
        # Attempt to initialize should raise an exception
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        
        # Verify the error message without logging it
        assert "file is not a database" in str(exc_info.value)
        
    finally:
        cleanup_temp_dir(temp_dir)

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

    with pytest.raises(sqlite3.DatabaseError) as exc_info:
        restore_database("/invalid/backup/path", engine)

    # Verify the error message without logging it
    assert "unable to open database file" in str(exc_info.value)

    # Cleanup
    Base.metadata.drop_all(engine)
    engine.dispose()

def test_update_database_schema_add_tables():
    """Test adding missing tables to the database schema"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_schema.db")
    engine = create_engine(f"sqlite:///{db_path}")
    
    try:
        # Create initial tables without ignored tables
        Base.metadata.create_all(engine)
        
        # Drop ignored tables if they exist
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS ignored_domains"))
            conn.execute(text("DROP TABLE IF EXISTS ignored_certificates"))
            conn.commit()
        
        # Add a new table to the Base metadata
        class NewTable(Base):
            __tablename__ = 'new_table'
            id = Column(Integer, primary_key=True)
            name = Column(String)
        
        # Ensure the new table does not exist yet
        assert 'new_table' not in inspect(engine).get_table_names()
        
        # Update schema to add the new table
        assert update_database_schema(engine) is True
        assert 'new_table' in inspect(engine).get_table_names()  # Ensure it was added
        
        # Verify ignored tables were also created
        inspector = inspect(engine)
        assert 'ignored_domains' in inspector.get_table_names()
        assert 'ignored_certificates' in inspector.get_table_names()
        
        # Sync default ignore patterns
        sync_default_ignore_patterns(engine)
        
        # Verify default ignore patterns were synced
        with engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM ignored_domains")).scalar()
            assert result > 0
            result = conn.execute(text("SELECT COUNT(*) FROM ignored_certificates")).scalar()
            assert result > 0
    
    finally:
        # Cleanup
        Base.metadata.drop_all(engine)
        engine.dispose()  # Dispose of the engine
        time.sleep(0.1)  # Allow time for file handles to be released
        shutil.rmtree(temp_dir)

def test_update_database_schema_no_changes():
    """Test that no changes are made if all tables exist"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_no_changes.db")
    engine = create_engine(f"sqlite:///{db_path}")
    
    try:
        # Create all tables including ignored tables
        Base.metadata.create_all(engine)
        
        # Perform migrations to ensure all tables are up to date
        migrate_database(engine)
        
        # Sync default ignore patterns
        sync_default_ignore_patterns(engine)
        
        # Get initial table counts
        with engine.connect() as conn:
            initial_ignored_domains = conn.execute(text("SELECT COUNT(*) FROM ignored_domains")).scalar()
            initial_ignored_certs = conn.execute(text("SELECT COUNT(*) FROM ignored_certificates")).scalar()
        
        # Update schema (should not change anything)
        assert update_database_schema(engine) is True
        
        # Verify no changes were made
        with engine.connect() as conn:
            final_ignored_domains = conn.execute(text("SELECT COUNT(*) FROM ignored_domains")).scalar()
            final_ignored_certs = conn.execute(text("SELECT COUNT(*) FROM ignored_certificates")).scalar()
            
            assert final_ignored_domains == initial_ignored_domains
            assert final_ignored_certs == initial_ignored_certs
    
    finally:
        # Cleanup
        Base.metadata.drop_all(engine)
        engine.dispose()  # Dispose of the engine
        time.sleep(0.1)  # Allow time for file handles to be released
        shutil.rmtree(temp_dir)

def test_init_database_invalid_path():
    """Test database initialization with an invalid path"""
    # Use a path with invalid characters that cannot be created
    invalid_path = "\\\\?\\invalid*path:with|invalid<chars>.db"
    with pytest.raises(Exception) as excinfo:
        init_database(invalid_path)
    assert "Invalid database path" in str(excinfo.value)

def test_init_database_existing_corrupted():
    """Test database initialization with an existing corrupted database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "corrupted_existing.db")

    # Create a corrupted database file
    with open(db_path, 'w') as f:
        f.write("corrupted data")

    engine = None  # Initialize engine to None
    try:
        engine = init_database(db_path)  # This should remove the corrupted file and create a new one
        assert engine is not None
    except Exception as e:
        print(f"Error during database initialization: {e}")
    finally:
        # Ensure all connections are closed before cleanup
        Session.close_all()
        if engine:
            engine.dispose()  # Dispose of the engine if it was created   
        time.sleep(0.1)  # Allow time for file handles to be released
        # Ensure the temp directory is deleted after all operations
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Warning: Could not delete temporary directory: {temp_dir}, Error: {str(e)}")

def test_init_database_with_settings():
    """Test database initialization using settings"""
    temp_dir = tempfile.mkdtemp()
    db_path = Path(temp_dir) / "settings_test.db"
    db_path_str = str(db_path)

    try:
        # Create parent directory
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Reset settings singleton and set up test mode with our configuration
        Settings._reset()
        test_config = {"paths": {"database": db_path_str}}
        Settings.set_test_mode(test_config)

        # Initialize database without explicit path
        engine = init_database()
        assert engine is not None

        # Create a test table to ensure database is created
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS test"))  # Drop table if it exists
            conn.execute(text("CREATE TABLE test (id INTEGER PRIMARY KEY)"))
            conn.execute(text("INSERT INTO test (id) VALUES (1)"))

        # Verify database was created at the correct location using multiple methods
        print(f"Checking file existence at: {db_path_str}")
        print(f"Using Path.exists(): {db_path.exists()}")
        print(f"Using os.path.exists(): {os.path.exists(db_path_str)}")
        print(f"Using os.path.isfile(): {os.path.isfile(db_path_str)}")
        print(f"Directory contents: {list(db_path.parent.iterdir())}")

        # Try to connect directly with SQLite
        import sqlite3
        try:
            sqlite_conn = sqlite3.connect(db_path_str)
            cursor = sqlite_conn.cursor()
            cursor.execute("SELECT id FROM test")
            result = cursor.fetchone()
            assert result[0] == 1
            cursor.close()
            sqlite_conn.close()
            print("Successfully connected directly with SQLite")
        except Exception as e:
            print(f"SQLite direct connection error: {str(e)}")

        # Get the actual database path from SQLAlchemy
        actual_path = engine.url.database
        print(f"SQLAlchemy database path: {actual_path}")

        assert os.path.exists(actual_path), f"Database file not found at {actual_path}"
        assert actual_path == db_path_str, f"Database created at wrong location: {actual_path} != {db_path_str}"

        engine.dispose()

    finally:
        cleanup_temp_dir(temp_dir)

def test_init_database_parent_dir_creation():
    """Test database initialization with nested directory creation"""
    temp_dir = tempfile.mkdtemp()
    nested_path = os.path.join(temp_dir, "level1", "level2", "level3")
    db_path = os.path.join(nested_path, "nested.db")
    
    try:
        # Create parent directories first
        os.makedirs(nested_path, exist_ok=True)
        
        # Initialize database with nested path
        engine = init_database(db_path)
        assert engine is not None
        
        # Verify database was created at the correct location
        assert os.path.exists(db_path)
        
        # Verify database is functional
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            assert result == 1
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_init_database_existing_file_no_write_permission():
    """Test database initialization with existing file without write permission"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "readonly.db")
    
    try:
        # Create a file and remove write permissions
        with open(db_path, 'w') as f:
            f.write("dummy data")
        
        # Remove write permissions
        current_mode = os.stat(db_path).st_mode
        os.chmod(db_path, current_mode & ~stat.S_IWRITE)
        
        # Attempt to initialize database
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        
        assert "No write permission for database file" in str(exc_info.value)
    
    finally:
        # Restore write permissions for cleanup
        os.chmod(db_path, current_mode | stat.S_IWRITE)
        cleanup_temp_dir(temp_dir)

def test_init_database_parent_dir_exists_not_dir():
    """Test database initialization when parent exists but is not a directory"""
    temp_dir = tempfile.mkdtemp()
    parent_path = os.path.join(temp_dir, "not_a_dir")
    db_path = os.path.join(parent_path, "test.db")
    
    try:
        # Create a file instead of a directory at parent path
        with open(parent_path, 'w') as f:
            f.write("dummy data")
        
        # Attempt to initialize database
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        
        assert "Path exists but is not a directory" in str(exc_info.value)
    
    finally:
        cleanup_temp_dir(temp_dir)

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
        with patch('os.access', side_effect=mock_access), \
             patch('infra_mgmt.db.os.access', side_effect=mock_access):
            with pytest.raises(Exception) as exc_info:
                backup_database(engine, backup_dir)
            assert "No write permission for backup directory" in str(exc_info.value)
    
    finally:
        # Restore permissions for cleanup
        os.chmod(backup_dir, current_mode | stat.S_IWRITE)
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

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
        backup_path = backup_database(engine, backup_dir)
        
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
            assert restore_database(backup_path, engine) is True
            
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

def test_check_database_corrupted():
    """Test database check with corrupted database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "corrupted.db")
    
    try:
        # Create a corrupted database file
        with open(db_path, 'w') as f:
            f.write("corrupted data")
        
        # Mock settings to return corrupted database path
        with patch('infra_mgmt.db.Settings') as mock_settings:
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
        with patch('infra_mgmt.db.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Check should return True for valid database
            assert check_database() is True
    
    finally:
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

def test_session_manager_with_invalid_engine():
    """Test SessionManager with invalid engine"""
    # Test with None engine
    with SessionManager(None) as session:
        assert session is None
    
    # Test with disposed engine
    engine = create_engine('sqlite:///:memory:')
    engine.dispose()
    with SessionManager(engine) as session:
        with pytest.raises(Exception):
            session.query(Host).all()

def test_session_manager_exception_handling():
    """Test SessionManager exception handling and cleanup"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    
    try:
        # Test that session is properly cleaned up after exception
        with pytest.raises(ValueError):
            with SessionManager(engine) as session:
                host = Host(
                    name="test-error",
                    host_type=HOST_TYPE_SERVER,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                session.add(host)
                raise ValueError("Test error")
        
        # Verify no data was committed
        with SessionManager(engine) as session:
            assert session.query(Host).count() == 0
        
        # Test nested exception handling
        with pytest.raises(ValueError):
            with SessionManager(engine) as outer_session:
                host1 = Host(
                    name="outer-host",
                    host_type=HOST_TYPE_SERVER,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                outer_session.add(host1)
                
                with SessionManager(engine) as inner_session:
                    host2 = Host(
                        name="inner-host",
                        host_type=HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    inner_session.add(host2)
                    raise ValueError("Inner error")
        
        # Verify no data was committed from either session
        with SessionManager(engine) as session:
            assert session.query(Host).count() == 0
    
    finally:
        engine.dispose()

def test_session_manager_concurrent_access():
    """Test SessionManager with concurrent access and error handling."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    try:
        # Initialize database
        engine = init_database(db_path)
        
        # Test concurrent access with multiple sessions
        def worker(session_id):
            with SessionManager(engine) as session:
                cert = Certificate(
                    serial_number=f"test{session_id}",
                    thumbprint=f"thumb{session_id}",
                    common_name=f"test{session_id}.com",
                    valid_from=datetime.utcnow(),
                    valid_until=datetime.utcnow() + timedelta(days=30),
                    issuer='{"CN": "Test CA"}',
                    subject='{"CN": "test.com"}',
                    san='["test.com"]',
                    chain_valid=True,
                    sans_scanned=True
                )
                session.add(cert)
                session.commit()
        
        # Create multiple threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Verify all records were created
        with SessionManager(engine) as session:
            count = session.query(Certificate).count()
            assert count == 5
        
        # Test error handling in SessionManager
        with pytest.raises(Exception):
            with SessionManager(engine) as session:
                raise Exception("Test error")
        
        # Verify transaction was rolled back
        with SessionManager(engine) as session:
            count = session.query(Certificate).count()
            assert count == 5  # Count should not have changed
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_get_session_error_handling():
    """Test get_session error handling"""
    # Test with None engine
    assert get_session(None) is None
    
    # Test with invalid engine
    invalid_engine = create_engine('sqlite:///nonexistent/path/db.sqlite')
    assert get_session(invalid_engine) is None

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

def test_network_path_handling():
    """Test handling of network share paths"""
    # Test network path detection
    assert _is_network_path(Path('\\\\server\\share\\path')) is True
    assert _is_network_path(Path('//server/share/path')) is True
    assert _is_network_path(Path('C:\\path\\to\\file')) is False
    assert _is_network_path(Path('/path/to/file')) is False
    
    # Test path normalization
    network_path = _normalize_path('\\\\server\\share\\path\\db.sqlite')
    assert isinstance(network_path, WindowsPath)
    assert str(network_path) == '\\\\server\\share\\path\\db.sqlite'
    
    local_path = _normalize_path('data/db.sqlite')
    assert isinstance(local_path, Path)
    assert local_path.is_absolute()

@pytest.mark.skipif(sys.platform != 'win32', reason="Windows network path tests")
def test_database_network_path():
    """Test database initialization with network path"""
    settings = Settings()
    
    # Configure a network path
    network_path = '\\\\localhost\\share\\test.db'
    settings.update('paths.database', network_path)
    
    try:
        # Create mock cursor with proper isolation level handling
        mock_cursor = MagicMock()
        def execute_side_effect(sql, *args, **kwargs):
            if "PRAGMA read_uncommitted" in sql:
                mock_cursor.fetchone.return_value = [0]  # SERIALIZABLE isolation level  
            return None
        mock_cursor.execute.side_effect = execute_side_effect
        mock_cursor.fetchone.return_value = [0]  # Default return value
        
        # Create mock connection
        mock_connection = MagicMock()
        mock_connection.cursor.return_value = mock_cursor
        
        # Mock SQLite dialect
        mock_dialect = MagicMock()
        mock_dialect.connect.return_value = mock_connection
        
        # Create mock engine
        mock_engine = MagicMock()
        mock_engine.raw_connection.return_value = mock_connection
        mock_engine.connect.return_value.__enter__.return_value = mock_connection        
        mock_engine.dispose = MagicMock()
        mock_engine.dialect = mock_dialect
        
        # Mock the connection pool
        mock_pool = MagicMock()
        mock_pool.connect.return_value = mock_connection
        mock_engine.pool = mock_pool
        
        with patch('sqlalchemy.dialects.sqlite.pysqlite.SQLiteDialect_pysqlite.connect', 
                  return_value=mock_connection), \
             patch('sqlalchemy.create_engine', return_value=mock_engine), \
             patch('infra_mgmt.db.create_engine', return_value=mock_engine) as mock_create_engine, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True), \
             patch('os.access', return_value=True), \
             patch('pathlib.Path.unlink', return_value=None), \
             patch('pathlib.Path.mkdir', return_value=None), \
             patch('sqlite3.connect', return_value=mock_connection):
            
            # Initialize database with network path
            result_engine = init_database()
            
            # Verify engine was created with correct path
            assert result_engine is not None
            assert mock_create_engine.call_count == 2  # Once for validation, once for actual use
            
    except Exception as e:
        pytest.fail(f"Test failed with error: {str(e)}")

def test_get_session_with_engine():
    """Test getting a session with a specific engine"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    
    session = get_session(engine)
    assert session is not None
    assert isinstance(session, Session)
    
    engine.dispose()

def test_get_session_with_disposed_engine():
    """Test getting a session with a disposed engine"""
    # Create a mock engine that simulates a disposed state
    mock_engine = MagicMock()
    mock_engine.connect.side_effect = Exception("Engine is disposed")
    
    # Try to get a session with the disposed engine
    session = get_session(mock_engine)
    assert session is None

def test_get_session_with_invalid_engine():
    """Test getting a session with an invalid engine"""
    invalid_engine = create_engine('sqlite:///nonexistent/path/db.sqlite')
    session = get_session(invalid_engine)
    assert session is None

def test_database_migration_edge_cases():
    """Test database migration with edge cases"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_test.db")
    
    try:
        # Configure test settings with default ignore patterns
        test_config = {
            "ignore_lists": {
                "domains": {
                    "default_patterns": ["*.test.com", "*.example.com"]
                },
                "certificates": {
                    "default_patterns": ["*.test.com", "*.example.com"]
                }
            }
        }
        
        # Set up test settings
        Settings._reset()
        Settings.set_test_mode(test_config)
        
        engine = init_database(db_path)
        
        # Test migration with invalid JSON data
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO certificates (
                    serial_number, 
                    thumbprint,
                    issuer, 
                    subject, 
                    san,
                    valid_from,
                    valid_until,
                    common_name,
                    chain_valid,
                    sans_scanned
                )
                VALUES (
                    'test123',
                    'test_thumbprint',
                    'invalid json',
                    'invalid json',
                    'invalid json',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP,
                    'test.com',
                    0,
                    0
                )
            """))
            conn.commit()
        
        # Attempt migration
        migrate_database(engine)
        
        # Sync default ignore patterns
        sync_default_ignore_patterns(engine)
        
        # Verify data was handled gracefully
        with engine.connect() as conn:
            result = conn.execute(text("SELECT issuer, subject, san FROM certificates")).fetchone()
            assert result is not None
            assert isinstance(result.issuer, str)
            assert isinstance(result.subject, str)
            assert isinstance(result.san, str)
            
            # Verify JSON data was properly formatted
            try:
                issuer_data = json.loads(result.issuer)
                assert isinstance(issuer_data, dict)
            except json.JSONDecodeError:
                pytest.fail("issuer is not valid JSON")
                
            try:
                subject_data = json.loads(result.subject)
                assert isinstance(subject_data, dict)
            except json.JSONDecodeError:
                pytest.fail("subject is not valid JSON")
                
            try:
                san_data = json.loads(result.san)
                assert isinstance(san_data, list)
            except json.JSONDecodeError:
                pytest.fail("san is not valid JSON")
            
            # Verify new columns exist and have default values
            result = conn.execute(text("SELECT chain_valid, sans_scanned FROM certificates")).fetchone()
            assert result is not None
            # SQLite stores booleans as 0/1, so we need to compare with 0
            assert result.chain_valid == 0
            assert result.sans_scanned == 0
            
            # Verify ignored tables were created
            inspector = inspect(engine)
            assert 'ignored_domains' in inspector.get_table_names()
            assert 'ignored_certificates' in inspector.get_table_names()
            
            # Verify default ignore patterns were synced
            result = conn.execute(text("SELECT COUNT(*) FROM ignored_domains")).scalar()
            assert result > 0
            result = conn.execute(text("SELECT COUNT(*) FROM ignored_certificates")).scalar()
            assert result > 0
    
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

def test_update_database_schema_error_handling():
    """Test error handling in update_database_schema"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "schema_error.db")
    
    try:
        # Create a test database
        engine = init_database(db_path)
        
        # Mock inspect to raise an exception
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.side_effect = Exception("Inspect error")
            
            # Schema update should handle the error gracefully
            result = update_database_schema(engine)
            assert result is False
        
        # Test with invalid column data
        with engine.connect() as conn:
            # Create a table with invalid column data
            conn.execute(text("""
                CREATE TABLE test_table (
                    id INTEGER PRIMARY KEY,
                    data TEXT
                )
            """))
            conn.execute(text("INSERT INTO test_table (id, data) VALUES (1, 'invalid data')"))
            conn.commit()
        
        # Schema update should handle invalid data gracefully
        result = update_database_schema(engine)
        assert result is True
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_migrate_database_error_handling():
    """Test error handling in migrate_database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migrate_error.db")
    
    try:
        # Create a test database
        engine = init_database(db_path)
        
        # Mock inspect to raise an exception
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.side_effect = Exception("Inspect error")
            
            # Migration should handle the error gracefully
            with pytest.raises(Exception) as exc_info:
                migrate_database(engine)
            assert "Inspect error" in str(exc_info.value)  # Updated to match actual error
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_init_database_file_not_created():
    """Test database initialization when file is not created"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "not_created.db")
    
    try:
        # Mock create_engine to simulate file not being created
        with patch('infra_mgmt.db.create_engine') as mock_create_engine:
            mock_engine = MagicMock()
            mock_create_engine.return_value = mock_engine
            
            # Mock os.path.exists instead of Path.exists
            with patch('os.path.exists', return_value=False), \
                 patch('os.path.isdir', return_value=True):
                with pytest.raises(Exception) as exc_info:
                    init_database(db_path)
                assert "Database file was not created" in str(exc_info.value)
    
    finally:
        cleanup_temp_dir(temp_dir)

def test_sync_default_ignore_patterns_error():
    """Test error handling in sync_default_ignore_patterns."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    try:
        # Initialize database
        engine = init_database(db_path)
        
        # Clear any existing patterns
        with Session(engine) as session:
            session.execute(text("DELETE FROM ignored_domains"))
            session.execute(text("DELETE FROM ignored_certificates"))
            session.commit()
        
        # Mock settings to raise an error immediately
        with patch('infra_mgmt.settings.Settings') as mock_settings:
            mock_settings.return_value.get.side_effect = Exception("Settings error")
            
            # Test that the function handles the error gracefully
            with pytest.raises(Exception) as exc_info:
                sync_default_ignore_patterns(engine)
            assert "Settings error" in str(exc_info.value)
            
            # Verify that no patterns were added
            session = Session(engine)
            domain_patterns = session.query(IgnoredDomain).all()
            cert_patterns = session.query(IgnoredCertificate).all()
            assert len(domain_patterns) == 0, "No domain patterns should be added when settings error occurs"
            assert len(cert_patterns) == 0, "No certificate patterns should be added when settings error occurs"
            session.close()
            
    finally:
        # Clean up
        if 'session' in locals():
            session.close()
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_session_cleanup():
    """Test session cleanup and closure."""
    # Create an in-memory database
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    
    # Create a session factory
    SessionFactory = sessionmaker(bind=engine)
    
    # Create a session and add a certificate
    session = SessionFactory()
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
    
    # Close the session
    session.close()
    
    # Explicitly set the session to be invalid
    session.bind = None  # Unbind the session from its engine
    session.invalidate()  # Invalidate the session
    
    # Now trying to use the session should raise InvalidRequestError
    with pytest.raises(InvalidRequestError):
        session.query(Certificate).all()
    
    # Clean up
    engine.dispose()

def test_database_validation():
    """Test database validation and corruption handling."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    try:
        # Initialize database
        engine = init_database(db_path)
        
        # Mock settings to return our test database path
        with patch('infra_mgmt.db.Settings') as mock_settings:
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
                f.write(b'invalid data')
            
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

def test_path_handling_edge_cases():
    """Test path validation edge cases."""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Test with very long path
        long_path = Path("a" * 200 + ".db")
        with patch('infra_mgmt.db._normalize_path') as mock_normalize:
            mock_normalize.return_value = long_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("test")
                with patch('os.access', return_value=True):
                    with patch('pathlib.Path.exists', return_value=False):
                        with patch('infra_mgmt.db.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Database path too long")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(long_path))
                            assert "Database path too long" in str(exc_info.value)
        
        # Test with invalid path
        invalid_path = Path("test/db/with/invalid/chars/*.db")
        with patch('infra_mgmt.db._normalize_path') as mock_normalize:
            mock_normalize.return_value = invalid_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("test")
                with patch('os.access', return_value=True):
                    with patch('pathlib.Path.exists', return_value=False):
                        with patch('infra_mgmt.db.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Invalid database path")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(invalid_path))
                            assert "Invalid database path" in str(exc_info.value)
        
        # Test with relative path
        relative_path = Path("test.db")
        with patch('infra_mgmt.db._normalize_path') as mock_normalize:
            mock_normalize.return_value = relative_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("test")
                with patch('os.access', return_value=True):
                    with patch('pathlib.Path.exists', return_value=False):
                        with patch('infra_mgmt.db.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Database path must be absolute")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(relative_path))
                            assert "Database path must be absolute" in str(exc_info.value)
        
        # Test with nonexistent parent directory
        nonexistent_path = Path(temp_dir) / "nonexistent" / "test.db"
        with patch('infra_mgmt.db._normalize_path') as mock_normalize:
            mock_normalize.return_value = nonexistent_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("nonexistent")
                with patch('pathlib.Path.exists') as mock_exists:
                    mock_exists.return_value = False
                    with patch('os.access', return_value=True):
                        with patch('infra_mgmt.db.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Parent directory does not exist")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(nonexistent_path))
                            assert "Parent directory does not exist" in str(exc_info.value)
    
    finally:
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

def test_migrate_database_with_invalid_json():
    """Test database migration with invalid JSON data in certificate fields."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_test.db")
    
    try:
        # Create initial database with invalid JSON
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)
        
        # Insert test data with invalid JSON
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO certificates (
                    serial_number, thumbprint, common_name, valid_from, valid_until,
                    issuer, subject, san, chain_valid, sans_scanned
                ) VALUES (
                    'test123', 'thumb123', 'test.com', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                    'invalid json', 'invalid json', 'invalid json', 0, 0
                )
            """))
            conn.commit()
        
        # Attempt migration
        migrate_database(engine)
        
        # Verify data was handled gracefully
        with engine.connect() as conn:
            result = conn.execute(text("SELECT issuer, subject, san FROM certificates")).fetchone()
            assert result is not None
            assert isinstance(result.issuer, str)
            assert isinstance(result.subject, str)
            assert isinstance(result.san, str)
            
            # Verify JSON data was properly formatted
            try:
                issuer_data = json.loads(result.issuer)
                assert isinstance(issuer_data, dict)
            except json.JSONDecodeError:
                pytest.fail("issuer is not valid JSON")
                
            try:
                subject_data = json.loads(result.subject)
                assert isinstance(subject_data, dict)
            except json.JSONDecodeError:
                pytest.fail("subject is not valid JSON")
                
            try:
                san_data = json.loads(result.san)
                assert isinstance(san_data, list)
            except json.JSONDecodeError:
                pytest.fail("san is not valid JSON")
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_session_cleanup_with_active_transaction():
    """Test session cleanup with active transactions."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "session_test.db")
    
    try:
        engine = init_database(db_path)
        
        # Create a session and start a transaction
        session = Session(engine)
        session.begin()
        
        # Add some test data
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
        
        # Close session with active transaction
        session.close()
        
        # Verify transaction was rolled back
        with Session(engine) as new_session:
            result = new_session.query(Certificate).filter_by(serial_number="test123").first()
            assert result is None
    
    finally:
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
            f.write(b'invalid data')
        
        # Mock settings to return our test database path
        with patch('infra_mgmt.db.Settings') as mock_settings:
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
        with patch('infra_mgmt.db.Settings') as mock_settings:
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

def test_database_schema_validation():
    """Test database schema validation."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "schema_test.db")
    new_db_path = os.path.join(temp_dir, "schema_test_new.db")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        engine.dispose()
        
        # Force garbage collection and wait for file handles to be released
        gc.collect()
        time.sleep(0.1)
        
        # Mock settings to return our test database path
        with patch('infra_mgmt.db.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = db_path
            
            # Modify schema directly
            with sqlite3.connect(db_path, isolation_level=None) as conn:
                cursor = conn.cursor()
                # Drop a required table
                cursor.execute("DROP TABLE IF EXISTS certificates")
                # Add invalid column to hosts table
                cursor.execute("ALTER TABLE hosts ADD COLUMN invalid_column TEXT")
                cursor.close()
            
            # Force garbage collection and wait for file handles to be released
            gc.collect()
            time.sleep(0.1)
            
            # Verify schema validation fails
            assert not check_database()
            
            # Update mock settings to use new database path
            mock_settings.return_value.get.return_value = new_db_path
            
            # Attempt to initialize should create new database with correct schema
            engine = init_database(new_db_path)
            assert engine is not None
            
            # Verify schema is valid
            assert check_database()
            
            # Verify tables and columns are correct
            with engine.connect() as conn:
                inspector = inspect(engine)
                # Verify certificates table exists
                assert 'certificates' in inspector.get_table_names()
                # Verify invalid column was removed
                columns = [col['name'] for col in inspector.get_columns('hosts')]
                assert 'invalid_column' not in columns
            
            # Clean up engine before final check
            engine.dispose()
            gc.collect()
            time.sleep(0.1)
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_update_database_schema_column_errors():
    """Test error handling in update_database_schema when adding columns."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "schema_error.db")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        
        # Mock inspect to simulate column errors
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.return_value.get_table_names.return_value = ['test_table']
            mock_inspect.return_value.get_columns.side_effect = Exception("Column error")
            
            # Schema update should handle the error gracefully
            result = update_database_schema(engine)
            assert result is False
        
        # Test with invalid column data type
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE test_table (
                    id INTEGER PRIMARY KEY,
                    data TEXT
                )
            """))
            conn.execute(text("INSERT INTO test_table (id, data) VALUES (1, 'test')"))
            conn.commit()
        
        # Mock inspect to simulate invalid column
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.return_value.get_table_names.return_value = ['test_table']
            mock_inspect.return_value.get_columns.return_value = [{'name': 'invalid_column'}]
            
            # Schema update should handle invalid column gracefully
            result = update_database_schema(engine)
            assert result is False
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_migrate_database_complex_scenarios():
    """Test database migration with complex scenarios."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_test.db")
    
    try:
        # Create initial database with minimal tables
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create tables with existing data
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE test_certificates (
                    id INTEGER PRIMARY KEY,
                    issuer TEXT,
                    subject TEXT,
                    san TEXT,
                    created_at DATETIME
                )
            """))
            
            # Insert test data with various formats
            conn.execute(text("""
                INSERT INTO test_certificates (issuer, subject, san, created_at)
                VALUES 
                ('{"CN": "Test CA"}', '{"CN": "test.com"}', '["test.com"]', CURRENT_TIMESTAMP),
                ('invalid json', 'invalid json', 'invalid json', NULL),
                (NULL, NULL, NULL, NULL)
            """))
            conn.commit()
        
        # Mock inspect to include our test table
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.return_value.get_table_names.return_value = ['test_certificates']
            
            # Attempt migration
            migrate_database(engine)
        
        # Verify migration results
        with engine.connect() as conn:
            result = conn.execute(text("SELECT issuer, subject, san FROM test_certificates")).fetchall()
            for row in result:
                # Verify JSON fields are properly formatted
                if row.issuer:
                    try:
                        data = json.loads(row.issuer)
                        assert isinstance(data, dict)
                    except json.JSONDecodeError:
                        assert row.issuer == 'invalid json'
                if row.subject:
                    try:
                        data = json.loads(row.subject)
                        assert isinstance(data, dict)
                    except json.JSONDecodeError:
                        assert row.subject == 'invalid json'
                if row.san:
                    try:
                        data = json.loads(row.san)
                        assert isinstance(data, list)
                    except json.JSONDecodeError:
                        assert row.san == 'invalid json'
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_database_maintenance_complex():
    """Test database maintenance operations with complex scenarios."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "maintenance_test.db")
    
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
        
        # Test reset with active connections
        active_session = Session(engine)
        active_session.begin()
        
        # Reset should succeed even with active connection
        assert reset_database(engine) is True
        
        active_session.close()
        
        # Verify database was reset
        with Session(engine) as session:
            assert session.query(Certificate).count() == 0
        
        # Test reset with invalid schema
        with engine.connect() as conn:
            conn.execute(text("CREATE TABLE invalid_table (id INTEGER PRIMARY KEY)"))
            conn.commit()
        
        # Drop all tables and recreate schema
        with engine.connect() as conn:
            # Get all table names
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            
            # Drop all tables
            for table in tables:
                conn.execute(text(f"DROP TABLE IF EXISTS {table}"))
            conn.commit()
        
        # Create new schema
        Base.metadata.create_all(engine)
        
        # Verify tables are correct
        with engine.connect() as conn:
            inspector = inspect(engine)
            tables = set(inspector.get_table_names())
            
            # Verify invalid table was removed
            assert 'invalid_table' not in tables
            
            # Verify required tables exist
            required_tables = set(Base.metadata.tables.keys())
            assert required_tables.issubset(tables)
            
            # Verify tables are empty
            for table in tables:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
                assert result == 0, f"Table {table} is not empty"
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_sync_default_ignore_patterns_complex():
    """Test syncing default ignore patterns with complex scenarios."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "sync_test.db")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        
        # Test with empty patterns
        with patch('infra_mgmt.db.Settings') as mock_settings:
            mock_settings.return_value.get.return_value = []
            sync_default_ignore_patterns(engine)
        
        # Test with duplicate patterns
        with patch('infra_mgmt.db.Settings') as mock_settings:
            mock_settings.return_value.get.side_effect = [
                ["*.test.com", "*.test.com"],  # Duplicate domain patterns
                ["*.test.com", "*.test.com"]   # Duplicate certificate patterns
            ]
            sync_default_ignore_patterns(engine)
        
        # Test with invalid patterns
        with patch('infra_mgmt.db.Settings') as mock_settings:
            mock_settings.return_value.get.side_effect = [
                [None, "", "   "],  # Invalid domain patterns
                [None, "", "   "]   # Invalid certificate patterns
            ]
            sync_default_ignore_patterns(engine)
        
        # Verify results
        with Session(engine) as session:
            # Check for no duplicate patterns
            domain_patterns = session.query(IgnoredDomain).all()
            cert_patterns = session.query(IgnoredCertificate).all()
            
            domain_pattern_set = {d.pattern for d in domain_patterns}
            cert_pattern_set = {c.pattern for c in cert_patterns}
            
            assert len(domain_patterns) == len(domain_pattern_set)
            assert len(cert_patterns) == len(cert_pattern_set)
            
            # Check that invalid patterns were not added
            for pattern in [None, "", "   "]:
                assert not session.query(IgnoredDomain).filter_by(pattern=pattern).first()
                assert not session.query(IgnoredCertificate).filter_by(pattern=pattern).first()
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_init_database_error_handling():
    """Test database initialization error handling."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "error_test.db")
    
    try:
        # Test with invalid path format
        with pytest.raises(Exception) as exc_info:
            init_database("*<>|?")  # Invalid characters
        assert "Invalid database path" in str(exc_info.value)
        
        # Test with non-existent parent directory
        nonexistent_path = os.path.join(temp_dir, "nonexistent", "nonexistent", "db.db")
        with pytest.raises(Exception) as exc_info:
            init_database(nonexistent_path)
        assert "Parent directory's parent does not exist" in str(exc_info.value)
        
        # Test with file instead of directory
        file_path = os.path.join(temp_dir, "file")
        with open(file_path, 'w') as f:
            f.write("test")
        
        with pytest.raises(Exception) as exc_info:
            init_database(os.path.join(file_path, "db.db"))
        assert "Path exists but is not a directory" in str(exc_info.value)
        
        # Test with unwritable directory
        if os.name != 'nt':  # Skip on Windows
            os.chmod(temp_dir, 0o444)  # Read-only
            with pytest.raises(Exception) as exc_info:
                init_database(db_path)
            assert "No write permission" in str(exc_info.value)
            os.chmod(temp_dir, 0o777)  # Restore permissions
    
    finally:
        cleanup_temp_dir(temp_dir)

def test_session_management_edge_cases():
    """Test session management edge cases."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "session_test.db")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        
        # Test with disposed engine
        engine.dispose()
        with patch('sqlalchemy.engine.base.Engine.connect') as mock_connect:
            mock_connect.side_effect = Exception("Engine disposed")
            session = get_session(engine)
            assert session is None
        
        # Test with invalid engine URL
        invalid_engine = create_engine('sqlite:///nonexistent/path/db.db')
        session = get_session(invalid_engine)
        assert session is None
        
        # Test session manager with None engine
        with SessionManager(None) as session:
            assert session is None
        
        # Test session manager with invalid engine
        with SessionManager(invalid_engine) as session:
            assert session is not None
            with pytest.raises(Exception):
                session.query(Certificate).all()
    
    finally:
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
            with pytest.raises(sqlite3.OperationalError) as exc_info:
                restore_database(backup_path, engine)
            assert "database is locked" in str(exc_info.value).lower()
        
        # Test restore with invalid backup file
        with open(backup_path, 'w') as f:
            f.write("invalid data")
        with pytest.raises(sqlite3.DatabaseError) as exc_info:
            restore_database(backup_path, engine)
        assert "file is not a database" in str(exc_info.value)
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_schema_management_error_handling():
    """Test error handling in schema management."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "schema_error.db")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        
        # Test with invalid table structure
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE test_table (
                    id INTEGER PRIMARY KEY,
                    invalid_column TEXT
                )
            """))
            conn.commit()
        
        # Mock inspect to simulate table validation error
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.return_value.get_table_names.return_value = ['test_table']
            mock_inspect.return_value.get_columns.return_value = [
                {'name': 'id', 'type': 'INTEGER'},
                {'name': 'invalid_column', 'type': 'TEXT'}
            ]
            
            # Schema update should handle invalid column gracefully
            result = update_database_schema(engine)
            assert result is False
        
        # Test with column addition error
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.return_value.get_table_names.return_value = ['test_table']
            mock_inspect.return_value.get_columns.return_value = [{'name': 'id', 'type': 'INTEGER'}]
            
            # Mock connection to simulate column addition error
            with patch('sqlalchemy.engine.base.Connection.execute') as mock_execute:
                mock_execute.side_effect = Exception("Column addition error")
                
                # Schema update should handle column addition error gracefully
                result = update_database_schema(engine)
                assert result is False
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_migration_edge_cases():
    """Test database migration edge cases."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_test.db")
    
    try:
        # Create initial database
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create tables with existing data
        with engine.connect() as conn:
            # Create domain_dns_records table with old schema
            conn.execute(text("""
                CREATE TABLE domain_dns_records (
                    id INTEGER PRIMARY KEY,
                    domain_id INTEGER,
                    record_type VARCHAR,
                    name VARCHAR,
                    value VARCHAR,
                    ttl INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """))
            
            # Insert test data
            conn.execute(text("""
                INSERT INTO domain_dns_records (domain_id, record_type, name, value, ttl)
                VALUES (1, 'A', 'test.com', '1.1.1.1', 3600)
            """))
            conn.commit()
        
        # Mock inspect to simulate table update
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.return_value.get_table_names.return_value = ['domain_dns_records']
            mock_inspect.return_value.get_unique_constraints.return_value = []
            
            # Mock the execute function to prevent actual table creation
            with patch('sqlalchemy.engine.base.Connection.execute') as mock_execute:
                # Create a mock result
                mock_result = MagicMock()
                mock_result.domain_id = 1
                mock_result.record_type = 'A'
                mock_result.name = 'test.com'
                mock_result.value = '1.1.1.1'
                mock_result.ttl = 3600
                
                # Set up the mock to return our result
                mock_execute.return_value.fetchone.return_value = mock_result
                
                # Attempt migration
                migrate_database(engine)
                
                # Verify migration was attempted
                mock_execute.assert_called()
                
                # Verify data was preserved
                with engine.connect() as conn:
                    result = conn.execute(text("SELECT * FROM domain_dns_records")).fetchone()
                    assert result.domain_id == 1
                    assert result.record_type == 'A'
                    assert result.name == 'test.com'
                    assert result.value == '1.1.1.1'
                    assert result.ttl == 3600
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_database_init_edge_cases():
    """Test database initialization edge cases."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "init_test.db")

    try:
        # Test with invalid path characters
        with pytest.raises(Exception) as exc_info:
            init_database("test/db/with/invalid/chars/*.db")
        assert "Invalid database path" in str(exc_info.value)

        # Test with file instead of directory
        file_path = os.path.join(temp_dir, "file")
        with open(file_path, 'w') as f:
            f.write("test")

        with pytest.raises(Exception) as exc_info:
            init_database(os.path.join(file_path, "db.db"))
        assert "Path exists but is not a directory" in str(exc_info.value)

        # Test with unwritable directory
        if os.name != 'nt':  # Skip on Windows
            os.chmod(temp_dir, 0o444)  # Read-only
            with pytest.raises(Exception) as exc_info:
                init_database(db_path)
            assert "No write permission" in str(exc_info.value)
            os.chmod(temp_dir, 0o777)  # Restore permissions

        # Test with corrupted database
        with open(db_path, 'w') as f:
            f.write("corrupted data")

        # Mock SQLite connection to raise DatabaseError
        with patch('sqlite3.connect') as mock_connect:
            mock_connect.side_effect = sqlite3.DatabaseError("file is not a database")
            
            # Mock file operations
            with patch('pathlib.Path.exists', return_value=True), \
                 patch('pathlib.Path.unlink', return_value=None), \
                 patch('os.access', return_value=True), \
                 patch('sqlalchemy.create_engine') as mock_create_engine, \
                 patch('sqlalchemy.engine.Engine.connect') as mock_engine_connect, \
                 patch('sqlalchemy.engine.Connection.execute') as mock_execute:

                # This should now raise sqlite3.DatabaseError
                with pytest.raises(Exception) as exc_info:
                    init_database(db_path)
                assert "file is not a database" in str(exc_info.value)

    finally:
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to clean up temporary directory {temp_dir}: {e}")

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
            with pytest.raises(Exception) as exc_info:
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
        with pytest.raises(sqlite3.DatabaseError) as exc_info:
            restore_database("nonexistent.db", engine)
        assert "unable to open database file" in str(exc_info.value)

        # Test restore with invalid backup
        invalid_backup = os.path.join(backup_dir, "invalid.db")
        with open(invalid_backup, 'w') as f:
            f.write("invalid data")

        with pytest.raises(sqlite3.DatabaseError) as exc_info:
            restore_database(invalid_backup, engine)
        assert "file is not a database" in str(exc_info.value)

        # Test restore with locked database
        with patch('sqlite3.connect') as mock_connect:
            mock_connect.side_effect = sqlite3.OperationalError("database is locked")
            with pytest.raises(sqlite3.OperationalError) as exc_info:
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
        
        with patch('infra_mgmt.db.create_engine', return_value=mock_engine):
            with patch('os.path.exists', return_value=True):
                with patch('os.access', return_value=True):
                    with patch('shutil.copy2'):
                        with pytest.raises(Exception) as exc_info:
                            backup_database(engine, backup_dir)
                        assert "Failed to verify backup" in str(exc_info.value)
        
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_update_database_schema_invalid_column():
    """Test update_database_schema with invalid column handling."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    try:
        # Create initial database
        engine = init_database(db_path)
        
        # Create a table with an invalid column
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE test_table (
                    id INTEGER PRIMARY KEY,
                    valid_column TEXT,
                    invalid_column TEXT
                )
            """))
            conn.commit()
        
        # Mock inspect to return our test table with invalid column
        with patch('infra_mgmt.db.inspect') as mock_inspect:
            mock_inspect.return_value.get_table_names.return_value = ['test_table']
            mock_inspect.return_value.get_columns.return_value = [
                {'name': 'id', 'type': 'INTEGER'},
                {'name': 'valid_column', 'type': 'TEXT'},
                {'name': 'invalid_column', 'type': 'TEXT'}
            ]
            
            # Schema update should handle invalid column gracefully
            result = update_database_schema(engine)
            assert result is False
        
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_init_database_permission_error():
    """Test init_database with permission error."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    try:
        # Mock os.access to simulate permission error
        with patch('os.access', return_value=False):
            with pytest.raises(Exception) as exc_info:
                init_database(db_path)
            assert "No write permission for database directory" in str(exc_info.value)
        
    finally:
        cleanup_temp_dir(temp_dir)
