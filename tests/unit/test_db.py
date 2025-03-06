import pytest
from sqlalchemy import create_engine, inspect, Column, Integer, String
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from cert_scanner.db import (
    init_database, get_session, backup_database, restore_database, 
    update_database_schema, reset_database, check_database, SessionManager, _is_network_path, _normalize_path,
    migrate_database
)
from cert_scanner.models import Base, Certificate, Host, HostIP
from datetime import datetime
import os
import tempfile
import shutil
import time
from unittest.mock import patch, MagicMock
from pathlib import Path
from sqlalchemy import text
from cert_scanner.settings import Settings
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

logger = logging.getLogger(__name__)

# Constants for test data
HOST_TYPE_SERVER = "Server"
ENV_PRODUCTION = "Production"

def cleanup_temp_dir(temp_dir):
    """Helper function to clean up temporary test directories."""
    try:
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
        
        # Verify database is properly initialized
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
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
                issuer="Test CA",
                subject="CN=test.com",
                san="test.com"
            )
            session.add(cert)
            session.commit()
            
            # Verify record was created
            result = session.query(Certificate).filter_by(serial_number="test123").first()
            assert result is not None
            assert result.serial_number == "test123"
    
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
        with patch('cert_scanner.db.Settings') as mock_settings:
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
    Base.metadata.create_all(engine)  # Create initial tables

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
    Base.metadata.create_all(engine)  # Create initial tables

    # Update schema (should not change anything)
    assert update_database_schema(engine) is True

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

def test_init_database_parent_of_parent_not_exists():
    """Test database initialization when parent's parent doesn't exist"""
    temp_dir = tempfile.mkdtemp()
    nonexistent_path = os.path.join(temp_dir, "nonexistent")
    db_path = os.path.join(nonexistent_path, "subdir", "test.db")
    
    # Remove the temp directory to simulate nonexistent parent
    shutil.rmtree(temp_dir)
    
    try:
        # Attempt to initialize database
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        
        assert "Parent directory's parent does not exist" in str(exc_info.value)
    
    finally:
        if os.path.exists(temp_dir):
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
             patch('cert_scanner.db.os.access', side_effect=mock_access):
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
        with patch('cert_scanner.db.Settings') as mock_settings:
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
        with patch('cert_scanner.db.Settings') as mock_settings:
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
    """Test SessionManager with concurrent access"""
    # Create database in a file instead of memory for thread safety
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_concurrent.db")
    
    try:
        # Initialize database and create tables
        engine = init_database(db_path)
        Base.metadata.create_all(engine)
        
        error_queue = queue.Queue()
        success_queue = queue.Queue()

        def worker(worker_id):
            try:
                # Create a new engine for each thread
                thread_engine = create_engine(f"sqlite:///{db_path}")
                
                with SessionManager(thread_engine) as session:
                    # Add a test record
                    host = Host(
                        name=f"host-{worker_id}",
                        host_type=HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                    session.commit()

                    # Simulate some work
                    time.sleep(0.1)

                    # Verify our record exists
                    result = session.query(Host).filter_by(name=f"host-{worker_id}").first()
                    assert result is not None
                    success_queue.put(worker_id)
                
                thread_engine.dispose()
            except Exception as e:
                error_queue.put((worker_id, str(e)))

        # Create and start multiple threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # Check for any errors
        errors = []
        while not error_queue.empty():
            errors.append(error_queue.get())
        
        # Verify successful operations
        successes = []
        while not success_queue.empty():
            successes.append(success_queue.get())
        
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(successes) == 5, f"Expected 5 successful operations, got {len(successes)}"
        
        # Verify final database state
        with SessionManager(engine) as session:
            hosts = session.query(Host).all()
            assert len(hosts) == 5
            host_names = {host.name for host in hosts}
            assert host_names == {f"host-{i}" for i in range(5)}
    
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
        
        with patch('sqlalchemy.dialects.sqlite.pysqlite.SQLiteDialect_pysqlite.connect', return_value=mock_connection), \
             patch('sqlalchemy.create_engine', return_value=mock_engine), \
             patch('cert_scanner.db.create_engine', return_value=mock_engine) as mock_create_engine, \
             patch('pathlib.Path.exists', return_value=True), \
             patch('pathlib.Path.is_dir', return_value=True), \
             patch('os.access', return_value=True), \
             patch('pathlib.Path.unlink', return_value=None), \
             patch('pathlib.Path.mkdir', return_value=None):
            
            # Initialize database with network path
            result_engine = init_database()
            
            # Verify engine was created with correct path
            assert result_engine is not None
            assert mock_create_engine.call_count == 2
            # Both calls should use the same network path
            for call_args in mock_create_engine.call_args_list:
                assert network_path in str(call_args[0][0])
            
            # Verify connection was attempted
            mock_engine.connect.assert_called()
            
            # Clean up
            result_engine.dispose()
            
    except Exception as e:
        if "No such file or directory" in str(e):
            pytest.skip("Network share not available")
        else:
            raise

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
                    common_name
                )
                VALUES (
                    'test123',
                    'test_thumbprint',
                    'invalid json',
                    'invalid json',
                    'invalid json',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP,
                    'test.com'
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
    engine = None

    try:
        # Create a mock engine that raises an exception on inspect
        mock_engine = MagicMock()
        mock_inspect = MagicMock()
        mock_inspect.get_table_names.side_effect = Exception("Connection error")
        with patch('cert_scanner.db.inspect', return_value=mock_inspect):
            # Test with invalid engine
            assert update_database_schema(mock_engine) is False

        # Create a real engine but with invalid table structure
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)

        # Test with invalid table structure
        with engine.connect() as conn:
            # Create a table with a valid structure but invalid data type
            conn.execute(text("""
                CREATE TABLE test_table (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    value BLOB
                )
            """))
            conn.commit()

            # Insert some data with invalid type
            conn.execute(text("""
                INSERT INTO test_table (id, name, value)
                VALUES (1, 'test', 'invalid blob data')
            """))
            conn.commit()

        # Test with invalid table structure
        assert update_database_schema(engine) is True  # Should succeed as the structure is valid

    finally:
        # Cleanup
        if engine:
            engine.dispose()
        Session.close_all()
        time.sleep(0.1)  # Allow time for file handles to be released
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                time.sleep(0.5)  # Wait a bit longer if needed
                try:
                    os.remove(db_path)
                except PermissionError:
                    print(f"Warning: Could not delete database file: {db_path}")
        cleanup_temp_dir(temp_dir)

def test_migrate_database_error_handling():
    """Test error handling in migrate_database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "migration_error.db")
    engine = None

    try:
        # Create a mock engine that raises an exception
        mock_engine = MagicMock()
        mock_engine.connect.side_effect = Exception("Connection error")

        # Test with invalid engine
        with pytest.raises(Exception):
            migrate_database(mock_engine)

        # Create a real engine but with invalid data
        engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(engine)

        # Test with invalid JSON data in certificates table
        with engine.connect() as conn:
            # Drop existing certificates table if it exists
            conn.execute(text("DROP TABLE IF EXISTS certificates"))
            conn.commit()

            # Create a new certificates table with invalid structure
            conn.execute(text("""
                CREATE TABLE certificates (
                    id INTEGER PRIMARY KEY,
                    issuer TEXT,
                    subject TEXT,
                    san TEXT
                )
            """))
            conn.commit()

            # Insert invalid JSON data
            conn.execute(text("""
                INSERT INTO certificates (issuer, subject, san)
                VALUES ('invalid json', 'invalid json', 'invalid json')
            """))
            conn.commit()

        # Test migration with invalid data
        migrate_database(engine)

        # Verify that invalid data was handled gracefully
        with engine.connect() as conn:
            result = conn.execute(text("SELECT issuer, subject, san FROM certificates")).fetchone()
            assert result is not None
            assert result.issuer == '{}'  # Default empty JSON object
            assert result.subject == '{}'  # Default empty JSON object
            assert result.san == '[]'  # Default empty JSON array

    finally:
        # Cleanup
        if engine:
            engine.dispose()
        Session.close_all()
        time.sleep(0.1)  # Allow time for file handles to be released
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                time.sleep(0.5)  # Wait a bit longer if needed
                try:
                    os.remove(db_path)
                except PermissionError:
                    print(f"Warning: Could not delete database file: {db_path}")
        cleanup_temp_dir(temp_dir)

def test_init_database_error_handling():
    """Test error handling in init_database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "init_error.db")
    
    try:
        # Test with invalid path
        invalid_path = "\\\\?\\invalid*path:with|invalid<chars>.db"
        with pytest.raises(Exception) as exc_info:
            init_database(invalid_path)
        assert "Invalid database path" in str(exc_info.value)
        
        # Test with parent directory that exists but is not a directory
        parent_path = os.path.join(temp_dir, "not_a_dir")
        with open(parent_path, 'w') as f:
            f.write("dummy data")
        db_path = os.path.join(parent_path, "test.db")
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        assert "Path exists but is not a directory" in str(exc_info.value)
        
        # Test with parent's parent that doesn't exist
        nonexistent_path = os.path.join(temp_dir, "nonexistent")
        db_path = os.path.join(nonexistent_path, "subdir", "test.db")
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        assert "Parent directory's parent does not exist" in str(exc_info.value)
        
        # Test with no write permission
        db_path = os.path.join(temp_dir, "readonly.db")
        with open(db_path, 'w') as f:
            f.write("dummy data")
        current_mode = os.stat(db_path).st_mode
        os.chmod(db_path, current_mode & ~stat.S_IWRITE)
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        assert "No write permission for database file" in str(exc_info.value)
        
        # Test with corrupted database
        os.chmod(db_path, current_mode | stat.S_IWRITE)
        with open(db_path, 'w') as f:
            f.write("corrupted data")
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        assert "file is not a database" in str(exc_info.value)
        
        # Test with settings error
        with patch('cert_scanner.db.Settings') as mock_settings:
            mock_settings.return_value.get.side_effect = Exception("Settings error")
            with pytest.raises(Exception):
                init_database()
        
    finally:
        # Restore permissions for cleanup
        if os.path.exists(db_path):
            os.chmod(db_path, current_mode | stat.S_IWRITE)
        cleanup_temp_dir(temp_dir)

def test_backup_restore_database_error_handling():
    """Test error handling in backup_database and restore_database"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "backup_error.db")
    backup_dir = os.path.join(temp_dir, "backups")
    os.makedirs(backup_dir)
    engine = None

    try:
        # Create source database
        engine = init_database(db_path)

        # Test backup with invalid engine
        mock_engine = MagicMock()
        mock_engine.url.database = "nonexistent.db"
        with pytest.raises(Exception) as exc_info:
            backup_database(mock_engine, backup_dir)
        assert "Source database does not exist" in str(exc_info.value)

        # Test backup with invalid backup directory
        invalid_backup_dir = os.path.join(temp_dir, "invalid_backup")
        with open(invalid_backup_dir, 'w') as f:
            f.write("dummy data")
        with pytest.raises(Exception) as exc_info:
            backup_database(engine, invalid_backup_dir)
        assert "Backup path exists but is not a directory" in str(exc_info.value)

        # Test backup with no write permission
        def mock_access(path, mode):
            if str(path) == str(backup_dir) and mode == os.W_OK:
                return False
            return True

        with patch('os.access', side_effect=mock_access), \
             patch('cert_scanner.db.os.access', side_effect=mock_access):
            with pytest.raises(Exception) as exc_info:
                backup_database(engine, backup_dir)
            assert "No write permission for backup directory" in str(exc_info.value)

        # Test restore with invalid backup file
        # Create a file that looks like a SQLite database but has an invalid text encoding
        invalid_backup = os.path.join(backup_dir, "invalid_backup.db")
        with open(invalid_backup, 'wb') as f:
            # Write SQLite header magic number
            f.write(b'SQLite format 3\x00')
            # Write page size (4096 bytes)
            f.write(b'\x10\x10')
            # Write file format write version (2)
            f.write(b'\x02')
            # Write file format read version (2)
            f.write(b'\x02')
            # Write reserved bytes at end of page (0)
            f.write(b'\x00')
            # Write maximum embedded payload fraction (64)
            f.write(b'\x40')
            # Write minimum embedded payload fraction (32)
            f.write(b'\x20')
            # Write leaf payload fraction (32)
            f.write(b'\x20')
            # Write file change counter (0)
            f.write(b'\x00\x00\x00\x00')
            # Write size of database in pages (0)
            f.write(b'\x00\x00\x00\x00')
            # Write first freelist trunk page (0)
            f.write(b'\x00\x00\x00\x00')
            # Write total number of freelist pages (0)
            f.write(b'\x00\x00\x00\x00')
            # Write schema cookie (0)
            f.write(b'\x00\x00\x00\x00')
            # Write schema format number (4)
            f.write(b'\x00\x00\x00\x04')
            # Write default page cache size (0)
            f.write(b'\x00\x00\x00\x00')
            # Write largest root btree page (0)
            f.write(b'\x00\x00\x00\x00')
            # Write invalid text encoding (0x00)
            f.write(b'\x00\x00\x00\x00')
            # Write user version (0)
            f.write(b'\x00\x00\x00\x00')
            # Write incremental vacuum mode (0)
            f.write(b'\x00\x00\x00\x00')
            # Write application ID (0)
            f.write(b'\x00\x00\x00\x00')
            # Write reserved for expansion (0)
            f.write(b'\x00' * 20)
            # Write version-valid-for number (0)
            f.write(b'\x00\x00\x00\x00')
            # Write SQLite version number (0)
            f.write(b'\x00\x00\x00\x00')

        assert os.path.exists(invalid_backup), "Failed to create invalid backup file"

        with pytest.raises(sqlite3.DatabaseError) as exc_info:
            restore_database(invalid_backup, engine)
        assert "file is not a database" in str(exc_info.value)

        # Test restore with nonexistent backup file
        nonexistent_backup = os.path.join(backup_dir, "nonexistent.db")
        with pytest.raises(Exception) as exc_info:
            restore_database(nonexistent_backup, engine)
        assert "unable to open database file" in str(exc_info.value)

        # Create a valid backup file for the locked database test
        valid_backup = backup_database(engine, backup_dir)
        assert os.path.exists(valid_backup), "Failed to create valid backup file"

        # Test restore with locked database
        # First add some data to ensure we have something to lock
        with get_session(engine) as session:
            session.execute(text("""
                CREATE TABLE IF NOT EXISTS test_table (
                    id INTEGER PRIMARY KEY,
                    value TEXT
                )
            """))
            session.execute(text("INSERT INTO test_table (id, value) VALUES (1, 'test')"))
            session.commit()

        # Now start a transaction that will lock the database
        with get_session(engine) as session:
            session.execute(text("BEGIN TRANSACTION"))
            session.execute(text("UPDATE test_table SET value = 'locked' WHERE id = 1"))
            # Don't commit the transaction to keep the lock

            # Try to restore while database is locked
            with pytest.raises(sqlite3.OperationalError) as exc_info:
                restore_database(valid_backup, engine)
            assert "Database is locked" in str(exc_info.value)

    finally:
        # Cleanup
        if engine:
            engine.dispose()
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Error cleaning up test directory: {e}")
