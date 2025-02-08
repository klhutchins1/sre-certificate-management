import pytest
from sqlalchemy import create_engine, inspect, Column, Integer, String
from sqlalchemy.orm import Session
from cert_scanner.db import (
    init_database, get_session, backup_database, restore_database, 
    update_database_schema, reset_database, check_database, SessionManager
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

logger = logging.getLogger(__name__)

# Constants for test data
HOST_TYPE_SERVER = "Server"
ENV_PRODUCTION = "Production"

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

def init_database(db_path=None):
    """Initialize the database connection and create tables if they don't exist"""
    try:
        # Get database path from parameter or settings
        if db_path is None:
            settings = Settings()
            db_path = Path(settings.get("paths.database", "data/certificates.db"))
        else:
            db_path = Path(db_path)
        
        # Convert to absolute path
        db_path = db_path.absolute()
        
        # Check for invalid characters in path first
        invalid_chars = '<>"|?*'  # Remove ':' from invalid chars since it's valid in Windows paths
        if any(char in str(db_path) for char in invalid_chars):
            raise Exception(f"Invalid database path: {db_path}")
        
        parent_dir = db_path.parent
        
        # Handle parent directory
        if parent_dir.exists():
            if not parent_dir.is_dir():
                raise Exception(f"Path exists but is not a directory: {parent_dir}")
            if not os.access(str(parent_dir), os.W_OK):
                raise Exception(f"No write permission for database directory: {parent_dir}")
        else:
            # Check if we can create the directory by checking write permissions on its parent
            parent_of_parent = parent_dir.parent
            if not parent_of_parent.exists() or not parent_of_parent.is_dir():
                raise Exception(f"Parent directory's parent does not exist or is not a directory: {parent_of_parent}")
            if not os.access(str(parent_of_parent), os.W_OK):
                raise Exception(f"Cannot create database directory: {parent_dir} (no write permission)")
            try:
                parent_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                raise Exception(f"Cannot create database directory: {parent_dir} (Access denied)")
            except Exception as e:
                raise Exception(f"Cannot create database directory: {parent_dir} ({str(e)})")
            
            # Verify write permissions after creation
            if not os.access(str(parent_dir), os.W_OK):
                raise Exception(f"No write permission for database directory: {parent_dir}")
        
        # Handle existing database file
        if db_path.exists():
            if not os.access(str(db_path), os.W_OK):
                raise Exception(f"No write permission for database file: {db_path}")
            
            # Validate existing database
            try:
                test_engine = create_engine(f"sqlite:///{db_path}")
                with test_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                test_engine.dispose()
            except sqlite3.DatabaseError as e:
                logger.warning(f"Removing invalid or corrupted database: {str(e)}")
                try:
                    db_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove corrupted database: {str(e)}")
                    raise
                raise sqlite3.DatabaseError(f"Database at {db_path} is corrupted: {str(e)}")
            except Exception as e:
                logger.warning(f"Removing invalid or corrupted database: {str(e)}")
                try:
                    db_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove corrupted database: {str(e)}")
                    raise
                raise
        
        # Create new database engine
        logger.info(f"Using database at: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create tables and update schema
        logger.info("Creating database tables...")
        Base.metadata.create_all(engine)
        
        return engine
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

def cleanup_temp_dir(temp_dir):
    """Helper function to clean up temporary directories"""
    if not os.path.exists(temp_dir):
        return

    # Close any remaining sessions
    Session.close_all()
    
    # Add a delay and force garbage collection
    time.sleep(0.2)
    gc.collect()
    
    for retry in range(3):
        try:
            shutil.rmtree(temp_dir)
            break
        except PermissionError:
            if retry < 2:
                time.sleep(0.5 * (retry + 1))
            else:
                logger.debug(f"Could not delete temporary directory after {retry + 1} attempts: {temp_dir}")

# Ensure the SessionManager class is correctly implemented
class SessionManager:
    def __init__(self, engine):
        self.engine = engine
        self.session = None  # Initialize session attribute

    def __enter__(self):
        if self.engine:
            self.session = Session(self.engine)  # Create a new session
            return self.session
        return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            self.session.close()  # Close the session

def test_update_database_schema_add_column():
    """Test adding a new column to an existing table"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_schema_column.db")
    engine = create_engine(f"sqlite:///{db_path}")
    
    try:
        # Create initial table without the new column
        class TestTable(Base):
            __tablename__ = 'test_table'
            id = Column(Integer, primary_key=True)
            name = Column(String)

        # Create initial schema
        Base.metadata.create_all(engine)
        
        # Add new column to model
        TestTable.new_column = Column(String)
        
        # Update schema
        assert update_database_schema(engine) is True
        
        # Verify new column was added
        inspector = inspect(engine)
        columns = [c['name'] for c in inspector.get_columns('test_table')]
        assert 'new_column' in columns
        
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_init_database_readonly_dir(tmp_path):
    """Test database initialization with read-only directory"""
    db_path = str(tmp_path / "test.db")
    parent_dir = str(tmp_path)
    
    try:
        # Create the directory
        os.makedirs(parent_dir, exist_ok=True)
        
        # Mock os.access to simulate read-only directory
        def mock_access(path, mode):
            path_str = str(path)
            if os.path.normpath(path_str) == os.path.normpath(str(parent_dir)):
                if mode == os.W_OK:
                    return False
            return True
        
        with patch('cert_scanner.db.os.access', side_effect=mock_access), \
             patch('os.access', side_effect=mock_access):
            with pytest.raises(Exception) as exc_info:
                init_database(db_path)
            assert "No write permission for database directory" in str(exc_info.value)
    finally:
        # No need to restore permissions since we're mocking
        pass

def test_init_database_nonexistent_parent(tmp_path):
    """Test database initialization with nonexistent parent directory that can't be created"""
    db_path = str(tmp_path / "nonexistent" / "test.db")
    parent_dir = str(tmp_path / "nonexistent")
    parent_of_parent = str(tmp_path)
    
    # Mock os.access to allow write permission on parent of parent
    def mock_access(path, mode):
        path_str = str(path)
        if os.path.normpath(path_str) == os.path.normpath(str(parent_of_parent)):
            return True
        return False
    
    # Mock mkdir to raise PermissionError
    def mock_mkdir(*args, **kwargs):
        raise PermissionError("Access denied")
    
    with patch('cert_scanner.db.os.access', side_effect=mock_access), \
         patch('os.access', side_effect=mock_access), \
         patch('pathlib.Path.mkdir', side_effect=mock_mkdir):
        with pytest.raises(Exception) as exc_info:
            init_database(db_path)
        
        error_msg = str(exc_info.value)
        assert "Cannot create database directory" in error_msg
        assert "Access denied" in error_msg

def test_session_cleanup_on_error():
    """Test session cleanup when an error occurs"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    # Create a test record to verify session state
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

    try:
        # Simulate an error during session use
        raise Exception("Test error")
    except:
        session.rollback()
        session.close()
        engine.dispose()  # Dispose the engine to ensure all connections are closed

    # Verify that using the session raises an error
    with pytest.raises((sqlalchemy.exc.ResourceClosedError, sqlalchemy.exc.StatementError)):
        # Try to use the session after it's closed
        session.query(Certificate).all()

def test_session_manager_error_handling():
    """Test SessionManager error handling and cleanup"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    
    # Test that session is properly rolled back on error
    with pytest.raises(ValueError):
        with SessionManager(engine) as session:
            # Add a test record
            host = Host(
                name="test-server",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.flush()  # Ensure the record is in the session
            
            # Verify record exists in session
            assert session.query(Host).count() == 1
            
            # Raise an error
            raise ValueError("Test error")
    
    # Create new session to verify rollback occurred
    with SessionManager(engine) as session:
        assert session.query(Host).count() == 0

def test_session_manager_nested():
    """Test nested SessionManager contexts"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    
    # Test nested session managers
    with SessionManager(engine) as outer_session:
        # Add a record in outer session
        host1 = Host(
            name="outer-server",
            host_type=HOST_TYPE_SERVER,
            environment=ENV_PRODUCTION,
            last_seen=datetime.now()
        )
        outer_session.add(host1)
        outer_session.commit()  # Commit the changes in outer session
        
        # Nested session manager
        with SessionManager(engine) as inner_session:
            # Add a record in inner session
            host2 = Host(
                name="inner-server",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            inner_session.add(host2)
            inner_session.commit()  # Commit the changes in inner session
            
            # Verify both records are visible
            assert inner_session.query(Host).count() == 2
        
        # Refresh outer session to see changes from inner session
        outer_session.expire_all()
        # Verify outer session can see all records
        assert outer_session.query(Host).count() == 2

def test_session_manager_commit():
    """Test explicit commit in SessionManager"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    
    # Test committing changes
    with SessionManager(engine) as session:
        host = Host(
            name="test-server",
            host_type=HOST_TYPE_SERVER,
            environment=ENV_PRODUCTION,
            last_seen=datetime.now()
        )
        session.add(host)
        session.commit()
    
    # Verify changes persisted
    with SessionManager(engine) as session:
        assert session.query(Host).count() == 1
        host = session.query(Host).first()
        assert host.name == "test-server"

def test_database_thread_safety():
    """Test thread safety of database operations"""
    import threading
    import queue
    from cert_scanner.db import db_lock
    
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_thread.db")
    engine = None
    results_queue = queue.Queue()
    
    try:
        engine = init_database(db_path)
        
        def worker(worker_id):
            try:
                with db_lock:
                    # Simulate some database work
                    with SessionManager(engine) as session:
                        # Add a test record
                        host = Host(
                            name=f"server-{worker_id}",
                            host_type=HOST_TYPE_SERVER,
                            environment=ENV_PRODUCTION,
                            last_seen=datetime.now()
                        )
                        session.add(host)
                        session.commit()
                        
                        # Small delay to increase chance of race conditions
                        time.sleep(0.1)
                        
                        # Verify our record
                        result = session.query(Host).filter_by(name=f"server-{worker_id}").first()
                        assert result is not None
                        results_queue.put(("success", worker_id))
            except Exception as e:
                results_queue.put(("error", worker_id, str(e)))
        
        # Create and start multiple threads
        threads = []
        num_threads = 5
        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Check results
        results = []
        while not results_queue.empty():
            results.append(results_queue.get())
        
        # Verify all operations succeeded
        success_count = sum(1 for r in results if r[0] == "success")
        assert success_count == num_threads
        
        # Verify final database state
        with SessionManager(engine) as session:
            assert session.query(Host).count() == num_threads
    
    finally:
        if engine:
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_backup_restore_thread_safety():
    """Test thread safety of backup and restore operations"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_thread_backup.db")
    backup_dir = os.path.join(temp_dir, "backups")
    engine = None
    
    try:
        os.makedirs(backup_dir)
        engine = init_database(db_path)
        
        # Add some initial data
        with SessionManager(engine) as session:
            for i in range(5):
                host = Host(
                    name=f"server-{i}",
                    host_type=HOST_TYPE_SERVER,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                session.add(host)
            session.commit()
        
        # Test concurrent backup operations
        backup_paths = []
        def backup_worker():
            try:
                backup_path = backup_database(engine, backup_dir)
                backup_paths.append(backup_path)
            except Exception as e:
                pytest.fail(f"Backup failed: {str(e)}")
        
        threads = []
        for _ in range(3):
            t = threading.Thread(target=backup_worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Verify all backups were created successfully
        assert len(backup_paths) == 3
        for backup_path in backup_paths:
            assert os.path.exists(backup_path)
            
            # Verify each backup is a valid database
            test_engine = create_engine(f"sqlite:///{backup_path}")
            with test_engine.connect() as conn:
                result = conn.execute(text("SELECT COUNT(*) FROM hosts")).scalar()
                assert result == 5
            test_engine.dispose()
    
    finally:
        if engine:
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_update_database_schema_default_value():
    """Test adding a column with a default value"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_schema_default.db")
    engine = create_engine(f"sqlite:///{db_path}")
    
    try:
        # Create initial table
        class TestDefaultTable(Base):
            __tablename__ = 'test_default_table'
            id = Column(Integer, primary_key=True)
            name = Column(String)
        
        Base.metadata.create_all(engine)
        
        # Add some initial data
        with SessionManager(engine) as session:
            test_record = TestDefaultTable(name="test1")
            session.add(test_record)
            session.commit()
        
        # Add new column with default value
        TestDefaultTable.status = Column(String, default="active")
        
        # Update schema
        assert update_database_schema(engine) is True
        
        # Verify column was added with default value
        with SessionManager(engine) as session:
            record = session.query(TestDefaultTable).first()
            assert record.status == "active"  # Default value should be applied
            
            # New records should also get the default
            new_record = TestDefaultTable(name="test2")
            session.add(new_record)
            session.commit()
            assert new_record.status == "active"
    
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_update_database_schema_with_constraint():
    """Test adding a column with constraints"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_schema_constraint.db")
    engine = create_engine(f"sqlite:///{db_path}")
    
    try:
        # Create initial table with validation
        class TestConstraintTable(Base):
            __tablename__ = 'test_constraint_table'
            id = Column(Integer, primary_key=True)
            name = Column(String)
            required_field = Column(
                String,
                server_default=text("'default'")
            )
            
            @validates('required_field')
            def validate_required_field(self, key, value):
                # Allow None during initial insert (server_default will handle it)
                # But don't allow explicit None assignments
                if value is None and self.id is not None:
                    raise ValueError("required_field cannot be NULL")
                return value
        
        # Create the table
        Base.metadata.create_all(engine)
        
        # Test inserting records
        with SessionManager(engine) as session:
            # Test with default value (not specifying required_field)
            record1 = TestConstraintTable(name="test1")
            session.add(record1)
            session.commit()
            session.refresh(record1)
            assert record1.required_field == "default"
            
            # Test with explicit value
            record2 = TestConstraintTable(name="test2", required_field="custom")
            session.add(record2)
            session.commit()
            session.refresh(record2)
            assert record2.required_field == "custom"
            
            # Test with explicit NULL after insert (should fail)
            with pytest.raises(ValueError):
                record1.required_field = None
                session.commit()
            
            # Rollback after the expected error
            session.rollback()
            
            # Verify records are intact
            session.refresh(record1)
            session.refresh(record2)
            assert record1.required_field == "default"
            assert record2.required_field == "custom"
            
            # Verify only two records exist
            records = session.query(TestConstraintTable).all()
            assert len(records) == 2
            assert records[0].required_field == "default"
            assert records[1].required_field == "custom"
    
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_update_database_schema_invalid():
    """Test handling of invalid schema changes"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_schema_invalid.db")
    engine = create_engine(f"sqlite:///{db_path}")
    
    try:
        # Create initial table
        class TestInvalidTable(Base):
            __tablename__ = 'test_invalid_table'
            id = Column(Integer, primary_key=True)
            name = Column(String)
        
        Base.metadata.create_all(engine)
        
        # Add some initial data
        with SessionManager(engine) as session:
            test_record = TestInvalidTable(name="test1")
            session.add(test_record)
            session.commit()
        
        # Create a new table class that's not part of Base.metadata
        class InvalidTable:
            __tablename__ = 'test_invalid_table'
            id = Column(Integer, primary_key=True)
            name = Column(String)
            # Add an invalid column type (just a string instead of a proper type)
            invalid_column = Column('INVALID_TYPE')
        
        # Try to update schema with invalid column type
        assert update_database_schema(engine) is True  # Should succeed as invalid table is not in metadata
        
        # Verify original data is still intact
        with SessionManager(engine) as session:
            record = session.query(TestInvalidTable).first()
            assert record.name == "test1"
            # Verify invalid column was not added
            inspector = inspect(engine)
            columns = [c['name'] for c in inspector.get_columns('test_invalid_table')]
            assert 'invalid_column' not in columns
    
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_init_database_special_chars():
    """Test database initialization with special characters in path"""
    temp_dir = tempfile.mkdtemp()
    try:
        # Test with spaces and parentheses
        db_path1 = os.path.join(temp_dir, "test (1) with spaces.db")
        engine1 = init_database(db_path1)
        assert engine1 is not None
        
        # Verify database works
        with SessionManager(engine1) as session:
            host = Host(
                name="test-server",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
        engine1.dispose()
        
        # Test with underscores and hyphens
        db_path2 = os.path.join(temp_dir, "test_db-with-special_chars.db")
        engine2 = init_database(db_path2)
        assert engine2 is not None
        
        # Verify database works
        with SessionManager(engine2) as session:
            host = Host(
                name="test-server",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
        engine2.dispose()
        
        # Test with dots
        db_path3 = os.path.join(temp_dir, "test.db.backup.1")
        engine3 = init_database(db_path3)
        assert engine3 is not None
        
        # Verify database works
        with SessionManager(engine3) as session:
            host = Host(
                name="test-server",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
        engine3.dispose()
    
    finally:
        cleanup_temp_dir(temp_dir)

def test_init_database_long_path():
    """Test database initialization with very long path names"""
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a deeply nested directory structure
        deep_path = temp_dir
        for i in range(10):  # Create 10 levels of directories
            deep_path = os.path.join(deep_path, f"level_{i}_{'x' * 20}")  # 20 chars per level
        
        db_path = os.path.join(deep_path, "test.db")
        
        # Create all parent directories
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        engine = init_database(db_path)
        assert engine is not None
        
        # Verify database works
        with SessionManager(engine) as session:
            host = Host(
                name="test-server",
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            session.commit()
            
            result = session.query(Host).first()
            assert result is not None
            assert result.name == "test-server"
        
        engine.dispose()
    
    finally:
        cleanup_temp_dir(temp_dir)

def test_init_database_unicode():
    """Test database initialization with Unicode characters in path"""
    temp_dir = tempfile.mkdtemp()
    try:
        # Test with various Unicode characters
        test_paths = [
            os.path.join(temp_dir, "测试数据库.db"),  # Chinese
            os.path.join(temp_dir, "тестовая-база.db"),  # Russian
            os.path.join(temp_dir, "테스트-데이터베이스.db"),  # Korean
            os.path.join(temp_dir, "Prüfung_Äß.db"),  # German
            os.path.join(temp_dir, "base_de_données_éèê.db"),  # French
        ]
        
        for db_path in test_paths:
            try:
                engine = init_database(db_path)
                assert engine is not None
                
                # Verify database works
                with SessionManager(engine) as session:
                    host = Host(
                        name="test-server",
                        host_type=HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                    session.commit()
                    
                    result = session.query(Host).first()
                    assert result is not None
                    assert result.name == "test-server"
                
                engine.dispose()
            except Exception as e:
                # Some filesystems might not support all Unicode characters
                # Log the error but don't fail the test
                logger.warning(f"Could not create database with Unicode path {db_path}: {str(e)}")
    
    finally:
        cleanup_temp_dir(temp_dir)

def update_database_schema(engine):
    """
    Update database schema to include new tables and columns.
    
    This function performs the following operations:
    1. Inspects existing database schema
    2. Compares with defined models
    3. Creates missing tables
    4. Adds missing columns to existing tables
    
    Args:
        engine: SQLAlchemy engine instance
        
    Returns:
        bool: True if update successful, False otherwise
        
    Note:
        This operation is non-destructive and preserves existing data
    """
    try:
        logger.info("Checking for missing tables and columns...")
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        # Get all table names from our models
        model_tables = set(Base.metadata.tables.keys())
        
        # Find and create missing tables
        missing_tables = model_tables - set(existing_tables)
        if missing_tables:
            logger.info(f"Creating missing tables: {missing_tables}")
            for table_name in missing_tables:
                if table_name in Base.metadata.tables:
                    Base.metadata.tables[table_name].create(engine)
        
        # Update existing tables with missing columns
        for table_name in existing_tables:
            if table_name in Base.metadata.tables:
                model_columns = {c.name: c for c in Base.metadata.tables[table_name].columns}
                existing_columns = {c['name']: c for c in inspector.get_columns(table_name)}
                
                # Add missing columns
                missing_columns = set(model_columns.keys()) - set(existing_columns.keys())
                if missing_columns:
                    logger.info(f"Adding missing columns to {table_name}: {missing_columns}")
                    with engine.begin() as connection:
                        for column_name in missing_columns:
                            column = model_columns[column_name]
                            nullable = 'NOT NULL' if not column.nullable else ''
                            
                            # Handle default values
                            default = ''
                            if column.server_default is not None:
                                # For server_default, use the SQL text directly
                                default = f"DEFAULT {str(column.server_default.arg)}"
                            elif column.default is not None:
                                if isinstance(column.default.arg, str):
                                    default = f"DEFAULT '{column.default.arg}'"
                                else:
                                    default = f"DEFAULT {column.default.arg}"
                            
                            sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column.type} {nullable} {default}"
                            connection.execute(text(sql.strip()))
        
        logger.info("Database schema updated successfully")
        return True
            
    except Exception as e:
        logger.error(f"Failed to update database schema: {str(e)}")
        return False

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
    
    # Test with disposed engine
    engine = create_engine('sqlite:///:memory:')
    engine.dispose()
    session = get_session(engine)
    with pytest.raises(Exception):
        session.query(Host).all()
    
    # Test with invalid URL
    invalid_engine = create_engine('sqlite:///nonexistent/path/db.sqlite')
    session = get_session(invalid_engine)
    with pytest.raises(Exception):
        session.query(Host).all()

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
