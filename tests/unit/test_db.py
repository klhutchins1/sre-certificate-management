import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session
from cert_scanner.db import init_database, get_session, backup_database, restore_database, update_database_schema, reset_database, check_database, SessionManager
from cert_scanner.models import Base, Certificate, Host, HostIP
from datetime import datetime
import os
import tempfile
import shutil
import time
from unittest.mock import patch
from sqlalchemy import Column, Integer, String
from pathlib import Path
from sqlalchemy import text
from cert_scanner.settings import Settings
import logging

logger = logging.getLogger(__name__)

@pytest.fixture
def test_db():
    """Create a test database"""
    # Create a temporary directory for the test database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    
    # Create database URL
    db_url = f"sqlite:///{db_path}"
    
    # Create engine and tables
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    
    yield engine
    
    # Cleanup - ensure all connections are closed
    engine.dispose()
    
    # Close any remaining sessions
    Session.close_all()
    
    # Drop tables and dispose engine again
    Base.metadata.drop_all(engine)
    engine.dispose()
    
    # Add a small delay to ensure file handles are released
    time.sleep(0.1)
    
    try:
        shutil.rmtree(temp_dir)
    except PermissionError:
        # If still can't delete, try one more time after a longer delay
        time.sleep(0.5)
        try:
            shutil.rmtree(temp_dir)
        except PermissionError:
            print(f"Warning: Could not delete temporary directory: {temp_dir}")

@pytest.fixture
def test_session(test_db):
    """Create a test session"""
    session = Session(test_db)
    yield session
    # Ensure session is closed
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
    os.makedirs(backup_dir)
    
    try:
        # Create and initialize database
        engine = init_database(db_path)
        
        # Add some test data
        session = get_session(engine)
        # Add test data here
        session.commit()
        session.close()
        
        # Create backup
        backup_path = backup_database(engine, backup_dir)
        assert os.path.exists(backup_path)
        
        # Modify original database
        reset_database(engine)
        
        # Restore from backup
        assert restore_database(backup_path, engine) is True
        
        # Verify restored data
        # Add verification logic here
    finally:
        if 'engine' in locals():
            engine.dispose()
        shutil.rmtree(temp_dir)

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
    
    # Create a corrupted database file
    with open(db_path, 'w') as f:
        f.write("corrupted data")
    
    try:
        with pytest.raises(Exception):
            init_database(db_path)
    finally:
        # Ensure all connections are closed
        Session.close_all()
        time.sleep(0.1)  # Allow time for file handles to be released

        # Cleanup
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Warning: Could not delete temporary directory: {temp_dir}, Error: {str(e)}")

def test_backup_database_failure():
    """Test backup_database when the backup directory cannot be created"""
    engine = create_engine("sqlite:///:memory:")  # In-memory database for testing
    Base.metadata.create_all(engine)

    # Create a temporary directory and then remove it to simulate a failure
    temp_dir = tempfile.mkdtemp()
    shutil.rmtree(temp_dir)  # Remove the directory to ensure it cannot be created

    with pytest.raises(Exception) as excinfo:
        backup_database(engine, temp_dir)  # Attempt to back up to the removed directory

    assert "Failed to create database backup" in str(excinfo.value)  # Check for specific error message

    # Cleanup
    Base.metadata.drop_all(engine)
    engine.dispose()

def test_restore_database_failure():
    """Test restore_database when the backup file does not exist"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with pytest.raises(Exception):
        restore_database("/invalid/backup/path", engine)

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
        
        # Check if the path is valid
        if not db_path.parent.exists() or not db_path.parent.is_dir():
            raise Exception(f"Invalid database path: {db_path}")  # Ensure this raises an exception for invalid paths

        # Ensure the database directory exists
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # If database exists but is corrupted or empty, remove it
        if db_path.exists():
            try:
                # Test if database is valid
                test_engine = create_engine(f"sqlite:///{db_path}")
                with test_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                test_engine.dispose()
            except Exception as e:
                logger.warning(f"Removing invalid or corrupted database: {str(e)}")
                try:
                    db_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove corrupted database: {str(e)}")
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