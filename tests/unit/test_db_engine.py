from datetime import datetime
import json
import os
from pathlib import Path, WindowsPath
import shutil
import sqlite3
import stat
import tempfile
import time
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session
from infra_mgmt.db.engine import init_database, is_network_path, normalize_path
from infra_mgmt.models import Certificate, IgnoredCertificate, IgnoredDomain
from .test_helpers import cleanup_temp_dir
import sys


from infra_mgmt.settings import Settings, _is_network_path
# ... (add other necessary imports and fixtures)
# Paste the relevant test functions here from test_db.py 

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

def test_init_database_file_not_created():
    """Test database initialization when file is not created"""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "not_created.db")
    
    try:
        # Mock create_engine to simulate file not being created
        with patch('infra_mgmt.db.engine.create_engine') as mock_create_engine:
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
def test_path_handling_edge_cases():
    """Test path validation edge cases."""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Test with very long path
        long_path = Path("a" * 200 + ".db")
        with patch('infra_mgmt.db.engine.normalize_path') as mock_normalize:
            mock_normalize.return_value = long_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("test")
                with patch('os.access', return_value=True):
                    with patch('pathlib.Path.exists', return_value=False):
                        with patch('infra_mgmt.db.engine.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Database path too long")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(long_path))
                            assert "Database path too long" in str(exc_info.value)
        
        # Test with invalid path
        invalid_path = Path("test/db/with/invalid/chars/*.db")
        with patch('infra_mgmt.db.engine.normalize_path') as mock_normalize:
            mock_normalize.return_value = invalid_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("test")
                with patch('os.access', return_value=True):
                    with patch('pathlib.Path.exists', return_value=False):
                        with patch('infra_mgmt.db.engine.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Invalid database path")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(invalid_path))
                            assert "Invalid database path" in str(exc_info.value)
        
        # Test with relative path
        relative_path = Path("test.db")
        with patch('infra_mgmt.db.engine.normalize_path') as mock_normalize:
            mock_normalize.return_value = relative_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("test")
                with patch('os.access', return_value=True):
                    with patch('pathlib.Path.exists', return_value=False):
                        with patch('infra_mgmt.db.engine.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Database path must be absolute")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(relative_path))
                            assert "Database path must be absolute" in str(exc_info.value)
        
        # Test with nonexistent parent directory
        nonexistent_path = Path(temp_dir) / "nonexistent" / "test.db"
        with patch('infra_mgmt.db.engine.normalize_path') as mock_normalize:
            mock_normalize.return_value = nonexistent_path
            with patch('pathlib.Path.parent') as mock_parent:
                mock_parent.return_value = Path("nonexistent")
                with patch('pathlib.Path.exists') as mock_exists:
                    mock_exists.return_value = False
                    with patch('os.access', return_value=True):
                        with patch('infra_mgmt.db.engine.create_engine') as mock_create_engine:
                            mock_create_engine.side_effect = Exception("Parent directory does not exist")
                            with pytest.raises(Exception) as exc_info:
                                init_database(str(nonexistent_path))
                            assert "Parent directory does not exist" in str(exc_info.value)
    
    finally:
        cleanup_temp_dir(temp_dir)
@pytest.mark.skipif(sys.platform != 'win32', reason="Windows network path tests")
def test_network_path_handling():
    """Test handling of network share paths"""
    # Test network path detection
    assert is_network_path(Path('\\\\server\\share\\path')) is True
    assert is_network_path(Path('//server/share/path')) is True
    assert is_network_path(Path('C:\\path\\to\\file')) is False
    assert is_network_path(Path('/path/to/file')) is False
    
    # Test path normalization
    network_path = normalize_path('\\\\server\\share\\path\\db.sqlite')
    assert isinstance(network_path, WindowsPath)
    assert str(network_path) == '\\\\server\\share\\path\\db.sqlite'
    
    local_path = normalize_path('data/db.sqlite')
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
             patch('sqlalchemy.engine.Engine.connect') as mock_engine_connect, \
             patch('sqlalchemy.engine.Connection.execute') as mock_execute, \
             patch('infra_mgmt.db.engine.create_engine', return_value=mock_engine) as mock_create_engine, \
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
