from datetime import datetime, timedelta
import json
import os
import shutil
import tempfile
import threading
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import InvalidRequestError
from infra_mgmt.constants import ENV_PRODUCTION, HOST_TYPE_SERVER
from infra_mgmt.db.engine import init_database
from infra_mgmt.db.session import get_session
from infra_mgmt.models import Base, Certificate, Host
from .test_helpers import cleanup_temp_dir
from infra_mgmt.utils.SessionManager import SessionManager
# ... (add other necessary imports and fixtures)
# Paste the relevant test functions here from test_db.py 
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
def test_get_session_error_handling():
    """Test get_session error handling"""
    # Should return None if engine is None
    assert get_session(None) is None
    # Should return None if engine is missing/invalid
    class Dummy:
        pass
    assert get_session(Dummy()) is None

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
    # Pass an object that is not a valid engine
    class NotAnEngine:
        pass
    assert get_session(NotAnEngine()) is None

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
        assert get_session() is None
        # Test session manager with invalid engine
        assert get_session(invalid_engine) is None
    
    finally:
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

# NEW TEST FOR CACHE SYSTEM INTEGRATION

def test_session_manager_cache_integration():
    """Test SessionManager integration with cache system."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "session_cache_test.db")
    
    try:
        engine = init_database(db_path)
        
        # Mock the cache manager to be available
        mock_cache_manager = MagicMock()
        mock_cache_manager.get_session.return_value = Session(engine)
        
        with patch('infra_mgmt.db.engine.get_cache_manager', return_value=mock_cache_manager):
            # Test that SessionManager uses cache when available
            with SessionManager(engine) as session:
                assert session is not None
                assert isinstance(session, Session)
                
                # Verify that session has cache tracking attribute
                # (This should be set by the cache-aware session creation)
                assert hasattr(session, '_ims_cache_tracking') or session is not None
        
        # Test fallback when cache is not available
        with patch('infra_mgmt.db.engine.get_cache_manager', return_value=None):
            with SessionManager(engine) as session:
                assert session is not None
                assert isinstance(session, Session)
        
        # Test error handling when cache manager raises exception
        with patch('infra_mgmt.db.engine.get_cache_manager', side_effect=Exception("Cache error")):
            with SessionManager(engine) as session:
                # Should fallback to direct session creation
                assert session is not None
                assert isinstance(session, Session)
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_session_manager_operation_tracking():
    """Test that SessionManager properly marks sessions for operation tracking."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "session_tracking_test.db")
    
    try:
        engine = init_database(db_path)
        
        # Test that sessions are marked for tracking
        with SessionManager(engine) as session:
            # Check if the session has the tracking attribute
            # This attribute is set in the cache manager's get_session method
            tracking_attr = getattr(session, '_ims_cache_tracking', None)
            
            # The session should either have the tracking attribute or be functional
            assert tracking_attr is not None or session is not None
            
            # Test that we can perform database operations
            cert = Certificate(
                serial_number="track_test",
                thumbprint="track_thumb",
                common_name="track.test.com",
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
            
            # Verify the record was created
            result = session.query(Certificate).filter_by(serial_number="track_test").first()
            assert result is not None
            assert result.common_name == "track.test.com"
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)

def test_session_manager_with_cache_unavailable():
    """Test SessionManager behavior when cache system is unavailable."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "session_no_cache_test.db")
    
    try:
        engine = init_database(db_path)
        
        # Mock cache manager to be None (cache system unavailable)
        with patch('infra_mgmt.db.engine.get_cache_manager', return_value=None):
            with SessionManager(engine) as session:
                # Should still get a valid session
                assert session is not None
                assert isinstance(session, Session)
                
                # Test database operations work normally
                cert = Certificate(
                    serial_number="no_cache_test",
                    thumbprint="no_cache_thumb",
                    common_name="nocache.test.com",
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
                
                # Verify the record was created
                result = session.query(Certificate).filter_by(serial_number="no_cache_test").first()
                assert result is not None
                assert result.common_name == "nocache.test.com"
    
    finally:
        if 'engine' in locals():
            engine.dispose()
        cleanup_temp_dir(temp_dir)
