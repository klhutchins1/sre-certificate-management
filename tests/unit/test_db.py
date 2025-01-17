import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from cert_scanner.db import init_database, get_session
from cert_scanner.models import Base, Certificate, Host, HostIP
from datetime import datetime
import os
import tempfile
import shutil
import time

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

def test_get_session(test_db):
    """Test session creation and management"""
    # Get a session
    session = get_session(test_db)
    assert session is not None
    
    # Test session can perform operations
    cert = Certificate(
        serial_number="test456",
        thumbprint="def456",
        common_name="example.com",
        valid_from=datetime.now(),
        valid_until=datetime.now(),
        issuer="Test CA",
        subject="CN=example.com",
        san="example.com"
    )
    session.add(cert)
    session.commit()
    
    # Verify operation worked
    result = session.query(Certificate).filter_by(serial_number="test456").first()
    assert result is not None
    assert result.serial_number == "test456"
    
    # Clean up
    session.close()

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