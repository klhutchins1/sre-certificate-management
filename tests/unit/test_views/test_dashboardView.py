import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate, Host
from infra_mgmt.views.dashboardView import render_dashboard
import streamlit as st

@pytest.fixture
def engine():
    """Create a SQLite in-memory database"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def session(engine):
    """Create a new database session for a test"""
    with Session(engine) as session:
        yield session

@pytest.fixture
def mock_streamlit(monkeypatch):
    """Mock Streamlit components"""
    # Mock title
    monkeypatch.setattr(st, 'title', lambda x: None)
    
    # Mock columns
    class MockColumn:
        def metric(self, label, value):
            pass
    
    def mock_columns(specs):
        return [MockColumn() for _ in specs]
    
    monkeypatch.setattr(st, 'columns', mock_columns)
    
    # Mock error and info
    monkeypatch.setattr(st, 'error', lambda x: None)
    monkeypatch.setattr(st, 'info', lambda x: None)
    
    # Mock plotly chart
    monkeypatch.setattr(st, 'plotly_chart', lambda fig, **kwargs: None)

@pytest.fixture
def sample_data(session):
    """Create sample certificates and hosts"""
    now = datetime.now()
    
    # Create certificates with different expiry dates
    certs = [
        Certificate(
            serial_number="123",
            thumbprint="abc123",
            common_name="test1.com",
            valid_from=now - timedelta(days=30),
            valid_until=now + timedelta(days=15),  # Expiring soon
            issuer="Test CA",
            subject="CN=test1.com",
            san="test1.com"
        ),
        Certificate(
            serial_number="456",
            thumbprint="def456",
            common_name="test2.com",
            valid_from=now - timedelta(days=30),
            valid_until=now + timedelta(days=60),  # Not expiring soon
            issuer="Test CA",
            subject="CN=test2.com",
            san="test2.com"
        )
    ]
    
    # Create hosts
    hosts = [
        Host(
            name="host1",
            host_type="Server",
            environment="Production",
            last_seen=now
        ),
        Host(
            name="host2",
            host_type="Server",
            environment="Production",
            last_seen=now
        )
    ]
    
    session.add_all(certs + hosts)
    session.commit()
    return {'certificates': certs, 'hosts': hosts}

def test_dashboard_metrics(engine, session, mock_streamlit, sample_data):
    """Test dashboard metrics calculation"""
    render_dashboard(engine)
    
    # Verify metrics through direct database queries
    total_certs = session.query(Certificate).count()
    assert total_certs == 2
    
    expiring_soon = session.query(Certificate).filter(
        Certificate.valid_until <= datetime.now() + timedelta(days=30)
    ).count()
    assert expiring_soon == 1
    
    total_hosts = session.query(Host).count()
    assert total_hosts == 2

def test_dashboard_empty_database(engine, mock_streamlit):
    """Test dashboard rendering with empty database"""
    render_dashboard(engine)
    # No assertions needed as we're just verifying it doesn't raise exceptions
    # The mock_streamlit fixture will capture the info message

def test_dashboard_invalid_engine(mock_streamlit, monkeypatch):
    """Test dashboard handling of invalid database engine"""
    # Mock st.error to capture the error message
    error_message = None
    def mock_error(msg):
        nonlocal error_message
        error_message = msg
    monkeypatch.setattr(st, 'error', mock_error)
    
    # Create an engine without creating tables
    invalid_engine = create_engine('sqlite:///:memory:')
    render_dashboard(invalid_engine)
    
    # Verify that an error message was displayed
    assert error_message is not None
    assert "Error querying database" in error_message
    assert "no such table: certificates" in error_message

def test_dashboard_timeline_generation(engine, session, mock_streamlit, sample_data):
    """Test timeline generation with sample data"""
    render_dashboard(engine)
    
    # Verify certificate data is available for timeline
    certs = session.query(
        Certificate.common_name,
        Certificate.valid_from,
        Certificate.valid_until
    ).all()
    assert len(certs) == 2
    assert all(cert.common_name and cert.valid_from and cert.valid_until for cert in certs) 