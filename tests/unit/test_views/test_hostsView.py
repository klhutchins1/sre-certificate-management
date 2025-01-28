import pytest
from datetime import datetime, timedelta
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from cert_scanner.models import Base, Certificate, Host, HostIP, CertificateBinding
from cert_scanner.views.hostsView import render_hosts_view

@pytest.fixture(scope="function")
def engine():
    """Create in-memory database for testing"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture(scope="function")
def session(engine):
    """Create database session"""
    Session = scoped_session(sessionmaker(bind=engine))
    session = Session()
    yield session
    session.close()
    Session.remove()

@pytest.fixture
def mock_streamlit():
    """Mock streamlit module"""
    with patch('cert_scanner.views.hostsView.st') as mock_st:
        # Create persistent column mocks
        column_mocks = {}
        def get_column_mocks(*args):
            num_cols = len(args[0]) if isinstance(args[0], (list, tuple)) else args[0]
            key = f"cols_{num_cols}"
            if key not in column_mocks:
                column_mocks[key] = [MagicMock(name=f"col_{i}") for i in range(num_cols)]
            return column_mocks[key]
        mock_st.columns.side_effect = get_column_mocks
        
        # Mock tabs to return list of MagicMocks with context manager methods
        def mock_tabs(*args):
            tabs = [MagicMock() for _ in range(len(args[0]))]
            for tab in tabs:
                tab.__enter__ = MagicMock(return_value=tab)
                tab.__exit__ = MagicMock(return_value=None)
            return tabs
        mock_st.tabs.side_effect = mock_tabs
        
        # Mock session state
        mock_st.session_state = MagicMock()
        mock_st.session_state.__setitem__ = MagicMock()
        mock_st.session_state.__getitem__ = MagicMock()
        mock_st.session_state.get = MagicMock()
        
        yield mock_st

@pytest.fixture
def sample_data(session):
    """Create sample data for testing"""
    # Create certificate
    cert = Certificate(
        common_name="test.example.com",
        serial_number="123456",
        valid_from=datetime.now() - timedelta(days=30),
        valid_until=datetime.now() + timedelta(days=335),
        issuer={"CN": "Test CA"},
        subject={"CN": "test.example.com"},
        thumbprint="abcdef123456"
    )
    
    # Create host and IP
    host = Host(
        name="test-host",
        host_type="Server",
        environment="Production",
        last_seen=datetime.now()
    )
    host_ip = HostIP(
        ip_address="192.168.1.1",
        is_active=True,
        last_seen=datetime.now()
    )
    host.ip_addresses.append(host_ip)
    
    # Create binding
    binding = CertificateBinding(
        host=host,
        host_ip=host_ip,
        certificate=cert,
        port=443,
        platform="F5",
        last_seen=datetime.now()
    )
    
    session.add_all([cert, host, binding])
    session.commit()
    
    return {
        'certificate': cert,
        'host': host,
        'binding': binding
    }

def test_render_hosts_view_empty(mock_streamlit, engine):
    """Test rendering hosts view with no data"""
    render_hosts_view(engine)
    
    # Verify title was set
    mock_streamlit.title.assert_called_once_with("Hosts")
    
    # Verify empty state warning
    mock_streamlit.warning.assert_called_once_with("No certificate bindings found in database")

def test_render_hosts_view_with_data(mock_streamlit, engine, sample_data):
    """Test rendering hosts view with sample data"""
    # Mock filter selections
    mock_streamlit.selectbox.side_effect = [
        "All",          # Platform filter
        "All",          # Status filter
        "All",          # Port filter
        None           # IP:Port selection
    ]
    
    render_hosts_view(engine)
    
    # Verify title was set
    mock_streamlit.title.assert_called_once_with("Hosts")
    
    # Get the first set of columns (2 columns for metrics)
    mock_cols = mock_streamlit.columns.side_effect(2)
    
    # Verify metrics were displayed in columns
    mock_cols[0].metric.assert_called_once_with("Total IPs", 1)
    mock_cols[1].metric.assert_called_once_with("Total Hosts", 1)
    
    # Verify dataframe was created
    mock_streamlit.dataframe.assert_called()

def test_host_details_display(mock_streamlit, engine, sample_data):
    """Test displaying host details when IP:Port is selected"""
    # Mock filter and selection values
    mock_streamlit.selectbox.side_effect = [
        "All",          # Platform filter
        "All",          # Status filter
        "All",          # Port filter
        f"{sample_data['binding'].host_ip.ip_address}:{sample_data['binding'].port}"  # IP:Port selection
    ]
    
    render_hosts_view(engine)
    
    # Verify binding details were displayed
    mock_streamlit.subheader.assert_any_call(
        f"Binding Details: {sample_data['binding'].host_ip.ip_address}:{sample_data['binding'].port}"
    )
    
    # Verify metrics
    mock_streamlit.metric.assert_any_call("Platform", "F5")
    mock_streamlit.metric.assert_any_call("Status", "Valid")
    
    # Verify tabs were created
    mock_streamlit.tabs.assert_called_with(["Certificate Details", "History"])

def test_filter_functionality(mock_streamlit, engine, sample_data):
    """Test filter functionality in hosts view"""
    # Mock filter selections
    mock_streamlit.selectbox.side_effect = [
        "F5",           # Platform filter
        "Valid",        # Status filter
        "443",          # Port filter
        None           # IP:Port selection
    ]
    
    render_hosts_view(engine)
    
    # Verify filter options were created
    mock_streamlit.selectbox.assert_any_call(
        'Filter by Platform',
        ['All', 'F5']
    )
    mock_streamlit.selectbox.assert_any_call(
        'Filter by Status',
        ['All', 'Valid']
    )
    mock_streamlit.selectbox.assert_any_call(
        'Filter by Port',
        ['All', 443]
    ) 