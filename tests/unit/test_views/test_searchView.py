import pytest
from datetime import datetime, timedelta
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from infra_mgmt.models import Base, Certificate, Host, HostIP, CertificateBinding
from infra_mgmt.views.searchView import render_search_view
from unittest.mock import ANY

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
    with patch('infra_mgmt.views.searchView.st') as mock_st, \
         patch('infra_mgmt.components.page_header.st') as mock_header_st:
        # Create persistent column mocks
        column_mocks = {}
        def get_column_mocks(*args):
            num_cols = len(args[0]) if isinstance(args[0], (list, tuple)) else args[0]
            key = f"cols_{num_cols}"
            if key not in column_mocks:
                column_mocks[key] = [MagicMock(name=f"col_{i}") for i in range(num_cols)]
            return column_mocks[key]
        mock_st.columns.side_effect = get_column_mocks
        mock_header_st.columns.side_effect = get_column_mocks
        # Mock session state
        mock_st.session_state = MagicMock()
        mock_st.session_state.__setitem__ = MagicMock()
        mock_st.session_state.__getitem__ = MagicMock()
        mock_st.session_state.get = MagicMock()
        yield (mock_st, mock_header_st)

@pytest.fixture
def sample_data(session):
    """Create sample data for testing"""
    # Create certificates
    cert1 = Certificate(
        common_name="test.example.com",
        serial_number="123456",
        valid_from=datetime.now() - timedelta(days=30),
        valid_until=datetime.now() + timedelta(days=335),
        issuer={"CN": "Test CA"},
        subject={"CN": "test.example.com"},
        san='["test.example.com", "*.example.com"]',
        thumbprint="abcdef123456"
    )
    
    cert2 = Certificate(
        common_name="expired.example.com",
        serial_number="654321",
        valid_from=datetime.now() - timedelta(days=395),
        valid_until=datetime.now() - timedelta(days=30),
        issuer={"CN": "Test CA"},
        subject={"CN": "expired.example.com"},
        san='["expired.example.com"]',
        thumbprint="fedcba654321"
    )
    
    # Create hosts and IPs
    host1 = Host(
        name="test-host",
        host_type="Server",
        environment="Production",
        last_seen=datetime.now()
    )
    host_ip1 = HostIP(
        ip_address="192.168.1.1",
        is_active=True,
        last_seen=datetime.now()
    )
    host1.ip_addresses.append(host_ip1)
    
    host2 = Host(
        name="prod-host",
        host_type="Server",
        environment="Production",
        last_seen=datetime.now()
    )
    host_ip2 = HostIP(
        ip_address="192.168.1.2",
        is_active=True,
        last_seen=datetime.now()
    )
    host2.ip_addresses.append(host_ip2)
    
    # Create bindings
    binding1 = CertificateBinding(
        host=host1,
        host_ip=host_ip1,
        certificate=cert1,
        port=443,
        platform="F5",
        last_seen=datetime.now()
    )
    
    binding2 = CertificateBinding(
        host=host2,
        host_ip=host_ip2,
        certificate=cert2,
        port=443,
        platform="Akamai",
        last_seen=datetime.now()
    )
    
    session.add_all([cert1, cert2, host1, host2, binding1, binding2])
    session.commit()
    
    return {
        'certificates': [cert1, cert2],
        'hosts': [host1, host2],
        'bindings': [binding1, binding2]
    }

def test_render_search_view_empty(mock_streamlit, engine):
    mock_st, mock_header_st = mock_streamlit
    # Mock search input and filters
    mock_st.text_input.return_value = "nonexistentquery123456789"  # Use a query that won't match anything
    mock_st.selectbox.side_effect = [
        "All",          # Search type
        "All",          # Status filter
        "All"           # Platform filter
    ]
    render_search_view(engine)
    # Check that the header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Search</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"
    # Verify empty state message
    mock_st.info.assert_called_once_with("No results found")

def test_render_search_view_with_data(mock_streamlit, engine, sample_data):
    mock_st, mock_header_st = mock_streamlit
    # Mock search input and filters
    mock_st.text_input.return_value = "test"
    mock_st.selectbox.side_effect = [
        "All",          # Search type
        "All",          # Status filter
        "All"           # Platform filter
    ]
    render_search_view(engine)
    # Check that the header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Search</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"
    # Verify subheaders for both sections
    mock_st.subheader.assert_any_call("Certificates")
    mock_st.subheader.assert_any_call("Hosts")
    # Verify dataframes were created
    assert mock_st.dataframe.call_count == 2

def test_certificate_search(mock_streamlit, engine, sample_data):
    mock_st, mock_header_st = mock_streamlit
    # Mock search input and filters
    mock_st.text_input.return_value = "test.example.com"
    mock_st.selectbox.side_effect = [
        "Certificates",  # Search type
        "Valid",         # Status filter
        "F5"            # Platform filter
    ]
    render_search_view(engine)
    # Verify only certificate results are shown
    mock_st.subheader.assert_called_once_with("Certificates")
    mock_st.dataframe.assert_called_once()

def test_host_search(mock_streamlit, engine, sample_data):
    mock_st, mock_header_st = mock_streamlit
    # Mock search input and filters
    mock_st.text_input.return_value = "test-host"
    mock_st.selectbox.side_effect = [
        "Hosts",        # Search type
        "Valid",        # Status filter
        "F5"           # Platform filter
    ]
    render_search_view(engine)
    # Verify only host results are shown
    mock_st.subheader.assert_called_once_with("Hosts")
    mock_st.dataframe.assert_called_once()

def test_ip_search(mock_streamlit, engine, sample_data):
    mock_st, mock_header_st = mock_streamlit
    # Mock search input and filters
    mock_st.text_input.return_value = "192.168.1"
    mock_st.selectbox.side_effect = [
        "IP Addresses", # Search type
        "All",         # Status filter
        "All"          # Platform filter
    ]
    render_search_view(engine)
    # Verify host results are shown (IP search shows in host section)
    mock_st.subheader.assert_called_once_with("Hosts")
    mock_st.dataframe.assert_called_once()

def test_filter_functionality(mock_streamlit, engine, sample_data):
    mock_st, mock_header_st = mock_streamlit
    # Mock search input and filters
    mock_st.text_input.return_value = "example.com"
    mock_st.selectbox.side_effect = [
        "All",         # Search type
        "Valid",       # Status filter
        "F5"          # Platform filter
    ]
    render_search_view(engine)
    # Verify filter options were created
    mock_st.selectbox.assert_any_call(
        "Search In",
        ["All", "Certificates", "Hosts", "IP Addresses"]
    )
    mock_st.selectbox.assert_any_call(
        "Certificate Status",
        ["All", "Valid", "Expired"]
    ) 