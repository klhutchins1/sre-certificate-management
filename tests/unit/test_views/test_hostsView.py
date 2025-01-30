import pytest
from datetime import datetime, timedelta
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from cert_scanner.models import Base, Certificate, Host, HostIP, CertificateBinding
from cert_scanner.views.hostsView import render_hosts_view, render_binding_details
from cert_scanner.constants import platform_options

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
        
        # Mock AgGrid
        mock_st.AgGrid = MagicMock(return_value={'selected_rows': []})
        
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
    # Mock AgGrid to return no selection
    mock_streamlit.AgGrid.return_value = {'selected_rows': []}
    
    render_hosts_view(engine)
    
    # Verify title was set
    mock_streamlit.title.assert_called_once_with("Hosts")
    
    # Get the first set of columns (2 columns for metrics)
    mock_cols = mock_streamlit.columns.side_effect(2)
    
    # Verify metrics were displayed in columns
    mock_cols[0].metric.assert_called_once_with("Total IPs", 1)
    mock_cols[1].metric.assert_called_once_with("Total Hosts", 1)
    
    # Verify session was stored in session state
    mock_streamlit.session_state.__setitem__.assert_called_with('session', mock_streamlit.session_state.get.return_value)
    
    # Verify AgGrid was called
    mock_streamlit.AgGrid.assert_called_once()

def test_host_selection_handling(mock_streamlit, engine, sample_data):
    """Test handling of host selection in AG Grid"""
    # Mock grid response with both data and selection
    mock_streamlit.AgGrid.return_value = {
        'data': pd.DataFrame([{
            '_id': sample_data['binding'].id,
            'IP Address': sample_data['binding'].host_ip.ip_address,
            'Port': sample_data['binding'].port,
            'Platform': 'F5'
        }]),
        'selected_rows': [{
            '_id': sample_data['binding'].id,
            'IP Address': sample_data['binding'].host_ip.ip_address,
            'Port': sample_data['binding'].port
        }]
    }
    
    render_hosts_view(engine)
    
    # Verify binding details were displayed
    mock_streamlit.subheader.assert_called_with(f"🔗 {sample_data['binding'].host.name}")
    
    # Verify tabs were created for details
    mock_streamlit.tabs.assert_called_with(["Overview", "Certificate Details"])
    
    # Verify divider was added before details
    mock_streamlit.divider.assert_called()

def test_binding_details_render(mock_streamlit, sample_data):
    """Test rendering of binding details"""
    render_binding_details(sample_data['binding'])
    
    # Verify subheader was set
    mock_streamlit.subheader.assert_called_with(f"🔗 {sample_data['binding'].host.name}")
    
    # Verify tabs were created
    mock_streamlit.tabs.assert_called_with(["Overview", "Certificate Details"])
    
    # Verify markdown was called with binding details
    mock_streamlit.markdown.assert_any_call("""
                **IP Address:** 192.168.1.1  
                **Port:** 443  
                **Platform:** F5  
                **Last Seen:** {}
            """.format(sample_data['binding'].last_seen.strftime('%Y-%m-%d %H:%M')))

def test_ag_grid_configuration(mock_streamlit, engine, sample_data):
    """Test AG Grid configuration"""
    render_hosts_view(engine)
    
    # Get the AgGrid call arguments
    grid_call = mock_streamlit.AgGrid.call_args
    
    assert grid_call is not None
    kwargs = grid_call[1]
    
    # Verify grid configuration
    assert kwargs['update_mode'] == 'SELECTION_CHANGED'
    assert kwargs['data_return_mode'] == 'FILTERED'
    assert kwargs['fit_columns_on_grid_load'] is True
    assert kwargs['theme'] == 'streamlit'
    assert kwargs['allow_unsafe_jscode'] is True
    assert kwargs['key'] == 'host_grid'
    assert kwargs['enable_enterprise_modules'] is False
    assert kwargs['height'] == 400

def test_error_handling_in_selection(mock_streamlit, engine, sample_data):
    """Test error handling in selection processing"""
    # Mock AgGrid to return invalid data to trigger error
    mock_streamlit.AgGrid.return_value = {'selected_rows': [{'_id': 'invalid'}]}
    
    render_hosts_view(engine)
    
    # Verify error was displayed
    mock_streamlit.error.assert_called()

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

def test_platform_update(mock_streamlit, engine, sample_data):
    """Test platform update functionality in binding details"""
    # Mock session state to return a session
    mock_session = MagicMock()
    mock_streamlit.session_state.get.return_value = mock_session
    
    # Mock selectbox to return a new platform value
    mock_streamlit.selectbox.return_value = "Akamai"
    
    # Mock button click
    mock_streamlit.button.return_value = True
    
    # Render binding details
    render_binding_details(sample_data['binding'])
    
    # Verify platform selection was created
    mock_streamlit.selectbox.assert_any_call(
        "Platform",
        options=[''] + list(platform_options.keys()),
        format_func=mock_streamlit.selectbox.call_args[1]['format_func'],
        key=f"platform_select_{sample_data['binding'].id}",
        index=0
    )
    
    # Verify update button was created and clicked
    mock_streamlit.button.assert_called_with(
        "Update Platform",
        key=f"update_platform_{sample_data['binding'].id}",
        type="primary"
    )
    
    # Verify session commit was called
    mock_session.commit.assert_called_once()
    
    # Verify success message was shown inline
    mock_streamlit.success.assert_called_with("✅ Platform updated successfully!")

def test_inline_platform_update(mock_streamlit, engine, sample_data):
    """Test inline platform update functionality in AG Grid"""
    # Mock grid response with updated platform
    original_df = pd.DataFrame([{
        '_id': sample_data['binding'].id,
        'Platform': 'F5',
        'Hostname': sample_data['binding'].host.name
    }])
    
    updated_df = pd.DataFrame([{
        '_id': sample_data['binding'].id,
        'Platform': 'Akamai',
        'Hostname': sample_data['binding'].host.name
    }])
    
    mock_streamlit.AgGrid.return_value = {
        'data': updated_df,
        'selected_rows': []
    }
    
    render_hosts_view(engine)
    
    # Verify success message was shown inline
    mock_streamlit.success.assert_called_with(f"✅ Platform updated for {sample_data['binding'].host.name}")
    
    # Verify platform was updated in database
    with Session(engine) as session:
        binding = session.query(CertificateBinding).get(sample_data['binding'].id)
        assert binding.platform == 'Akamai'

def test_inline_platform_update_error(mock_streamlit, engine, sample_data):
    """Test error handling for inline platform update"""
    # Mock grid response with invalid binding ID
    updated_df = pd.DataFrame([{
        '_id': 99999,  # Invalid ID
        'Platform': 'Akamai',
        'Hostname': 'Invalid Host'
    }])
    
    mock_streamlit.AgGrid.return_value = {
        'data': updated_df,
        'selected_rows': []
    }
    
    render_hosts_view(engine)
    
    # Verify error message was shown
    mock_streamlit.error.assert_called()
    
    # Verify platform was not updated in database
    with Session(engine) as session:
        binding = session.query(CertificateBinding).get(sample_data['binding'].id)
        assert binding.platform == 'F5'  # Original platform value 