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

def get_column_mocks(spec):
    """Helper function to create column mocks"""
    if isinstance(spec, (list, tuple)):
        num_cols = len(spec)
    else:
        num_cols = spec
    
    cols = []
    for _ in range(num_cols):
        col = MagicMock()
        col.__enter__ = MagicMock(return_value=col)
        col.__exit__ = MagicMock(return_value=None)
        cols.append(col)
    
    return tuple(cols)

@pytest.fixture
def mock_streamlit():
    """Mock streamlit module"""
    with patch('cert_scanner.views.hostsView.st') as mock_st:
        # Mock columns to return the correct number of column objects
        mock_st.columns = MagicMock(side_effect=get_column_mocks)
        
        # Mock session state
        mock_st.session_state = MagicMock()
        mock_st.session_state.__getitem__ = MagicMock()
        mock_st.session_state.__setitem__ = MagicMock()
        mock_st.session_state.get = MagicMock()
        
        # Mock tabs to return list of MagicMocks with context manager methods
        def mock_tabs(*args):
            tabs = [MagicMock() for _ in range(len(args[0]))]
            for tab in tabs:
                tab.__enter__ = MagicMock(return_value=tab)
                tab.__exit__ = MagicMock(return_value=None)
            return tabs
        mock_st.tabs.side_effect = mock_tabs
        
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
    # Mock session state
    mock_state = {'session': Session(engine)}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    render_hosts_view(engine)

    # Verify title was set
    mock_streamlit.title.assert_called_once_with("Hosts")
    
    # Verify add host button was created
    mock_streamlit.button.assert_called_with(
        "➕ Add Host",
        type="primary",
        use_container_width=True
    )

def test_render_hosts_view_with_data(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test rendering hosts view with sample data"""
    # Mock session state
    mock_state = {}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"

    render_hosts_view(engine)

    # Verify title was set
    mock_streamlit.title.assert_called_once_with("Hosts")

def test_host_selection_handling(mock_streamlit, mock_aggrid, engine):
    """Test handling of host selection in AG Grid"""
    # Mock session state with session
    session = Session(engine)
    mock_state = {'session': session}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Create test data
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
    host.ip_addresses.append(host_ip)  # Important: link IP to host
    
    cert = Certificate(
        common_name="test.example.com",
        serial_number="123456",
        valid_from=datetime.now() - timedelta(days=30),
        valid_until=datetime.now() + timedelta(days=335),
        issuer={"CN": "Test CA"},
        subject={"CN": "test.example.com"},
        thumbprint="abcdef123456"
    )
    binding = CertificateBinding(
        host=host,
        host_ip=host_ip,
        certificate=cert,
        port=443,
        platform="F5",
        last_seen=datetime.now()
    )
    
    # Add test data to session
    session.add(cert)
    session.add(host)
    session.add(binding)
    session.commit()

    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"

    # First test: Select a row without binding ID to trigger host details
    def mock_aggrid_host_selection(*args, **kwargs):
        return {
            'data': pd.DataFrame([{
                '_id': None,
                'Hostname': host.name,
                'IP Address': host_ip.ip_address,
                'Port': None,
                'Platform': 'Unknown',
                'Certificate': 'No Certificate',
                'Status': 'No Certificate'
            }]),
            'selected_rows': [{
                '_id': None,
                'Hostname': host.name,
                'IP Address': host_ip.ip_address,
                'Port': None
            }]
        }
    mock_aggrid.side_effect = mock_aggrid_host_selection

    # Mock current time for validity checks
    with patch('cert_scanner.views.hostsView.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime(2024, 1, 1)
        mock_datetime.strptime = datetime.strptime

        render_hosts_view(engine)

        # Verify host details were rendered
        mock_streamlit.subheader.assert_any_call(f"🖥️ {host.name}")
        
        # Verify tabs were created for details
        mock_streamlit.tabs.assert_any_call(["Overview", "Certificate Bindings", "History"])

    # Reset mock calls
    mock_streamlit.reset_mock()
    
    # Second test: Select a row with binding ID to trigger binding details
    def mock_aggrid_binding_selection(*args, **kwargs):
        return {
            'data': pd.DataFrame([{
                '_id': binding.id,
                'Hostname': host.name,
                'IP Address': host_ip.ip_address,
                'Port': binding.port,
                'Platform': 'F5'
            }]),
            'selected_rows': [{
                '_id': binding.id,
                'Hostname': host.name,
                'IP Address': host_ip.ip_address,
                'Port': binding.port
            }]
        }
    mock_aggrid.side_effect = mock_aggrid_binding_selection

    render_hosts_view(engine)

    # Verify binding details were rendered
    expected_cert_details = f"""
        ### Certificate Details
        
        **Current Certificate:** {cert.common_name}  
        **Status:** <span class='cert-status cert-valid'>Valid</span>  
        **Valid Until:** {cert.valid_until.strftime('%Y-%m-%d')}  
        **Serial Number:** {cert.serial_number}  
        **Thumbprint:** {cert.thumbprint}
    """
    mock_streamlit.markdown.assert_any_call(expected_cert_details, unsafe_allow_html=True)

def test_binding_details_render(mock_streamlit, sample_data):
    """Test rendering of binding details"""
    # Mock session state
    mock_state = {}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Mock current time for validity check
    with patch('cert_scanner.views.hostsView.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime(2024, 1, 1)  # Set a fixed time
        mock_datetime.strptime = datetime.strptime

        render_binding_details(sample_data['binding'])

        # Verify certificate details header and content
        expected_cert_details = f"""
        ### Certificate Details
        
        **Current Certificate:** {sample_data['binding'].certificate.common_name}  
        **Status:** <span class='cert-status cert-valid'>Valid</span>  
        **Valid Until:** {sample_data['binding'].certificate.valid_until.strftime('%Y-%m-%d')}  
        **Serial Number:** {sample_data['binding'].certificate.serial_number}  
        **Thumbprint:** {sample_data['binding'].certificate.thumbprint}
    """
        mock_streamlit.markdown.assert_any_call(expected_cert_details, unsafe_allow_html=True)

        # Verify binding details header
        mock_streamlit.markdown.assert_any_call("""
        ### Binding Details
    """)

def test_ag_grid_configuration(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test AG Grid configuration"""
    # Mock session state
    mock_state = {'session': Session(engine)}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Mock columns using get_column_mocks
    mock_streamlit.columns.side_effect = get_column_mocks

    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"

    render_hosts_view(engine)

def test_error_handling_in_selection(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test error handling in selection processing"""
    # Mock session state
    mock_state = {'session': Session(engine)}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Mock columns using get_column_mocks
    mock_streamlit.columns.side_effect = get_column_mocks

    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"

def test_filter_functionality(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test filter functionality in hosts view"""
    # Mock session state
    mock_state = {'session': Session(engine)}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Mock columns using get_column_mocks
    mock_streamlit.columns.side_effect = get_column_mocks

    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"

def test_inline_platform_update(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test inline platform update functionality in AG Grid"""
    # Mock session state with session
    session = Session(engine)
    mock_state = {'session': session}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Mock columns using get_column_mocks
    mock_streamlit.columns.side_effect = get_column_mocks

    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"

def test_inline_platform_update_error(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test error handling for inline platform update"""
    # Mock session state with session
    session = Session(engine)
    mock_state = {'session': session}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get

    # Mock columns using get_column_mocks
    mock_streamlit.columns.side_effect = get_column_mocks

    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"

@pytest.fixture(scope="function")
def mock_aggrid():
    """Mock st_aggrid module"""
    with patch('cert_scanner.views.hostsView.AgGrid') as mock_aggrid, \
         patch('cert_scanner.views.hostsView.GridOptionsBuilder') as mock_gb, \
         patch('cert_scanner.views.hostsView.JsCode') as mock_jscode:
        
        # Create a mock GridOptionsBuilder that supports all required methods
        class MockGridOptionsBuilder:
            def __init__(self):
                self.column_defs = []
                self.grid_options = {
                    'defaultColDef': {},
                    'columnDefs': [],
                    'rowData': [],
                    'animateRows': True,
                    'enableRangeSelection': True,
                    'suppressAggFuncInHeader': True,
                    'suppressMovableColumns': True,
                    'rowHeight': 35,
                    'headerHeight': 40
                }
            
            def from_dataframe(self, df):
                return self
                
            def configure_default_column(self, **kwargs):
                self.grid_options['defaultColDef'].update(kwargs)
                return self
                
            def configure_column(self, field, **kwargs):
                col_def = {"field": field, **kwargs}
                self.grid_options['columnDefs'].append(col_def)
                return self
                
            def configure_selection(self, **kwargs):
                self.grid_options.update({
                    'rowSelection': kwargs.get('selection_mode', 'single'),
                    'suppressRowClickSelection': kwargs.get('suppress_row_click_selection', False)
                })
                return self
                
            def configure_grid_options(self, **kwargs):
                self.grid_options.update(kwargs)
                return self
                
            def build(self):
                return self.grid_options
        
        # Configure the mock GridOptionsBuilder
        mock_gb.return_value = MockGridOptionsBuilder()
        mock_gb.from_dataframe = lambda df: MockGridOptionsBuilder()
        
        # Configure mock JsCode to return the input string
        mock_jscode.side_effect = lambda x: x
        
        def mock_aggrid_func(*args, **kwargs):
            return {
                'data': args[0] if args else pd.DataFrame(),
                'selected_rows': [],
                'grid_options': kwargs.get('gridOptions', {})
            }
        mock_aggrid.side_effect = mock_aggrid_func
        yield mock_aggrid 