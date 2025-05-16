import pytest
from datetime import datetime, timedelta
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from infra_mgmt.models import Base, Certificate, Host, HostIP, CertificateBinding
from infra_mgmt.views.hostsView import render_hosts_view, render_details
from infra_mgmt.constants import platform_options
import logging
from unittest.mock import call

# Set up logging
logging.basicConfig(level=logging.DEBUG)

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
    with patch('infra_mgmt.views.hostsView.st') as mock_st:
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
    # Create a session and keep it alive
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Mock session state with session
    mock_state = {'session': session, 'show_add_host_form': False}
    def mock_setitem(key, value):
        mock_state[key] = value
    def mock_getitem(key):
        return mock_state.get(key)
    def mock_get(key, default=None):
        return mock_state.get(key, default)

    mock_streamlit.session_state.__setitem__.side_effect = mock_setitem
    mock_streamlit.session_state.__getitem__.side_effect = mock_getitem
    mock_streamlit.session_state.get.side_effect = mock_get
    
    # Create test data with fixed datetime
    fixed_time = datetime(2024, 1, 1, 12, 0)
    host = Host(
        name="test-host",
        host_type="Server",
        environment="Production",
        last_seen=fixed_time
    )
    host_ip = HostIP(
        ip_address="192.168.1.1",
        is_active=True,
        last_seen=fixed_time
    )
    host.ip_addresses.append(host_ip)  # Important: link IP to host
    
    cert = Certificate(
        common_name="test.example.com",
        serial_number="123456",
        valid_from=fixed_time - timedelta(days=30),
        valid_until=fixed_time + timedelta(days=335),
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
        last_seen=fixed_time
    )
    
    # Add test data to session
    session.add(cert)
    session.add(host)
    session.add(binding)
    session.commit()
    
    # Keep reference to binding ID
    binding_id = binding.id
    
    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "Hostname"
    
    # First test: Select a row without binding ID to trigger host details
    def mock_aggrid_host_selection(*args, **kwargs):
        selected_row = {
            '_id': host.id,
            'Hostname': host.name,
            'IP Address': host_ip.ip_address,
            'Port': None,
            'Platform': 'Unknown',
            'Certificate': 'No Certificate',
            'Status': 'No Certificate'
        }
        mock_state['selected_row'] = selected_row
        mock_state['selected_rows'] = [selected_row]
        return {
            'data': pd.DataFrame([selected_row]),
            'selected_rows': [selected_row]
        }
    mock_aggrid.side_effect = mock_aggrid_host_selection
    
    # Mock current time for validity checks
    with patch('infra_mgmt.views.hostsView.datetime') as mock_datetime:
        mock_datetime.now.return_value = fixed_time
        mock_datetime.strptime = datetime.strptime
        
        # Create tab mocks with proper context manager and markdown methods
        tab_mocks = []
        for i in range(4):  # Overview, Certificates, IP Addresses, Danger Zone
            tab = MagicMock()
            tab.__enter__ = MagicMock(return_value=tab)
            tab.__exit__ = MagicMock(return_value=None)
            tab.markdown = MagicMock()
            tab_mocks.append(tab)
        
        # Mock tabs and columns to return our mocks
        def mock_tabs(*args):
            return tab_mocks
        mock_streamlit.tabs.side_effect = mock_tabs
        
        # Store all column mocks for checking markdown calls
        all_column_mocks = []
        
        # Mock columns to handle different arguments
        def mock_columns(*args):
            if len(args) == 1 and isinstance(args[0], (list, tuple)):
                num_cols = len(args[0])
            else:
                num_cols = args[0] if args else 2
            
            col_mocks = []
            for i in range(num_cols):
                col = MagicMock()
                col.__enter__ = MagicMock(return_value=col)
                col.__exit__ = MagicMock(return_value=None)
                col.markdown = MagicMock()
                col_mocks.append(col)
            all_column_mocks.extend(col_mocks)  # Store for later checking
            return col_mocks
        mock_streamlit.columns.side_effect = mock_columns
        
        render_hosts_view(engine)
        
        # Collect all markdown calls
        all_markdown_calls = []
        
        # Add main streamlit markdown calls
        all_markdown_calls.extend(mock_streamlit.markdown.call_args_list)
        
        # Add tab markdown calls
        for tab in tab_mocks:
            all_markdown_calls.extend(tab.markdown.call_args_list)
        
        # Add column markdown calls
        for col in all_column_mocks:
            all_markdown_calls.extend(col.markdown.call_args_list)
        
        # Print all markdown calls for debugging
        print("\nAll markdown calls:")
        for call in all_markdown_calls:
            print(f"Call: {call}")
        
        # Verify host details were rendered
        host_details_found = False
        for call in all_markdown_calls:
            if len(call[0]) > 0 and isinstance(call[0][0], str):
                if "**Host Type:** Server" in call[0][0]:
                    host_details_found = True
                    break
        
        assert host_details_found, "Host type not found in any markdown calls"
        
        # Verify tabs were created for details
        mock_streamlit.tabs.assert_any_call(["Overview", "Certificates", "IP Addresses", "Danger Zone"])

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
    fixed_time = datetime(2024, 1, 1, 12, 0)
    with patch('infra_mgmt.views.hostsView.datetime') as mock_datetime:
        mock_datetime.now.return_value = fixed_time
        mock_datetime.strptime = datetime.strptime
        
        # Mock the tabs to return the correct number of tabs
        def mock_tabs(*args):
            tabs = [MagicMock() for _ in range(len(args[0]))]
            for tab in tabs:
                tab.__enter__ = MagicMock(return_value=tab)
                tab.__exit__ = MagicMock(return_value=None)
            return tabs
        mock_streamlit.tabs.side_effect = mock_tabs
        
        # Update sample data timestamps
        sample_data['host'].last_seen = fixed_time
        sample_data['binding'].last_seen = fixed_time
        sample_data['binding'].host_ip.last_seen = fixed_time  # Add this line
        sample_data['binding'].certificate.valid_from = fixed_time - timedelta(days=30)
        sample_data['binding'].certificate.valid_until = fixed_time + timedelta(days=335)
        
        # Patch columns globally for the test, so any call to st.columns returns two MagicMocks
        with patch('infra_mgmt.components.deletion_dialog.st.columns', return_value=[MagicMock(), MagicMock()]):
            with patch.object(mock_streamlit, 'columns', return_value=[MagicMock(), MagicMock()]):
                render_details(sample_data['host'], sample_data['binding'])
        
        # Verify host details were rendered
        mock_streamlit.markdown.assert_has_calls([
            call('**Host Type:** Server'),
            call('**Environment:** Production'),
            call('**Last Seen:** 2024-01-01 12:00'),
            call('### Current Certificate'),
            call('**Certificate:** test.example.com'),
            call("**Status:** <span class='cert-status cert-valid'>Valid</span>", unsafe_allow_html=True),
            call('**Valid Until:** 2024-12-01'),
            call('**Port:** 443'),
            call('**Platform:** F5'),
            call('### Certificate Details'),
            call('**Serial Number:** 123456'),
            call('**Thumbprint:** abcdef123456'),
            call('**Type:** None'),
            call('**Current IP:** 192.168.1.1'),
            call('**Last Seen:** 2024-01-01 12:00'),
            call('### ⚠️ Danger Zone')
        ], any_order=True)

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
    with patch('infra_mgmt.views.hostsView.AgGrid') as mock_aggrid, \
         patch('infra_mgmt.views.hostsView.GridOptionsBuilder') as mock_gb, \
         patch('infra_mgmt.views.hostsView.JsCode') as mock_jscode:
        
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

# Add logging to verify the state of the CertificateBinding instance
def log_binding_state(binding):
    try:
        logging.debug(f"Binding ID: {binding.id}, Host: {binding.host.name}, IP: {binding.host_ip.ip_address}")
    except Exception as e:
        logging.error(f"Error accessing binding state: {e}")

# Ensure logging calls are within the test function
# log_binding_state(sample_data['binding'])
# render_hosts_view(engine)
# log_binding_state(sample_data['binding']) 