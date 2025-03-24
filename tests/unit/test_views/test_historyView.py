import pytest
from datetime import datetime, timedelta
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from infra_mgmt.models import Base, Certificate, Host, HostIP, CertificateBinding, CertificateScan
from infra_mgmt.views.historyView import (
    render_history_view,
    render_scan_history,
    render_host_certificate_history,
    create_timeline_chart
)

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
    with patch('infra_mgmt.views.historyView.st') as mock_st:
        # Mock columns to return list of MagicMocks
        def mock_columns(*args):
            num_cols = len(args[0]) if isinstance(args[0], (list, tuple)) else args[0]
            return [MagicMock() for _ in range(num_cols)]
        mock_st.columns.side_effect = mock_columns
        
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
    host = Host(name="test-host")
    host_ip = HostIP(ip_address="192.168.1.1")
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
    
    # Create scan
    scan = CertificateScan(
        certificate=cert,
        host=host,
        scan_date=datetime.now(),
        status="Valid",
        port=443
    )
    
    session.add_all([cert, host, binding, scan])
    session.commit()
    
    return {
        'certificate': cert,
        'host': host,
        'binding': binding,
        'scan': scan
    }

def test_render_history_view(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test rendering the main history view"""
    # Mock selectbox to return valid values for all calls
    mock_streamlit.selectbox.side_effect = [
        "test.example.com",  # Common Name selection
        "Last 30 Days",      # Time period for scan history
        "All",               # Status filter for scan history
        "All",              # Host filter for scan history
        f"{sample_data['host'].name} ({sample_data['binding'].host_ip.ip_address})"  # Host selection for certificate history
    ]
    
    render_history_view(engine)
    
    # Verify title was set
    mock_streamlit.title.assert_called_once_with("Certificate History")
    
    # Verify tabs were created
    mock_streamlit.tabs.assert_called_once_with(["Common Name History", "Scan History", "Host Certificate History"])

def test_render_scan_history_empty(mock_streamlit, engine):
    """Test rendering scan history with no data"""
    render_scan_history(engine)
    
    # Verify empty state warning
    mock_streamlit.warning.assert_called_once_with("No scan history found")

def test_render_scan_history_with_data(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test rendering scan history with sample data"""
    # Reset any previous mock calls
    mock_streamlit.metric.reset_mock()
    
    # Mock selectbox to return valid values for filters
    mock_streamlit.selectbox.side_effect = [
        "Last 30 Days",  # Time period
        "All",          # Status filter
        "All"           # Host filter
    ]
    
    render_scan_history(engine)
    
    # Get all metric calls
    metric_calls = mock_streamlit.metric.call_args_list
    
    # Verify each metric was called with correct values
    assert any(call.args[0] == "Total Scans" for call in metric_calls), "Total Scans metric not found"
    assert any(call.args[0] == "Success Rate" for call in metric_calls), "Success Rate metric not found"
    assert any(call.args[0] == "Unique Hosts" for call in metric_calls), "Unique Hosts metric not found"
    
    # Verify dataframe was created
    mock_aggrid.assert_called()

def test_render_host_certificate_history_empty(mock_streamlit, engine):
    """Test rendering host certificate history with no data"""
    render_host_certificate_history(engine)
    
    # Verify empty state warning
    mock_streamlit.warning.assert_called_once_with("No host data found")

def test_render_host_certificate_history_with_data(mock_streamlit, engine, sample_data):
    """Test rendering host certificate history with sample data"""
    # Mock selectbox to return a valid host
    mock_streamlit.selectbox.return_value = f"{sample_data['host'].name} ({sample_data['binding'].host_ip.ip_address})"
    
    render_host_certificate_history(engine)
    
    # Verify host selection was created
    mock_streamlit.selectbox.assert_called_with(
        "Select Host",
        options=[f"{sample_data['host'].name} ({sample_data['binding'].host_ip.ip_address})"],
        index=None,
        placeholder="Choose a host to view certificate history..."
    )
    
    # Verify subheaders were created
    mock_streamlit.subheader.assert_any_call("Certificate Timeline")
    mock_streamlit.subheader.assert_any_call("Detailed History")

@patch('plotly.figure_factory.create_gantt')
def test_create_timeline_chart(mock_create_gantt):
    """Test timeline chart creation"""
    # Create test data
    data = {
        "Certificate": ["test.example.com"],
        "Start": [datetime.now()],
        "End": [datetime.now() + timedelta(days=365)]
    }
    
    # Mock figure factory
    mock_fig = MagicMock()
    mock_fig.update_layout = MagicMock()
    mock_create_gantt.return_value = mock_fig
    
    # Create chart
    fig = create_timeline_chart(data)
    
    # Verify gantt chart was created
    mock_create_gantt.assert_called_once()
    
    # Verify layout was updated
    mock_fig.update_layout.assert_called_with(
        title="Certificate Timeline",
        height=230,  # 200 + (1 * 30) for one certificate
        xaxis_title="Date",
        showlegend=False
    )

def test_scan_history_filters(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test scan history filters"""
    # Mock filter selections
    mock_streamlit.selectbox.side_effect = [
        "Last 30 Days",  # Time period
        "All",          # Status filter
        "All"           # Host filter
    ]
    
    render_scan_history(engine)
    
    # Verify filter options were created
    mock_streamlit.selectbox.assert_any_call(
        "Time Period",
        ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
        index=2
    )
    
    # Verify dataframe was filtered and displayed
    mock_aggrid.assert_called()
    
    # Verify metrics were displayed
    metric_calls = mock_streamlit.metric.call_args_list
    assert len(metric_calls) == 3, "Expected 3 metrics to be displayed"

def test_host_certificate_history_timeline(mock_streamlit, engine, sample_data):
    """Test host certificate history timeline display"""
    # Mock host selection
    mock_streamlit.selectbox.return_value = f"{sample_data['host'].name} ({sample_data['binding'].host_ip.ip_address})"
    
    # Mock plotly chart
    with patch('infra_mgmt.views.historyView.create_timeline_chart') as mock_create_chart:
        mock_fig = MagicMock()
        mock_create_chart.return_value = mock_fig
        
        render_host_certificate_history(engine)
        
        # Verify timeline chart was created and displayed
        mock_create_chart.assert_called_once()
        mock_streamlit.plotly_chart.assert_called_with(mock_fig)

@pytest.fixture(scope="function")
def mock_aggrid():
    """Mock st_aggrid module"""
    with patch('infra_mgmt.views.historyView.AgGrid') as mock_aggrid, \
         patch('infra_mgmt.views.historyView.GridOptionsBuilder') as mock_gb, \
         patch('infra_mgmt.views.historyView.JsCode') as mock_jscode:
        
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