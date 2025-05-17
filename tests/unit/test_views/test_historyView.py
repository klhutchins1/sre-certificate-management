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
    create_timeline_chart,
    render_certificate_tracking
)
from unittest.mock import ANY

# Add this helper class at the top of the file, after imports
class SessionStateMock(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)
    def __setattr__(self, name, value):
        self[name] = value

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
    with patch('infra_mgmt.views.historyView.st') as mock_st, \
         patch('infra_mgmt.components.page_header.st') as mock_header_st:
        def mock_columns(spec):
            num_cols = len(spec) if isinstance(spec, (list, tuple)) else spec
            return [MagicMock() for _ in range(num_cols)]
        mock_st.columns.side_effect = mock_columns
        mock_header_st.columns.side_effect = mock_columns
        mock_st.markdown = MagicMock()
        mock_header_st.markdown = MagicMock()
        mock_st.divider = MagicMock()
        mock_header_st.divider = MagicMock()
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
        yield (mock_st, mock_header_st)

@pytest.fixture
def sample_data(session):
    """Insert sample data for testing, but do not return ORM objects."""
    from infra_mgmt.models import Certificate, Host, HostIP, CertificateBinding, CertificateScan
    from datetime import datetime, timedelta
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
    # Do not return ORM objects
    return None

def test_render_history_view(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test rendering the main history view"""
    mock_st, mock_header_st = mock_streamlit
    # Inserted data is already in the database via sample_data fixture
    # Query the host and IP to construct the expected key
    from infra_mgmt.models import Host
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    with Session() as session:
        host = session.query(Host).first()
        host_ip = host.ip_addresses[0]
        host_key = f"{host.name} ({host_ip.ip_address})"
    # Set up selectbox side effects for all tabs
    mock_st.selectbox.side_effect = [
        "test.example.com",  # Common Name selection
        "Last 30 Days",      # Time period for scan history
        "All",               # Status filter for scan history
        "All",               # Host filter for scan history
        host_key              # Host selection for certificate history
    ]
    render_history_view(engine)
    # Check that the header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Certificate History</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"
    mock_st.tabs.assert_called_once_with(["Common Name History", "Scan History", "Host Certificate History"])

def test_render_scan_history_empty(mock_streamlit, engine):
    """Test rendering scan history with no data"""
    mock_st, mock_header_st = mock_streamlit
    render_scan_history(engine)
    
    # Verify empty state warning
    mock_st.warning.assert_called_once_with("No scan history found")

def test_render_scan_history_with_data(mock_streamlit, mock_aggrid, engine, sample_data):
    """Test rendering scan history with sample data"""
    mock_st, mock_header_st = mock_streamlit
    # Reset any previous mock calls
    mock_st.metric.reset_mock()
    
    # Mock selectbox to return valid values for filters
    mock_st.selectbox.side_effect = [
        "Last 30 Days",  # Time period
        "All",          # Status filter
        "All"           # Host filter
    ]
    
    render_scan_history(engine)
    
    # Get all metric calls
    metric_calls = mock_st.metric.call_args_list
    # Verify each metric was called with correct values
    assert any(call.args[0] == "Total Scans" for call in metric_calls), "Total Scans metric not found"
    assert any(call.args[0] == "Success Rate" for call in metric_calls), "Success Rate metric not found"
    assert any(call.args[0] == "Unique Hosts" for call in metric_calls), "Unique Hosts metric not found"
    # Assert that Success Rate is 100%
    success_rate_call = next((call for call in metric_calls if call.args[0] == "Success Rate"), None)
    assert success_rate_call is not None
    assert "100.0%" in str(success_rate_call.args[1]) or "100%" in str(success_rate_call.args[1])
    # Verify dataframe was created
    mock_aggrid.assert_called()

def test_render_host_certificate_history_empty(mock_streamlit, engine):
    """Test rendering host certificate history with no data"""
    mock_st, mock_header_st = mock_streamlit
    # Ensure the database is empty and selectbox returns None
    mock_st.selectbox.return_value = None
    render_host_certificate_history(engine)
    # The view does not call st.warning or st.info in this case
    mock_st.selectbox.assert_called_once()
    assert not mock_st.warning.called
    assert not mock_st.info.called

def test_render_host_certificate_history_with_data(mock_streamlit, engine, sample_data):
    """Test rendering host certificate history with sample data"""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.models import Host
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    with Session() as session:
        host = session.query(Host).first()
        host_ip = host.ip_addresses[0]
        host_key = f"{host.name} ({host_ip.ip_address})"
    mock_st.selectbox.return_value = host_key
    render_host_certificate_history(engine)
    mock_st.selectbox.assert_called_with(
        "Select Host",
        options=[host_key],
        index=None,
        placeholder="Choose a host to view certificate history..."
    )
    mock_st.subheader.assert_any_call("Certificate Timeline")
    mock_st.subheader.assert_any_call("Detailed History")

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
    mock_st, mock_header_st = mock_streamlit
    # Mock filter selections
    mock_st.selectbox.side_effect = [
        "Last 30 Days",  # Time period
        "All",          # Status filter
        "All"           # Host filter
    ]
    
    render_scan_history(engine)
    
    # Verify filter options were created
    mock_st.selectbox.assert_any_call(
        "Time Period",
        ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
        index=2
    )
    
    # Verify dataframe was filtered and displayed
    mock_aggrid.assert_called()
    
    # Verify metrics were displayed
    metric_calls = mock_st.metric.call_args_list
    assert len(metric_calls) == 3, "Expected 3 metrics to be displayed"

def test_host_certificate_history_timeline(mock_streamlit, engine, sample_data):
    """Test host certificate history timeline display"""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.models import Host
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    with Session() as session:
        host = session.query(Host).first()
        host_ip = host.ip_addresses[0]
        host_key = f"{host.name} ({host_ip.ip_address})"
    mock_st.selectbox.return_value = host_key
    with patch('infra_mgmt.views.historyView.create_timeline_chart') as mock_create_chart:
        mock_fig = MagicMock()
        mock_create_chart.return_value = mock_fig
        render_host_certificate_history(engine)
        mock_create_chart.assert_called_once()
        mock_st.plotly_chart.assert_called_with(mock_fig)

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

def test_render_host_certificate_history_error(mock_streamlit, engine, monkeypatch):
    """Test error handling in render_host_certificate_history (lines 96-97)"""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views import historyView
    monkeypatch.setattr(
        historyView.HistoryService,
        "get_host_certificate_history",
        lambda engine: {'success': False, 'error': 'fail'}
    )
    historyView.render_host_certificate_history(engine)
    mock_st.warning.assert_called_once_with('fail')

def test_render_scan_history_empty_error(mock_streamlit, monkeypatch, engine):
    """Test empty scan history in render_scan_history (line 248)"""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views import historyView
    monkeypatch.setattr(
        historyView.HistoryService,
        "get_scan_history",
        lambda session: []
    )
    historyView.render_scan_history(engine)
    mock_st.warning.assert_called_once_with("No scan history found")

def test_render_cn_history_empty_cn(mock_streamlit, monkeypatch, engine):
    """Test empty CN history in render_cn_history (get_cn_history returns empty, lines 652-653)"""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views import historyView
    monkeypatch.setattr(
        historyView.HistoryService,
        "get_cn_history",
        lambda session: []
    )
    historyView.render_cn_history(engine)
    mock_st.warning.assert_called_once_with("No certificate data found")

def test_render_cn_history_no_certs_for_cn(mock_streamlit, monkeypatch, engine):
    """Test no certificates for selected CN in render_cn_history (lines 852-880)"""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views import historyView
    # Return a CN, but no certs for it
    monkeypatch.setattr(
        historyView.HistoryService,
        "get_cn_history",
        lambda session: ["test.example.com"]
    )
    monkeypatch.setattr(
        historyView.HistoryService,
        "get_certificates_by_cn",
        lambda session, cn: []
    )
    # Patch selectbox to select the CN
    mock_st.selectbox.return_value = "test.example.com"
    historyView.render_cn_history(engine)
    mock_st.info.assert_called_once_with("No certificates found with this common name")

def test_render_certificate_tracking_no_entries(mock_streamlit):
    """Test info message when no tracking entries exist."""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views.historyView import render_certificate_tracking
    cert = MagicMock()
    cert.tracking_entries = []
    session = MagicMock()
    render_certificate_tracking(cert, session)
    mock_st.info.assert_called_once_with("No change entries found for this certificate")

def test_render_certificate_tracking_with_entries(mock_streamlit):
    """Test DataFrame/grid display when tracking entries exist."""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views.historyView import render_certificate_tracking
    cert = MagicMock()
    entry = MagicMock()
    entry.change_number = "CHG123"
    entry.planned_change_date = "2024-01-01"
    entry.status = "Completed"
    entry.notes = "Test"
    entry.created_at = "2024-01-01"
    entry.updated_at = "2024-01-02"
    entry.id = 1
    cert.tracking_entries = [entry]
    session = MagicMock()
    render_certificate_tracking(cert, session)
    # Should call st.dataframe or AgGrid
    assert mock_st.info.call_count == 0

def test_render_certificate_tracking_add_button(mock_streamlit, monkeypatch):
    """Test Add Change Entry button shows form."""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views.historyView import render_certificate_tracking
    from datetime import datetime
    cert = MagicMock()
    cert.id = 1
    cert.tracking_entries = []
    session = MagicMock()
    # Simulate button click
    mock_st.button.return_value = True
    # Patch form fields to return real values
    mock_st.text_input.return_value = "CHG123"
    mock_st.date_input.return_value = datetime.now().date()
    mock_st.selectbox.return_value = "Completed"
    mock_st.text_area.return_value = "Test"
    # Patch add_certificate_tracking_entry to return success
    monkeypatch.setattr(
        "infra_mgmt.views.historyView.HistoryService.add_certificate_tracking_entry",
        lambda session, cert_id, change_number, planned_date, status, notes: {'success': True}
    )
    # Use SessionStateMock for session_state
    state = SessionStateMock()
    mock_st.session_state = state
    # Patch st.form to check if it is called
    form_ctx = MagicMock()
    form_ctx.__enter__.return_value = form_ctx
    form_ctx.__exit__.return_value = None
    mock_st.form.return_value = form_ctx
    render_certificate_tracking(cert, session)
    mock_st.form.assert_called_once_with("tracking_entry_form")

def test_render_certificate_tracking_form_success(mock_streamlit, monkeypatch):
    """Test form submission success path."""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views.historyView import render_certificate_tracking
    cert = MagicMock()
    cert.id = 1
    cert.tracking_entries = []
    session = MagicMock()
    # Use SessionStateMock for session_state
    state = SessionStateMock({'show_tracking_entry': True, 'editing_cert_id': 1})
    mock_st.session_state = state
    # Patch form context manager
    form_ctx = MagicMock()
    form_ctx.__enter__.return_value = form_ctx
    form_ctx.__exit__.return_value = None
    mock_st.form.return_value = form_ctx
    # Patch form fields
    mock_st.text_input.return_value = "CHG123"
    mock_st.date_input.return_value = "2024-01-01"
    mock_st.selectbox.return_value = "Completed"
    mock_st.text_area.return_value = "Test"
    # Simulate form submit
    form_ctx.form_submit_button.return_value = True
    # Patch add_certificate_tracking_entry
    monkeypatch.setattr(
        "infra_mgmt.views.historyView.HistoryService.add_certificate_tracking_entry",
        lambda session, cert_id, change_number, planned_date, status, notes: {'success': True}
    )
    render_certificate_tracking(cert, session)
    mock_st.success.assert_called_once_with("Change entry added!")
    assert state['show_tracking_entry'] is False
    mock_st.rerun.assert_called_once()

def test_render_certificate_tracking_form_failure(mock_streamlit, monkeypatch):
    """Test form submission failure path."""
    mock_st, mock_header_st = mock_streamlit
    from infra_mgmt.views.historyView import render_certificate_tracking
    cert = MagicMock()
    cert.id = 1
    cert.tracking_entries = []
    session = MagicMock()
    # Simulate form shown
    mock_st.session_state.get.side_effect = lambda k, d=None: True if k == 'show_tracking_entry' or k == 'editing_cert_id' else None
    mock_st.session_state.__getitem__.side_effect = lambda k: 1 if k == 'editing_cert_id' else None
    # Patch form context manager
    form_ctx = MagicMock()
    form_ctx.__enter__.return_value = form_ctx
    form_ctx.__exit__.return_value = None
    mock_st.form.return_value = form_ctx
    # Patch form fields
    mock_st.text_input.return_value = "CHG123"
    mock_st.date_input.return_value = "2024-01-01"
    mock_st.selectbox.return_value = "Completed"
    mock_st.text_area.return_value = "Test"
    # Simulate form submit
    form_ctx.form_submit_button.return_value = True
    # Patch add_certificate_tracking_entry
    monkeypatch.setattr(
        "infra_mgmt.views.historyView.HistoryService.add_certificate_tracking_entry",
        lambda session, cert_id, change_number, planned_date, status, notes: {'success': False, 'error': 'fail'}
    )
    render_certificate_tracking(cert, session)
    mock_st.error.assert_called_once_with("Error saving change entry: fail") 