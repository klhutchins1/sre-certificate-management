import pytest
from datetime import datetime, timedelta, date
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from infra_mgmt.models import Base, Certificate, Host, HostIP, CertificateBinding, CertificateTracking
from infra_mgmt.views.certificatesView import (
    render_certificate_list,
    render_certificate_card,
    render_certificate_overview,
    render_certificate_details,
    render_certificate_bindings,
    render_certificate_tracking
)
import json
from unittest import mock
from st_aggrid import GridUpdateMode, DataReturnMode
from unittest.mock import call

@pytest.fixture(scope="function")
def mock_aggrid():
    """Mock st_aggrid module"""
    with patch('infra_mgmt.views.certificatesView.AgGrid') as mock_aggrid, \
         patch('infra_mgmt.views.certificatesView.GridOptionsBuilder') as mock_gb, \
         patch('infra_mgmt.views.certificatesView.JsCode') as mock_jscode:
        
        # Create a mock GridOptionsBuilder that supports all required methods
        class MockGridOptionsBuilder:
            def __init__(self):
                self.column_defs = []
                self.grid_options = {}
            
            def from_dataframe(self, df):
                return self
                
            def configure_default_column(self, **kwargs):
                self.default_column_options = kwargs
                
            def configure_column(self, field, **kwargs):
                self.column_defs.append({"field": field, **kwargs})
                
            def configure_selection(self, **kwargs):
                self.selection_options = kwargs
                
            def configure_grid_options(self, **kwargs):
                self.grid_options.update(kwargs)
                
            def build(self):
                return {
                    "columnDefs": self.column_defs,
                    "defaultColDef": self.default_column_options,
                    **self.grid_options
                }
        
        # Configure the mock GridOptionsBuilder
        mock_gb.return_value = MockGridOptionsBuilder()
        mock_gb.from_dataframe = lambda df: MockGridOptionsBuilder()
        
        # Configure mock JsCode to return the input string
        mock_jscode.side_effect = lambda x: x
        
        def mock_aggrid_func(*args, **kwargs):
            return {
                'data': args[0] if args else pd.DataFrame(),
                'selected_rows': [],
                'grid_options': kwargs.get('gridOptions', {}),
            }
        mock_aggrid.side_effect = mock_aggrid_func
        yield mock_aggrid

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
    with patch('infra_mgmt.views.certificatesView.st') as mock_st:
        # Mock columns to always return a list of MagicMocks
        def mock_columns(*args):
            # If args is a list/tuple, use its length, otherwise use the first arg
            num_cols = len(args[0]) if isinstance(args[0], (list, tuple)) else args[0]
            return [MagicMock() for _ in range(num_cols)]
        mock_st.columns.side_effect = mock_columns
        
        # Mock tabs to return list of MagicMocks with context manager methods
        def mock_tabs(*args):
            tabs = [MagicMock() for _ in range(4)]
            for tab in tabs:
                tab.__enter__ = MagicMock(return_value=tab)
                tab.__exit__ = MagicMock(return_value=None)
            return tabs
        mock_st.tabs.side_effect = mock_tabs
        
        # Mock session state with a MagicMock
        mock_st.session_state = MagicMock()
        mock_st.session_state.__setitem__ = MagicMock()
        mock_st.session_state.__getitem__ = MagicMock()
        mock_st.session_state.get = MagicMock()
        
        yield mock_st

@pytest.fixture
def sample_certificate():
    """Create a sample certificate for testing"""
    return Certificate(
        id=1,
        common_name="test.example.com",
        serial_number="123456",
        valid_from=datetime(2024, 1, 1),
        valid_until=datetime(2025, 1, 1),
        issuer={"CN": "Test CA", "O": "Test Org"},
        subject={"CN": "test.example.com", "O": "Test Company"},
        thumbprint="abcdef123456",
        key_usage="Digital Signature, Key Encipherment",
        signature_algorithm="sha256WithRSAEncryption",
        san=["test.example.com", "*.example.com"],
        sans_scanned=False,
        certificate_bindings=[],
        tracking_entries=[],
        scans=[]
    )

@pytest.fixture
def sample_binding(sample_certificate):
    """Create a sample certificate binding"""
    host = Host(name="test.example.com")
    host_ip = HostIP(ip_address="192.168.1.1")
    binding = CertificateBinding(
        id=1,
        host=host,
        host_ip=host_ip,
        port=443,
        platform="F5",
        last_seen=datetime(2024, 1, 1, 12, 0),
        certificate=sample_certificate
    )
    return binding

def test_render_certificate_list_empty(mock_streamlit, engine):
    """Test rendering certificate list when no certificates exist"""
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
    
    render_certificate_list(engine)
    
    # Verify title and add button are shown
    mock_streamlit.title.assert_called_with("Certificates")
    
    # Verify button was created with correct text and type based on session state
    mock_streamlit.button.assert_called_with(
        "➕ Add Certificate",
        type="primary",
        use_container_width=True
    )
    
    # Verify empty state warning
    mock_streamlit.warning.assert_called_with("No certificates found in database")

def test_render_certificate_list_with_data(mock_streamlit, mock_aggrid, engine, sample_certificate, session):
    """Test rendering certificate list with sample data"""
    # Add certificate to session
    session.add(sample_certificate)
    session.commit()
    
    # Mock empty placeholder
    mock_placeholder = MagicMock()
    mock_streamlit.empty.return_value = mock_placeholder
    
    # Mock SessionManager
    mock_session_manager = MagicMock()
    mock_session_manager.__enter__ = MagicMock(return_value=session)
    mock_session_manager.__exit__ = MagicMock(return_value=None)
    
    with patch('infra_mgmt.views.certificatesView.SessionManager', return_value=mock_session_manager):
        # Mock current time to ensure certificate is valid
        with patch('infra_mgmt.views.certificatesView.datetime') as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 6, 1)  # A date between valid_from and valid_until
            mock_datetime.strptime = datetime.strptime
            
            render_certificate_list(engine)
    
    # Verify AG Grid was created with correct parameters
    assert mock_aggrid.call_count > 0, "AG Grid was not created"
    
    # Get the first AG Grid call
    grid_call = mock_aggrid.call_args_list[0]
    df = grid_call[0][0]  # Get the DataFrame passed to AG Grid
    kwargs = grid_call[1]  # Get the keyword arguments
    
    # Convert df to dict for easier assertion
    data = df.to_dict('records')[0] if not df.empty else {}
    
    # Verify certificate data
    assert data.get("Common Name") == "test.example.com", "Common Name mismatch"
    assert data.get("Serial Number") == "123456", "Serial Number mismatch"
    assert data.get("Status") == "Valid", "Status mismatch"
    
    # Verify grid configuration
    assert kwargs.get("update_mode") == GridUpdateMode.SELECTION_CHANGED, "Update mode mismatch"
    assert kwargs.get("data_return_mode") == DataReturnMode.FILTERED_AND_SORTED, "Data return mode mismatch"
    assert kwargs.get("fit_columns_on_grid_load") is True, "Fit columns setting mismatch"
    assert kwargs.get("theme") == "streamlit", "Theme mismatch"
    assert kwargs.get("allow_unsafe_jscode") is True, "Allow unsafe jscode setting mismatch"
    assert kwargs.get("height") == 600, "Height mismatch"

def test_render_certificate_overview(mock_streamlit, sample_certificate, sample_binding, session):
    """Test rendering certificate overview"""
    # Add binding to certificate
    sample_certificate.certificate_bindings = [sample_binding]
    session.add(sample_certificate)
    session.commit()
    
    # Mock current time to ensure certificate is valid
    with patch('infra_mgmt.views.certificatesView.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime(2024, 6, 1)  # A date between valid_from and valid_until
        mock_datetime.strptime = datetime.strptime
        
        render_certificate_overview(sample_certificate, session)
    
    # Get all markdown calls
    markdown_calls = [args[0] for args, _ in mock_streamlit.markdown.call_args_list if not isinstance(args[0], dict)]
    markdown_text = '\n'.join(markdown_calls)
    
    # Check for required information in the markdown text, ignoring whitespace
    assert "**Common Name:** test.example.com" in markdown_text, "Common name not found"
    assert "**Valid From:** 2024-01-01" in markdown_text, "Valid from date not found"
    assert "**Valid Until:** 2025-01-01" in markdown_text, "Valid until date not found"
    assert "<span class='cert-status cert-valid'>Valid</span>" in markdown_text, "Status with styling not found"
    assert "**Total Bindings:** 1" in markdown_text, "Total bindings not found"
    assert "**Platforms:** F5" in markdown_text, "Platforms not found"
    assert "**SANs Scanned:** No" in markdown_text, "SANs scanned status not found"
    
    # Verify SAN expander was created
    mock_streamlit.expander.assert_called_with("Subject Alternative Names", expanded=True)

def test_render_certificate_details(mock_streamlit, sample_certificate):
    """Test rendering certificate details"""
    render_certificate_details(sample_certificate)
    
    # Verify JSON data structure
    mock_streamlit.json.assert_called_once_with({
        "Serial Number": "123456",
        "Thumbprint": "abcdef123456",
        "Issuer": {"CN": "Test CA", "O": "Test Org"},
        "Subject": {"CN": "test.example.com", "O": "Test Company"},
        "Key Usage": "Digital Signature, Key Encipherment",
        "Signature Algorithm": "sha256WithRSAEncryption"
    })

def test_render_certificate_bindings(mock_streamlit, sample_certificate, sample_binding, session):
    """Test rendering certificate bindings"""
    # Add binding to certificate
    sample_binding.binding_type = "IP"  # Ensure binding type is IP
    sample_binding.port = 443
    sample_binding.host.name = "test.example.com"
    sample_binding.host_ip.ip_address = "192.168.1.1"
    sample_binding.platform = "F5"
    sample_binding.last_seen = datetime(2024, 1, 1, 12, 0)
    sample_certificate.certificate_bindings = [sample_binding]
    session.add(sample_certificate)
    session.commit()
    
    # Configure form
    mock_form = MagicMock()
    mock_form.__enter__ = MagicMock(return_value=mock_form)
    mock_form.__exit__ = MagicMock(return_value=None)
    mock_streamlit.form.return_value = mock_form
    
    # Mock selectbox to return string value
    mock_streamlit.selectbox.return_value = "F5"
    
    render_certificate_bindings(sample_certificate, session)
    
    # Verify expander was created for adding new binding
    mock_streamlit.expander.assert_called_with("➕ Add New Binding", expanded=False)
    
    # Verify binding details were displayed
    markdown_calls = [args[0] for args, _ in mock_streamlit.markdown.call_args_list]
    binding_details = '\n'.join(markdown_calls)
    
    # Check for binding information in the formatted HTML/markdown
    assert "### Current Bindings" in binding_details, "Bindings header not found"
    assert '<div class="binding-title">🔗 test.example.com</div>' in binding_details, "Binding hostname not found"
    assert '<span class="binding-info-label">IP:</span>' in binding_details, "IP label not found"
    assert '<span class="binding-info-value">192.168.1.1</span>' in binding_details, "IP value not found"
    assert '<span class="binding-info-label">Port:</span>' in binding_details, "Port label not found"
    assert '<span class="binding-info-value">443</span>' in binding_details, "Port value not found"
    assert '<span class="binding-info-label">Type:</span>' in binding_details, "Type label not found"
    assert '<span class="binding-info-value">IP</span>' in binding_details, "Type value not found"
    assert '<span class="binding-info-label">Seen:</span>' in binding_details, "Last seen label not found"
    assert '<span class="binding-info-value">2024-01-01 12:00</span>' in binding_details, "Last seen value not found"

def test_render_certificate_tracking(mock_streamlit, sample_certificate, session):
    """Test rendering certificate tracking"""
    # Configure columns
    col1, col2 = MagicMock(), MagicMock()
    mock_streamlit.columns.return_value = [col1, col2]
    
    # Configure form
    mock_form = MagicMock()
    mock_form.__enter__ = MagicMock(return_value=None)
    mock_form.__exit__ = MagicMock(return_value=None)
    mock_streamlit.form.return_value = mock_form
    
    render_certificate_tracking(sample_certificate, session)
    
    # Verify subheader was created
    mock_streamlit.subheader.assert_called_with("Change History")
    
    # Verify add button was created
    mock_streamlit.button.assert_called_with(
        "➕ Add Change Entry",
        type="primary",
        use_container_width=True
    )
    
    # Verify empty state message
    mock_streamlit.info.assert_called_with("No change entries found for this certificate")

def test_render_certificate_card(mock_streamlit, sample_certificate, session):
    """Test rendering certificate details card"""
    # Add certificate to session
    session.add(sample_certificate)
    session.commit()
    
    # Mock current time to ensure certificate is valid
    with patch('infra_mgmt.views.certificatesView.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime(2024, 6, 1)  # A date between valid_from and valid_until
        mock_datetime.strptime = datetime.strptime
        
        # Mock the tabs to return the correct number of tabs
        def mock_tabs(*args):
            tabs = [MagicMock() for _ in range(len(args[0]))]
            for tab in tabs:
                tab.__enter__ = MagicMock(return_value=tab)
                tab.__exit__ = MagicMock(return_value=None)
            return tabs
        mock_streamlit.tabs.side_effect = mock_tabs
        
        render_certificate_card(sample_certificate, session)
        
        # Verify tabs were created with all expected tabs including Danger Zone
        mock_streamlit.tabs.assert_called_once_with(["Overview", "Bindings", "Details", "Change Tracking", "Danger Zone"])
        
        # Verify certificate details were rendered in order
        mock_streamlit.markdown.assert_has_calls([
            call('**Common Name:** test.example.com'),
            call('**Valid From:** 2024-01-01'),
            call("**Valid Until:** 2025-01-01 <span class='cert-status cert-valid'>Valid</span>", unsafe_allow_html=True),
            call('**Serial Number:** `123456`'),
            call('**Total Bindings:** 0'),
            call('**Thumbprint:** `abcdef123456`'),
            call('**Chain Status:** ⚠️ Unverified Chain'),
            call('**Key Usage:** Digital Signature, Key Encipherment'),
            call('**Platforms:** *None*'),
            call('**SANs Scanned:** No'),
            call('### ⚠️ Danger Zone')
        ], any_order=False)

def test_render_certificate_overview_with_sans(mock_streamlit, sample_certificate, session):
    """Test rendering certificate overview with SANs"""
    # Configure mock columns
    mock_streamlit.columns.side_effect = lambda *args: [MagicMock() for _ in range(len(args[0]) if isinstance(args[0], (list, tuple)) else args[0])]
    
    render_certificate_overview(sample_certificate, session)
    
    # Calculate expected height based on number of SANs
    expected_height = max(68, 35 + (21 * len(sample_certificate.san)))
    
    # Verify SAN text area was created with correct height
    mock_streamlit.text_area.assert_called_with(
        "Subject Alternative Names",
        value="*.example.com\ntest.example.com",
        height=expected_height,
        disabled=True,
        label_visibility="collapsed"
    )

def test_render_certificate_bindings_add_new(mock_streamlit, sample_certificate, session):
    """Test adding a new binding"""
    # Configure form
    mock_form = MagicMock()
    mock_form.__enter__ = MagicMock(return_value=mock_form)
    mock_form.__exit__ = MagicMock(return_value=None)
    mock_streamlit.form.return_value = mock_form
    
    # Configure form inputs
    mock_streamlit.text_input.side_effect = ["test.example.com", "192.168.1.1"]
    mock_streamlit.number_input.return_value = 443
    mock_streamlit.selectbox.side_effect = ["IP", "F5"]
    mock_streamlit.form_submit_button.return_value = True
    
    render_certificate_bindings(sample_certificate, session)
    
    # Verify form inputs were created with correct parameters
    mock_streamlit.text_input.assert_any_call(
        "Hostname",
        key=f"hostname_{sample_certificate.id}",
        placeholder="Enter hostname"
    )
    mock_streamlit.text_input.assert_any_call(
        "IP Address",
        key=f"ip_{sample_certificate.id}",
        placeholder="Optional"
    )
    mock_streamlit.number_input.assert_called_with(
        "Port",
        min_value=1,
        max_value=65535,
        value=443,
        key=f"port_{sample_certificate.id}"
    )

def test_add_certificate_button(mock_streamlit, engine):
    """Test add certificate button functionality"""
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
    
    # Test initial state (Add Certificate button)
    mock_streamlit.button.return_value = False
    render_certificate_list(engine)
    
    mock_streamlit.button.assert_called_with(
        "➕ Add Certificate",
        type="primary",
        use_container_width=True
    )
    
    # Test state after clicking Add Certificate
    mock_streamlit.button.reset_mock()
    mock_streamlit.button.return_value = True
    mock_state['show_manual_entry'] = False  # Ensure initial state
    
    render_certificate_list(engine)
    
    # The button click should have toggled the state
    assert mock_state['show_manual_entry'] is True, "Manual entry form not shown after button click"
    
    # Test cancel button state
    mock_streamlit.button.reset_mock()
    mock_streamlit.button.return_value = False
    
    render_certificate_list(engine)
    
    mock_streamlit.button.assert_called_with(
        "❌ Cancel",
        type="secondary",
        use_container_width=True
    )

def test_certificate_selection(mock_streamlit, mock_aggrid, engine, sample_certificate, session):
    """Test certificate selection"""
    # Add certificate to session
    session.add(sample_certificate)
    session.commit()
    
    # Mock SessionManager
    mock_session_manager = MagicMock()
    mock_session_manager.__enter__ = MagicMock(return_value=session)
    mock_session_manager.__exit__ = MagicMock(return_value=None)
    
    # Configure mock_aggrid to return selected row
    def mock_aggrid_with_selection(*args, **kwargs):
        return {
            'data': args[0] if args else pd.DataFrame(),
            'selected_rows': [{
                '_id': sample_certificate.id,
                'Common Name': sample_certificate.common_name,
                'Status': 'Valid'
            }],
            'grid_options': kwargs.get('gridOptions', {})
        }
    mock_aggrid.side_effect = mock_aggrid_with_selection
    
    with patch('infra_mgmt.views.certificatesView.SessionManager', return_value=mock_session_manager):
        # Mock current time to ensure certificate is valid
        with patch('infra_mgmt.views.certificatesView.datetime') as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 6, 1)
            mock_datetime.strptime = datetime.strptime
            
            render_certificate_list(engine)
    
    # Verify grid configuration
    grid_calls = mock_aggrid.call_args_list
    assert len(grid_calls) > 0, "AG Grid was not created"
    
    grid_options = grid_calls[0][1].get('gridOptions', {})
    assert grid_options.get('defaultColDef', {}).get('resizable') is True
    assert grid_options.get('defaultColDef', {}).get('sortable') is True
    assert grid_options.get('defaultColDef', {}).get('filter') is True
    
    # Verify certificate card was rendered for selection
    mock_streamlit.divider.assert_called()
    mock_streamlit.subheader.assert_any_call(f"📜 {sample_certificate.common_name}")

def test_expired_certificate_styling(mock_streamlit, mock_aggrid, engine, session):
    """Test styling of expired certificates"""
    # Create an expired certificate
    expired_cert = Certificate(
        common_name="expired.com",
        serial_number="654321",
        valid_from=datetime.now() - timedelta(days=730),  # 2 years ago
        valid_until=datetime.now() - timedelta(days=365),  # 1 year ago
        thumbprint="def456",
        subject={"CN": "expired.com"},
        issuer={"CN": "Test CA"},
        san=["expired.com"],
        key_usage=None,
        signature_algorithm=None,
        sans_scanned=False
    )
    session.add(expired_cert)
    session.commit()
    
    # Mock SessionManager
    mock_session_manager = MagicMock()
    mock_session_manager.__enter__ = MagicMock(return_value=session)
    mock_session_manager.__exit__ = MagicMock(return_value=None)
    
    with patch('infra_mgmt.views.certificatesView.SessionManager', return_value=mock_session_manager):
        render_certificate_list(engine)
    
    # Verify AG Grid was created with styling configuration
    grid_calls = mock_aggrid.call_args_list
    assert len(grid_calls) > 0, "AG Grid was not created"
    
    # Get the grid options to verify styling
    grid_options = grid_calls[0][1].get('gridOptions', {})
    column_defs = grid_options.get('columnDefs', [])
    
    # Find the Status column configuration
    status_col = next((col for col in column_defs if col.get("field") == "Status"), None)
    assert status_col is not None, "Status column not found"
    
    # Verify the cell class function for status styling
    cell_class = status_col.get("cellClass")
    assert "ag-status-expired" in cell_class, "Expired status styling not found"
    assert "ag-status-valid" in cell_class, "Valid status styling not found"

def test_new_certificate_appears_in_list(mock_streamlit, mock_aggrid, engine, session):
    """Test that newly added certificates appear in the certificate list"""
    # Create initial certificate
    cert1 = Certificate(
        serial_number="123456",
        thumbprint="abc123",
        common_name="test1.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=365),
        issuer={"CN": "Test CA", "O": "Test Org"},
        subject={"CN": "test1.com", "O": "Test Company"},
        san=["test1.com"],
        key_usage="Digital Signature",
        signature_algorithm="sha256WithRSAEncryption",
        sans_scanned=False
    )
    session.add(cert1)
    session.commit()

    # Mock SessionManager
    mock_session_manager = MagicMock()
    mock_session_manager.__enter__ = MagicMock(return_value=session)
    mock_session_manager.__exit__ = MagicMock(return_value=None)

    # First render to get initial state
    with patch('infra_mgmt.views.certificatesView.SessionManager', return_value=mock_session_manager):
        render_certificate_list(engine)

    # Verify first certificate appears
    initial_grid_call = mock_aggrid.call_args_list[0]
    initial_df = initial_grid_call[0][0]
    assert len(initial_df) == 1
    assert initial_df.iloc[0]["Common Name"] == "test1.com"

    # Add new certificate
    cert2 = Certificate(
        serial_number="789012",
        thumbprint="def456",
        common_name="test2.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=365),
        issuer={"CN": "Test CA", "O": "Test Org"},
        subject={"CN": "test2.com", "O": "Test Company"},
        san=["test2.com"],
        key_usage="Digital Signature",
        signature_algorithm="sha256WithRSAEncryption",
        sans_scanned=False
    )
    session.add(cert2)
    session.commit()

    # Mock current time to ensure certificates are valid
    with patch('infra_mgmt.views.certificatesView.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime.now()
        mock_datetime.strptime = datetime.strptime
        
        # Render again after adding new certificate
        with patch('infra_mgmt.views.certificatesView.SessionManager', return_value=mock_session_manager):
            render_certificate_list(engine)

    # Verify both certificates appear
    final_grid_call = mock_aggrid.call_args_list[-1]
    final_df = final_grid_call[0][0]
    assert len(final_df) == 2
    assert "test1.com" in final_df["Common Name"].values
    assert "test2.com" in final_df["Common Name"].values 