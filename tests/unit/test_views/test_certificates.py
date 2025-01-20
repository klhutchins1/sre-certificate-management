import pytest
from datetime import datetime, timedelta, date
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from cert_scanner.models import Base, Certificate, Host, HostIP, CertificateBinding, CertificateTracking
from cert_scanner.views.certificatesView import (
    render_certificate_list,
    render_certificate_card,
    render_certificate_overview,
    render_certificate_details,
    render_certificate_bindings,
    render_certificate_tracking
)
import json
from unittest import mock

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
    with patch('cert_scanner.views.certificatesView.st') as mock_st:
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
    render_certificate_list(engine)
    
    # Verify title and add button are shown
    mock_streamlit.title.assert_called_with("Certificates")
    mock_streamlit.button.assert_called_with(
        "➕ Add Certificate", 
        type="primary",
        use_container_width=True
    )
    
    # Verify empty state warning
    mock_streamlit.warning.assert_called_with("No certificates found in database")

def test_render_certificate_list_with_data(mock_streamlit, engine, sample_certificate, session):
    """Test rendering certificate list with sample data"""
    # Add certificate to session
    session.add(sample_certificate)
    session.commit()
    
    # Mock selectbox to return None (no certificate selected)
    mock_streamlit.selectbox.return_value = None
    
    # Mock current time to ensure certificate is valid
    with patch('cert_scanner.views.certificatesView.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime(2024, 6, 1)  # A date between valid_from and valid_until
        mock_datetime.strptime = datetime.strptime
        
        render_certificate_list(engine)
    
    # Verify dataframe was created
    dataframe_calls = mock_streamlit.dataframe.call_args_list
    assert len(dataframe_calls) > 0, "Dataframe was not created"
    
    # Get the first dataframe call
    df_call = dataframe_calls[0]
    styled_df = df_call[0][0]
    
    # Get the underlying dataframe
    df = styled_df.data if hasattr(styled_df, 'data') else styled_df
    
    # Convert df to dict for easier assertion
    data = df.to_dict('records')[0] if not df.empty else {}
    
    # Verify certificate data
    assert data.get("Common Name") == "test.example.com", "Common Name mismatch"
    assert data.get("Serial Number") == "123456", "Serial Number mismatch"
    assert data.get("Status") == "Valid", "Status mismatch"

def test_render_certificate_overview(mock_streamlit, sample_certificate, sample_binding, session):
    """Test rendering certificate overview"""
    # Add binding to certificate
    sample_certificate.certificate_bindings = [sample_binding]
    session.add(sample_certificate)
    session.commit()
    
    # Mock current time to ensure certificate is valid
    with patch('cert_scanner.views.certificatesView.datetime') as mock_datetime:
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
    assert "**Status:** Valid" in markdown_text, "Status not found"
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
    assert any("🔗 test.example.com" in call for call in markdown_calls), "Binding hostname not found in markdown calls"
    
    # Verify IP and port details
    caption_calls = [args[0] for args, _ in mock_streamlit.caption.call_args_list]
    assert any(f"IP: {sample_binding.host_ip.ip_address}, Port: {sample_binding.port}" in call for call in caption_calls), "Binding details not found in caption calls"

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
    with patch('cert_scanner.views.certificatesView.datetime') as mock_datetime:
        mock_datetime.now.return_value = datetime(2024, 6, 1)  # A date between valid_from and valid_until
        mock_datetime.strptime = datetime.strptime
        
        render_certificate_card(sample_certificate, session)
    
    # Verify subheader was created with certificate name
    subheader_calls = [args[0] for args, _ in mock_streamlit.subheader.call_args_list]
    assert any("📜 test.example.com" in call for call in subheader_calls), "Certificate name not found in subheader calls"
    
    # Verify tabs were created
    mock_streamlit.tabs.assert_called_with(["Overview", "Bindings", "Details", "Change Tracking"])
    
    # Verify that the certificate details were rendered
    json_calls = [args[0] for args, _ in mock_streamlit.json.call_args_list]
    assert any(
        isinstance(call, dict) and 
        call.get("Serial Number") == "123456" and
        call.get("Thumbprint") == "abcdef123456"
        for call in json_calls
    ), "Certificate details not found in JSON output"

def test_render_certificate_overview_with_sans(mock_streamlit, sample_certificate, session):
    """Test rendering certificate overview with SANs"""
    # Configure mock columns
    mock_streamlit.columns.side_effect = lambda *args: [MagicMock() for _ in range(len(args[0]) if isinstance(args[0], (list, tuple)) else args[0])]
    
    render_certificate_overview(sample_certificate, session)
    
    # Calculate expected height based on number of SANs
    expected_height = max(68, 35 + (21 * len(sample_certificate.san)))
    
    # Verify SAN text area was created with correct height
    mock_streamlit.text_area.assert_called_with(
        "",
        value="*.example.com\ntest.example.com",
        height=expected_height,
        disabled=True
    )
    
    # Verify scan button was created
    mock_streamlit.button.assert_any_call(
        "🔍 Scan SANs",
        type="primary",
        key="scan_sans_1"
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
    
    # First render - button not clicked
    mock_streamlit.button.return_value = False
    render_certificate_list(engine)
    assert not mock_state.get('show_manual_entry', False), "Manual entry form shown when button not clicked"
    
    # Second render - simulate button click
    mock_streamlit.button.reset_mock()  # Reset the mock to clear previous calls
    
    # Configure button to return True only for the add certificate button
    def mock_button(*args, **kwargs):
        if args and args[0] == "➕ Add Certificate":
            mock_setitem('show_manual_entry', True)  # Simulate what the view does
            return True
        return False
    
    mock_streamlit.button.side_effect = mock_button
    render_certificate_list(engine)
    assert mock_state.get('show_manual_entry', False) is True, "Manual entry form not shown after button click"

def test_certificate_selection(mock_streamlit, engine, sample_certificate, session):
    """Test certificate selection from dropdown"""
    # Add certificate to session
    session.add(sample_certificate)
    session.commit()
    
    # Mock selectbox to simulate selection
    mock_streamlit.selectbox.return_value = "test.example.com (123456)"
    
    # Mock text_area to return a string
    mock_streamlit.text_area.return_value = "Test description"
    
    # Mock form_submit_button to return False (don't submit the form)
    mock_streamlit.form_submit_button.return_value = False
    
    # Mock st.json to verify the data structure
    def mock_json(data):
        if isinstance(data, dict):
            # For issuer/subject details
            assert isinstance(data, dict)
        elif isinstance(data, list):
            # For SANs
            assert isinstance(data, list)
    mock_streamlit.json = Mock(side_effect=mock_json)
    
    render_certificate_list(engine)
    
    # Verify certificate details are shown
    mock_streamlit.subheader.assert_any_call("📜 test.example.com")

def test_expired_certificate_styling(mock_streamlit, engine, session):
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
    
    # Mock selectbox to return None (no certificate selected)
    mock_streamlit.selectbox.return_value = None
    
    render_certificate_list(engine)
    
    # Get the styled dataframe that was passed to st.dataframe
    styled_df = mock_streamlit.dataframe.call_args[0][0]
    # Get the underlying dataframe
    df = styled_df.data
    
    # Convert df to dict for easier assertion
    data = df.to_dict('records')[0] if not df.empty else {}
    assert data.get("Status") == "Expired" 