import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from sqlalchemy import create_engine
from cert_scanner.models import Base
from cert_scanner.views.scannerView import render_scan_interface, render_scan_results

@pytest.fixture
def engine():
    """Create a test database engine"""
    engine = create_engine('sqlite:///:memory:')
    # Create all tables
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def mock_session_state():
    """Mock Streamlit session state"""
    mock_state = MagicMock()
    mock_state.get.return_value = False  # For transitioning flag
    mock_state.scan_results = {
        "success": [],
        "error": [],
        "warning": []
    }
    with patch('streamlit.session_state', new=mock_state):
        yield mock_state

@pytest.fixture
def mock_scan():
    """Create a mock scan object"""
    scan = MagicMock()
    scan.scan_date = datetime(2024, 1, 1, 12, 0)
    scan.hostname = "example.com"
    scan.port = 443
    return scan

@pytest.mark.test_interface
def test_render_scan_interface(engine):
    """Test the scan interface rendering functionality"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.session_state', new=MagicMock()) as mock_state:
        
        # Configure mock expander context manager
        mock_expander_ctx = MagicMock()
        mock_expander.return_value.__enter__.return_value = mock_expander_ctx
        
        # Configure columns
        col1, col2 = MagicMock(), MagicMock()
        mock_columns.return_value = [col1, col2]
        
        # Configure session state
        mock_state.get.return_value = False  # For transitioning flag
        mock_state.scan_results = {
            "success": [],
            "error": [],
            "warning": []
        }
        
        render_scan_interface(engine)
        
        # Verify title was set
        mock_title.assert_called_once_with("Scan Certificates")
        
        # Verify text area was created with correct parameters
        mock_text_area.assert_called_once_with(
            "Enter hostnames to scan (one per line)",
            height=150,
            placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444""",
            value=""
        )
        
        # Verify expander was created with help text
        mock_expander.assert_called_once_with("ℹ️ Input Format Help")

@pytest.mark.test_interface
def test_render_scan_interface_with_input(engine):
    """Test scan interface with user input"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.session_state', new=MagicMock()) as mock_state:
        
        # Configure mock text area to return some input
        mock_text_area.return_value = "example.com\ntest.com:443"
        
        # Configure mock expander context manager
        mock_expander_ctx = MagicMock()
        mock_expander.return_value.__enter__.return_value = mock_expander_ctx
        
        # Configure columns
        col1, col2 = MagicMock(), MagicMock()
        mock_columns.return_value = [col1, col2]
        
        # Configure session state
        mock_state.get.return_value = False  # For transitioning flag
        mock_state.scan_results = {
            "success": [],
            "error": [],
            "warning": []
        }
        
        render_scan_interface(engine)
        
        # Verify text area was called with correct parameters
        mock_text_area.assert_called_once_with(
            "Enter hostnames to scan (one per line)",
            height=150,
            placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444""",
            value=""
        )

@pytest.mark.test_results
def test_render_scan_results(mock_session_state, mock_scan):
    """Test scan results rendering"""
    with patch('streamlit.markdown') as mock_markdown:
        # Create mock scans with different hostnames
        success_scan = mock_scan
        error_scan = MagicMock()
        error_scan.scan_date = datetime(2024, 1, 1, 12, 0)
        error_scan.hostname = "test.com"
        error_scan.port = 8443
        
        # Set up session state with scan results
        mock_session_state.scan_results = {
            "success": [success_scan],
            "error": [error_scan],
            "warning": []
        }
        
        render_scan_results()
        
        # Verify success and error messages were displayed
        mock_markdown.assert_any_call("### ✅ Successful Scans")
        mock_markdown.assert_any_call("### ❌ Failed Scans")
        
        # Verify scan details were displayed
        mock_markdown.assert_any_call(
            "<span style='font-family: monospace'>example.com:443 "
            "(🕒 2024-01-01 12:00 • <span style='color:green'>Valid</span>)</span>",
            unsafe_allow_html=True
        )
        mock_markdown.assert_any_call(
            "<span style='font-family: monospace'>test.com:8443 "
            "(🕒 2024-01-01 12:00 • <span style='color:red'>Failed</span>)</span>",
            unsafe_allow_html=True
        )

@pytest.mark.test_integration
def test_scan_interface_and_results_integration(engine, mock_session_state, mock_scan):
    """Test interface and results display together"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.markdown') as mock_markdown:
        
        # Configure mock expander context manager
        mock_expander_ctx = MagicMock()
        mock_expander.return_value.__enter__.return_value = mock_expander_ctx
        
        # Configure columns
        col1, col2 = MagicMock(), MagicMock()
        mock_columns.return_value = [col1, col2]
        
        # First render the interface
        render_scan_interface(engine)
        
        # Verify interface elements
        mock_text_area.assert_called_once()
        mock_expander.assert_called_once()
        
        # Update session state with scan results
        mock_session_state.scan_results = {
            "success": [mock_scan],
            "error": [],
            "warning": []
        }
        
        # Then render scan results
        render_scan_results()
        
        # Verify results were displayed
        mock_markdown.assert_any_call("### ✅ Successful Scans")
        mock_markdown.assert_any_call(
            "<span style='font-family: monospace'>example.com:443 "
            "(🕒 2024-01-01 12:00 • <span style='color:green'>Valid</span>)</span>",
            unsafe_allow_html=True
        )
