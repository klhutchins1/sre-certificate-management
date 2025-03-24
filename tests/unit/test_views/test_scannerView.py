"""
Unit tests for the scanner view module.
"""

import pytest
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from infra_mgmt.certificate_scanner import CertificateInfo, ScanResult
from infra_mgmt.scanner import ScanManager
from infra_mgmt.models import Domain, Certificate
from sqlalchemy import create_engine
from infra_mgmt.models import Certificate, CertificateScan, Host
from infra_mgmt.views.scannerView import render_scan_interface
from urllib.parse import urlparse

@pytest.fixture
def engine():
    """Create an in-memory SQLite database for testing"""
    engine = create_engine('sqlite:///:memory:')
    # Create tables
    Certificate.metadata.create_all(engine)
    CertificateScan.metadata.create_all(engine)
    Host.metadata.create_all(engine)
    return engine

@pytest.fixture
def mock_session_state():
    """Create a mock session state"""
    mock_state = MagicMock()
    mock_state.scan_results = {
        'success': [],
        'error': [],
        'warning': []
    }
    mock_state.scanner = MagicMock()
    mock_state.domain_scanner = MagicMock()
    mock_state.get.return_value = False  # For transitioning flag
    return mock_state

@pytest.fixture
def mock_cert_info():
    """Create a mock certificate info object"""
    return CertificateInfo(
        hostname='test.example.com',
        ip_addresses=['192.168.1.1'],
        port=443,
        common_name='test.example.com',
        issuer={'CN': 'Test CA'},
        valid_from=datetime(2024, 1, 1),
        expiration_date=datetime(2025, 1, 1),
        serial_number='123456',
        thumbprint='abcdef',
        subject={'CN': 'test.example.com'},
        san=['test.example.com', 'www.test.example.com'],
        key_usage=None,
        extended_key_usage=None,
        signature_algorithm=None,
        version=None
    )

@pytest.fixture
def mock_streamlit():
    """Mock streamlit module"""
    mock_st = MagicMock()
    
    # Mock columns to return list of MagicMocks with proper context manager
    def mock_columns(spec):
        if isinstance(spec, list):
            num_cols = len(spec)
        else:
            num_cols = spec
        cols = []
        for _ in range(num_cols):
            col = MagicMock()
            col.__enter__ = MagicMock(return_value=col)
            col.__exit__ = MagicMock(return_value=None)
            col.markdown = MagicMock()
            col.button = MagicMock()
            col.text_input = MagicMock()
            col.number_input = MagicMock()
            cols.append(col)
        return cols
    
    mock_st.columns.side_effect = mock_columns
    
    # Mock session state
    mock_st.session_state = MagicMock()
    mock_st.session_state.scan_results = {
        'success': [],
        'error': [],
        'warning': []
    }
    mock_st.session_state.scan_targets = []
    mock_st.session_state.get.return_value = False
    mock_st.session_state.scanner = MagicMock()
    
    # Mock other commonly used methods
    mock_st.title = MagicMock()
    mock_st.header = MagicMock()
    mock_st.subheader = MagicMock()
    mock_st.markdown = MagicMock()
    mock_st.text = MagicMock()
    mock_st.text_area = MagicMock()
    mock_st.button = MagicMock()
    mock_st.checkbox = MagicMock()
    mock_st.selectbox = MagicMock()
    mock_st.radio = MagicMock()
    mock_st.empty = MagicMock()
    mock_st.error = MagicMock()
    mock_st.warning = MagicMock()
    mock_st.info = MagicMock()
    mock_st.success = MagicMock()
    mock_st.spinner = MagicMock()
    mock_st.progress = MagicMock()
    mock_st.expander = MagicMock()
    
    # Configure expander context manager
    mock_expander = MagicMock()
    mock_expander.__enter__ = MagicMock(return_value=mock_expander)
    mock_expander.__exit__ = MagicMock(return_value=None)
    mock_st.expander.return_value = mock_expander
    
    # Configure spinner context manager
    mock_spinner = MagicMock()
    mock_spinner.__enter__ = MagicMock(return_value=mock_spinner)
    mock_spinner.__exit__ = MagicMock(return_value=None)
    mock_st.spinner.return_value = mock_spinner
    
    return mock_st

@pytest.mark.test_interface
def test_render_scan_interface(mock_streamlit, engine):
    """Test the scan interface rendering functionality"""
    # Configure mock text area
    mock_streamlit.text_area.return_value = "example.com"
    
    # Configure mock expander
    mock_expander = MagicMock()
    mock_expander.__enter__ = MagicMock(return_value=mock_expander)
    mock_expander.__exit__ = MagicMock(return_value=None)
    mock_streamlit.expander.return_value = mock_expander
    
    # Call the function
    with patch('infra_mgmt.views.scannerView.st', mock_streamlit):
        domains, scan_button, stop_button, clear_button, results_container = render_scan_interface(engine)
    
    # Verify title was set
    mock_streamlit.title.assert_called_once_with("Domain & Certificate Scanner")
    
    # Verify text area was configured correctly
    mock_streamlit.text_area.assert_called_once()
    
    # Verify help expander was created
    mock_streamlit.expander.assert_called_once()
    
    # Verify buttons were created
    assert scan_button is not None
    assert stop_button is not None
    assert clear_button is not None
    assert results_container is not None

@pytest.mark.test_interface
def test_render_scan_interface_with_input(engine, mock_session_state):
    """Test scan interface with user input"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.session_state', mock_session_state):
        
        # Configure mock text area to return some input
        mock_text_area.return_value = "example.com\ntest.com:443"
        
        # Configure mock expander context manager
        mock_expander_ctx = MagicMock()
        mock_expander.return_value.__enter__.return_value = mock_expander_ctx
        mock_expander.return_value.__exit__.return_value = None
        
        # Configure columns
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_columns.return_value = [col1, col2]
        
        render_scan_interface(engine)
        
        # Verify text area was called with correct parameters
        mock_text_area.assert_called_once_with(
            "Enter domains to scan (one per line)",
            value="",
            height=150,
            placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
        )

@pytest.mark.test_integration
def test_scan_interface_and_results_integration(engine, mock_session_state, mock_cert_info):
    """Test interface and results display together"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.markdown') as mock_markdown, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.session_state', mock_session_state):
        
        # Configure mock expander context manager
        mock_expander_ctx = MagicMock()
        mock_expander.return_value.__enter__.return_value = mock_expander_ctx
        mock_expander.return_value.__exit__.return_value = None
        
        # Configure columns
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_columns.return_value = [col1, col2]
        
        # Configure button to simulate scan completion
        mock_button.return_value = True
        
        # Configure text area with input
        mock_text_area.return_value = "example.com"
        
        # Configure scanner to return results
        scan_result = ScanResult(certificate_info=mock_cert_info)
        mock_session_state.scanner.scan_certificate.return_value = scan_result
        
        # First render the interface
        render_scan_interface(engine)
        
        # Verify interface elements
        mock_text_area.assert_called()
        mock_expander.assert_called()
        
        # Verify scanner was called
        mock_session_state.scanner.scan_certificate.assert_called_with("example.com", 443)

@pytest.mark.test_scan_button
def test_scan_button_functionality(engine, mock_session_state, mock_cert_info):
    """Test the scan button functionality with valid input"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.progress') as mock_progress, \
         patch('streamlit.empty') as mock_empty, \
         patch('streamlit.error') as mock_error, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.session_state', mock_session_state):
        
        # Configure mocks
        mock_text_area.return_value = "example.com\ntest.com:8443"
        mock_button.return_value = True  # Simulate button click
        
        # Configure scanner to return results
        scan_result = ScanResult(certificate_info=mock_cert_info)
        mock_session_state.scanner.scan_certificate.return_value = scan_result
        
        # Configure columns
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_columns.return_value = [col1, col2]
        
        # Configure expander
        mock_expander_ctx = MagicMock()
        mock_expander.return_value.__enter__.return_value = mock_expander_ctx
        mock_expander.return_value.__exit__.return_value = None
        
        # Configure progress and empty containers
        mock_progress_bar = MagicMock()
        mock_progress.return_value = mock_progress_bar
        mock_empty.return_value = MagicMock()
        
        # Configure spinner
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=None)
        
        render_scan_interface(engine)
        
        # Verify scanner was called for each hostname
        assert mock_session_state.scanner.scan_certificate.call_count == 2
        mock_session_state.scanner.scan_certificate.assert_any_call('example.com', 443)
        mock_session_state.scanner.scan_certificate.assert_any_call('test.com', 8443)

@pytest.mark.test_display
def test_recent_scans_display(engine, mock_session_state):
    """Test that recent scans are displayed correctly"""
    with patch('infra_mgmt.views.scannerView.Session') as mock_session_class, \
         patch('infra_mgmt.views.scannerView.st') as mock_st:

        # Configure mocks
        mock_st.text_area.return_value = "example.com"
        mock_st.button.return_value = False  # Don't trigger scan

        # Configure columns with context managers
        col1 = MagicMock()
        col2 = MagicMock()
        mock_st.columns.return_value = [col1, col2]

        # Configure expander
        mock_expander = MagicMock()
        mock_expander.__enter__.return_value = mock_expander
        mock_st.expander.return_value = mock_expander

        # Setup test data
        scan_time = datetime.now()
        mock_cert = MagicMock(
            common_name='example.com',
            valid_until=datetime.now() + timedelta(days=30)
        )

        # Create a mock successful scan
        mock_scan = MagicMock(
            scan_date=scan_time,
            status='Valid',
            certificate=mock_cert,
            host_id=None,
            port=443
        )

        # Create a mock failed scan
        mock_failed_scan = MagicMock(
            scan_date=scan_time,
            status='Failed',
            certificate=None,
            host_id=1,
            port=443
        )

        # Configure mock session
        mock_session_instance = MagicMock()
        mock_session_class.return_value = mock_session_instance
        mock_session_instance.__enter__.return_value = mock_session_instance
        mock_session_instance.__exit__.return_value = None

        # Mock the host for failed scan
        mock_host = MagicMock(name='example-failed.com')

        # Setup query chain for recent scans
        mock_scan_query = MagicMock()
        mock_host_query = MagicMock()

        def query_side_effect(*args):
            if args and args[0] == CertificateScan:
                return mock_scan_query
            elif args and args[0] == Host:
                return mock_host_query
            return MagicMock()

        mock_session_instance.query.side_effect = query_side_effect

        # Configure scan query chain
        mock_scan_query.outerjoin.return_value = mock_scan_query
        mock_scan_query.order_by.return_value = mock_scan_query
        mock_scan_query.limit.return_value = mock_scan_query
        mock_scan_query.all.return_value = [mock_scan, mock_failed_scan]

        # Configure host query chain
        mock_host_query.filter_by.return_value.first.return_value = mock_host

        # Configure session state
        mock_st.session_state = mock_session_state
        mock_session_state.scan_results = {
            'success': [],
            'error': [],
            'warning': []
        }
        mock_session_state.scan_targets = []
        mock_session_state.get.return_value = False
        mock_session_state.scanner = MagicMock()

        # Call the function
        render_scan_interface(engine)

        # Verify the subheader was called
        mock_st.subheader.assert_called_with("Recent Scans")

        # Verify that recent scans were displayed with correct formatting
        markdown_calls = [args[0] for args, kwargs in mock_st.markdown.call_args_list if args]
        
        # Check for div wrapper
        assert any("<div class='text-small'>" in call for call in markdown_calls), "Missing text-small div wrapper"
        
        # Check for successful scan
        expected_success = f"**example.com** <span class='text-muted'>(🕒 {scan_time.strftime('%Y-%m-%d %H:%M')} • <span class='text-success'>Valid</span>)</span>"
        assert any(expected_success in call for call in markdown_calls), "Successful scan not displayed correctly"
        
        # Check for failed scan - note that the host name comes from the mock_host
        expected_failure = f"**{mock_host.name}:{mock_failed_scan.port}** <span class='text-muted'>(🕒 {scan_time.strftime('%Y-%m-%d %H:%M')} • <span class='text-danger'>Failed</span>)</span>"
        assert any(expected_failure in call for call in markdown_calls), "Failed scan not displayed correctly"
        
        # Check for closing div
        assert any("</div>" in call for call in markdown_calls), "Missing closing div tag"

@pytest.mark.test_input_validation
def test_input_validation_scenarios(engine, mock_session_state):
    """Test various input validation scenarios"""
    test_cases = [
        ("example.com", True, "Standard hostname"),
        ("example.com:8443", True, "Hostname with port"),
        ("https://example.com", True, "URL format"),
        ("http://example.com:8080", True, "URL with port"),
        ("192.168.1.1", True, "IP address"),
        ("192.168.1.1:443", True, "IP with port"),
        ("example.com:99999", False, "Invalid port"),
        ("", False, "Empty input"),
        ("http://", False, "Invalid URL"),
        ("example.com:-1", False, "Negative port")
    ]

    for input_text, is_valid, description in test_cases:
        print(f"\n=== Testing {description}: {input_text} ===")

        # Create a mock streamlit module with proper error handling
        mock_st = MagicMock()
        error_messages = []
        button_clicked = True  # Simulate button always clicked

        def mock_error(message):
            print(f"Error message called: {message}")
            error_messages.append(message)
            return MagicMock()

        def mock_button(*args, **kwargs):
            print("DEBUG: Button clicked")
            return button_clicked

        # Configure streamlit mock
        mock_st.configure_mock(**{
            'text_area.return_value': input_text,
            'empty.return_value': MagicMock(),
            'progress.return_value': MagicMock(),
            'columns.return_value': [MagicMock(), MagicMock()],
            'expander.return_value.__enter__.return_value': MagicMock(),
            'session_state': mock_session_state,
            'error': mock_error,
            'button': mock_button,
            'markdown.return_value': None,
            'spinner.return_value.__enter__.return_value': None,
            'spinner.return_value.__exit__.return_value': None
        })

        with patch('infra_mgmt.views.scannerView.st', new=mock_st), \
             patch('infra_mgmt.views.scannerView.Session') as mock_session_class:

            # Initialize session state
            mock_session_state.scan_results = {
                'success': [],
                'error': [],
                'warning': []
            }
            mock_session_state.scan_targets = []
            mock_session_state.get.return_value = False
            mock_session_state.scanner = MagicMock()
            mock_session_state.scanner.scan_certificate.return_value = None  # Prevent actual scanning

            # Mock the database session
            mock_session_instance = MagicMock()
            mock_session_class.return_value = mock_session_instance
            mock_session_instance.__enter__.return_value = mock_session_instance
            mock_session_instance.__exit__.return_value = None

            # Configure query chain for recent scans
            mock_query = MagicMock()
            mock_session_instance.query.return_value = mock_query
            mock_query.outerjoin.return_value = mock_query
            mock_query.order_by.return_value = mock_query
            mock_query.limit.return_value = mock_query
            mock_query.all.return_value = []

            # Call the function
            print(f"\nDEBUG: Calling render_scan_interface with input: {input_text}")
            render_scan_interface(engine)
            print(f"DEBUG: After render_scan_interface, error_messages: {error_messages}")

            # Verify error handling
            if not is_valid:
                print(f"DEBUG: Expecting errors for invalid input: {input_text}")
                assert any(
                    "Invalid port number" in msg or 
                    "Please enter at least one" in msg or 
                    "Hostname cannot be empty" in msg or
                    "Port must be between" in msg
                    for msg in error_messages
                ), f"Expected error for invalid input: {input_text}. Got messages: {error_messages}"
            else:
                assert not any("error" in msg.lower() for msg in error_messages), \
                    f"Got unexpected error for valid input: {input_text}. Messages: {error_messages}"

@pytest.mark.test_error_handling
def test_scan_error_handling(engine, mock_session_state):
    """Test handling of various scan errors"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.error') as mock_error, \
         patch('streamlit.empty') as mock_empty, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.progress') as mock_progress, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.session_state', mock_session_state):

        # Configure mocks
        mock_text_area.return_value = "example.com"
        mock_button.return_value = True
        mock_empty.return_value = MagicMock()
        mock_progress.return_value = MagicMock()
        mock_columns.return_value = [MagicMock(), MagicMock()]
        mock_expander.return_value.__enter__.return_value = MagicMock()
        mock_spinner.return_value.__enter__.return_value = None
        mock_spinner.return_value.__exit__.return_value = None

        # Initialize session state
        mock_session_state.scan_results = {
            'success': [],
            'error': [],
            'warning': []
        }
        mock_session_state.scan_targets = []
        mock_session_state.get.return_value = False
        mock_session_state.scanner = MagicMock()
        mock_session_state.scanner.scan_certificate.side_effect = ConnectionError("Connection failed")

        render_scan_interface(engine)

        # Verify error was displayed
        error_calls = [str(call) for call in mock_error.call_args_list]
        assert any(
            'Connection failed' in str(call) or
            'Error scanning' in str(call) or
            'Failed to retrieve certificate' in str(call)
            for call in error_calls
        ), f"Connection error not displayed. Got error calls: {error_calls}"

        # Verify error was added to scan results
        assert len(mock_session_state.scan_results['error']) > 0, "Error not added to scan results"

@pytest.mark.test_session_state
def test_session_state_management(engine):
    """Test session state initialization and management"""
    with patch('streamlit.session_state') as mock_state, \
         patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.empty') as mock_empty, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.title') as mock_title:
        
        # Configure mocks
        mock_text_area.return_value = "example.com"
        mock_button.return_value = True  # Simulate button click
        mock_empty.return_value = MagicMock()
        mock_columns.return_value = [MagicMock(), MagicMock()]
        
        # Test initialization of scan results
        mock_state.get.return_value = False
        mock_state.__contains__ = lambda x, y: 'scan_results' not in y
        mock_state.scan_results = {
            'success': [],
            'error': [],
            'warning': []
        }
        
        render_scan_interface(engine)
        
        assert hasattr(mock_state, 'scan_results')
        assert isinstance(mock_state.scan_results, dict)
        assert all(k in mock_state.scan_results for k in ['success', 'error', 'warning'])
        
        # Test clearing of scan targets
        mock_state.scan_targets = ['example.com']
        mock_button.return_value = True  # Simulate button click to trigger clearing
        render_scan_interface(engine)
        
        # Verify scan_targets was cleared
        mock_state.scan_targets = []

@pytest.mark.test_database_integration
def test_database_integration(engine, mock_session_state, mock_cert_info):
    """Test database interactions during scanning"""
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.empty') as mock_empty, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.progress') as mock_progress, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.session_state', mock_session_state):
        
        # Configure mocks
        mock_text_area.return_value = "example.com"
        mock_button.return_value = True
        mock_session_state.scanner = MagicMock()
        mock_session_state.scanner.scan_certificate.return_value = mock_cert_info
        mock_columns.return_value = [MagicMock(), MagicMock()]
        mock_expander.return_value.__enter__.return_value = MagicMock()
        
        mock_progress_bar = MagicMock()
        mock_progress.return_value = mock_progress_bar
        mock_empty.return_value = MagicMock()
        
        # Initialize session state
        mock_session_state.scan_results = {
            'success': [],
            'error': [],
            'warning': []
        }
        mock_session_state.scan_targets = []
        mock_session_state.get.return_value = False  # For transitioning flag
        
        # Create tables
        from infra_mgmt.models import Base
        Base.metadata.create_all(engine)
        
        render_scan_interface(engine)
        
        # Verify database entries
        from sqlalchemy.orm import Session
        with Session(engine) as session:
            # Check certificate was saved
            cert = session.query(Certificate).first()
            assert cert is not None
            assert cert.common_name == mock_cert_info.common_name
            
            # Check scan record was created
            scan = session.query(CertificateScan).first()
            assert scan is not None
            assert scan.port == 443
            assert scan.status == "Valid"
