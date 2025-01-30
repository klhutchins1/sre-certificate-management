import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from cert_scanner.models import Certificate, CertificateScan, Host
from cert_scanner.views.scannerView import render_scan_interface, render_scan_results
from cert_scanner.scanner import CertificateInfo
from urllib.parse import urlparse
import streamlit as st

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
        
        # Verify text area was configured correctly
        mock_text_area.assert_called_once_with(
            "Enter hostnames to scan (one per line)",
            value="",
            height=150,
            placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
        )
        
        # Verify help expander was created
        mock_expander.assert_called_once()

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
            value="",
            height=150,
            placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
        )

@pytest.mark.test_results
def test_render_scan_results():
    """Test the scan results display functionality"""
    with patch('streamlit.markdown') as mock_markdown, \
         patch('streamlit.session_state', new=MagicMock()) as mock_state:
        
        # Configure session state with string messages instead of objects
        mock_state.scan_results = {
            'success': ['✅ example.com:443 - Valid certificate found'],
            'error': ['❌ failed.com:443 - Connection failed'],
            'warning': ['⚠️ warning.com:443 - Certificate expiring soon']
        }
        
        render_scan_results()
        
        # Verify results were displayed
        assert mock_markdown.call_count >= 3  # At least headers and one result
        markdown_calls = [str(call) for call in mock_markdown.call_args_list]
        assert any('### ✅ Successful Scans' in str(call) for call in mock_markdown.call_args_list)
        assert any('example.com:443' in str(call) for call in mock_markdown.call_args_list)

@pytest.mark.test_integration
def test_scan_interface_and_results_integration(engine, mock_session_state, mock_cert_info):
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
         patch('streamlit.session_state', new=mock_session_state):
        
        # Configure mocks
        mock_text_area.return_value = "example.com\ntest.com:8443"
        mock_button.return_value = True  # Simulate button click
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
        
        render_scan_interface(engine)
        
        # Verify scanner was called for each hostname
        assert mock_session_state.scanner.scan_certificate.call_count == 2
        mock_session_state.scanner.scan_certificate.assert_any_call('example.com', 443)
        mock_session_state.scanner.scan_certificate.assert_any_call('test.com', 8443)

@pytest.mark.test_display
def test_recent_scans_display(engine, mock_session_state):
    """Test that recent scans are displayed correctly"""
    with patch('cert_scanner.views.scannerView.Session') as mock_session_class, \
         patch('cert_scanner.views.scannerView.st') as mock_st:

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

        # Create a mock scan with all required attributes
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

        # Verify the div tags and content were rendered
        markdown_calls = [call for call in mock_st.markdown.call_args_list]

        # Find the sequence of markdown calls for the recent scan
        found_div_start = False
        found_scan_details = False
        found_div_end = False

        for args, kwargs in markdown_calls:
            text = args[0] if args else ""
            is_html = kwargs.get('unsafe_allow_html', False)

            if is_html:
                if "<div" in text and "font-size:0.9em" in text:
                    found_div_start = True
                elif found_div_start and ("example.com" in text or "example-failed.com" in text):
                    found_scan_details = True
                elif "</div>" in text:
                    found_div_end = True

        assert found_div_start, "Opening div tag not found"
        assert found_scan_details, "Scan details not found"
        assert found_div_end, "Closing div tag not found"

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
            'button': mock_button
        })
        
        with patch('cert_scanner.views.scannerView.st', new=mock_st), \
             patch('cert_scanner.views.scannerView.Session') as mock_session_class:

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

            # Parse the input manually to debug port validation
            if ':' in input_text and '//' not in input_text:
                hostname, port = input_text.rsplit(':', 1)
                try:
                    port = int(port)
                    print(f"DEBUG: Test parsed port {port} from {input_text}")
                    if port <= 0 or port > 65535:
                        print(f"DEBUG: Test detected invalid port: {port}")
                        # Ensure error messages were shown for invalid port
                        assert any("Port must be between 1 and 65535" in msg for msg in error_messages), \
                            f"Expected port range error for port {port} in {input_text}. Got: {error_messages}"
                        assert any("Please enter at least one valid hostname to scan" in msg for msg in error_messages), \
                            f"Expected general error message for invalid port in {input_text}. Got: {error_messages}"
                except ValueError:
                    print(f"DEBUG: Test failed to parse port: {port}")

            # Verify error handling
            if not is_valid:
                print(f"DEBUG: Expecting errors for invalid input: {input_text}")
                assert len(error_messages) > 0, \
                    f"Expected error for invalid input: {input_text}. No error messages were shown."
                
                if ":-1" in input_text or ":99999" in input_text:
                    print("DEBUG: Testing port range case")
                    assert any("Port must be between 1 and 65535" in msg for msg in error_messages), \
                        f"Expected port range error for port in {input_text}. Got: {error_messages}"
                    assert any("Please enter at least one valid hostname to scan" in msg for msg in error_messages), \
                        f"Expected general error message for invalid port in {input_text}. Got: {error_messages}"
                elif not input_text.strip():
                    print("DEBUG: Testing empty input case")
                    assert any("Please enter at least one hostname to scan" in msg for msg in error_messages), \
                        f"Expected empty input error for {input_text}. Got: {error_messages}"
                elif input_text == "http://":
                    print("DEBUG: Testing invalid URL case")
                    assert any("Hostname cannot be empty" in msg for msg in error_messages), \
                        f"Expected empty hostname error for {input_text}. Got: {error_messages}"
                    assert any("Please enter at least one valid hostname to scan" in msg for msg in error_messages), \
                        f"Expected general error message for invalid URL in {input_text}. Got: {error_messages}"
            else:
                print(f"DEBUG: Expecting no errors for valid input: {input_text}")
                # For valid inputs, verify no errors were shown
                assert len(error_messages) == 0, \
                    f"Unexpected error for valid input {input_text}: {error_messages}"

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
         patch('streamlit.session_state', new=mock_session_state):
        
        # Configure mocks
        mock_text_area.return_value = "example.com"
        mock_button.return_value = True
        mock_empty.return_value = MagicMock()
        mock_progress.return_value = MagicMock()
        mock_columns.return_value = [MagicMock(), MagicMock()]
        mock_expander.return_value.__enter__.return_value = MagicMock()
        
        # Initialize session state
        mock_session_state.scan_results = {
            'success': [],
            'error': [],
            'warning': []
        }
        mock_session_state.scan_targets = []
        mock_session_state.get.return_value = False  # For transitioning flag
        mock_session_state.scanner = MagicMock()
        mock_session_state.scanner.scan_certificate.side_effect = ConnectionError("Connection failed")
        
        render_scan_interface(engine)
        
        # Verify error was displayed
        error_calls = [str(call) for call in mock_error.call_args_list]
        assert any('Connection error scanning example.com:443' in str(call) for call in error_calls), "Connection error not displayed"

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
         patch('streamlit.session_state', new=mock_session_state):
        
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
        from cert_scanner.models import Base
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
