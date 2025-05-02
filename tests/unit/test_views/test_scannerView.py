"""
Unit tests for the scanner view module.
"""

import pytest
import streamlit as st
from unittest.mock import Mock, patch, MagicMock, ANY
from datetime import datetime, timezone, timedelta
import urllib3
import requests
import dns.resolver
import gc
import weakref
from sqlalchemy import create_engine, NullPool

from infra_mgmt.scanner.certificate_scanner import CertificateInfo, ScanResult
from infra_mgmt.scanner import ScanManager
from infra_mgmt.models import Domain, Certificate, CertificateScan, Host, CertificateBinding, Base
from infra_mgmt.views.scannerView import render_scan_interface
from urllib.parse import urlparse

# Global variable for tracking sessions
_SESSIONS = weakref.WeakSet()

@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Cleanup resources after each test"""
    yield
    
    # Clear Streamlit session state
    if hasattr(st, 'session_state'):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
    
    # Force garbage collection multiple times to break potential circular references
    for _ in range(3):
        gc.collect()
        
    # Clear any remaining sessions
    sessions = list(_SESSIONS)  # Make a copy of the set
    for session in sessions:
        if session:
            try:
                session.close()
                session.bind.dispose()
            except:
                pass
    _SESSIONS.clear()
    
    # Final garbage collection pass
    gc.collect()
    gc.collect(2)  # Generation 2 collection

@pytest.fixture(autouse=True)
def mock_network():
    """Mock all network calls to prevent real network access during tests"""
    patches = [
        patch('requests.get'),
        patch('requests.post'),
        patch('socket.socket'),
        patch('dns.resolver.resolve'),
        patch('urllib3.connectionpool.HTTPSConnectionPool._validate_conn')
    ]
    
    mocks = []
    for p in patches:
        m = p.start()
        mocks.append(m)
    
    # Configure mock responses
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.ok = True
    mocks[0].return_value = mock_response  # get
    mocks[1].return_value = mock_response  # post
    mocks[3].return_value = [MagicMock(address='1.2.3.4')]  # dns
    
    yield
    
    # Stop all patches
    for p in patches:
        try:
            p.stop()
        except:
            pass

@pytest.fixture
def engine():
    """Create an in-memory SQLite database for testing"""
    # Create engine with pooling disabled to prevent connection leaks
    engine = create_engine(
        'sqlite:///:memory:',
        echo=False,
        poolclass=NullPool  # Disable connection pooling
    )
    
    # Create all tables
    Base.metadata.create_all(engine)
    
    yield engine
    
    # Ensure all connections are closed
    engine.dispose()
    
    # Drop all tables
    Base.metadata.drop_all(engine)
    
    # Remove engine reference
    del engine

@pytest.fixture
def db_session(engine):
    """Create a new database session for a test"""
    from sqlalchemy.orm import sessionmaker, scoped_session
    
    # Create scoped session to ensure thread safety
    session_factory = sessionmaker(bind=engine)
    Session = scoped_session(session_factory)
    session = Session()
    
    # Track session for cleanup
    global _SESSIONS
    _SESSIONS.add(session)
    
    yield session
    
    # Cleanup
    try:
        session.rollback()
    except:
        pass
    try:
        session.close()
    except:
        pass
    Session.remove()

@pytest.fixture
def mock_session_state():
    """Create a mock session state that behaves like Streamlit's session state"""
    class MockSessionState:
        def __init__(self):
            # Initialize with default values
            self._data = {
                'scan_results': {
                    'success': [],
                    'error': [],
                    'warning': [],
                    'no_cert': []
                },
                'scan_in_progress': False,
                'current_operation': None,
                'scan_input': "",
                'scanned_domains': set(),
                'selected_sans': set(),
                'scan_queue': set(),
                'notifications': [],
                'scan_targets': []  # Ensure scan_targets is always present
            }
            
            # Create a mock tracker
            mock_tracker = MagicMock()
            mock_tracker.queue_size.return_value = 0
            
            # Create a mock infra_mgmt
            mock_infra_mgmt = MagicMock()
            mock_infra_mgmt.tracker = mock_tracker
            
            # Create a minimal scan manager mock
            scan_manager = MagicMock(spec=[
                'scan_target', 
                'reset_scan_state', 
                'get_scan_stats',
                'process_scan_target',
                'add_to_queue'  # Add missing method
            ])
            scan_manager.get_scan_stats.return_value = {'success_count': 0, 'error_count': 0}
            scan_manager.process_scan_target.return_value = ('example.com', 443, True, True)
            scan_manager.add_to_queue.return_value = None
            scan_manager.infra_mgmt = mock_infra_mgmt
            self._data['scan_manager'] = scan_manager
            
            # Create a mock get method that returns a MagicMock
            self._get_mock = MagicMock()
            self._get_mock.return_value = False
        
        def get(self, key, default=None):
            """Get a value from session state with a default"""
            return self._data.get(key, default)
        
        def __contains__(self, key):
            """Check if a key exists in session state"""
            return str(key) in self._data
        
        def __getitem__(self, key):
            """Get a value from session state"""
            return self._data[str(key)]
        
        def __setitem__(self, key, value):
            """Set a value in session state"""
            self._data[str(key)] = value
        
        def __getattr__(self, name):
            """Get an attribute from session state"""
            if name == 'get':
                return self.get
            if name in self._data:
                return self._data[name]
            raise AttributeError(f"{name}")
        
        def __setattr__(self, name, value):
            """Set an attribute in session state"""
            if name.startswith('_'):
                super().__setattr__(name, value)
            else:
                self._data[name] = value
        
        def clear(self):
            """Clear session state"""
            self._data.clear()
            self._get_mock.reset_mock()
        
        def __delitem__(self, key):
            """Delete a value from session state"""
            key = str(key)
            if key in self._data:
                del self._data[key]
            else:
                raise AttributeError(f"{key}")
        
        def __delattr__(self, name):
            if name in self._data:
                del self._data[name]
            else:
                raise AttributeError(f"{name}")
    
    mock_state = MockSessionState()
    yield mock_state
    mock_state.clear()

@pytest.fixture
def mock_cert_info():
    """Create a mock certificate info object"""
    now = datetime.now(timezone.utc)
    return CertificateInfo(
        serial_number='123456',
        thumbprint='abcdef',
        subject={'CN': 'test.example.com'},
        issuer={'CN': 'Test CA'},
        valid_from=now,
        expiration_date=now + timedelta(days=365),
        san=['test.example.com', 'www.test.example.com'],
        key_usage=None,
        signature_algorithm=None,
        common_name='test.example.com',
        chain_valid=True,
        ip_addresses=['192.168.1.1'],
        validation_errors=[],
        platform='test',
        headers={}
    )

@pytest.fixture
def mock_scan_result():
    """Create a mock scan result object"""
    now = datetime.now(timezone.utc)
    cert_info = CertificateInfo(
        serial_number='123456',
        thumbprint='abcdef',
        subject={'CN': 'test.example.com'},
        issuer={'CN': 'Test CA'},
        valid_from=now,
        expiration_date=now + timedelta(days=365),
        san=['test.example.com', 'www.test.example.com'],
        key_usage=None,
        signature_algorithm=None,
        common_name='test.example.com',
        chain_valid=True,
        ip_addresses=['192.168.1.1'],
        validation_errors=[],
        platform='test',
        headers={}
    )
    result = ScanResult(
        certificate_info=cert_info,
        ip_addresses=['192.168.1.1'],
        warnings=[]
    )
    
    yield result
    
    # Clear references
    result.certificate_info = None
    result.ip_addresses.clear()
    result.warnings.clear()

@pytest.fixture
def mock_streamlit():
    """Mock streamlit module"""
    # Create a minimal mock with only necessary methods
    mock_st = MagicMock(spec=[
        'text_area', 'button', 'checkbox', 'empty', 'container',
        'columns', 'markdown', 'error', 'warning', 'info', 'title',
        'expander', 'session_state', 'divider', 'subheader'
    ])
    
    # Simple session state
    mock_st.session_state = {
        'scan_results': {'success': [], 'error': [], 'warning': [], 'no_cert': []},
        'scan_in_progress': False,
        'current_operation': None,
        'scan_input': "",
        'scanned_domains': set(),
        'selected_sans': set(),
        'scan_queue': set(),
        'notifications': []
    }
    
    # Mock expander context manager
    mock_expander = MagicMock()
    mock_expander.__enter__ = MagicMock(return_value=mock_expander)
    mock_expander.__exit__ = MagicMock(return_value=None)
    mock_st.expander.return_value = mock_expander
    
    # Mock container context manager
    mock_container = MagicMock()
    mock_container.__enter__ = MagicMock(return_value=mock_container)
    mock_container.__exit__ = MagicMock(return_value=None)
    mock_st.container.return_value = mock_container
    
    # Mock columns
    mock_cols = [MagicMock(spec=[]), MagicMock(spec=[])]
    for col in mock_cols:
        col.__enter__ = MagicMock(return_value=col)
        col.__exit__ = MagicMock(return_value=None)
    mock_st.columns.return_value = mock_cols
    
    yield mock_st
    
    # Cleanup
    mock_st.session_state.clear()
    mock_st.columns.return_value = None
    mock_st.expander.return_value = None
    mock_st.container.return_value = None

def create_mock_streamlit():
    """Create a minimal mock streamlit instance"""
    mock_st = MagicMock()
    
    # Basic session state
    mock_st.session_state = MagicMock()
    mock_st.session_state.scan_results = {'success': [], 'error': [], 'warning': [], 'no_cert': []}
    mock_st.session_state.scan_in_progress = False
    mock_st.session_state.current_operation = None
    mock_st.session_state.scan_input = ""
    mock_st.session_state.scanned_domains = set()
    mock_st.session_state.selected_sans = set()
    mock_st.session_state.scan_queue = set()
    mock_st.session_state.scan_manager = MagicMock()
    
    # Basic UI elements
    mock_st.text_area.return_value = "example.com"
    mock_st.checkbox.return_value = True
    mock_st.button.return_value = False
    
    # Basic containers
    mock_container = MagicMock()
    mock_container.__enter__.return_value = mock_container
    mock_container.__exit__.return_value = None
    mock_st.container.return_value = mock_container
    
    # Basic columns
    mock_cols = [MagicMock(), MagicMock()]
    for col in mock_cols:
        col.__enter__.return_value = col
        col.__exit__.return_value = None
    mock_st.columns.return_value = mock_cols
    
    return mock_st

def test_render_scan_interface(mock_session_state):
    """Test basic interface rendering"""
    # Create a simple engine
    engine = create_engine('sqlite:///:memory:', echo=False, poolclass=NullPool)
    Base.metadata.create_all(engine)
    
    # Ensure scan_targets is present
    mock_session_state.scan_targets = []
    
    try:
        # Create minimal mocks without circular references
        mock_st = MagicMock(spec=[
            'title', 'text_area', 'checkbox', 'columns', 'session_state',
            'empty', 'expander', 'markdown', 'button', 'container',
            'progress', 'spinner', 'divider', 'subheader'
        ])
        
        # Configure columns with context managers
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_st.columns.return_value = [col1, col2]
        
        # Use the fixture's session state
        mock_st.session_state = mock_session_state
        
        # Mock expander context manager
        mock_expander = MagicMock()
        mock_expander.__enter__ = MagicMock(return_value=mock_expander)
        mock_expander.__exit__ = MagicMock(return_value=None)
        mock_st.expander.return_value = mock_expander
        
        # Mock container context manager
        mock_container = MagicMock()
        mock_container.__enter__ = MagicMock(return_value=mock_container)
        mock_container.__exit__ = MagicMock(return_value=None)
        mock_st.container.return_value = mock_container
        
        # Mock progress context manager
        mock_progress = MagicMock()
        mock_progress.__enter__ = MagicMock(return_value=mock_progress)
        mock_progress.__exit__ = MagicMock(return_value=None)
        mock_st.progress.return_value = mock_progress
        
        # Mock spinner context manager
        mock_spinner = MagicMock()
        mock_spinner.__enter__ = MagicMock(return_value=mock_spinner)
        mock_spinner.__exit__ = MagicMock(return_value=None)
        mock_st.spinner.return_value = mock_spinner
        
        # Run test with minimal patching
        with patch('infra_mgmt.views.scannerView.st', new=mock_st):
            render_scan_interface(engine)
        
        # Minimal assertions
        assert mock_st.title.called
        assert mock_st.columns.called
        assert mock_st.expander.called
    
    finally:
        # Clean up database
        engine.dispose()
        Base.metadata.drop_all(engine)
        
        # Clear references
        mock_st.columns.return_value = None
        mock_st.expander.return_value = None
        mock_st.container.return_value = None
        mock_st.progress.return_value = None
        mock_st.spinner.return_value = None

@pytest.mark.test_interface
def test_render_scan_interface_with_input(engine, mock_session_state):
    """Test scan interface with user input"""
    # Ensure scan_targets is present
    mock_session_state.scan_targets = []
    # Create minimal mocks to avoid memory leaks
    mock_st = MagicMock(spec=[
        'title', 'text_area', 'checkbox', 'columns', 'session_state',
        'empty', 'expander', 'markdown', 'button', 'container',
        'progress', 'spinner', 'info', 'error', 'warning', 'divider', 'subheader'
    ])
    
    # Configure basic mocks
    mock_st.text_area.return_value = "example.com\ntest.com:443"
    
    # Configure columns with context managers
    col1, col2 = MagicMock(), MagicMock()
    col1.__enter__ = MagicMock(return_value=col1)
    col1.__exit__ = MagicMock(return_value=None)
    col2.__enter__ = MagicMock(return_value=col2)
    col2.__exit__ = MagicMock(return_value=None)
    mock_st.columns.return_value = [col1, col2]
    
    # Use the fixture's session state
    mock_st.session_state = mock_session_state
    
    # Mock expander context manager
    mock_expander = MagicMock()
    mock_expander.__enter__ = MagicMock(return_value=mock_expander)
    mock_expander.__exit__ = MagicMock(return_value=None)
    mock_st.expander.return_value = mock_expander
    
    # Mock container context manager
    mock_container = MagicMock()
    mock_container.__enter__ = MagicMock(return_value=mock_container)
    mock_container.__exit__ = MagicMock(return_value=None)
    mock_st.container.return_value = mock_container
    
    # Mock progress and spinner
    mock_progress = MagicMock()
    mock_progress.__enter__ = MagicMock(return_value=mock_progress)
    mock_progress.__exit__ = MagicMock(return_value=None)
    mock_st.progress.return_value = mock_progress
    
    mock_spinner = MagicMock()
    mock_spinner.__enter__ = MagicMock(return_value=mock_spinner)
    mock_spinner.__exit__ = MagicMock(return_value=None)
    mock_st.spinner.return_value = mock_spinner
    
    # Configure scan manager
    mock_session_state.scan_manager.scan_target.return_value = MagicMock(
        certificate_info=MagicMock(
            common_name='example.com',
            chain_valid=True
        ),
        ip_addresses=['192.168.1.1'],
        warnings=[]
    )
    
    try:
        # Run test with minimal patching
        with patch('streamlit.session_state', mock_session_state), \
             patch('infra_mgmt.views.scannerView.st', mock_st):
            render_scan_interface(engine)
            
            # Basic assertions
            mock_st.text_area.assert_called_once_with(
                "Enter domains to scan (one per line)",
                value="",
                height=150,
                placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
            )
    finally:
        # Clear references
        mock_st.columns.return_value = None
        mock_st.expander.return_value = None
        mock_st.container.return_value = None
        mock_st.progress.return_value = None
        mock_st.spinner.return_value = None

@pytest.mark.test_integration
def test_scan_interface_and_results_integration(engine, mock_session_state, mock_scan_result):
    """Test interface and results display together"""
    # Ensure scan_targets is present
    mock_session_state.scan_targets = []
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.markdown') as mock_markdown, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.session_state', mock_session_state), \
         patch('streamlit.progress') as mock_progress, \
         patch('streamlit.empty') as mock_empty, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.checkbox') as mock_checkbox, \
         patch('streamlit.container') as mock_container, \
         patch('streamlit.tabs') as mock_tabs:
        
        # Configure mocks
        mock_text_area.return_value = "example.com"
        mock_button.return_value = True
        mock_session_state.scan_manager.scan_target.return_value = mock_scan_result
        mock_checkbox.return_value = True
        
        # Configure progress tracking
        mock_progress_bar = MagicMock()
        mock_progress.return_value = mock_progress_bar
        mock_empty.return_value = MagicMock()
        
        # Configure spinner
        mock_spinner_ctx = MagicMock()
        mock_spinner.return_value.__enter__ = MagicMock(return_value=mock_spinner_ctx)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=None)
        
        # Configure columns with context managers
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_columns.return_value = [col1, col2]
        
        # Configure container
        mock_container_ctx = MagicMock()
        mock_container.return_value.__enter__ = MagicMock(return_value=mock_container_ctx)
        mock_container.return_value.__exit__ = MagicMock(return_value=None)
        
        # Configure tabs
        mock_tabs_list = [MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        for tab in mock_tabs_list:
            tab.__enter__ = MagicMock(return_value=tab)
            tab.__exit__ = MagicMock(return_value=None)
        mock_tabs.return_value = mock_tabs_list
        
        # Configure expander
        mock_expander_ctx = MagicMock()
        mock_expander.return_value.__enter__ = MagicMock(return_value=mock_expander_ctx)
        mock_expander.return_value.__exit__ = MagicMock(return_value=None)
        
        # Configure scan manager
        mock_session_state.scan_manager.process_scan_target.return_value = ('example.com', 443, True, True)
        mock_session_state.scan_manager.scan_target.return_value = mock_scan_result
        
        render_scan_interface(engine)
        
        # Verify scan was initiated
        assert mock_session_state.scan_in_progress == True
        
        # Verify scan manager was called with correct parameters
        mock_session_state.scan_manager.scan_target.assert_called_with(
            session=ANY,
            domain='example.com',
            port=443,
            check_whois=True,
            check_dns=True,
            check_subdomains=True,
            check_sans=True,
            detect_platform=True,
            validate_chain=True,
            status_container=ANY,
            progress_container=ANY,
            current_step=ANY,
            total_steps=ANY
        )

@pytest.mark.test_scan_button
def test_scan_button_functionality(engine, mock_session_state, mock_scan_result):
    """Test the scan button functionality with valid input"""
    # Ensure scan_targets is present
    mock_session_state.scan_targets = []
    with patch('streamlit.text_area') as mock_text_area, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.progress') as mock_progress, \
         patch('streamlit.empty') as mock_empty, \
         patch('streamlit.error') as mock_error, \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.title') as mock_title, \
         patch('streamlit.expander') as mock_expander, \
         patch('streamlit.session_state', mock_session_state), \
         patch('streamlit.checkbox') as mock_checkbox:
        
        # Configure mocks
        mock_text_area.return_value = "example.com\ntest.com:8443"
        mock_button.return_value = True  # Simulate button click
        mock_session_state.scan_in_progress = False
        
        # Create and configure scan manager mock with stable side effects
        mock_scan_manager = MagicMock()
        process_scan_results = [
            ('example.com', 443, True, True),  # First domain
            ('test.com', 8443, True, True)     # Second domain
        ]
        mock_scan_manager.process_scan_target = MagicMock()
        mock_scan_manager.process_scan_target.side_effect = process_scan_results
        
        mock_scan_manager.scan_target = MagicMock(return_value=mock_scan_result)
        mock_scan_manager.get_scan_stats = MagicMock(return_value={'success_count': 2, 'error_count': 0})
        mock_scan_manager.reset_scan_state = MagicMock()
        mock_scan_manager.add_to_queue = MagicMock()
        
        # Create mock tracker with stable queue size
        mock_tracker = MagicMock()
        mock_tracker.queue_size = MagicMock(return_value=0)
        
        # Create mock infra_mgmt with stable tracker
        mock_infra_mgmt = MagicMock()
        mock_infra_mgmt.tracker = mock_tracker
        
        # Add infra_mgmt to scan manager
        mock_scan_manager.infra_mgmt = mock_infra_mgmt
        
        # Set scan manager in session state
        mock_session_state.scan_manager = mock_scan_manager
        
        # Configure progress tracking with proper context managers
        mock_progress_bar = MagicMock()
        mock_progress_bar.__enter__ = MagicMock(return_value=mock_progress_bar)
        mock_progress_bar.__exit__ = MagicMock(return_value=None)
        mock_progress.return_value = mock_progress_bar
        
        # Configure empty container
        mock_empty_container = MagicMock()
        mock_empty.return_value = mock_empty_container
        
        # Configure spinner with context manager
        mock_spinner_ctx = MagicMock()
        mock_spinner_ctx.__enter__ = MagicMock(return_value=mock_spinner_ctx)
        mock_spinner_ctx.__exit__ = MagicMock(return_value=None)
        mock_spinner.return_value = mock_spinner_ctx
        
        # Configure columns with context managers
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_columns.return_value = [col1, col2]
        
        # Configure expander with context manager
        mock_expander_ctx = MagicMock()
        mock_expander_ctx.__enter__ = MagicMock(return_value=mock_expander_ctx)
        mock_expander_ctx.__exit__ = MagicMock(return_value=None)
        mock_expander.return_value = mock_expander_ctx
        
        # Configure checkboxes to return True
        mock_checkbox.return_value = True
        
        # Run the interface
        render_scan_interface(engine)
        
        # Verify scan was initiated
        assert mock_session_state.scan_in_progress == True
        
        # Verify process_scan_target was called twice
        assert mock_scan_manager.process_scan_target.call_count == 2
        
        # Verify scan_target was called with correct parameters for both domains
        expected_calls = [
            call(
                session=ANY,
                domain='example.com',
                port=443,
                check_whois=True,
                check_dns=True,
                check_subdomains=True,
                check_sans=True,
                detect_platform=True,
                validate_chain=True,
                status_container=ANY,
                progress_container=ANY,
                current_step=ANY,
                total_steps=ANY
            ),
            call(
                session=ANY,
                domain='test.com',
                port=8443,
                check_whois=True,
                check_dns=True,
                check_subdomains=True,
                check_sans=True,
                detect_platform=True,
                validate_chain=True,
                status_container=ANY,
                progress_container=ANY,
                current_step=ANY,
                total_steps=ANY
            )
        ]
        
        mock_scan_manager.scan_target.assert_has_calls(expected_calls, any_order=True)
        
        # Verify progress was tracked
        assert mock_progress.called
        assert mock_empty.called  # For status container

@pytest.mark.test_display
def test_recent_scans_display(engine, mock_session_state):
    """Test that recent scans are displayed correctly"""
    # Ensure scan_targets is present
    mock_session_state.scan_targets = []
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
        mock_expander.__enter__ = MagicMock(return_value=mock_expander)
        mock_expander.__exit__ = MagicMock(return_value=None)
        mock_st.expander.return_value = mock_expander

        # Setup test data with timezone-aware datetimes
        scan_time = datetime.now(timezone.utc)
        mock_cert = MagicMock(
            common_name='example.com',
            valid_until=datetime.now(timezone.utc) + timedelta(days=30)
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
        mock_session_instance.__enter__ = MagicMock(return_value=mock_session_instance)
        mock_session_instance.__exit__ = MagicMock(return_value=None)

        # Mock the host for failed scan
        mock_host = MagicMock(name='example-failed.com')

        # Setup query chain for recent scans
        mock_scan_query = MagicMock()
        mock_host_query = MagicMock()

        # Configure query side effect
        mock_session_instance.query = MagicMock()
        def query_side_effect(*args):
            if args and args[0] == CertificateScan:
                return mock_scan_query
            elif args and args[0] == Host:
                return mock_host_query
            return MagicMock()
        mock_session_instance.query.side_effect = query_side_effect

        # Configure scan query chain
        mock_scan_query.outerjoin = MagicMock(return_value=mock_scan_query)
        mock_scan_query.order_by = MagicMock(return_value=mock_scan_query)
        mock_scan_query.limit = MagicMock(return_value=mock_scan_query)
        mock_scan_query.all = MagicMock(return_value=[mock_scan, mock_failed_scan])

        # Configure host query chain
        mock_host_query.filter_by = MagicMock(return_value=MagicMock(first=MagicMock(return_value=mock_host)))

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
    # Ensure scan_targets is present
    mock_session_state.scan_targets = []
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
        ("example.com:-1", False, "Negative port"),
        ("not_a_domain", False, "Invalid domain format"),
        ("example.com:abc", False, "Non-numeric port")
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

        # Configure streamlit mock
        mock_st.error = mock_error
        mock_st.text_area = MagicMock(return_value=input_text)
        mock_st.empty = MagicMock(return_value=MagicMock())
        mock_st.progress = MagicMock(return_value=MagicMock())
        mock_st.button = MagicMock(return_value=True)  # Always clicked
        mock_st.checkbox = MagicMock(return_value=True)  # All options enabled
        
        # Configure columns
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_st.columns = MagicMock(return_value=[col1, col2])

        # Configure expander
        mock_expander = MagicMock()
        mock_expander.__enter__ = MagicMock(return_value=mock_expander)
        mock_expander.__exit__ = MagicMock(return_value=None)
        mock_st.expander = MagicMock(return_value=mock_expander)

        # Configure container
        mock_container = MagicMock()
        mock_container.__enter__ = MagicMock(return_value=mock_container)
        mock_container.__exit__ = MagicMock(return_value=None)
        mock_st.container = MagicMock(return_value=mock_container)

        # Configure tabs
        mock_tabs = [MagicMock(), MagicMock(), MagicMock(), MagicMock()]
        for tab in mock_tabs:
            tab.__enter__ = MagicMock(return_value=tab)
            tab.__exit__ = MagicMock(return_value=None)
        mock_st.tabs = MagicMock(return_value=mock_tabs)

        # Configure session state
        mock_st.session_state = mock_session_state

        with patch('infra_mgmt.views.scannerView.st', mock_st), \
             patch('infra_mgmt.views.scannerView.Session') as mock_session_class:

            # Mock the database session
            mock_session_instance = MagicMock()
            mock_session_class.return_value = mock_session_instance
            mock_session_instance.__enter__ = MagicMock(return_value=mock_session_instance)
            mock_session_instance.__exit__ = MagicMock(return_value=None)

            # Configure query chain for recent scans
            mock_query = MagicMock()
            mock_session_instance.query = MagicMock(return_value=mock_query)
            mock_query.outerjoin = MagicMock(return_value=mock_query)
            mock_query.order_by = MagicMock(return_value=mock_query)
            mock_query.limit = MagicMock(return_value=mock_query)
            mock_query.all = MagicMock(return_value=[])

            # Call the function
            render_scan_interface(engine)

            # Verify error handling
            if not is_valid:
                print(f"DEBUG: Expecting errors for invalid input: {input_text}")
                assert any(
                    "Invalid port number" in msg or 
                    "Please enter at least one" in msg or 
                    "Invalid domain format" in msg or
                    "Port must be between" in msg or
                    "Non-numeric port" in msg
                    for msg in error_messages
                ), f"Expected error for invalid input: {input_text}. Got messages: {error_messages}"
            else:
                assert not any("error" in msg.lower() for msg in error_messages), \
                    f"Got unexpected error for valid input: {input_text}. Messages: {error_messages}"

@pytest.mark.test_database_integration
def test_database_integration(engine, mock_session_state, mock_scan_result):
    """Test database interactions during scanning"""
    # Ensure scan_targets is present
    mock_session_state.scan_targets = []
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

        # Create and configure scanner mock
        mock_scanner = MagicMock()
        mock_scanner.scan_certificate = MagicMock(return_value=mock_scan_result)
        mock_scanner.scan_target = MagicMock(return_value=mock_scan_result)
        mock_scanner.process_scan_target = MagicMock(return_value=('example.com', 443, True, True))
        mock_scanner.get_scan_stats = MagicMock(return_value={'success_count': 0, 'error_count': 0})
        mock_scanner.reset_scan_state = MagicMock()
        mock_session_state.scanner = mock_scanner
        mock_session_state.scan_manager = mock_scanner  # Ensure both references exist
        
        # Configure columns with context managers
        col1, col2 = MagicMock(), MagicMock()
        col1.__enter__ = MagicMock(return_value=col1)
        col1.__exit__ = MagicMock(return_value=None)
        col2.__enter__ = MagicMock(return_value=col2)
        col2.__exit__ = MagicMock(return_value=None)
        mock_columns.return_value = [col1, col2]
        
        # Configure expander with context manager
        mock_expander_ctx = MagicMock()
        mock_expander_ctx.__enter__ = MagicMock(return_value=mock_expander_ctx)
        mock_expander_ctx.__exit__ = MagicMock(return_value=None)
        mock_expander.return_value = mock_expander_ctx
        
        # Configure progress tracking
        mock_progress_bar = MagicMock()
        mock_progress_bar.__enter__ = MagicMock(return_value=mock_progress_bar)
        mock_progress_bar.__exit__ = MagicMock(return_value=None)
        mock_progress.return_value = mock_progress_bar
        
        # Configure empty container
        mock_empty_container = MagicMock()
        mock_empty.return_value = mock_empty_container
        
        # Configure spinner with context manager
        mock_spinner_ctx = MagicMock()
        mock_spinner_ctx.__enter__ = MagicMock(return_value=mock_spinner_ctx)
        mock_spinner_ctx.__exit__ = MagicMock(return_value=None)
        mock_spinner.return_value = mock_spinner_ctx
        
        # Initialize session state
        mock_session_state.scan_results = {
            'success': [],
            'error': [],
            'warning': []
        }
        mock_session_state.scan_targets = []
        mock_session_state.scan_in_progress = False
        mock_session_state.current_operation = None
        mock_session_state.scan_input = "example.com"
        mock_session_state.scanned_domains = set()
        mock_session_state.selected_sans = set()
        mock_session_state.scan_queue = set()
        mock_session_state.get = MagicMock(return_value=False)  # For transitioning flag
        
        # Create tables
        Base.metadata.create_all(engine)
        
        # Run the interface
        render_scan_interface(engine)
        
        # Verify database entries
        with Session(engine) as session:
            # Check certificate was saved
            cert = session.query(Certificate).first()
            assert cert is not None
            assert cert.common_name == mock_scan_result.certificate_info.common_name
            assert cert.chain_valid == mock_scan_result.certificate_info.chain_valid
            
            # Check scan record was created
            scan = session.query(CertificateScan).first()
            assert scan is not None
            assert scan.port == 443
            assert scan.status == "Valid"

# Patch streamlit to include a tabs method that returns four MagicMock tab objects
@pytest.fixture(autouse=True)
def patch_streamlit_tabs(monkeypatch):
    tabs_mocks = [MagicMock() for _ in range(4)]
    monkeypatch.setattr(st, "tabs", MagicMock(return_value=tabs_mocks))
    yield

# Ensure process_scan_target always returns four values in all mocks
@pytest.fixture(autouse=True)
def patch_process_scan_target(monkeypatch):
    # Patch ScanManager.process_scan_target to always return four values
    original = ScanManager.process_scan_target
    def always_four(*args, **kwargs):
        # Return a valid tuple (is_valid, hostname, port, error)
        return (True, "example.com", 443, None)
    monkeypatch.setattr(ScanManager, "process_scan_target", always_four)
    yield
    monkeypatch.setattr(ScanManager, "process_scan_target", original)
