"""
Unit tests for the app module.
"""

import pytest
import streamlit as st
from infra_mgmt.app import init_session_state, render_sidebar, main
from infra_mgmt.scanner.certificate_scanner import CertificateScanner, CertificateInfo
from infra_mgmt.scanner import ScanManager
from infra_mgmt.settings import Settings
from unittest.mock import patch, MagicMock, call
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate, Domain
import threading
import logging

@pytest.fixture(autouse=True)
def mock_streamlit():
    """Mock streamlit components and context"""
    with patch('streamlit.sidebar'):
        with patch('streamlit.radio', return_value="Dashboard"):
            with patch('streamlit.columns') as mock_columns:
                # Create a mock column object that supports metric method
                class MockColumn:
                    def metric(self, label, value):
                        pass
                
                # Make columns return a list of mock column objects
                def mock_columns_func(specs):
                    return [MockColumn() for _ in range(len(specs) if isinstance(specs, list) else specs)]
                
                mock_columns.side_effect = mock_columns_func
                yield

@pytest.fixture(autouse=True)
def setup_streamlit():
    """Setup streamlit session state before each test"""
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    yield

@pytest.fixture
def mock_db_engine():
    """Create a test database engine with schema"""
    engine = create_engine('sqlite:///:memory:')
    # Create all tables
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def mock_settings(monkeypatch):
    """Mock settings for testing"""
    test_config = {
        "paths": {
            "database": ":memory:",
            "backups": "tests/data/backups"
        }
    }
    Settings.set_test_mode(test_config)
    yield Settings()
    Settings._reset()

@pytest.fixture
def mock_render_functions():
    """Mock all render functions for views"""
    with patch('infra_mgmt.app.render_dashboard') as mock_dashboard, \
         patch('infra_mgmt.app.render_certificate_list') as mock_certificates, \
         patch('infra_mgmt.app.render_hosts_view') as mock_hosts, \
         patch('infra_mgmt.app.render_applications_view') as mock_applications, \
         patch('infra_mgmt.app.render_scan_interface') as mock_scan, \
         patch('infra_mgmt.app.render_history_view') as mock_history, \
         patch('infra_mgmt.app.render_search_view') as mock_search, \
         patch('infra_mgmt.app.render_settings_view') as mock_settings:
        
        yield {
            'dashboard': mock_dashboard,
            'certificates': mock_certificates,
            'hosts': mock_hosts,
            'applications': mock_applications,
            'scan': mock_scan,
            'history': mock_history,
            'search': mock_search,
            'settings': mock_settings
        }

@patch('infra_mgmt.app.init_database')
def test_init_session_state(mock_init_db, mock_settings, mock_db_engine):
    """Test session state initialization"""
    # Setup mock database
    mock_init_db.return_value = mock_db_engine
    
    # Initial state should be empty
    assert 'initialized' not in st.session_state
    assert 'scanner' not in st.session_state
    assert 'selected_cert' not in st.session_state
    assert 'current_view' not in st.session_state
    assert 'engine' not in st.session_state
    
    # Initialize session state
    init_session_state()
    
    # Verify state was initialized
    assert st.session_state.initialized is True
    assert isinstance(st.session_state.scanner, CertificateScanner)
    assert st.session_state.selected_cert is None
    assert st.session_state.current_view == "Dashboard"
    assert st.session_state.engine is mock_db_engine
    mock_init_db.assert_called_once()

@patch('streamlit.radio')
def test_render_sidebar(mock_radio):
    """Test sidebar navigation rendering"""
    # Set initial view
    st.session_state.current_view = "Dashboard"
    
    # Mock radio button return value
    mock_radio.return_value = "🔐 Certificates"
    
    # Render sidebar
    new_view = render_sidebar()
    
    # Verify view was updated
    assert new_view == "Certificates"
    assert st.session_state.current_view == "Certificates"

@patch('streamlit.radio')
def test_sidebar_navigation_options(mock_radio):
    """Test all navigation options in sidebar"""
    st.session_state.current_view = "Dashboard"

    # Expected navigation options with their icons
    expected_options = {
        "Dashboard": "📊 Dashboard",
        "Certificates": "🔐 Certificates",
        "Hosts": "💻 Hosts",
        "Applications": "📦 Applications",
        "Scanner": "🔍 Scanner",
        "Search": "🔎 Search",
        "History": "📋 History",
        "Settings": "⚙️ Settings"
    }

    # Test each navigation option
    for view, display in expected_options.items():
        mock_radio.return_value = display
        new_view = render_sidebar()
        assert new_view == view, f"Expected view {view} but got {new_view}"
        assert st.session_state.current_view == view

@patch('infra_mgmt.app.render_sidebar')
@patch('infra_mgmt.app.init_database')
def test_main_view_rendering(mock_init_db, mock_sidebar, mock_render_functions, mock_settings, mock_db_engine):
    """Test that main function renders the correct view based on current_view"""
    # Setup mock database
    mock_init_db.return_value = mock_db_engine
    
    # Mock sidebar to return different views
    views = ["Dashboard", "Certificates", "Hosts", "Applications", "Scanner", "Search", "History", "Settings"]
    mock_functions = {
        "Dashboard": mock_render_functions['dashboard'],
        "Certificates": mock_render_functions['certificates'],
        "Hosts": mock_render_functions['hosts'],
        "Applications": mock_render_functions['applications'],
        "Scanner": mock_render_functions['scan'],
        "Search": mock_render_functions['search'],
        "History": mock_render_functions['history'],
        "Settings": mock_render_functions['settings']
    }
    
    for view in views:
        # Setup
        mock_sidebar.return_value = view
        st.session_state.current_view = view
        st.session_state.initialized = True
        st.session_state.engine = mock_db_engine
        
        # Run main
        main()
        
        # Verify correct render function was called
        mock_functions[view].assert_called_once_with(mock_db_engine)
        
        # Reset mock
        for mock_func in mock_functions.values():
            mock_func.reset_mock()

@patch('infra_mgmt.app.render_sidebar')
@patch('infra_mgmt.app.init_database')
def test_main_initializes_session(mock_init_db, mock_sidebar, mock_settings, mock_db_engine):
    """Test that main function initializes session state if not initialized"""
    # Setup mock database
    mock_init_db.return_value = mock_db_engine
    mock_sidebar.return_value = "Dashboard"
    
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Run main
    with patch('infra_mgmt.app.render_dashboard') as mock_dashboard:
        main()
        
        # Verify session was initialized
        assert st.session_state.initialized is True
        assert isinstance(st.session_state.scanner, CertificateScanner)
        assert st.session_state.engine is mock_db_engine
        mock_init_db.assert_called_once()
        
        # Verify dashboard was rendered
        mock_dashboard.assert_called_once_with(mock_db_engine)

@patch('infra_mgmt.app.init_session_state')
@patch('infra_mgmt.app.render_sidebar')
@patch('infra_mgmt.app.init_database')
def test_main_preserves_session(mock_init_db, mock_sidebar, mock_init_session, mock_settings, mock_db_engine):
    """Test that main function preserves existing session state"""
    # Setup mock database
    mock_init_db.return_value = mock_db_engine
    mock_sidebar.return_value = "Dashboard"

    # Create a test scanner
    test_scanner = CertificateScanner()

    # Run main with all necessary mocks
    with patch('infra_mgmt.app.st.session_state', new_callable=MagicMock) as mock_session_state, \
         patch('infra_mgmt.app.render_dashboard') as mock_dashboard:
        # Initialize session with custom values
        mock_session_state.initialized = True
        mock_session_state.scanner = test_scanner
        mock_session_state.selected_cert = "test_cert"
        mock_session_state.current_view = "Dashboard"
        mock_session_state.engine = mock_db_engine
        
        # Run main
        main()

        # Verify session values were preserved
        assert mock_session_state.scanner is test_scanner, "Scanner object was replaced"
        assert mock_session_state.selected_cert == "test_cert"
        assert mock_session_state.engine is mock_db_engine
        # Verify init_database wasn't called again
        mock_init_db.assert_not_called()
        # Verify init_session_state was called
        mock_init_session.assert_called_once()
        # Verify dashboard was rendered
        mock_dashboard.assert_called_once_with(mock_db_engine)

@patch('infra_mgmt.app.init_database')
def test_main_handles_database_failure(mock_init_db, mock_settings):
    """Test that main function handles database initialization failure gracefully"""
    # Setup mock database to return None (initialization failure)
    mock_init_db.return_value = None
    
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Run main with necessary mocks
    with patch('infra_mgmt.app.render_sidebar') as mock_sidebar, \
         patch('infra_mgmt.app.render_dashboard') as mock_dashboard:
        mock_sidebar.return_value = "Dashboard"
        
        # Run main
        main()
        
        # Verify session was still initialized
        assert st.session_state.initialized is True
        assert isinstance(st.session_state.scanner, CertificateScanner)
        assert st.session_state.engine is None
        mock_init_db.assert_called_once()
        
        # Verify dashboard was still rendered
        mock_dashboard.assert_called_once_with(None)

@patch('infra_mgmt.static.styles.load_css')
def test_styling_and_layout(mock_load_css):
    """Test that styling and layout is properly loaded"""
    # Force module reload to trigger module-level code
    import importlib
    import infra_mgmt.app
    importlib.reload(infra_mgmt.app)

    # Run main to trigger CSS loading
    with patch('streamlit.radio', return_value="📊 Dashboard"), \
         patch('infra_mgmt.app.render_dashboard'), \
         patch('infra_mgmt.app.st.sidebar', new_callable=MagicMock) as mock_st_sidebar:
        
        # Mock the sidebar context manager
        mock_st_sidebar.__enter__ = MagicMock(return_value=mock_st_sidebar)
        mock_st_sidebar.__exit__ = MagicMock(return_value=None)
        
        # Initialize session state
        st.session_state = MagicMock()
        st.session_state.initialized = True
        st.session_state.current_view = "Dashboard"
        st.session_state.engine = create_engine('sqlite:///:memory:')
        
        main()

    # Verify CSS was loaded
    mock_load_css.assert_called()

@patch('streamlit.sidebar')
@patch('streamlit.title')
@patch('streamlit.markdown')
@patch('streamlit.radio')
@patch('streamlit.caption')
def test_sidebar_complete_render(mock_caption, mock_radio, mock_markdown, mock_title, mock_sidebar):
    """Test complete sidebar rendering including title, dividers and version"""
    # Setup
    st.session_state.current_view = "Dashboard"
    mock_radio.return_value = "📊 Dashboard"
    
    # Render sidebar
    render_sidebar()
    
    # Verify all sidebar elements were rendered
    mock_title.assert_called_once_with("SRO Infra Manager")
    assert mock_markdown.call_count >= 2  # Should be called at least twice for dividers
    mock_caption.assert_called_once_with("v1.0.0")
    mock_radio.assert_called_once()

@patch('infra_mgmt.app.init_database')
def test_database_initialization_logging(mock_init_db, caplog):
    """Test that database initialization is properly logged"""
    # Setup
    mock_init_db.return_value = create_engine('sqlite:///:memory:')
    
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Initialize session state
    with caplog.at_level(logging.INFO):
        init_session_state()
    
    # Verify logging messages
    assert "Initializing session state..." in caplog.text
    assert "Initializing database engine..." in caplog.text
    assert "Database engine initialized successfully" in caplog.text

@patch('infra_mgmt.app.init_database')
def test_database_initialization_error_logging(mock_init_db, caplog):
    """Test that database initialization errors are properly logged"""
    # Setup database initialization to fail
    mock_init_db.return_value = None
    
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Initialize session state
    with caplog.at_level(logging.ERROR):
        init_session_state()
    
    # Verify error was logged
    assert "Failed to initialize database engine" in caplog.text

def test_thread_safe_initialization():
    """Test that session state initialization is thread-safe"""
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Create multiple threads to initialize session state
    threads = []
    for _ in range(5):
        thread = threading.Thread(target=init_session_state)
        threads.append(thread)
    
    # Start all threads
    for thread in threads:
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Verify session state was initialized only once
    assert st.session_state.initialized is True
    assert isinstance(st.session_state.scanner, CertificateScanner)

@patch('infra_mgmt.app.init_database')
def test_database_initialization_failure(mock_init_db, mock_settings):
    """Test handling of database initialization failure"""
    # Mock database initialization to fail
    mock_init_db.return_value = None
    
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Initialize session state
    init_session_state()
    
    # Verify session state reflects failed initialization
    assert st.session_state.initialized is True
    assert st.session_state.engine is None

@patch('streamlit.sidebar')
@patch('streamlit.radio')
@patch('streamlit.caption')
def test_sidebar_version_display(mock_caption, mock_radio, mock_sidebar):
    """Test that version is displayed in sidebar"""
    # Setup
    st.session_state.current_view = "Dashboard"
    mock_radio.return_value = "📊 Dashboard"
    
    # Render sidebar
    render_sidebar()
    
    # Verify version caption was displayed
    mock_caption.assert_called_once_with("v1.0.0")

@patch('streamlit.rerun')
@patch('streamlit.radio')
def test_view_change_triggers_rerun(mock_radio, mock_rerun):
    """Test that changing views triggers a rerun"""
    # Setup initial state
    st.session_state.current_view = "Dashboard"
    
    # Mock radio to return a different view
    mock_radio.return_value = "🔐 Certificates"
    
    # Render sidebar
    render_sidebar()
    
    # Verify that rerun was called
    assert st.session_state.current_view == "Certificates"
    mock_rerun.assert_called_once()

@patch('infra_mgmt.app.init_database')
@patch('streamlit.sidebar')
def test_main_error_handling(mock_sidebar, mock_init_db):
    """Test that main() properly initializes even when views have errors"""
    # Mock database initialization
    engine = create_engine('sqlite:///:memory:')
    mock_init_db.return_value = engine
    
    # Initialize session state with all required values
    st.session_state.current_view = "Dashboard"
    st.session_state.initialized = True
    st.session_state.engine = engine
    st.session_state.scanner = CertificateScanner()
    st.session_state.selected_cert = None
    
    # Mock the sidebar to return Dashboard
    mock_sidebar.return_value = "Dashboard"
    
    # Setup all required mocks
    with patch('streamlit.radio', return_value="📊 Dashboard") as mock_radio, \
         patch('infra_mgmt.app.render_dashboard') as mock_dashboard, \
         patch('streamlit.title'), \
         patch('streamlit.markdown'), \
         patch('streamlit.caption'), \
         patch('infra_mgmt.app.st.sidebar', new_callable=MagicMock) as mock_st_sidebar:
        
        # Mock the sidebar context manager
        mock_st_sidebar.__enter__ = MagicMock(return_value=mock_st_sidebar)
        mock_st_sidebar.__exit__ = MagicMock(return_value=None)
        
        # Run main
        main()
        
        # Verify the dashboard render was attempted
        mock_dashboard.assert_called_once_with(engine)

@patch('infra_mgmt.app.render_domain_list')
def test_domains_view_rendering(mock_domain_list, mock_render_functions, mock_db_engine):
    """Test that the Domains view is properly rendered"""
    # Clear session state first
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Initialize session state with the mock engine
    st.session_state.current_view = "Domains"
    st.session_state.engine = mock_db_engine
    st.session_state.initialized = True
    
    with patch('streamlit.radio', return_value="🌐 Domains"), \
         patch('streamlit.sidebar') as mock_sidebar, \
         patch('infra_mgmt.app.init_database', return_value=mock_db_engine):
        # Mock the sidebar context manager
        mock_sidebar.__enter__ = MagicMock(return_value=mock_sidebar)
        mock_sidebar.__exit__ = MagicMock(return_value=None)
        
        main()
        mock_domain_list.assert_called_once_with(mock_db_engine)

@patch('infra_mgmt.static.styles.load_css')
def test_css_loading_failure(mock_load_css):
    """Test that application continues to function even if CSS loading fails"""
    mock_load_css.side_effect = Exception("CSS loading failed")
    
    with patch('streamlit.radio', return_value="📊 Dashboard"), \
         patch('infra_mgmt.app.render_dashboard') as mock_dashboard:
        main()
        mock_dashboard.assert_called_once()

@patch('infra_mgmt.app.render_dashboard')
def test_view_rendering_failure(mock_dashboard):
    """Test that application handles view rendering failures gracefully"""
    mock_dashboard.side_effect = Exception("View rendering failed")
    
    with patch('streamlit.radio', return_value="📊 Dashboard"), \
         patch('streamlit.sidebar') as mock_sidebar, \
         patch('streamlit.title'), \
         patch('streamlit.markdown'), \
         patch('streamlit.caption'):
        # Mock the sidebar context manager
        mock_sidebar.__enter__ = MagicMock(return_value=mock_sidebar)
        mock_sidebar.__exit__ = MagicMock(return_value=None)
        
        mock_sidebar.return_value = "Dashboard"
        # The test should expect the exception to be raised
        with pytest.raises(Exception) as exc_info:
            main()
        assert str(exc_info.value) == "View rendering failed"

def test_concurrent_view_changes():
    """Test handling of rapid view changes"""
    # Create in-memory database and initialize schema
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    
    with patch('infra_mgmt.app.render_sidebar') as mock_sidebar, \
         patch('streamlit.radio', return_value="\U0001f4ca Dashboard"), \
         patch('streamlit.columns') as mock_columns, \
         patch('streamlit.sidebar') as mock_st_sidebar, \
         patch('streamlit.title'), \
         patch('streamlit.markdown'), \
         patch('streamlit.caption'), \
         patch('streamlit.button', return_value=False), \
         patch('streamlit.empty'), \
         patch('streamlit.divider'), \
         patch('infra_mgmt.app.init_database', return_value=engine), \
         patch('infra_mgmt.views.certificatesView.SessionManager') as mock_session_manager, \
         patch('infra_mgmt.services.CertificateService.CertificateService.add_manual_certificate', return_value={'success': True, 'certificate_id': 1}):
        
        # Mock the sidebar context manager
        mock_st_sidebar.__enter__ = MagicMock(return_value=mock_st_sidebar)
        mock_st_sidebar.__exit__ = MagicMock(return_value=None)
        
        # Mock the session manager context
        mock_session = MagicMock()
        mock_session_manager.return_value.__enter__.return_value = mock_session
        mock_session_manager.return_value.__exit__.return_value = None
        
        # Mock the database queries
        mock_session.query.return_value.count.return_value = 0
        mock_session.query.return_value.filter.return_value.count.return_value = 0
        
        # Create a mock column object that supports context manager and has metric method
        class MockColumn:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc_val, exc_tb):
                pass
            def metric(self, label, value):
                pass  # Just pass through, we don't need to verify the metric values
        
        # Make columns return a list of mock column objects based on the input
        def mock_columns_side_effect(*args, **kwargs):
            if isinstance(args[0], list):
                # Handle column widths
                return [MockColumn() for _ in range(len(args[0]))]
            else:
                # Handle number of columns
                return [MockColumn() for _ in range(args[0])]
        
        mock_columns.side_effect = mock_columns_side_effect
        
        # Simulate rapid view changes
        mock_sidebar.side_effect = ["Dashboard", "Certificates", "Dashboard"]
        
        # Initialize session state
        st.session_state.initialized = True
        st.session_state.engine = engine
        st.session_state.show_manual_entry = False
        
        for _ in range(3):
            main()
            assert st.session_state.current_view in ["Dashboard", "Certificates"]

def test_session_state_cleanup():
    """Test that session state is properly cleaned up"""
    # Initialize session state with test data
    st.session_state.test_data = "test"
    st.session_state.initialized = True
    
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Verify cleanup
    assert 'test_data' not in st.session_state
    assert 'initialized' not in st.session_state 