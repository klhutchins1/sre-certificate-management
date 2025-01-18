import pytest
import streamlit as st
from cert_scanner.app import init_session_state, render_sidebar, main
from cert_scanner.scanner import CertificateScanner
from cert_scanner.settings import Settings
from unittest.mock import patch, MagicMock, call
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from cert_scanner.models import Base, Certificate
import threading
import logging

@pytest.fixture(autouse=True)
def mock_streamlit():
    """Mock streamlit components and context"""
    with patch('streamlit.sidebar'):
        with patch('streamlit.radio', return_value="Dashboard"):
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
    with patch('cert_scanner.app.render_dashboard') as mock_dashboard, \
         patch('cert_scanner.app.render_certificate_list') as mock_certificates, \
         patch('cert_scanner.app.render_hosts_view') as mock_hosts, \
         patch('cert_scanner.app.render_scan_interface') as mock_scan, \
         patch('cert_scanner.app.render_history_view') as mock_history, \
         patch('cert_scanner.app.render_search_view') as mock_search, \
         patch('cert_scanner.app.render_settings_view') as mock_settings:
        
        yield {
            'dashboard': mock_dashboard,
            'certificates': mock_certificates,
            'hosts': mock_hosts,
            'scan': mock_scan,
            'history': mock_history,
            'search': mock_search,
            'settings': mock_settings
        }

@patch('cert_scanner.app.init_database')
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
        "Scan": "🔍 Scan",
        "History": "📜 History",
        "Search": "🔎 Search",
        "Settings": "⚙️ Settings"
    }
    
    # Test each navigation option
    for view, display in expected_options.items():
        mock_radio.return_value = display
        new_view = render_sidebar()
        assert new_view == view
        assert st.session_state.current_view == view

@patch('cert_scanner.app.render_sidebar')
@patch('cert_scanner.app.init_database')
def test_main_view_rendering(mock_init_db, mock_sidebar, mock_render_functions, mock_settings, mock_db_engine):
    """Test that main function renders the correct view based on current_view"""
    # Setup mock database
    mock_init_db.return_value = mock_db_engine
    
    # Mock sidebar to return different views
    views = ["Dashboard", "Certificates", "Hosts", "Scan", "History", "Search", "Settings"]
    mock_functions = {
        "Dashboard": mock_render_functions['dashboard'],
        "Certificates": mock_render_functions['certificates'],
        "Hosts": mock_render_functions['hosts'],
        "Scan": mock_render_functions['scan'],
        "History": mock_render_functions['history'],
        "Search": mock_render_functions['search'],
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

@patch('cert_scanner.app.render_sidebar')
@patch('cert_scanner.app.init_database')
def test_main_initializes_session(mock_init_db, mock_sidebar, mock_settings, mock_db_engine):
    """Test that main function initializes session state if not initialized"""
    # Setup mock database
    mock_init_db.return_value = mock_db_engine
    mock_sidebar.return_value = "Dashboard"
    
    # Clear session state
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    
    # Run main
    main()
    
    # Verify session was initialized
    assert st.session_state.initialized is True
    assert isinstance(st.session_state.scanner, CertificateScanner)
    assert st.session_state.engine is mock_db_engine
    mock_init_db.assert_called_once()

@patch('cert_scanner.app.render_sidebar')
@patch('cert_scanner.app.init_database')
def test_main_preserves_session(mock_init_db, mock_sidebar, mock_settings, mock_db_engine):
    """Test that main function preserves existing session state"""
    # Setup mock database
    mock_init_db.return_value = mock_db_engine
    mock_sidebar.return_value = "Dashboard"
    
    # Create a test scanner
    test_scanner = CertificateScanner()
    
    # Initialize session with custom values
    st.session_state.initialized = True
    st.session_state.scanner = test_scanner
    st.session_state.selected_cert = "test_cert"
    st.session_state.current_view = "Dashboard"
    st.session_state.engine = mock_db_engine
    
    # Run main
    main()
    
    # Verify session values were preserved
    assert st.session_state.scanner is test_scanner
    assert st.session_state.selected_cert == "test_cert"
    assert st.session_state.engine is mock_db_engine
    # Verify init_database wasn't called again
    mock_init_db.assert_not_called() 

@patch('streamlit.set_page_config')
def test_page_configuration(mock_set_page_config):
    """Test that page configuration is set correctly"""
    # Force module reload to trigger module-level code
    import importlib
    import cert_scanner.app
    importlib.reload(cert_scanner.app)
    
    # Verify page config was called with correct parameters
    mock_set_page_config.assert_called_once_with(
        page_title="Certificate Manager",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

@patch('streamlit.markdown')
def test_css_styling(mock_markdown):
    """Test that CSS styling is applied"""
    # Force module reload to trigger module-level code
    import importlib
    import cert_scanner.app
    importlib.reload(cert_scanner.app)
    
    # Verify markdown was called with CSS content
    mock_markdown.assert_called_once()
    css_content = mock_markdown.call_args[0][0]
    assert 'stAppViewContainer' in css_content
    assert 'stSidebar' in css_content
    assert mock_markdown.call_args[1].get('unsafe_allow_html') is True

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
    mock_title.assert_called_once_with("Certificate Manager")
    assert mock_markdown.call_count >= 2  # Should be called at least twice for dividers
    mock_caption.assert_called_once_with("v1.0.0")
    mock_radio.assert_called_once()

@patch('cert_scanner.app.init_database')
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

@patch('cert_scanner.app.init_database')
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

@patch('cert_scanner.app.init_database')
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

@patch('cert_scanner.app.init_database')
@patch('streamlit.sidebar')
def test_main_error_handling(mock_sidebar, mock_init_db):
    """Test that main() handles view rendering errors"""
    # Mock database initialization
    engine = create_engine('sqlite:///:memory:')
    mock_init_db.return_value = engine
    
    # Initialize session state with all required values
    st.session_state.current_view = "Dashboard"
    st.session_state.initialized = True
    st.session_state.engine = engine
    st.session_state.scanner = CertificateScanner()
    st.session_state.selected_cert = None
    
    # Mock the view to raise an exception
    def mock_view_error(*args, **kwargs):
        raise Exception("Test error")
    
    # Setup all required mocks
    with patch('streamlit.radio', return_value="📊 Dashboard") as mock_radio, \
         patch('cert_scanner.app.render_dashboard', side_effect=mock_view_error), \
         patch('streamlit.error') as mock_error, \
         patch('streamlit.title'), \
         patch('streamlit.markdown'), \
         patch('streamlit.caption'), \
         patch('cert_scanner.app.st.sidebar', new_callable=MagicMock) as mock_st_sidebar:
        
        # Mock the sidebar context manager
        mock_st_sidebar.__enter__ = MagicMock(return_value=mock_st_sidebar)
        mock_st_sidebar.__exit__ = MagicMock(return_value=None)
        
        # Run main - this should catch the error and display it
        main()
        
        # Verify the error was displayed
        mock_error.assert_called_once_with("Error rendering view: Test error") 