import pytest
import streamlit as st
from cert_scanner.app import init_session_state, render_sidebar, main
from cert_scanner.scanner import CertificateScanner
from cert_scanner.settings import Settings
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from cert_scanner.models import Base, Certificate

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