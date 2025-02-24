import pytest
from unittest.mock import Mock, patch, MagicMock, call
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from cert_scanner.views.settingsView import render_settings_view, restore_backup, list_backups
from cert_scanner.backup import create_backup
from cert_scanner.settings import Settings
from cert_scanner.models import Base, Domain
from pathlib import Path
import json
import yaml
import shutil
import os

@pytest.fixture(autouse=True)
def setup_test_mode():
    """Set up test mode for settings"""
    Settings.set_test_mode()
    yield
    Settings._reset()

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
def mock_streamlit(mocker):
    """Mock streamlit module with improved tab and column handling"""
    mock_st = mocker.MagicMock()
    
    # Mock columns to return list of MagicMocks with proper context manager
    def mock_columns(spec):
        # Handle both list/tuple specs and integer specs
        num_cols = len(spec) if isinstance(spec, (list, tuple)) else spec
        cols = []
        for _ in range(num_cols):
            col = mocker.MagicMock()
            # Add context manager methods
            col.__enter__ = mocker.MagicMock(return_value=col)
            col.__exit__ = mocker.MagicMock(return_value=None)
            cols.append(col)
        return cols
    
    mock_st.columns.side_effect = mock_columns
    
    # Mock tabs to return list of MagicMocks with proper context manager
    def mock_tabs(labels):
        tabs = []
        for label in labels:
            tab = mocker.MagicMock()
            # Add context manager methods
            tab.__enter__ = mocker.MagicMock(return_value=tab)
            tab.__exit__ = mocker.MagicMock(return_value=None)
            tabs.append(tab)
        return tabs
    
    mock_st.tabs.side_effect = mock_tabs
    
    # Mock session state with proper dict-like behavior
    class MockSessionState(dict):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._dict = {}
        
        def __getitem__(self, key):
            return self._dict.get(key)
        
        def __setitem__(self, key, value):
            self._dict[key] = value
        
        def get(self, key, default=None):
            return self._dict.get(key, default)
    
    mock_st.session_state = MockSessionState()
    
    # Add commonly used streamlit methods to the main mock
    mock_st.text_input = mocker.MagicMock()
    mock_st.number_input = mocker.MagicMock()
    mock_st.selectbox = mocker.MagicMock()
    mock_st.button = mocker.MagicMock()
    mock_st.text_area = mocker.MagicMock()
    mock_st.error = mocker.MagicMock()
    mock_st.success = mocker.MagicMock()
    mock_st.warning = mocker.MagicMock()
    mock_st.title = mocker.MagicMock()
    mock_st.header = mocker.MagicMock()
    mock_st.subheader = mocker.MagicMock()
    mock_st.markdown = mocker.MagicMock()
    mock_st.divider = mocker.MagicMock()
    mock_st.write = mocker.MagicMock()
    
    # Patch streamlit module
    mocker.patch('streamlit.text_input', mock_st.text_input)
    mocker.patch('streamlit.number_input', mock_st.number_input)
    mocker.patch('streamlit.selectbox', mock_st.selectbox)
    mocker.patch('streamlit.button', mock_st.button)
    mocker.patch('streamlit.text_area', mock_st.text_area)
    mocker.patch('streamlit.error', mock_st.error)
    mocker.patch('streamlit.success', mock_st.success)
    mocker.patch('streamlit.warning', mock_st.warning)
    mocker.patch('streamlit.title', mock_st.title)
    mocker.patch('streamlit.header', mock_st.header)
    mocker.patch('streamlit.subheader', mock_st.subheader)
    mocker.patch('streamlit.markdown', mock_st.markdown)
    mocker.patch('streamlit.divider', mock_st.divider)
    mocker.patch('streamlit.write', mock_st.write)
    mocker.patch('streamlit.columns', mock_st.columns)
    mocker.patch('streamlit.tabs', mock_st.tabs)
    mocker.patch('streamlit.session_state', mock_st.session_state)
    
    return mock_st

@pytest.fixture
def mock_settings(mocker):
    """Mock settings object"""
    settings = mocker.MagicMock()
    
    # Define a side effect function for get method
    def get_side_effect(key, default=None):
        settings_values = {
            "paths.database": "test/data/test.db",
            "paths.backups": "test/data/backups",
            "scanning.default_rate_limit": 60,
            "scanning.internal.rate_limit": 60,
            "scanning.external.rate_limit": 30,
            "scanning.internal.domains": ["test.internal"],
            "scanning.external.domains": ["test.external"],
            "alerts.expiry_warnings": [
                {"days": 60, "level": "critical"},
                {"days": 30, "level": "warning"}
            ],
            "alerts.failed_scans.consecutive_failures": 3,
            "exports.csv.delimiter": ",",
            "exports.csv.encoding": "utf-8"
        }
        return settings_values.get(key, default)
    
    # Mock the get method
    settings.get = mocker.MagicMock(side_effect=get_side_effect)
    
    # Store updates in a dictionary
    settings._updates = {}
    
    # Mock the update method to store values
    def update_side_effect(key, value):
        settings._updates[key] = value
        return True
    settings.update = mocker.MagicMock(side_effect=update_side_effect)
    
    # Mock the save method to return True by default
    settings.save = mocker.MagicMock(return_value=True)
    
    # Patch the Settings class to use our mock
    mocker.patch('cert_scanner.views.settingsView.Settings', return_value=settings)
    mocker.patch('cert_scanner.settings.Settings', return_value=settings)
    
    return settings

def test_render_settings_view_paths(mock_streamlit, mock_settings, engine):
    """Test rendering path settings view with improved validation"""
    # Mock input values for paths tab
    db_path = "new/database/path.db"
    backup_path = "new/backup/path"
    
    # Create mock input functions that return the correct values
    def mock_text_input(*args, **kwargs):
        if "Database Path" in str(args):
            return db_path
        elif "Backup Path" in str(args):
            return backup_path
        return ""
    
    mock_streamlit.text_input.side_effect = mock_text_input
    
    # Mock button clicks - only paths tab save button should be True
    def mock_button(*args, **kwargs):
        return "Save Path Settings" in str(args)
    
    mock_streamlit.button.side_effect = mock_button
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify settings were updated with correct paths
    assert mock_settings._updates == {
        "paths.database": db_path,
        "paths.backups": backup_path
    }
    
    # Verify success message
    mock_streamlit.success.assert_called_with("Path settings updated successfully!")
    
    # Verify save was called
    mock_settings.save.assert_called_once()

def test_render_settings_view_scanning(mock_streamlit, mock_settings, engine):
    """Test rendering scanning settings view with improved validation"""
    # Set up scanning tab inputs
    default_rate = 120
    internal_rate = 90
    external_rate = 30
    
    # Create mock number input function that returns the correct values
    def mock_number_input(*args, **kwargs):
        if "Default Rate Limit" in str(args):
            return default_rate
        elif "Internal Rate Limit" in str(args):
            return internal_rate
        elif "External Rate Limit" in str(args):
            return external_rate
        return 0
    
    mock_streamlit.number_input.side_effect = mock_number_input
    
    # Mock text area inputs with proper line splitting
    internal_domains = "internal1.com\ninternal2.com"
    external_domains = "external1.com\nexternal2.com"
    
    def mock_text_area(*args, **kwargs):
        if "Internal Domains" in str(args):
            return internal_domains
        elif "External Domains" in str(args):
            return external_domains
        return ""
    
    mock_streamlit.text_area.side_effect = mock_text_area
    
    # Mock button clicks - only scanning tab save button should be True
    def mock_button(*args, **kwargs):
        return "Save Scanning Settings" in str(args)
    
    mock_streamlit.button.side_effect = mock_button
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify settings were updated with correct scanning values
    assert mock_settings._updates == {
        "scanning.default_rate_limit": default_rate,
        "scanning.internal.rate_limit": internal_rate,
        "scanning.internal.domains": internal_domains.split('\n'),
        "scanning.external.rate_limit": external_rate,
        "scanning.external.domains": external_domains.split('\n')
    }
    
    # Verify success message
    mock_streamlit.success.assert_called_with("Scanning settings updated successfully!")
    
    # Verify save was called
    mock_settings.save.assert_called_once()

def test_render_settings_view_alerts(mock_streamlit, mock_settings, engine):
    """Test rendering alert settings view with improved validation"""
    # Mock input values for expiry warnings
    critical_days = 90
    warning_days = 30
    consecutive_failures = 5
    
    # Mock initial settings values
    settings_values = {
        "alerts.expiry_warnings": [
            {"days": critical_days, "level": "critical"},
            {"days": warning_days, "level": "warning"}
        ],
        "alerts.failed_scans.consecutive_failures": consecutive_failures,
        "paths.database": "test/data/test.db",
        "paths.backups": "test/data/backups",
        "scanning.default_rate_limit": 60,
        "scanning.internal.rate_limit": 60,
        "scanning.external.rate_limit": 30,
        "scanning.internal.domains": ["test.internal"],
        "scanning.external.domains": ["test.external"],
        "exports.csv.delimiter": ",",
        "exports.csv.encoding": "utf-8"
    }
    
    def get_side_effect(key, default=None):
        return settings_values.get(key, default)
    
    mock_settings.get.side_effect = get_side_effect
    
    # Create mock number input function that returns the correct values
    def mock_number_input(*args, **kwargs):
        if "Warning 1 Days" in str(args):
            return critical_days
        elif "Warning 2 Days" in str(args):
            return warning_days
        elif "Consecutive failures before alert" in str(args):
            return consecutive_failures
        return 0
    
    mock_streamlit.number_input.side_effect = mock_number_input
    
    # Create mock selectbox function that returns the correct values
    def mock_selectbox(*args, **kwargs):
        options = kwargs.get("options", ["info", "warning", "critical"])
        index = kwargs.get("index", 0)
        
        # Get the current warning based on the key
        key = kwargs.get("key", "")
        if "warning_level_0" in key:
            # First warning should be critical
            return "critical"
        elif "warning_level_1" in key:
            # Second warning should be warning
            return "warning"
        
        # Default to the value at the specified index
        return options[index]
    
    mock_streamlit.selectbox.side_effect = mock_selectbox
    
    # Mock button clicks - only alerts tab save button should be True
    def mock_button(*args, **kwargs):
        if "Remove Warning" in str(args):
            return False
        elif "Add Warning" in str(args):
            return False
        elif "Save Alert Settings" in str(args):
            return True
        return False
    
    mock_streamlit.button.side_effect = mock_button
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify settings were updated with correct alert values
    assert mock_settings._updates == {
        "alerts.expiry_warnings": [
            {"days": critical_days, "level": "critical"},
            {"days": warning_days, "level": "warning"}
        ],
        "alerts.failed_scans.consecutive_failures": consecutive_failures
    }
    
    # Verify success message
    mock_streamlit.success.assert_called_with("Alert settings updated successfully!")
    
    # Verify save was called
    mock_settings.save.assert_called_once()

def test_render_settings_view_exports(mock_streamlit, mock_settings, engine):
    """Test rendering export settings view with improved validation"""
    # Mock input values
    delimiter = ";"
    encoding = "utf-16"
    
    # Create mock text input function that returns the correct values
    def mock_text_input(*args, **kwargs):
        if "CSV Delimiter" in str(args):
            return delimiter
        elif "CSV Encoding" in str(args):
            return encoding
        return ""
    
    mock_streamlit.text_input.side_effect = mock_text_input
    
    # Mock button clicks - only exports tab buttons should be active
    def mock_button(*args, **kwargs):
        if "Save Export Settings" in str(args):
            return True
        return False
    
    mock_streamlit.button.side_effect = mock_button
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify settings were updated with correct export values
    assert mock_settings._updates == {
        "exports.csv.delimiter": delimiter,
        "exports.csv.encoding": encoding
    }
    
    # Verify success message
    mock_streamlit.success.assert_called_with("Export settings updated successfully!")
    
    # Verify save was called
    mock_settings.save.assert_called_once()

def test_create_backup_success(engine):
    """Test successful database backup creation."""
    with patch('streamlit.button') as mock_button, \
         patch('streamlit.success') as mock_success, \
         patch('streamlit.error') as mock_error, \
         patch('cert_scanner.settings.Settings') as mock_settings_class:
        
        # Configure mock settings
        mock_settings = MagicMock()
        mock_settings_class.return_value = mock_settings
        mock_settings.get.side_effect = lambda key, default=None: {
            "paths.database": "test.db",
            "paths.backups": "backups"
        }.get(key, default)
        
        # Configure mock button to trigger backup
        mock_button.return_value = True
        
        # Create some test data
        with Session(engine) as session:
            domain = Domain(domain_name="test.com")
            session.add(domain)
            session.commit()
        
        # Call the backup function
        success, message = create_backup(engine)
        
        # Verify backup was successful
        assert success is True
        assert "successfully" in message.lower()
        
        # Verify success message was shown
        mock_success.assert_called_once()
        mock_error.assert_not_called()

def test_backup_with_missing_database(engine):
    """Test backup handling when database is missing or inaccessible."""
    with patch('streamlit.button') as mock_button, \
         patch('streamlit.error') as mock_error, \
         patch('cert_scanner.settings.Settings') as mock_settings_class:
        
        # Configure mock settings
        mock_settings = MagicMock()
        mock_settings_class.return_value = mock_settings
        mock_settings.get.side_effect = lambda key, default=None: {
            "paths.database": "nonexistent.db",
            "paths.backups": "backups"
        }.get(key, default)
        
        # Configure mock button to trigger backup
        mock_button.return_value = True
        
        # Use an invalid database path
        invalid_engine = create_engine('sqlite:///nonexistent.db')
        
        # Attempt backup
        success, message = create_backup(invalid_engine)
        
        # Verify error handling
        assert success is False
        assert "Database file does not exist" in message
        mock_error.assert_called_once()

def test_restore_backup_success(mock_settings, tmp_path):
    """Test successful backup restoration"""
    # Set up test paths
    src_db_path = tmp_path / "source.db"
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Create source database with test data
    src_engine = create_engine(f'sqlite:///{src_db_path}')
    Base.metadata.create_all(src_engine)
    with src_engine.connect() as conn:
        conn.execute(text("CREATE TABLE test (id INTEGER PRIMARY KEY)"))
        conn.execute(text("INSERT INTO test (id) VALUES (1)"))
        conn.commit()
    
    # Create backup files
    timestamp = "20240101_120000"
    config_backup = backup_dir / f"config_{timestamp}.yaml"
    db_backup = backup_dir / f"certificates_{timestamp}.db"
    manifest_file = backup_dir / f"backup_{timestamp}.json"
    
    # Create test config backup
    test_config = {"test": "config"}
    with open(config_backup, "w") as f:
        yaml.dump(test_config, f)
    
    # Copy source database to backup
    shutil.copy2(src_db_path, db_backup)
    
    # Create manifest
    manifest = {
        "timestamp": timestamp,
        "database": str(db_backup),
        "config": str(config_backup),
        "created": "2024-01-01T12:00:00"
    }
    with open(manifest_file, "w") as f:
        json.dump(manifest, f)
    
    # Configure mock settings
    def get_side_effect(key, default=None):
        paths = {
            "paths.database": str(tmp_path / "restored.db"),
            "paths.backups": str(backup_dir)
        }
        return paths.get(key, default)
    
    mock_settings.get.side_effect = get_side_effect
    mock_settings._config = {}
    
    # Test restore
    success, message = restore_backup(manifest)
    assert success
    assert "successfully" in message.lower()
    
    # Verify restored database
    engine = create_engine(f'sqlite:///{tmp_path}/restored.db')
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM test")).fetchone()
        assert result[0] == 1

def test_list_backups(mock_settings, tmp_path):
    """Test listing available backups"""
    # Set up test paths
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure mock settings
    def get_side_effect(key, default=None):
        paths = {
            "paths.database": str(tmp_path / "test.db"),
            "paths.backups": str(backup_dir)
        }
        return paths.get(key, default)
    
    mock_settings.get.side_effect = get_side_effect
    
    # Create test backup
    timestamp = "20240101_120000"
    config_backup = backup_dir / f"config_{timestamp}.yaml"
    manifest_file = backup_dir / f"backup_{timestamp}.json"
    
    # Create test config backup
    with open(config_backup, "w") as f:
        yaml.dump({"test": "config"}, f)
    
    # Create manifest
    manifest = {
        "timestamp": timestamp,
        "database": None,
        "config": str(config_backup),
        "created": "2024-01-01T12:00:00"
    }
    with open(manifest_file, "w") as f:
        json.dump(manifest, f)
    
    # List backups
    backups = list_backups()
    assert len(backups) == 1
    assert backups[0]["timestamp"] == timestamp
    assert backups[0]["config"] == str(config_backup)
    assert backups[0]["created"] == "2024-01-01T12:00:00"

def test_restore_nonexistent_backup(mock_settings):
    """Test restoring from a nonexistent backup with improved error handling"""
    # Create manifest with nonexistent files
    manifest = {
        "config": "nonexistent.yaml",
        "database": "nonexistent.db",
        "created": "2024-01-01T12:00:00"
    }
    
    # Attempt restore
    success, message = restore_backup(manifest)
    
    # Verify restore failed
    assert not success
    assert "Config backup file not found" in message
    
    # Verify settings were not modified
    mock_settings.save.assert_not_called()
    assert not mock_settings._updates

def test_invalid_settings_validation(mock_streamlit, mock_settings, engine):
    """Test validation of invalid settings values with improved error handling"""
    # Mock invalid input values
    default_rate = -1
    internal_rate = 0
    external_rate = 0
    
    # Create mock number input function that returns invalid values
    def mock_number_input(*args, **kwargs):
        if "Default Rate Limit" in str(args):
            return default_rate
        elif "Internal Rate Limit" in str(args):
            return internal_rate
        elif "External Rate Limit" in str(args):
            return external_rate
        return 0
    
    mock_streamlit.number_input.side_effect = mock_number_input
    
    # Create mock text area function that returns empty values
    def mock_text_area(*args, **kwargs):
        return ""
    
    mock_streamlit.text_area.side_effect = mock_text_area
    
    # Mock button clicks - only scanning tab save button should be True
    def mock_button(*args, **kwargs):
        return "Save Scanning Settings" in str(args)
    
    mock_streamlit.button.side_effect = mock_button
    
    # Mock settings.save() to return False due to validation failure
    mock_settings.save.return_value = False
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify error message
    mock_streamlit.error.assert_any_call("Failed to save scanning settings")
    
    # Verify settings were attempted to be updated with invalid values
    assert mock_settings._updates == {
        "scanning.default_rate_limit": default_rate,
        "scanning.internal.rate_limit": internal_rate,
        "scanning.internal.domains": [],
        "scanning.external.rate_limit": external_rate,
        "scanning.external.domains": []
    }
    
    # Verify save was called
    mock_settings.save.assert_called_once() 