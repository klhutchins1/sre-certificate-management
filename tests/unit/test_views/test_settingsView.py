import pytest
from unittest.mock import Mock, patch, MagicMock, call
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from infra_mgmt.views.settingsView import render_settings_view
from infra_mgmt.backup import create_backup, restore_backup, list_backups
from infra_mgmt.settings import Settings
from infra_mgmt.models import Base, Domain
from pathlib import Path
import json
import yaml
import shutil
import os
import tempfile
import inspect
from unittest.mock import ANY

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
    with patch('infra_mgmt.views.settingsView.st') as mock_st, \
         patch('infra_mgmt.components.page_header.st') as mock_header_st:
        # Mock columns to return list of MagicMocks with proper context manager
        def mock_columns(spec):
            num_cols = len(spec) if isinstance(spec, (list, tuple)) else spec
            cols = []
            for _ in range(num_cols):
                col = mocker.MagicMock()
                col.__enter__ = mocker.MagicMock(return_value=col)
                col.__exit__ = mocker.MagicMock(return_value=None)
                cols.append(col)
            return cols
        mock_st.columns.side_effect = mock_columns
        mock_header_st.columns.side_effect = mock_columns
        
        # Mock tabs to return list of MagicMocks with proper context manager
        def mock_tabs(labels):
            tabs = []
            for label in labels:
                tab = mocker.MagicMock()
                tab_context = mocker.MagicMock()
                def enter_context(tab_label=label):
                    return tab_context
                tab.__enter__ = mocker.MagicMock(side_effect=enter_context)
                tab.__exit__ = mocker.MagicMock(return_value=None)
                tab_context.button = mock_st.button
                tab_context.number_input = mock_st.number_input
                tab_context.text_area = mock_st.text_area
                tab_context.markdown = mock_st.markdown
                tab_context.header = mock_st.header
                tab_context.subheader = mock_st.subheader
                tab_context.divider = mock_st.divider
                tab_context.success = mock_st.success
                tab_context.error = mock_st.error
                tab_context.warning = mock_st.warning
                tab_context.columns = mock_st.columns
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
        
        # Default button always returns False unless overridden in a test
        def default_mock_button(*args, **kwargs):
            return False
        mock_st.button.side_effect = default_mock_button
        
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
        
        yield (mock_st, mock_header_st)

@pytest.fixture
def mock_settings(mocker):
    """Mock settings object using the built-in test mode"""
    # Define test configuration
    test_config = {
        "paths": {
            "database": "tests/data/test.db",
            "backups": "tests/data/backups"
        },
        "scanning": {
            "default_rate_limit": 60,
            "internal": {
                "rate_limit": 60,
                "domains": ["test.internal"]
            },
            "external": {
                "rate_limit": 30,
                "domains": ["test.external"]
            }
        },
        "alerts": {
            "expiry_warnings": [
                {"days": 60, "level": "critical"},
                {"days": 30, "level": "warning"}
            ],
            "failed_scans": {
                "consecutive_failures": 3
            }
        },
        "exports": {
            "csv": {
                "delimiter": ",",
                "encoding": "utf-8"
            }
        }
    }
    
    # Set test mode with our test configuration
    Settings.set_test_mode(test_config)
    
    # Get the singleton instance
    settings = Settings()
    
    # Create a copy of the test config to avoid reference issues
    settings._config = test_config.copy()
    Settings._test_config = test_config.copy()  # Ensure class-level test config is also updated
    
    # Mock the Settings class to always return our instance
    mocker.patch('infra_mgmt.views.settingsView.Settings', return_value=settings)
    
    # Spy on the update and save methods to track calls
    mocker.spy(settings, 'update')
    mocker.spy(settings, 'save')
    
    yield settings
    
    # Reset test mode after the test
    Settings._reset()

def test_render_settings_view_paths(mock_streamlit, mock_settings, engine):
    mock_st, mock_header_st = mock_streamlit
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
    
    mock_st.text_input.side_effect = mock_text_input
    
    # Mock button clicks - only paths tab save button should be True
    def mock_button(*args, **kwargs):
        return "Save Path Settings" in str(args)
    
    mock_st.button.side_effect = mock_button
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify settings were updated with correct paths
    assert mock_settings.get("paths.database") == db_path
    assert mock_settings.get("paths.backups") == backup_path
    
    # Verify success message
    mock_st.success.assert_called_with("Path settings updated successfully!")
    
    # Verify save was called
    mock_settings.save.assert_called_once()

    # Check that the header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Settings</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"

def test_render_settings_view_scanning(mock_streamlit, mock_settings, engine):
    mock_st, mock_header_st = mock_streamlit
    """Test rendering scanning settings view with improved validation and CT global option"""
    from infra_mgmt.models import Base
    Base.metadata.create_all(engine)
    # Set up scanning tab inputs
    default_rate = 120
    internal_rate = 90
    external_rate = 30

    # Track button calls
    button_calls = []

    # Create 7 tab mocks to match the actual number of tabs in settingsView.py
    tab_mocks = [MagicMock() for _ in range(7)]
    scanning_tab_context = MagicMock()
    # Ensure the Scanning tab (index 1) is a real context manager for the test
    tab_mocks[1].__enter__.return_value = scanning_tab_context
    tab_mocks[1].__exit__.return_value = None
    mock_st.tabs.side_effect = lambda labels: tab_mocks

    # Simplify button mock for debugging
    def mock_button(label, **kwargs):
        print(f"BUTTON CALLED: {label}")
        return label == "Save Scanning Settings"
    mock_st.button.side_effect = mock_button
    
    # Create mock number input function that returns the correct values
    def mock_number_input(*args, **kwargs):
        if "Default Rate Limit" in str(args):
            return default_rate
        elif "Internal Rate Limit" in str(args):
            return internal_rate
        elif "External Rate Limit" in str(args):
            return external_rate
        elif "WHOIS Rate Limit" in str(args):
            return 10
        elif "DNS Rate Limit" in str(args):
            return 20
        elif "Certificate Transparency Rate Limit" in str(args):
            return 5
        elif "Socket Timeout" in str(args):
            return 10
        elif "Request Timeout" in str(args):
            return 15
        elif "DNS Timeout" in str(args):
            return 5.0
        return 0
    
    mock_st.number_input.side_effect = mock_number_input
    
    # Mock text area inputs with proper line splitting
    internal_domains = "internal1.com\ninternal2.com"
    external_domains = "external1.com\nexternal2.com"
    
    def mock_text_area(*args, **kwargs):
        if "Internal Domains" in str(args):
            return internal_domains
        elif "External Domains" in str(args):
            return external_domains
        return ""
    
    mock_st.text_area.side_effect = mock_text_area
    
    # Track settings updates
    original_update = mock_settings.update
    update_calls = []
    def mock_update(key, value):
        update_calls.append((key, value))
        print(f"Settings update called with key: {key}, value: {value}")
        # Create nested dicts for dot-separated keys
        keys = key.split('.')
        d = mock_settings._config
        for k in keys[:-1]:
            if k not in d or not isinstance(d[k], dict):
                d[k] = {}
            d = d[k]
        d[keys[-1]] = value
        return True
    
    mock_settings.update = mock_update
    
    # Patch mock_settings.get to return default_rate for 'scanning.default_rate_limit'
    orig_get = mock_settings.get
    def patched_get(key, default=None):
        if key == "scanning.default_rate_limit":
            return default_rate
        if key == "scanning.internal.rate_limit":
            return internal_rate
        if key == "scanning.external.rate_limit":
            return external_rate
        if key == "scanning.internal.domains":
            return internal_domains.split('\n')
        if key == "scanning.external.domains":
            return external_domains.split('\n')
        if key == "scanning.ct.enabled":
            return True  # Default global CT enabled
        return orig_get(key, default)
    mock_settings.get = patched_get

    # Patch notify to print when called
    def debug_notify(msg, level):
        print(f"NOTIFY CALLED: {msg}, {level}")
        if level == "success":
            print("Calling mock_st.success")
            return mock_st.success(msg)
        return None

    # Test both enabled and disabled CT global option
    for ct_enabled_value in [True, False]:
        # Patch the checkbox to return the test value
        mock_st.checkbox.side_effect = lambda *args, **kwargs: ct_enabled_value
        with patch('infra_mgmt.services.SettingsService.SettingsService.save_scanning_settings') as mock_save, \
             patch('infra_mgmt.views.settingsView.notify', side_effect=debug_notify):
            def save_scanning_settings(settings, default_rate, internal_rate, internal_domains, external_rate, external_domains, whois_rate, dns_rate, ct_rate, socket_timeout, request_timeout, dns_timeout, ct_enabled=True):
                # Assert ct_enabled is passed and matches the checkbox value
                assert ct_enabled == ct_enabled_value
                settings.update("scanning.default_rate_limit", default_rate)
                settings.update("scanning.internal.rate_limit", internal_rate)
                settings.update("scanning.internal.domains", internal_domains)
                settings.update("scanning.external.rate_limit", external_rate)
                settings.update("scanning.external.domains", external_domains)
                settings.update("scanning.ct.enabled", ct_enabled)
                return settings.save()  # Ensure save is called so the mock is triggered
            mock_save.side_effect = save_scanning_settings
            # Render settings view
            render_settings_view(engine)

        print("mock_st.success call args list:", mock_st.success.call_args_list)
        # Use the actual singleton for assertion
        settings_instance = Settings()
        # Check the actual config dict, not the patched get
        assert settings_instance._config["scanning"]["ct"]["enabled"] == ct_enabled_value
        # Verify success message
        mock_st.success.assert_any_call("Scanning settings updated successfully!")
        # Verify save was called
        mock_settings.save.assert_called()

        # Check that the header was rendered
        found = False
        for call in mock_header_st.markdown.call_args_list:
            if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Settings</h1>" and call.kwargs.get('unsafe_allow_html'):
                found = True
                break
        assert found, "Expected header markdown call not found"

def test_render_settings_view_alerts(mock_streamlit, mock_settings, engine):
    mock_st, mock_header_st = mock_streamlit
    """Test rendering alert settings view with improved validation"""
    # Mock input values for expiry warnings
    critical_days = 90
    warning_days = 30
    consecutive_failures = 5
    
    # Set initial settings values
    mock_settings.update("alerts.expiry_warnings", [
        {"days": critical_days, "level": "critical"},
        {"days": warning_days, "level": "warning"}
    ])
    mock_settings.update("alerts.failed_scans.consecutive_failures", consecutive_failures)
    
    # Create mock number input function that returns the correct values
    def mock_number_input(*args, **kwargs):
        if "Warning 1 Days" in str(args):
            return critical_days
        elif "Warning 2 Days" in str(args):
            return warning_days
        elif "Consecutive failures before alert" in str(args):
            return consecutive_failures
        return 0
    
    mock_st.number_input.side_effect = mock_number_input
    
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
    
    mock_st.selectbox.side_effect = mock_selectbox
    
    # Mock button clicks - only alerts tab save button should be True
    def mock_button(*args, **kwargs):
        if "Remove Warning" in str(args):
            return False
        elif "Add Warning" in str(args):
            return False
        elif "Save Alert Settings" in str(args):
            return True
        return False
    
    mock_st.button.side_effect = mock_button
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify settings were updated with correct alert values
    assert mock_settings.get("alerts.expiry_warnings") == [
        {"days": critical_days, "level": "critical"},
        {"days": warning_days, "level": "warning"}
    ]
    assert mock_settings.get("alerts.failed_scans.consecutive_failures") == consecutive_failures
    
    # Verify success message
    mock_st.success.assert_called_with("Alert settings updated successfully!")
    
    # Verify save was called
    mock_settings.save.assert_called_once()

    # Check that the header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Settings</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"

def test_render_settings_view_exports(mock_streamlit, mock_settings, engine):
    mock_st, mock_header_st = mock_streamlit
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
    
    mock_st.text_input.side_effect = mock_text_input
    
    # Mock button clicks - only exports tab buttons should be active
    def mock_button(*args, **kwargs):
        if "Save Export Settings" in str(args):
            return True
        return False
    
    mock_st.button.side_effect = mock_button
    
    # Render settings view
    render_settings_view(engine)
    
    # Verify settings were updated with correct export values
    assert mock_settings.get("exports.csv.delimiter") == delimiter
    assert mock_settings.get("exports.csv.encoding") == encoding
    
    # Verify success message
    mock_st.success.assert_called_with("Export settings updated successfully!")
    
    # Verify save was called
    mock_settings.save.assert_called_once()

    # Check that the header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Settings</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"

def test_create_backup_success(engine):
    """Test successful database backup creation."""
    from unittest.mock import patch
    test_config = {
        "paths": {
            "database": "test.db",
            "backups": "backups"
        }
    }
    Settings.set_test_mode(test_config)
    try:
        with patch('infra_mgmt.views.settingsView.st') as mock_st, \
             patch('infra_mgmt.components.page_header.st') as mock_header_st, \
             patch('streamlit.button') as mock_button, \
             patch('streamlit.success') as mock_success, \
             patch('streamlit.error') as mock_error:
            mock_button.return_value = True
            with Session(engine) as session:
                domain = Domain(domain_name="test.com")
                session.add(domain)
                session.commit()
            test_db = Path("test.db")
            if test_db.exists():
                test_db.unlink()
            with engine.connect() as conn:
                conn.execute(text("ATTACH DATABASE 'test.db' AS test"))
                conn.execute(text("SELECT sql FROM sqlite_master WHERE type='table'"))
                conn.execute(text("DETACH DATABASE test"))
            success, message = create_backup(engine)
            assert success, f"Backup failed: {message}"
            assert "successfully" in message.lower()
            backup_dir = Path("backups")
            assert backup_dir.exists()
            manifest_files = list(backup_dir.glob("backup_*.json"))
            assert len(manifest_files) == 1, "Expected one manifest file"
            with open(manifest_files[0], 'r') as f:
                manifest = json.load(f)
                assert 'timestamp' in manifest
                assert 'database' in manifest
                assert 'config' in manifest
                assert 'created' in manifest
                db_backup = Path(manifest['database'])
                assert db_backup.exists()
                config_backup = Path(manifest['config'])
                assert config_backup.exists()
            for file in backup_dir.glob("*"):
                file.unlink()
            backup_dir.rmdir()
            if test_db.exists():
                test_db.unlink()
    finally:
        Settings._reset()

def test_backup_with_missing_database(engine):
    """Test backup handling when database is missing or inaccessible."""
    from unittest.mock import patch
    test_config = {
        "paths": {
            "database": "nonexistent.db",
            "backups": "backups"
        }
    }
    Settings.set_test_mode(test_config)
    try:
        with patch('infra_mgmt.views.settingsView.st') as mock_st, \
             patch('infra_mgmt.components.page_header.st') as mock_header_st, \
             patch('streamlit.button') as mock_button, \
             patch('streamlit.error') as mock_error:
            mock_button.return_value = True
            db_path = Path("nonexistent.db")
            if db_path.exists():
                db_path.unlink()
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)
            success, message = create_backup(engine)
            assert success is False, "Backup should fail when database is missing"
            assert "database file" in message.lower(), f"Expected 'database file' in message, got: {message}"
            assert "not found" in message.lower() or "does not exist" in message.lower(), f"Expected 'not found' or 'does not exist' in message, got: {message}"
            assert len(list(backup_dir.glob("*"))) == 0, "No backup files should be created"
            if backup_dir.exists():
                backup_dir.rmdir()
    finally:
        Settings._reset()

def test_restore_backup_success(tmp_path):
    """Test successful backup restoration"""
    from unittest.mock import patch
    test_config = {
        "paths": {
            "database": str(tmp_path / "restored.db"),
            "backups": str(tmp_path / "backups")
        }
    }
    Settings.set_test_mode(test_config)
    try:
        with patch('infra_mgmt.views.settingsView.st') as mock_st, \
             patch('infra_mgmt.components.page_header.st') as mock_header_st:
            src_db_path = tmp_path / "source.db"
            backup_dir = tmp_path / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            src_engine = create_engine(f'sqlite:///{src_db_path}')
            Base.metadata.create_all(src_engine)
            with src_engine.connect() as conn:
                conn.execute(text("CREATE TABLE test (id INTEGER PRIMARY KEY)"))
                conn.execute(text("INSERT INTO test (id) VALUES (1)"))
                conn.commit()
            timestamp = "20240101_120000"
            config_backup = backup_dir / f"config_{timestamp}.yaml"
            db_backup = backup_dir / f"certificates_{timestamp}.db"
            manifest_file = backup_dir / f"backup_{timestamp}.json"
            test_config_yaml = {"test": "config"}
            with open(config_backup, "w") as f:
                yaml.dump(test_config_yaml, f)
            shutil.copy2(src_db_path, db_backup)
            manifest = {
                "timestamp": timestamp,
                "database": str(db_backup),
                "config": str(config_backup),
                "created": "2024-01-01T12:00:00"
            }
            with open(manifest_file, "w") as f:
                json.dump(manifest, f)
            success, message = restore_backup(str(manifest_file))
            assert success
            assert "successfully" in message.lower()
            engine = create_engine(f'sqlite:///{tmp_path}/restored.db')
            with engine.connect() as conn:
                result = conn.execute(text("SELECT * FROM test")).fetchone()
                assert result[0] == 1
    finally:
        Settings._reset()

def test_list_backups(tmp_path):
    """Test listing available backups"""
    from unittest.mock import patch
    test_config = {
        "paths": {
            "database": str(tmp_path / "test.db"),
            "backups": str(tmp_path / "backups")
        }
    }
    Settings.set_test_mode(test_config)
    try:
        with patch('infra_mgmt.views.settingsView.st') as mock_st, \
             patch('infra_mgmt.components.page_header.st') as mock_header_st:
            backup_dir = tmp_path / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = "20240101_120000"
            config_backup = backup_dir / f"config_{timestamp}.yaml"
            manifest_file = backup_dir / f"backup_{timestamp}.json"
            with open(config_backup, "w") as f:
                yaml.dump({"test": "config"}, f)
            db_file = backup_dir / f"certificates_{timestamp}.db"
            db_file.touch()
            manifest = {
                "timestamp": timestamp,
                "database": str(db_file),
                "config": str(config_backup),
                "created": "2024-01-01T12:00:00"
            }
            with open(manifest_file, "w") as f:
                json.dump(manifest, f)
            backups = list_backups()
            assert len(backups) == 1
            assert backups[0]["timestamp"] == timestamp
            assert backups[0]["config"] == str(config_backup)
            assert backups[0]["created"] == "2024-01-01T12:00:00"
    finally:
        Settings._reset()

def test_restore_nonexistent_backup():
    """Test restoring from a nonexistent backup with improved error handling"""
    from unittest.mock import patch
    import tempfile
    test_config = {
        "paths": {
            "database": "test.db",
            "backups": "backups"
        }
    }
    Settings.set_test_mode(test_config)
    try:
        with patch('infra_mgmt.views.settingsView.st') as mock_st, \
             patch('infra_mgmt.components.page_header.st') as mock_header_st:
            manifest = {
                "config": "nonexistent.yaml",
                "database": "nonexistent.db",
                "created": "2024-01-01T12:00:00"
            }
            with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tmp_manifest:
                json.dump(manifest, tmp_manifest)
                tmp_manifest_path = tmp_manifest.name
            success, message = restore_backup(tmp_manifest_path)
            assert not success
            assert (
                "Config backup file not found" in message or
                "not found" in message or
                "No such file" in message or
                "Invalid manifest structure" in message
            )
            settings = Settings()
            assert settings.get("paths.database") == "test.db"
            assert settings.get("paths.backups") == "backups"
    finally:
        Settings._reset()

def test_invalid_settings_validation(mock_streamlit, mock_settings, engine):
    mock_st, mock_header_st = mock_streamlit
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
    
    mock_st.number_input.side_effect = mock_number_input
    
    # Create mock text area function that returns empty values
    def mock_text_area(*args, **kwargs):
        return ""
    
    mock_st.text_area.side_effect = mock_text_area
    
    # Mock button clicks - only scanning tab save button should be True
    def mock_button(*args, **kwargs):
        return "Save Scanning Settings" in str(args)
    
    mock_st.button.side_effect = mock_button
    
    # Mock the notify function to capture error messages
    error_messages = []
    def mock_notify(message, level):
        if level == "error":
            error_messages.append(message)
    
    with patch('infra_mgmt.views.settingsView.notify', side_effect=mock_notify):
        # Render settings view
        render_settings_view(engine)
        
        # Verify error messages
        assert any("Invalid rate limit" in msg for msg in error_messages), "Expected rate limit validation error"
        
        # Verify settings were not updated with invalid values
        assert mock_settings.get("scanning.default_rate_limit") != default_rate
        assert mock_settings.get("scanning.internal.rate_limit") != internal_rate
        assert mock_settings.get("scanning.external.rate_limit") != external_rate
        
        # Verify save was not called since validation failed
        mock_settings.save.assert_not_called() 

    # Check that the header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Settings</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found" 