import pytest
import os
from pathlib import Path
import shutil
import yaml
from cert_scanner.settings import Settings, DEFAULT_CONFIG

@pytest.fixture(autouse=True)
def reset_settings():
    """Reset settings singleton before each test"""
    # Remove any existing config file
    if os.path.exists("config.yaml"):
        os.remove("config.yaml")
    
    # Reset settings instance
    Settings._reset()
    Settings._instance = None
    Settings._config = DEFAULT_CONFIG.copy()
    
    yield
    
    # Clean up after test
    Settings._reset()
    Settings._instance = None
    if os.path.exists("config.yaml"):
        os.remove("config.yaml")

@pytest.fixture
def test_config_path(tmp_path):
    """Create a temporary test config file"""
    config_path = tmp_path / "test_config.yaml"
    test_config = {
        "paths": {
            "database": "tests/data/test.db",
            "backups": "tests/data/backups"
        },
        "scanning": {
            "internal": {
                "rate_limit": 5,
                "delay": 1,
                "domains": ["test.internal.com"]
            }
        }
    }
    with open(config_path, 'w') as f:
        yaml.safe_dump(test_config, f)
    return config_path

@pytest.fixture
def clean_env():
    """Remove environment variables that might affect tests"""
    old_config = os.environ.get('CERT_SCANNER_CONFIG')
    if 'CERT_SCANNER_CONFIG' in os.environ:
        del os.environ['CERT_SCANNER_CONFIG']
    yield
    if old_config:
        os.environ['CERT_SCANNER_CONFIG'] = old_config
    elif 'CERT_SCANNER_CONFIG' in os.environ:
        del os.environ['CERT_SCANNER_CONFIG']

def test_settings_singleton():
    """Test that Settings class maintains singleton pattern"""
    settings1 = Settings()
    settings2 = Settings()
    assert settings1 is settings2

def test_default_config(clean_env):
    """Test that default config is loaded when no config file exists"""
    settings = Settings()
    assert settings.get("paths.database") == DEFAULT_CONFIG["paths"]["database"]
    assert settings.get("paths.backups") == DEFAULT_CONFIG["paths"]["backups"]

def test_load_config_from_env(test_config_path, clean_env):
    """Test loading config from environment variable"""
    os.environ['CERT_SCANNER_CONFIG'] = str(test_config_path)
    settings = Settings()
    assert settings.get("paths.database") == "tests/data/test.db"
    assert settings.get("scanning.internal.rate_limit") == 5

def test_get_existing_value():
    """Test getting an existing configuration value"""
    settings = Settings()
    settings._config = DEFAULT_CONFIG.copy()
    assert settings.get("paths.database") == DEFAULT_CONFIG["paths"]["database"]
    assert isinstance(settings.get("scanning.internal.rate_limit"), int)

def test_get_nonexistent_value():
    """Test getting a nonexistent configuration value"""
    settings = Settings()
    assert settings.get("nonexistent.key") is None
    assert settings.get("nonexistent.key", "default") == "default"

def test_update_value():
    """Test updating a configuration value"""
    settings = Settings()
    assert settings.update("paths.database", "new/path.db")
    assert settings.get("paths.database") == "new/path.db"

def test_update_nested_value():
    """Test updating a nested configuration value"""
    settings = Settings()
    assert settings.update("scanning.internal.rate_limit", 15)
    assert settings.get("scanning.internal.rate_limit") == 15

def test_update_nonexistent_key():
    """Test updating a nonexistent configuration key"""
    settings = Settings()
    assert not settings.update("nonexistent.key", "value")
    assert settings.get("nonexistent.key") is None

def test_save_config(tmp_path):
    """Test saving configuration to file"""
    settings = Settings()
    test_config = {"test": "value"}
    settings._config = test_config.copy()
    
    # Set up a temporary config file
    config_path = tmp_path / "config.yaml"
    with open(config_path, 'w') as f:
        yaml.safe_dump({}, f)
    
    # Save config
    original_path = os.getcwd()
    try:
        os.chdir(tmp_path)
        assert settings.save()
        
        # Verify saved content
        with open(config_path, 'r') as f:
            saved_config = yaml.safe_load(f)
        assert saved_config == test_config
    finally:
        os.chdir(original_path)

def test_config_validation():
    """Test configuration validation"""
    settings = Settings()
    
    # Test rate limit validation
    assert settings.update("scanning.internal.rate_limit", 10)  # Valid
    assert not settings.update("scanning.internal.rate_limit", 0)  # Invalid
    assert not settings.update("scanning.internal.rate_limit", -1)  # Invalid
    assert not settings.update("scanning.internal.rate_limit", "10")  # Invalid type
    
    # Test delay validation
    assert settings.update("scanning.internal.delay", 0)  # Valid
    assert settings.update("scanning.internal.delay", 1.5)  # Valid float
    assert not settings.update("scanning.internal.delay", -1)  # Invalid
    assert not settings.update("scanning.internal.delay", "1")  # Invalid type
    
    # Test expiry warnings validation
    valid_warnings = [
        {"days": 90, "level": "info"},
        {"days": 30, "level": "warning"},
        {"days": 7, "level": "critical"}
    ]
    assert settings.update("alerts.expiry_warnings", valid_warnings)
    
    invalid_warnings = [
        {"days": -1, "level": "warning"},  # Invalid days
        {"days": 30, "level": "invalid"},  # Invalid level
        {"days": "30", "level": "warning"}  # Invalid type
    ]
    assert not settings.update("alerts.expiry_warnings", invalid_warnings)
    
    # Test domain list validation
    assert settings.update("scanning.internal.domains", ["test.com"])  # Valid
    assert settings.update("scanning.internal.domains", [])  # Valid empty
    assert not settings.update("scanning.internal.domains", "test.com")  # Invalid type
    assert not settings.update("scanning.internal.domains", [1, 2])  # Invalid items 