import pytest
import os
from pathlib import Path
import yaml
from infra_mgmt.settings import Settings, DEFAULT_CONFIG

@pytest.fixture(autouse=True)
def reset_settings():
    """Reset settings singleton before each test"""
    Settings._reset()
    yield
    Settings._reset()

def test_settings_singleton():
    """Test that Settings class maintains singleton pattern"""
    settings1 = Settings()
    settings2 = Settings()
    assert settings1 is settings2

def test_default_config():
    """Test that default config is loaded when no config file exists"""
    Settings.set_test_mode()
    settings = Settings()
    assert Path(settings.get("paths.database")).as_posix() == Path(DEFAULT_CONFIG["paths"]["database"]).as_posix()
    assert Path(settings.get("paths.backups")).as_posix() == Path(DEFAULT_CONFIG["paths"]["backups"]).as_posix()

def test_load_config():
    """Test loading config"""
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
    Settings.set_test_mode(test_config)
    settings = Settings()
    assert settings.get("paths.database") == "tests/data/test.db"
    assert settings.get("scanning.internal.rate_limit") == 5

def test_get_existing_value():
    """Test getting an existing configuration value"""
    Settings.set_test_mode()
    settings = Settings()
    assert settings.get("paths.database") == DEFAULT_CONFIG["paths"]["database"]
    assert isinstance(settings.get("scanning.internal.rate_limit"), int)

def test_get_nonexistent_value():
    """Test getting a nonexistent configuration value"""
    Settings.set_test_mode()
    settings = Settings()
    assert settings.get("nonexistent.key") is None
    assert settings.get("nonexistent.key", "default") == "default"

def test_update_value():
    """Test updating a configuration value"""
    Settings.set_test_mode()
    settings = Settings()
    assert settings.update("paths.database", "new/path.db")
    assert settings.get("paths.database") == "new/path.db"

def test_update_nested_value():
    """Test updating a nested configuration value"""
    Settings.set_test_mode()
    settings = Settings()
    assert settings.update("scanning.internal.rate_limit", 15)
    assert settings.get("scanning.internal.rate_limit") == 15

def test_update_nonexistent_key():
    """Test updating a nonexistent configuration key"""
    Settings.set_test_mode()
    settings = Settings()
    assert not settings.update("nonexistent.key", "value")
    assert settings.get("nonexistent.key") is None

def test_save_config():
    """Test saving configuration to file"""
    Settings.set_test_mode()
    settings = Settings()
    test_config = {"test": "value"}
    settings._config = test_config.copy()
    
    # Save and verify the in-memory test config
    assert settings.save()
    assert Settings._test_config == test_config

def test_config_validation():
    """Test configuration validation"""
    Settings.set_test_mode()
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

def test_proxy_detection_config():
    Settings.set_test_mode()
    settings = Settings()
    # Set proxy detection config
    assert settings.update("proxy_detection.enabled", True)
    assert settings.update("proxy_detection.ca_fingerprints", ["abc123", "def456"])
    assert settings.update("proxy_detection.ca_subjects", ["CorpProxy Root CA"])
    assert settings.update("proxy_detection.ca_serials", ["9999"])
    assert settings.update("proxy_detection.bypass_external", True)
    assert settings.update("proxy_detection.bypass_patterns", ["*.test.com"])
    assert settings.update("proxy_detection.proxy_hostnames", ["test-proxy"])
    assert settings.update("proxy_detection.enable_hostname_validation", False)
    assert settings.update("proxy_detection.enable_authenticity_validation", False)
    assert settings.update("proxy_detection.warn_on_proxy_detection", False)
    # Retrieve and check
    assert settings.get("proxy_detection.enabled") is True
    assert settings.get("proxy_detection.ca_fingerprints") == ["abc123", "def456"]
    assert settings.get("proxy_detection.ca_subjects") == ["CorpProxy Root CA"]
    assert settings.get("proxy_detection.ca_serials") == ["9999"]
    assert settings.get("proxy_detection.bypass_external") is True
    assert settings.get("proxy_detection.bypass_patterns") == ["*.test.com"]
    assert settings.get("proxy_detection.proxy_hostnames") == ["test-proxy"]
    assert settings.get("proxy_detection.enable_hostname_validation") is False
    assert settings.get("proxy_detection.enable_authenticity_validation") is False
    assert settings.get("proxy_detection.warn_on_proxy_detection") is False 