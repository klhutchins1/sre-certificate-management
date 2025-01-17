import os
import yaml
from pathlib import Path
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "paths": {
        "database": "data/certificates.db",
        "backups": "data/backups"
    },
    "scanning": {
        "internal": {
            "rate_limit": 10,
            "delay": 2,
            "domains": []
        },
        "external": {
            "rate_limit": 5,
            "delay": 5,
            "domains": []
        }
    },
    "alerts": {
        "expiry_warnings": [
            {"days": 90, "level": "info"},
            {"days": 30, "level": "warning"},
            {"days": 7, "level": "critical"}
        ],
        "failed_scans": {
            "consecutive_failures": 3
        },
        "persistence_file": "data/alerts.json"
    },
    "exports": {
        "pdf": {
            "template": "reports/template.html",
            "logo": "reports/logo.png"
        },
        "csv": {
            "delimiter": ",",
            "encoding": "utf-8"
        }
    }
}

class Settings:
    _instance = None
    _config: Dict[str, Any] = {}
    _test_mode = False
    _test_config = None  # Store test config in memory
    _config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yaml")
    _original_config = None  # Store original config during tests
    _app_lock_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".app_running")
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            
            if cls._test_mode:
                # In test mode, use the test config or defaults
                cls._instance._config = cls._test_config.copy() if cls._test_config else DEFAULT_CONFIG.copy()
                # Remove stale lock file if it exists
                if os.path.exists(cls._app_lock_file):
                    try:
                        os.remove(cls._app_lock_file)
                    except Exception as e:
                        logger.error(f"Failed to remove stale lock file: {str(e)}")
            else:
                # Start with defaults
                cls._instance._config = DEFAULT_CONFIG.copy()
                # Only load config if it exists, never create it automatically
                if os.path.exists(cls._config_file):
                    try:
                        with open(cls._config_file, 'r') as f:
                            loaded_config = yaml.safe_load(f)
                            if loaded_config is not None:
                                cls._instance._merge_config(loaded_config)
                    except Exception as e:
                        logger.error(f"Error loading {cls._config_file}: {str(e)}")
                # Create app lock file
                try:
                    with open(cls._app_lock_file, 'w') as f:
                        f.write(str(os.getpid()))
                except Exception as e:
                    logger.error(f"Failed to create app lock file: {str(e)}")
        return cls._instance
    
    def __del__(self):
        # Remove app lock file when instance is destroyed
        if not self._test_mode and os.path.exists(self._app_lock_file):
            try:
                os.remove(self._app_lock_file)
            except Exception as e:
                logger.error(f"Failed to remove app lock file: {str(e)}")
    
    @classmethod
    def _reset(cls):
        """Reset the singleton instance (for testing)"""
        # Remove lock file if it exists
        if os.path.exists(cls._app_lock_file):
            try:
                os.remove(cls._app_lock_file)
            except Exception as e:
                logger.error(f"Failed to remove lock file: {str(e)}")
        
        # Restore original config if we have one and we're in test mode
        if cls._test_mode and cls._original_config and os.path.exists(cls._config_file):
            try:
                with open(cls._config_file, 'w') as f:
                    yaml.safe_dump(cls._original_config, f, default_flow_style=False)
            except Exception as e:
                logger.error(f"Error restoring original config: {str(e)}")
        
        cls._instance = None
        cls._test_mode = False
        cls._test_config = None
        cls._original_config = None
    
    @classmethod
    def set_test_mode(cls, test_config=None):
        """Enable test mode with optional test config"""
        # Remove lock file if it exists
        if os.path.exists(cls._app_lock_file):
            try:
                os.remove(cls._app_lock_file)
            except Exception as e:
                logger.error(f"Failed to remove lock file: {str(e)}")
            
        # Backup original config if it exists
        if os.path.exists(cls._config_file):
            try:
                with open(cls._config_file, 'r') as f:
                    cls._original_config = yaml.safe_load(f)
            except Exception as e:
                logger.error(f"Error backing up original config: {str(e)}")
        
        cls._test_mode = True
        cls._test_config = test_config.copy() if test_config else DEFAULT_CONFIG.copy()
        cls._instance = None  # Force recreation with test config
    
    def _merge_config(self, loaded_config: Dict[str, Any]):
        """Merge loaded config with defaults to ensure all keys exist"""
        def merge_dicts(default: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
            result = default.copy()
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_dicts(result[key], value)
                else:
                    result[key] = value
            return result
        
        self._config = merge_dicts(DEFAULT_CONFIG.copy(), loaded_config)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation"""
        try:
            value = self._config
            for k in key.split('.'):
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def update(self, key: str, value: Any) -> bool:
        """Update a configuration value using dot notation"""
        if not self._validate_config_value(key, value):
            return False
            
        try:
            keys = key.split('.')
            config = self._config
            
            # Create nested structure if it doesn't exist
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            config[keys[-1]] = value
            return True
        except Exception as e:
            logger.error(f"Error updating config key {key}: {str(e)}")
            return False
    
    def save(self) -> bool:
        """Save current configuration to file"""
        if self._test_mode:
            # In test mode, just update the in-memory test config
            self.__class__._test_config = self._config.copy()
            return True
            
        try:
            with open(self._config_file, 'w') as f:
                yaml.safe_dump(self._config, f, default_flow_style=False)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {str(e)}")
            return False
    
    def _validate_config_value(self, key: str, value: Any) -> bool:
        """Validate a configuration value"""
        try:
            # Check if key exists in default config structure
            current = DEFAULT_CONFIG
            for k in key.split('.'):
                if not isinstance(current, dict) or k not in current:
                    logger.error(f"Invalid config key: {key}")
                    return False
                current = current[k]
            
            # Rate limit validation
            if key.endswith('.rate_limit'):
                return isinstance(value, int) and value > 0
            
            # Delay validation
            if key.endswith('.delay'):
                return isinstance(value, (int, float)) and value >= 0
            
            # Expiry warnings validation
            if key == 'alerts.expiry_warnings':
                if not isinstance(value, list):
                    return False
                return all(
                    isinstance(w, dict) and
                    isinstance(w.get('days'), int) and w['days'] > 0 and
                    w.get('level') in ['info', 'warning', 'critical']
                    for w in value
                )
            
            # Path validation
            if key.startswith('paths.'):
                if not isinstance(value, str):
                    return False
                try:
                    # Check if path contains invalid characters
                    path = Path(value)
                    # Try to resolve the path to catch any system-specific issues
                    path.resolve()
                    return True
                except Exception as e:
                    logger.error(f"Invalid path {value}: {str(e)}")
                    return False
            
            # Domain list validation
            if key.endswith('.domains'):
                return isinstance(value, list) and all(isinstance(d, str) for d in value)
            
            return True
        except Exception as e:
            logger.error(f"Validation error for {key}: {str(e)}")
            return False

# Global settings instance
settings = Settings() 