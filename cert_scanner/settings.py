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
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            cls._instance._config = DEFAULT_CONFIG.copy()
            cls._instance._load_config()
        return cls._instance
    
    @classmethod
    def _reset(cls):
        """Reset the singleton instance (for testing)"""
        cls._instance = None
        cls._config = DEFAULT_CONFIG.copy()
    
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
    
    def _load_config(self):
        """Load configuration from file or create default"""
        config_paths = [
            "config.yaml",  # Current directory
            os.path.expanduser("~/.cert_scanner/config.yaml"),  # User's home
            "/etc/cert_scanner/config.yaml"  # System-wide
        ]
        
        # Also check if there's an environment variable pointing to config
        if "CERT_SCANNER_CONFIG" in os.environ:
            config_paths.insert(0, os.environ["CERT_SCANNER_CONFIG"])
        
        config_file = None
        for path in config_paths:
            if os.path.exists(path):
                config_file = path
                break
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config is not None:
                        # Merge with defaults to ensure all required keys exist
                        self._merge_config(loaded_config)
                logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                logger.error(f"Error loading config from {config_file}: {str(e)}")
                self._config = DEFAULT_CONFIG.copy()
        else:
            logger.warning("No config file found, using defaults")
            self._config = DEFAULT_CONFIG.copy()
            self._save_default_config()
    
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
    
    def _save_default_config(self):
        """Save default configuration if no config exists"""
        try:
            # Try to save in current directory first
            with open("config.yaml", 'w') as f:
                yaml.safe_dump(self._config, f, default_flow_style=False)
            logger.info("Created default config.yaml")
        except Exception as e:
            logger.error(f"Could not save default config: {str(e)}")
    
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
        try:
            with open("config.yaml", 'w') as f:
                yaml.safe_dump(self._config, f, default_flow_style=False)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {str(e)}")
            return False

# Global settings instance
settings = Settings() 