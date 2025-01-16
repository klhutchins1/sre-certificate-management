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
            cls._instance._load_config()
        return cls._instance
    
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
                    self._config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                logger.error(f"Error loading config from {config_file}: {str(e)}")
                self._config = DEFAULT_CONFIG
        else:
            logger.warning("No config file found, using defaults")
            self._config = DEFAULT_CONFIG
            self._save_default_config()
    
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
        try:
            keys = key.split('.')
            config = self._config
            for k in keys[:-1]:
                config = config[k]
            config[keys[-1]] = value
            return True
        except (KeyError, TypeError):
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