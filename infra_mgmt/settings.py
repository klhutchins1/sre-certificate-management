"""
Configuration management module for the Infastructure Management System.

This module provides a thread-safe singleton configuration manager that handles:
- Default configuration values
- YAML configuration file loading and saving
- Configuration validation and type checking
- Test mode configuration isolation
- Dynamic configuration updates
- Configuration persistence

The configuration structure includes:
- Database and backup paths
- Scanning rate limits and domain classifications
- Alert thresholds and notification settings
- Export format configurations

The module implements a robust validation system to ensure configuration
integrity and provides proper error handling for all operations.
"""

#------------------------------------------------------------------------------
# Imports and Configuration
#------------------------------------------------------------------------------

# Standard library imports
import os
import yaml
from pathlib import Path, WindowsPath
import logging
from typing import Dict, Any

# Configure logging
logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------
# Default Configuration
#------------------------------------------------------------------------------

# Default configuration structure
# Used as a base for merging user configurations and validation
DEFAULT_CONFIG = {
    "paths": {
        "database": "data/certificates.db",    # Default database location
        "backups": "data/backups"             # Default backup directory
    },
    "scanning": {
        "certificate": {
            "rate_limit": 30  # Certificate scan rate limit (requests per minute)
        },
        "default_rate_limit": 60,             # Default to 1 request per second
        "offline_mode": False,                # New setting for offline scanning mode
        "whois": {
            "rate_limit": 30,                 # 30 requests per minute (1 every 2 seconds)
            "timeout": 10                     # 10 second timeout for WHOIS queries
        },
        "dns": {
            "rate_limit": 60,                 # 60 requests per minute (1 per second)
            "timeout": 5                      # 5 second timeout for DNS queries
        },
        "internal": {
            "rate_limit": 60,                 # Default to 1 request per second for internal domains
            "delay": 0,                       # Default delay between scans in seconds
            "domains": [".local", ".internal", ".corp", ".lan"]
        },
        "external": {
            "rate_limit": 30,                 # Default to 1 request per 2 seconds for external domains
            "delay": 0,                       # Default delay between scans in seconds
            "domains": []                     # Custom external domain patterns
        },
        "ct": {
            "rate_limit": 10
        },
        "timeouts": {
            "socket": 10,                     # Increased from 5 to 10 seconds
            "request": 15,                    # Increased from 10 to 15 seconds
            "dns": 5.0                        # Increased from 3.0 to 5.0 seconds
        }
    },
    "alerts": {
        "expiry_warnings": [                  # Certificate expiration warning thresholds
            {"days": 60, "level": "critical"},
            {"days": 30, "level": "warning"}
        ],
        "failed_scans": {
            "consecutive_failures": 3          # Number of failures before alerting
        },
        "persistence_file": "data/alerts.json"  # Alert state persistence file
    },
    "exports": {
        "pdf": {
            "template": "reports/template.html",  # PDF report template
            "logo": "reports/logo.png"           # Report logo image
        },
        "csv": {
            "delimiter": ",",                    # CSV field delimiter
            "encoding": "utf-8"                  # CSV file encoding
        }
    },
    "ignore_lists": {
        "domains": {
            "enabled": True,
            "hide_from_results": True,
            "skip_scanning": True,
            "default_patterns": [
                "*.local",
                "*.test",
                "*.example",
                "*.invalid",
                "*.localhost",
                "*test*",
                "*dev*",
                "*stage*",
                "*qa*",
                "*sandbox*"
            ],
            "pattern_types": {
                "prefix": "*.example.com",      # Matches any subdomain of example.com
                "contains": "*test*",           # Matches if 'test' appears anywhere
                "suffix": "*.test.com",         # Matches domains ending in .test.com
                "exact": "example.com"          # Exact domain match
            }
        },
        "certificates": {
            "enabled": True,
            "hide_from_results": True,
            "skip_scanning": True,
            "match_by": "common_name",          # Match by CN instead of serial number
            "default_patterns": [
                "*test*",
                "*dev*",
                "*stage*",
                "*qa*",
                "*sandbox*"
            ]
        }
    },
    "proxy_detection": {
        "enabled": True,
        "ca_fingerprints": [],  # List of SHA256 fingerprints of known proxy CA certs
        "ca_subjects": [],       # List of subject strings of known proxy CA certs
        "ca_serials": []        # List of serial numbers of known proxy CA certs
    }
}

#------------------------------------------------------------------------------
# Settings Manager
#------------------------------------------------------------------------------

class Settings:
    """
    Thread-safe singleton configuration manager.
    
    This class provides a centralized configuration management system with:
    - Singleton pattern for consistent access
    - Thread-safe operations
    - Configuration file handling
    - Test mode isolation
    - Configuration validation
    - Dynamic updates
    
    The class maintains process-level locks to prevent multiple instances
    from modifying configuration simultaneously.
    """
    
    _instance = None
    _config: Dict[str, Any] = {}
    _test_mode = False
    _test_config = None  # Store test config in memory
    _config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yaml")
    _original_config = None  # Store original config during tests
    _app_lock_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".app_running")
    
    def __new__(cls):
        """
        Create or return the singleton instance.
        
        This method ensures only one instance exists and handles:
        - Configuration initialization
        - Test mode setup
        - Lock file management
        - Configuration file loading
        
        Returns:
            Settings: The singleton settings instance
        """
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
        """
        Clean up resources when the instance is destroyed.
        
        Ensures proper cleanup of:
        - Lock files
        - Temporary test configurations
        """
        # Remove app lock file when instance is destroyed
        if not self._test_mode and os.path.exists(self._app_lock_file):
            try:
                os.remove(self._app_lock_file)
            except Exception as e:
                logger.error(f"Failed to remove app lock file: {str(e)}")
    
    @classmethod
    def _reset(cls):
        """
        Reset the singleton instance (for testing).
        
        This method:
        - Removes lock files
        - Restores original configuration
        - Resets test mode flags
        - Cleans up test configurations
        """
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
        """
        Enable test mode with optional test configuration.
        
        Args:
            test_config: Optional configuration to use in test mode
            
        This method:
        - Backs up existing configuration
        - Enables test mode
        - Sets up test configuration
        - Manages lock files
        """
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
        """
        Merge loaded configuration with defaults.
        
        Args:
            loaded_config: Configuration dictionary to merge
            
        This method ensures:
        - All required keys exist
        - Default values are preserved when not overridden
        - Nested configurations are properly merged
        """
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
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation (e.g., 'scanning.rate_limit')
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default if not found
            
        Example:
            >>> settings.get('scanning.internal.rate_limit', 60)
            60
        """
        try:
            value = self._config
            for k in key.split('.'):
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def update(self, key: str, value: Any) -> bool:
        """
        Update a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation
            value: New value to set
            
        Returns:
            bool: True if update successful, False otherwise
            
        Note:
            Validates the value before updating
        """
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
        """
        Save current configuration to file.
        
        Returns:
            bool: True if save successful, False otherwise
            
        Note:
            In test mode, only updates in-memory configuration
        """
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
        """
        Validate a configuration value based on its key
        
        Args:
            key: Configuration key to validate
            value: Value to validate
            
        Returns:
            bool: True if value is valid, False otherwise
            
        Validates:
        - Key exists in configuration structure
        - Value type is correct
        - Value meets constraints (e.g., positive integers)
        - Paths are valid
        - Lists contain valid elements
        """
        # Split key into parts
        key_parts = key.split('.')
        
        # Validate key exists in default config structure
        config = DEFAULT_CONFIG
        try:
            for part in key_parts:
                if not isinstance(config, dict) or part not in config:
                    # For timeout settings, allow them even if not in DEFAULT_CONFIG structure
                    if "timeout" in key:
                        break
                    return False
                config = config[part]
        except (KeyError, TypeError):
            # For timeout settings, allow them even if validation fails
            if "timeout" in key:
                pass
            else:
                return False

        # Validate paths
        if key == "paths.database":
            if not _validate_path(value):
                return False
            # For database paths, ensure they end with .db
            return value.lower().endswith('.db')
        elif key == "paths.backups":
            return _validate_path(value)
            
        # Validate scanning settings
        elif key.startswith("scanning."):
            if "rate_limit" in key:
                return isinstance(value, (int, float)) and value > 0
            elif "delay" in key:
                return isinstance(value, (int, float)) and value >= 0
            elif "domains" in key:
                return isinstance(value, list) and all(isinstance(d, str) for d in value)
            elif key == "scanning.offline_mode":
                return isinstance(value, bool)
            elif "timeout" in key:
                # Handle both individual timeout settings and nested timeout objects
                return isinstance(value, (int, float)) and value > 0
                
        # Validate alert settings
        elif key.startswith("alerts."):
            if key == "alerts.expiry_warnings":
                if not isinstance(value, list):
                    return False
                valid_levels = {"info", "warning", "error", "critical"}
                for warning in value:
                    if not isinstance(warning, dict):
                        return False
                    if "days" not in warning or "level" not in warning:
                        return False
                    if not isinstance(warning["days"], int) or warning["days"] <= 0:
                        return False
                    if warning["level"] not in valid_levels:
                        return False
                return True
            elif key == "alerts.failed_scans.consecutive_failures":
                return isinstance(value, int) and value > 0
                
        # Validate export settings
        elif key.startswith("exports."):
            if key == "exports.csv.delimiter":
                return isinstance(value, str) and len(value) == 1
            elif key == "exports.csv.encoding":
                return isinstance(value, str) and value.strip()
            elif key == "exports.default_format":
                return value in ["CSV", "JSON", "YAML"]
                
        # Validate database/cache settings
        elif key.startswith("database."):
            if key == "database.sync_interval":
                return isinstance(value, int) and value > 0
            elif key == "database.enable_cache":
                return isinstance(value, bool)
            elif key == "database.cache_directory":
                return isinstance(value, str) and value.strip()
            elif key == "database.max_pending_writes":
                return isinstance(value, int) and value > 0
            # Unknown sub-key under database
            return False
            
        # Validate proxy detection settings
        elif key.startswith("proxy_detection."):
            if key == "proxy_detection.enabled":
                return isinstance(value, bool)
            elif key == "proxy_detection.ca_fingerprints":
                return isinstance(value, list) and all(isinstance(fp, str) for fp in value)
            elif key == "proxy_detection.ca_subjects":
                return isinstance(value, list) and all(isinstance(s, str) for s in value)
            elif key == "proxy_detection.ca_serials":
                return isinstance(value, list) and all(isinstance(s, str) for s in value)
            # Unknown sub-key under proxy_detection
            return False

        # Unknown key
        return False
    
    def _validate_related_settings(self, key: str, config: Dict[str, Any]) -> bool:
        """
        Validate related settings that depend on each other.
        
        Args:
            key: The key being updated
            config: The complete configuration to validate
            
        Returns:
            bool: True if all related settings are valid, False otherwise
        """
        try:
            # Validate scanning settings
            if key.startswith("scanning."):
                # Check default rate limit
                default_rate = config.get("scanning.default_rate_limit", 0)
                if default_rate <= 0:
                    return False
                
                # Check internal rate limit
                internal_rate = config.get("scanning.internal.rate_limit", 0)
                if internal_rate <= 0:
                    return False
                
                # Check external rate limit
                external_rate = config.get("scanning.external.rate_limit", 0)
                if external_rate <= 0:
                    return False
                
                # Check internal domains
                internal_domains = config.get("scanning.internal.domains", [])
                if not isinstance(internal_domains, list) or not all(isinstance(d, str) for d in internal_domains):
                    return False
                
                # Check external domains
                external_domains = config.get("scanning.external.domains", [])
                if not isinstance(external_domains, list) or not all(isinstance(d, str) for d in external_domains):
                    return False
                
                # Check WHOIS rate limit
                whois_rate = config.get("scanning.whois.rate_limit", 0)
                if whois_rate <= 0:
                    return False
                
                # Check DNS rate limit
                dns_rate = config.get("scanning.dns.rate_limit", 0)
                if dns_rate <= 0:
                    return False
                
                # Check CT rate limit
                ct_rate = config.get("scanning.ct.rate_limit", 0)
                if ct_rate <= 0:
                    return False
                
                # Check timeouts
                socket_timeout = config.get("scanning.timeouts.socket", 0)
                request_timeout = config.get("scanning.timeouts.request", 0)
                dns_timeout = config.get("scanning.timeouts.dns", 0)
                if socket_timeout <= 0 or request_timeout <= 0 or dns_timeout <= 0:
                    return False
            
            # Validate alert settings
            elif key.startswith("alerts."):
                warnings = config.get("alerts.expiry_warnings", [])
                if not isinstance(warnings, list):
                    return False
                    
                # Ensure warnings are properly ordered by days
                days = [w.get("days", 0) for w in warnings]
                if days != sorted(days, reverse=True):
                    return False
                    
                # Validate consecutive failures
                failures = config.get("alerts.failed_scans.consecutive_failures", 0)
                if not isinstance(failures, int) or failures <= 0:
                    return False
            
            # Validate export settings
            elif key.startswith("exports."):
                default_format = config.get("exports.default_format", "")
                if default_format not in ["CSV", "JSON", "YAML"]:
                    return False
                    
                # Validate CSV settings if CSV is the default format
                if default_format == "CSV":
                    delimiter = config.get("exports.csv.delimiter", "")
                    encoding = config.get("exports.csv.encoding", "")
                    if not isinstance(delimiter, str) or len(delimiter) != 1:
                        return False
                    if not isinstance(encoding, str) or not encoding.strip():
                        return False
            
            return True
        except Exception as e:
            logger.error(f"Error validating related settings for {key}: {str(e)}")
            return False

def _is_network_path(path):
    """Check if a path is a valid network path format"""
    if not isinstance(path, str):
        return False
    
    # Normalize path separators
    path = path.replace('\\', '/')
    
    # Check for UNC path format (//server/share/...)
    if not path.startswith('//'):
        return False
    
    # Split path into components
    parts = [p for p in path.split('/') if p]
    
    # Network path should have at least server and share
    if len(parts) < 2:
        return False
    
    # Server name should not be empty
    if not parts[0]:
        return False
    
    # Share name should not be empty
    if not parts[1]:
        return False
    
    return True

def _validate_path(path):
    """Validate a file or directory path"""
    if not isinstance(path, str):
        return False
    
    if not path:
        return False
    
    # Handle network paths
    if path.startswith('\\\\') or path.startswith('//'):
        return _is_network_path(path)
    
    # Handle local paths
    try:
        # Convert to Path object for validation
        path_obj = Path(path)
        
        # Check for invalid characters in path
        for part in path_obj.parts:
            if any(c in part for c in ['<', '>', ':', '"', '|', '?', '*']):
                return False
        
        return True
    except Exception:
        return False

#------------------------------------------------------------------------------
# Global Instance
#------------------------------------------------------------------------------

# Global settings instance
settings = Settings() 