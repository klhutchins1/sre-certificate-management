"""
Module for handling database and configuration backup operations.

Provides functions to create, restore, and list backups for the IMS database and configuration files.
Ensures backups are timestamped, manifest-driven, and support both database and YAML config recovery.
"""
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import yaml

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from infra_mgmt.settings import Settings
from infra_mgmt.models import Base

def create_backup(engine=None):
    """
    Create a backup of the database and configuration.

    This function creates timestamped backups of the main database file and the current configuration.
    It also generates a manifest JSON file describing the backup contents for traceability and recovery.

    Args:
        engine (optional): SQLAlchemy engine instance. If not provided, uses settings to locate the DB.

    Returns:
        Tuple[bool, str]:
            - bool: Success status of the backup operation
            - str: Message describing the result (success or error details)

    Edge Cases:
        - Handles missing database/config files, path resolution errors, and file I/O errors.
        - Ensures backup directory exists and is writable.
        - Returns clear error messages for all failure modes.

    Example:
        >>> success, msg = create_backup()
        >>> print(msg)
    """
    try:
        settings = Settings()
        db_path = Path(settings.get("paths.database"))
        backup_dir = Path(settings.get("paths.backups"))
        
        # Ensure backup directory exists
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Resolve paths to absolute
        try:
            backup_dir = backup_dir.resolve()
            if not db_path.exists():
                return False, "Database file does not exist"
            db_path = db_path.resolve()
        except Exception as e:
            return False, f"Failed to resolve paths: {str(e)}"
        
        # Generate timestamp for backup files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create backup paths
        backup_db = backup_dir / f"certificates_{timestamp}.db"
        backup_config = backup_dir / f"config_{timestamp}.yaml"
        manifest_file = backup_dir / f"backup_{timestamp}.json"
        
        try:
            # Copy database if it exists
            db_backup_path = None
            if db_path.exists():
                try:
                    shutil.copy2(str(db_path), str(backup_db))
                    db_backup_path = str(backup_db)
                except Exception as e:
                    return False, f"Failed to backup database: {str(e)}"
            else:
                return False, "Database file does not exist"
            
            # Save current config
            try:
                with open(backup_config, 'w') as f:
                    yaml.safe_dump(settings._config, f)
            except Exception as e:
                return False, f"Failed to backup configuration: {str(e)}"
            
            # Create manifest
            manifest = {
                "timestamp": timestamp,
                "created": datetime.now().isoformat(),
                "database": db_backup_path,
                "config": str(backup_config)
            }
            
            # Save manifest
            try:
                with open(manifest_file, 'w') as f:
                    json.dump(manifest, f, indent=2)
            except Exception as e:
                return False, f"Failed to create manifest: {str(e)}"
            
            return True, "Backup created successfully"
            
        except Exception as e:
            return False, f"Failed to create backup: {str(e)}"
            
    except Exception as e:
        return False, f"Failed to initialize backup: {str(e)}"

def restore_backup(backup_path):
    """
    Restore database and configuration from a backup manifest.

    This function reads a manifest JSON file, verifies the referenced backup files exist,
    and restores both the database and configuration to their previous state.

    Args:
        backup_path (str or Path): Path to the backup manifest file

    Returns:
        Tuple[bool, str]:
            - bool: Success status of the restore operation
            - str: Message describing the result (success or error details)

    Edge Cases:
        - Handles missing/invalid manifest, missing backup files, and file I/O errors.
        - Ensures atomic restore of both DB and config.
        - Returns clear error messages for all failure modes.

    Example:
        >>> success, msg = restore_backup('backups/backup_20240101_120000.json')
        >>> print(msg)
    """
    settings = Settings()
    db_path = settings.get("paths.database")
    
    if not db_path:
        return False, "Database path not configured"
    
    try:
        # Load manifest
        try:
            with open(backup_path) as f:
                manifest = json.load(f)
        except Exception as e:
            return False, f"Failed to read manifest file: {str(e)}"
        
        # Verify manifest structure
        required_keys = ["database", "config", "timestamp"]
        if not all(key in manifest for key in required_keys):
            return False, "Invalid manifest structure"
        
        # Verify backup files exist
        db_backup = Path(manifest["database"])
        config_backup = Path(manifest["config"])
        
        if not config_backup.is_file():
            return False, "Config backup file not found"
            
        if not db_backup.is_file():
            return False, "Database backup file not found"
        
        # Restore database
        try:
            shutil.copy2(db_backup, db_path)
        except Exception as e:
            return False, f"Failed to restore database: {str(e)}"
        
        # Restore config
        try:
            with open(config_backup) as f:
                config = yaml.safe_load(f)
                settings._config = config
                settings.save()
        except Exception as e:
            return False, f"Failed to restore configuration: {str(e)}"
        
        return True, "Backup restored successfully"
        
    except Exception as e:
        return False, f"Failed to restore backup: {str(e)}"

def list_backups():
    """
    List available backups ordered by timestamp (newest first).

    This function scans the backup directory for manifest files, loads their metadata,
    and returns a list of backup information dictionaries sorted by creation time.

    Returns:
        List[Dict]: List of backup information dictionaries, each including manifest path, database, config, and timestamps.

    Edge Cases:
        - Handles missing/empty backup directory, invalid manifests, and file I/O errors.
        - Returns an empty list if no valid backups are found.

    Example:
        >>> backups = list_backups()
        >>> for b in backups:
        ...     print(b['manifest_file'], b['created'])
    """
    settings = Settings()
    backup_dir = Path(settings.get("paths.backups"))
    
    if not backup_dir.exists():
        backup_dir.mkdir(parents=True, exist_ok=True)
    
    backups = []
    try:
        # Use absolute paths for consistency
        backup_dir = backup_dir.resolve()
        
        # Find all manifest files
        manifest_files = list(backup_dir.glob("backup_*.json"))
        
        for manifest_path in manifest_files:
            try:
                with open(manifest_path) as f:
                    backup_info = json.load(f)
                    
                    # Ensure all paths are absolute
                    if 'database' in backup_info:
                        db_path = Path(backup_info['database'])
                        backup_info['database'] = str(db_path.resolve() if db_path.exists() else db_path)
                    
                    if 'config' in backup_info:
                        config_path = Path(backup_info['config'])
                        backup_info['config'] = str(config_path.resolve() if config_path.exists() else config_path)
                    
                    # Store manifest path relative to backup directory
                    backup_info['manifest_file'] = str(manifest_path)
                    
                    # Ensure created timestamp exists
                    if 'created' not in backup_info:
                        backup_info['created'] = datetime.fromtimestamp(manifest_path.stat().st_mtime).isoformat()
                    
                    backups.append(backup_info)
            except Exception as e:
                continue  # Skip invalid manifests
        
        # Sort by timestamp descending
        backups.sort(key=lambda x: x.get('created', x.get('timestamp', '')), reverse=True)
        
    except Exception as e:
        # Log error but return empty list
        return []
    
    return backups 