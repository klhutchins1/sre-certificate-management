"""
Module for handling database and configuration backup operations.
"""
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import yaml

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cert_scanner.settings import Settings
from cert_scanner.models import Base

def create_backup(engine=None):
    """
    Create a backup of the database and configuration
    
    Args:
        engine: Optional SQLAlchemy engine instance
    
    Returns:
        Tuple[bool, str]: A tuple containing:
            - bool: Success status of the backup operation
            - str: Message describing the result
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
    Restore database and configuration from a backup
    
    Args:
        backup_path: Path to the backup manifest file
        
    Returns:
        Tuple[bool, str]: Success status and message
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
    List available backups ordered by timestamp (newest first)
    
    Returns:
        List[Dict]: List of backup information dictionaries
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