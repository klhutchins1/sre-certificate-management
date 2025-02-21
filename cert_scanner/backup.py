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
    """Create a backup of the database and configuration"""
    settings = Settings()
    db_path = settings.get("paths.database")
    backup_dir = Path(settings.get("paths.backups"))
    
    # Ensure backup directory exists
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate timestamp for backup files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    
    # Create backup paths
    backup_db = backup_dir / f"certificates_{timestamp}.db"
    backup_config = backup_dir / f"config_{timestamp}.yaml"
    manifest_file = backup_dir / f"backup_{timestamp}.json"
    
    try:
        # Copy database if it exists
        if Path(db_path).exists():
            shutil.copy2(db_path, backup_db)
        
        # Save current config
        with open(backup_config, 'w') as f:
            yaml.safe_dump(settings._config, f)
        
        # Create manifest
        manifest = {
            "timestamp": timestamp,
            "created": datetime.now().isoformat(),
            "database": str(backup_db),
            "config": str(backup_config)
        }
        
        # Save manifest
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f)
        
        return True
    except Exception as e:
        return False

def restore_backup(backup_path):
    """Restore database and configuration from a backup"""
    settings = Settings()
    db_path = settings.get("paths.database")
    
    try:
        # Load manifest
        with open(backup_path) as f:
            manifest = json.load(f)
        
        # Verify manifest structure
        required_keys = ["database", "config", "timestamp"]
        if not all(key in manifest for key in required_keys):
            return False
        
        # Restore database if it exists in backup
        db_backup = Path(manifest["database"])
        if db_backup.exists():
            shutil.copy2(db_backup, db_path)
        
        # Restore config
        config_backup = Path(manifest["config"])
        if config_backup.exists():
            with open(config_backup) as f:
                config = yaml.safe_load(f)
                settings._config = config
                settings.save()
        
        return True
    except Exception as e:
        return False

def list_backups():
    """List available backups ordered by timestamp (newest first)"""
    settings = Settings()
    backup_dir = Path(settings.get("paths.backups"))
    
    if not backup_dir.exists():
        return []
    
    backups = []
    for manifest in backup_dir.glob("backup_*.json"):
        try:
            with open(manifest) as f:
                backup_info = json.load(f)
                backup_info["manifest_file"] = str(manifest.relative_to(os.getcwd()))
                backups.append(backup_info)
        except Exception:
            continue
    
    # Sort by timestamp descending
    backups.sort(key=lambda x: x["timestamp"], reverse=True)
    return backups 