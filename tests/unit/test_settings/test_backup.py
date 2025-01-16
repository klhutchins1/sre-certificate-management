import pytest
import os
from pathlib import Path
import shutil
import json
from datetime import datetime
from cert_scanner.views.settingsView import create_backup, restore_backup, list_backups
from cert_scanner.settings import Settings
import time
import yaml

@pytest.fixture
def test_env(tmp_path):
    """Set up test environment with temporary paths"""
    # Create test directories
    db_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    db_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Create test database file
    db_file = db_dir / "test.db"
    with open(db_file, 'w') as f:
        f.write("test database content")
    
    # Create test config with proper YAML structure
    test_config = {
        "paths": {
            "database": str(db_file),
            "backups": str(backup_dir)
        },
        "scanning": {
            "internal": {
                "rate_limit": 60,
                "delay": 0.5,
                "domains": []
            },
            "external": {
                "rate_limit": 30,
                "delay": 1.0,
                "domains": []
            }
        }
    }
    
    # Update settings to use test paths
    settings = Settings()
    settings._config = test_config.copy()  # Use the same config we just created
    settings.save()  # This will create config.yaml
    
    return {
        'tmp_path': tmp_path,
        'db_file': db_file,
        'backup_dir': backup_dir,
        'config_file': Path("config.yaml")
    }

def test_create_backup(test_env):
    """Test creating a backup"""
    success, message = create_backup()
    assert success
    assert "successfully" in message
    
    # Check backup directory contents
    backup_files = list(test_env['backup_dir'].glob("*"))
    assert len(backup_files) == 3  # db, config, and manifest
    
    # Verify manifest
    manifest_file = next(test_env['backup_dir'].glob("backup_*.json"))
    with open(manifest_file, 'r') as f:
        manifest = json.load(f)
    
    assert 'timestamp' in manifest
    assert 'database' in manifest
    assert 'config' in manifest
    assert 'created' in manifest

def test_list_backups(test_env):
    """Test listing available backups"""
    # Create a test backup
    create_backup()
    
    backups = list_backups()
    assert len(backups) > 0
    
    # Verify backup structure
    backup = backups[0]
    assert 'timestamp' in backup
    assert 'database' in backup
    assert 'config' in backup
    assert 'created' in backup
    assert 'manifest_file' in backup

def test_restore_backup(test_env):
    """Test restoring from a backup"""
    # Create initial backup
    success, message = create_backup()
    assert success, f"Failed to create initial backup: {message}"

    # Get the original content
    with open(test_env['db_file'], 'r') as f:
        original_content = f.read()
    with open(test_env['config_file'], 'r') as f:
        original_config = f.read()

    # Modify current files
    with open(test_env['db_file'], 'w') as f:
        f.write("modified database")
    
    modified_config = {
        "paths": {
            "database": "modified/path/db",
            "backups": "modified/path/backups"
        }
    }
    with open("config.yaml", 'w') as f:
        yaml.safe_dump(modified_config, f)

    # Get backup to restore
    backups = list_backups()
    assert len(backups) > 0, "No backups found"

    # Restore backup
    success, message = restore_backup(backups[0])
    assert success, f"Restore failed: {message}"

    # Verify restored content
    with open(test_env['db_file'], 'r') as f:
        restored_content = f.read()
    assert restored_content == original_content, "Database content was not restored correctly"

    # Verify config was restored
    with open("config.yaml", 'r') as f:
        restored_config = f.read()
    assert restored_config == original_config, "Config was not restored correctly"

def test_restore_nonexistent_backup(test_env):
    """Test restoring from a nonexistent backup"""
    fake_manifest = {
        'config': 'nonexistent.yaml',
        'database': 'nonexistent.db'
    }
    success, message = restore_backup(fake_manifest)
    assert not success
    assert "not found" in message

def test_backup_with_missing_database(test_env):
    """Test creating backup when database file is missing"""
    # Remove database file
    os.remove(test_env['db_file'])
    
    # Backup should still succeed, just without database
    success, message = create_backup()
    assert success
    
    # Check manifest
    manifest_file = next(test_env['backup_dir'].glob("backup_*.json"))
    with open(manifest_file, 'r') as f:
        manifest = json.load(f)
    assert manifest['database'] is None

def test_backup_with_special_characters(test_env):
    """Test backup with special characters in paths"""
    # Use Windows-safe special characters
    special_path = test_env['tmp_path'] / "special-test_backup (1)"
    special_path.mkdir(exist_ok=True)
    
    settings = Settings()
    settings.update("paths.backups", str(special_path))
    
    success, message = create_backup()
    assert success
    
    # Verify backup was created
    assert len(list(special_path.glob("*"))) > 0

def test_multiple_backups_ordering(test_env):
    """Test that multiple backups are ordered correctly"""
    # Get settings instance and store original config
    settings = Settings()
    original_config = settings._config.copy()
    
    try:
        created_backups = []
        created_timestamps = set()
        
        # Create multiple backups with delays to ensure different timestamps
        for i in range(3):
            # Modify the database content slightly for each backup
            with open(test_env['db_file'], 'w') as f:
                f.write(f"test database content {i}")
            
            # Ensure settings are correct for each backup
            settings._config = original_config.copy()
            settings._config['paths']['database'] = str(test_env['db_file'])
            settings._config['paths']['backups'] = str(test_env['backup_dir'])
            settings.save()
            
            success, message = create_backup()
            assert success, f"Backup {i} failed: {message}"
            
            # Verify backup was created
            backup_files = list(test_env['backup_dir'].glob("*"))
            assert len(backup_files) > i * 3, f"Expected at least {i * 3} files for backup {i}, got {len(backup_files)}"
            
            # Get timestamp from manifest file
            manifest_files = list(test_env['backup_dir'].glob("backup_*.json"))
            for manifest_file in manifest_files:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                    created_timestamps.add(manifest['timestamp'])
            
            created_backups.extend([str(f) for f in backup_files])
            
            # List backups after each creation to debug
            current_backups = list_backups()
            print(f"\nAfter backup {i}:")
            print(f"Backup files in directory: {[str(f) for f in backup_files]}")
            print(f"Backups from list_backups(): {current_backups}")
            print(f"Unique timestamps so far: {created_timestamps}")
            
            time.sleep(0.001)  # Small delay just to be safe
        
        # Verify we have unique timestamps
        assert len(created_timestamps) == 3, f"Expected 3 unique timestamps, got {len(created_timestamps)}: {created_timestamps}"
        
        # Restore original settings for listing backups
        settings._config = original_config.copy()
        settings._config['paths']['database'] = str(test_env['db_file'])
        settings._config['paths']['backups'] = str(test_env['backup_dir'])
        settings.save()
        
        # Debug output
        print(f"\nFinal state:")
        print(f"All created backup files: {created_backups}")
        print(f"All files in backup dir: {[str(f) for f in test_env['backup_dir'].glob('*')]}")
        
        backups = list_backups()
        print(f"Final backups from list_backups(): {backups}")
        
        assert len(backups) >= 3, (
            f"Expected at least 3 backups, got {len(backups)}\n"
            f"Backup dir: {test_env['backup_dir']}\n"
            f"Backups: {backups}\n"
            f"Files in backup dir: {[str(f) for f in test_env['backup_dir'].glob('*')]}\n"
            f"Unique timestamps: {created_timestamps}"
        )
        
        # Verify timestamps are in descending order
        timestamps = [datetime.fromisoformat(b['created']) for b in backups]
        assert timestamps == sorted(timestamps, reverse=True), "Backups are not properly ordered by timestamp"
        
        # Verify each backup has the correct files
        for backup in backups[:3]:  # Check the first 3 backups
            assert Path(backup['config']).exists(), f"Config file missing for backup: {backup['created']}"
            assert Path(backup['database']).exists(), f"Database file missing for backup: {backup['created']}"
            
            # Verify backup content
            with open(Path(backup['database']), 'r') as f:
                content = f.read()
                assert "test database content" in content, f"Unexpected content in backup: {content}"
    finally:
        # Always restore original settings
        settings._config = original_config.copy()
        settings.save()  # Make sure we persist the original settings
        
        # Clean up any leftover files
        try:
            for file in test_env['backup_dir'].glob("*"):
                file.unlink()
            test_env['backup_dir'].rmdir()
        except Exception as e:
            print(f"Warning: Failed to clean up some test files: {e}") 