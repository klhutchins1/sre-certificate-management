import pytest
import os
from pathlib import Path
import shutil
import json
from datetime import datetime
from cert_scanner.views.settingsView import create_backup, restore_backup, list_backups
from cert_scanner.settings import Settings
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from cert_scanner.models import Base, Certificate
import time
import yaml

@pytest.fixture(autouse=True)
def cleanup_settings():
    """Clean up settings after each test"""
    yield
    Settings._reset()

@pytest.fixture
def test_env(tmp_path):
    """Set up test environment with temporary paths"""
    # Create test directories
    db_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    db_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # Create test database file using SQLAlchemy
    db_file = db_dir / "test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(engine)
    engine.dispose()
    
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
    
    # Enable test mode with our test config
    Settings.set_test_mode(test_config)
    
    yield {
        'tmp_path': tmp_path,
        'db_file': db_file,
        'backup_dir': backup_dir,
        'config_file': Path("config.yaml")
    }
    
    # Clean up
    Settings._reset()

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
    # Create a test record in the database
    engine = create_engine(f"sqlite:///{test_env['db_file']}")
    Session = sessionmaker(bind=engine)
    with Session() as session:
        cert = Certificate(
            serial_number="test123",
            thumbprint="abc123",
            common_name="test.com",
            valid_from=datetime.now(),
            valid_until=datetime.now(),
            issuer="Test CA",
            subject="CN=test.com",
            san="test.com"
        )
        session.add(cert)
        session.commit()
    Session.close_all()
    engine.dispose()

    # Store original settings
    settings = Settings()
    original_config = settings._config.copy()
    original_backup_path = settings.get("paths.backups")
    original_db_path = settings.get("paths.database")

    # Create initial backup
    success, message = create_backup()
    assert success, f"Failed to create initial backup: {message}"

    # Store original certificate data
    engine = create_engine(f"sqlite:///{test_env['db_file']}")
    Session = sessionmaker(bind=engine)
    with Session() as session:
        original_cert = session.query(Certificate).first()
        original_data = {
            'serial_number': original_cert.serial_number,
            'thumbprint': original_cert.thumbprint,
            'common_name': original_cert.common_name,
            'issuer': original_cert.issuer,
            'subject': original_cert.subject,
            'san': original_cert.san
        }
    Session.close_all()
    engine.dispose()

    # Modify database by adding another record
    engine = create_engine(f"sqlite:///{test_env['db_file']}")
    Session = sessionmaker(bind=engine)
    with Session() as session:
        cert = Certificate(
            serial_number="modified456",
            thumbprint="def456",
            common_name="modified.com",
            valid_from=datetime.now(),
            valid_until=datetime.now(),
            issuer="Test CA",
            subject="CN=modified.com",
            san="modified.com"
        )
        session.add(cert)
        session.commit()
    Session.close_all()
    engine.dispose()

    # Modify config
    modified_config = {
        "paths": {
            "database": str(test_env['db_file']),  # Use the actual test database path
            "backups": str(test_env['backup_dir'])  # Use the actual test backup path
        }
    }
    settings._config = modified_config
    settings.save()

    # Get backup to restore
    backups = list_backups()
    assert len(backups) > 0, "No backups found"
    backup_to_restore = backups[0]

    # Close all database connections before restore
    Session.close_all()

    # Restore backup
    success, message = restore_backup(backup_to_restore)
    assert success, f"Restore failed: {message}"

    # Verify database content through SQLAlchemy
    engine = create_engine(f"sqlite:///{test_env['db_file']}")
    Session = sessionmaker(bind=engine)
    with Session() as session:
        # Should only find the original record
        certs = session.query(Certificate).all()
        assert len(certs) == 1, "Wrong number of certificates after restore"
        restored_cert = certs[0]
        restored_data = {
            'serial_number': restored_cert.serial_number,
            'thumbprint': restored_cert.thumbprint,
            'common_name': restored_cert.common_name,
            'issuer': restored_cert.issuer,
            'subject': restored_cert.subject,
            'san': restored_cert.san
        }
        assert restored_data == original_data, "Certificate data does not match after restore"
    Session.close_all()
    engine.dispose()

    # Verify config was restored
    settings = Settings()  # Get fresh settings instance
    assert settings._config == original_config, "Config was not restored correctly"

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
            # Modify the database content by adding a test record
            engine = create_engine(f"sqlite:///{test_env['db_file']}")
            Session = sessionmaker(bind=engine)
            with Session() as session:
                cert = Certificate(
                    serial_number=f"test{i}",
                    thumbprint=f"abc{i}",
                    common_name=f"test{i}.com",
                    valid_from=datetime.now(),
                    valid_until=datetime.now(),
                    issuer="Test CA",
                    subject=f"CN=test{i}.com",
                    san=f"test{i}.com"
                )
                session.add(cert)
                session.commit()
            engine.dispose()
            
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
            
            time.sleep(0.001)  # Small delay just to be safe
        
        # Verify we have unique timestamps
        assert len(created_timestamps) == 3, f"Expected 3 unique timestamps, got {len(created_timestamps)}: {created_timestamps}"
        
        # List backups and verify order
        backups = list_backups()
        assert len(backups) >= 3, (
            f"Expected at least 3 backups, got {len(backups)}\n"
            f"Backup dir: {test_env['backup_dir']}\n"
            f"Backups: {backups}\n"
            f"Files in backup dir: {[str(f) for f in test_env['backup_dir'].glob('*')]}\n"
            f"Unique timestamps: {created_timestamps}"
        )
        
        # Verify timestamps are in descending order
        timestamps = [datetime.fromisoformat(b['created']) for b in backups]
        assert all(timestamps[i] >= timestamps[i+1] for i in range(len(timestamps)-1)), "Backups not in descending order"
    
    finally:
        # Clean up any engines
        engine = create_engine(f"sqlite:///{test_env['db_file']}")
        engine.dispose()
        
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