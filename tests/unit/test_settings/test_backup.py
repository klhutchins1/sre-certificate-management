import pytest
import os
from pathlib import Path, WindowsPath
import shutil
import json
from datetime import datetime
from infra_mgmt.backup import create_backup, restore_backup, list_backups
from infra_mgmt.settings import Settings
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from infra_mgmt.models import Base, Certificate
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

    # Get backup to restore
    backups = list_backups()
    assert len(backups) > 0, "No backups found"
    backup_to_restore = backups[0]['manifest_file']

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
    nonexistent_path = test_env['backup_dir'] / "nonexistent_backup.json"
    success, message = restore_backup(str(nonexistent_path))
    assert not success
    assert "Failed to read manifest file" in message

def test_backup_with_missing_database(test_env):
    """Test backup behavior when database file is missing."""
    # Remove the database file
    db_path = Path(test_env['db_file'])
    if db_path.exists():
        db_path.unlink()
    
    # Attempt to create backup
    success, message = create_backup()
    
    # Verify error handling
    assert success is False, "Backup should fail when database is missing"
    assert "database file" in message.lower(), f"Expected 'database file' in message, got: {message}"
    assert any(phrase in message.lower() for phrase in ["not found", "does not exist"]), f"Expected 'not found' or 'does not exist' in message, got: {message}"
    
    # Verify no backup files were created
    backup_dir = Path(test_env['backup_dir'])
    if backup_dir.exists():
        assert len(list(backup_dir.glob("*"))) == 0, "No backup files should be created"

def test_backup_with_special_characters(test_env):
    """Test backup creation with special characters in paths."""
    # Create test files with special characters
    special_dir = test_env['backup_dir'] / "special-test_backup (1)"
    special_dir.mkdir(exist_ok=True)
    
    test_files = [
        "file with spaces.txt",
        "file_with_!@#$%^&*().txt",
        "file_with_unicode_测试.txt"
    ]
    
    for filename in test_files:
        file_path = special_dir / filename
        file_path.write_text("test content")
    
    # Create backup
    success, message = create_backup()
    
    # Verify backup succeeded
    assert success, f"Backup failed: {message}"
    
    # Verify backup files exist
    assert special_dir.exists(), "Backup directory not created"
    
    # Find the latest backup
    backup_files = list(special_dir.glob("*"))
    assert len(backup_files) > 0, "No backup files created"
    latest_backup = max(backup_files, key=lambda x: x.stat().st_mtime)
    
    # Verify manifest exists
    manifest_files = list(special_dir.glob("*"))
    assert len(manifest_files) > 0, "No manifest file created"
    
    # Cleanup
    for file_path in special_dir.glob("*"):
        file_path.unlink()
    special_dir.rmdir()
    latest_backup.unlink()
    manifest_files[0].unlink()

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
            expected_files = (i + 1) * 3  # Each backup creates 3 files
            assert len(backup_files) >= expected_files, f"Expected at least {expected_files} files after backup {i}, got {len(backup_files)}"
            
            # Get timestamp from manifest file
            manifest_files = list(test_env['backup_dir'].glob("backup_*.json"))
            for manifest_file in manifest_files:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                    created_timestamps.add(manifest['timestamp'])
            
            created_backups.extend([str(f) for f in backup_files])
            
            time.sleep(1)  # Ensure different timestamps
        
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

def test_create_backup_success(test_env):
    """Test successful backup creation"""
    # Create test data
    engine = create_engine(f"sqlite:///{test_env['db_file']}")
    Base.metadata.create_all(engine)
    engine.dispose()
    
    # Create backup
    success, message = create_backup()
    assert success, f"Backup failed: {message}"
    assert "successfully" in message
    
    # Verify backup files
    backup_files = list(test_env['backup_dir'].glob("*"))
    assert len(backup_files) == 3, "Expected 3 backup files (db, config, manifest)"
    
    # Verify manifest
    manifest_files = list(test_env['backup_dir'].glob("backup_*.json"))
    assert len(manifest_files) == 1, "Expected one manifest file"
    
    with open(manifest_files[0], 'r') as f:
        manifest = json.load(f)
        assert 'database' in manifest
        assert 'config' in manifest
        assert 'created' in manifest
        assert 'timestamp' in manifest 