"""
Backup and restore for IMS.

Handles:
- Backup creation
- Restore logic
"""


from datetime import datetime
import os
import random
import shutil
import sqlite3

from sqlalchemy import Engine, create_engine, text
from .engine import normalize_path


def backup_database(engine, backup_dir):
    """
    Create a backup of the current database.
    
    Args:
        engine: SQLAlchemy engine instance
        backup_dir: Directory to store backup file
        
    Returns:
        str: Path to backup file
        
    Raises:
        Exception: If backup operation fails
    """
    try:
        # Get source database path from engine and verify it exists
        source_path = engine.url.database
        if not os.path.exists(source_path):
            raise Exception(f"Source database does not exist: {source_path}")
        
        # Convert backup directory to Path and resolve
        backup_path = normalize_path(str(backup_dir)).resolve()
        
        # Check if backup directory exists and is writable
        if backup_path.exists():
            if not backup_path.is_dir():
                raise Exception(f"Backup path exists but is not a directory: {backup_path}")
            if not os.access(str(backup_path), os.W_OK):
                raise Exception(f"No write permission for backup directory: {backup_path}")
        else:
            # Try to create backup directory
            try:
                backup_path.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                raise Exception(f"No write permission to create backup directory: {backup_path}")
            except Exception as e:
                raise Exception(f"Failed to create backup directory: {str(e)}")
            
            # Verify directory was created and is writable
            if not backup_path.is_dir():
                raise Exception(f"Failed to create backup directory: {backup_path}")
            if not os.access(str(backup_path), os.W_OK):
                raise Exception(f"No write permission for created backup directory: {backup_path}")
        
        # Generate unique backup filename with timestamp and random suffix
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_suffix = ''.join(random.choices('0123456789abcdef', k=8))
        backup_file = backup_path / f"database_backup_{timestamp}_{random_suffix}.db"
        
        # Create backup using shutil
        try:
            # Try to create the backup file first
            with open(str(backup_file), 'wb') as f:
                pass
            os.remove(str(backup_file))
            
            # Now copy the actual database file
            shutil.copy2(source_path, str(backup_file))
        except PermissionError:
            raise Exception(f"Failed to create backup file")
        except Exception as e:
            raise Exception(f"Failed to create backup file")
        
        # Verify backup is valid
        try:
            backup_engine = create_engine(f"sqlite:///{backup_file}")
            with backup_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            backup_engine.dispose()
        except Exception as e:
            # Clean up invalid backup
            try:
                if backup_file.exists():
                    backup_file.unlink()
            except Exception:
                pass
            raise Exception(f"Failed to verify backup: {str(e)}")
        
        return str(backup_file)
    except Exception as e:
        raise Exception(f"Failed to create database backup: {str(e)}")

def restore_database(backup_path: str, engine: Engine) -> bool:
    """Restore database from backup file.
    
    Args:
        backup_path: Path to backup file
        engine: SQLAlchemy engine for target database
        
    Returns:
        bool: True if restore was successful
        
    Raises:
        sqlite3.DatabaseError: If backup file is invalid or database is locked
    """
    if not os.path.exists(backup_path):
        raise sqlite3.DatabaseError("unable to open database file")
        
    # Check if database is locked by attempting to acquire a write lock
    try:
        with sqlite3.connect(engine.url.database, timeout=0.1) as conn:
            # Try to acquire a write lock
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ROLLBACK")
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            raise sqlite3.OperationalError("Database is locked")
        raise
        
    # Validate backup file
    try:
        with sqlite3.connect(backup_path) as conn:
            # Try to read some basic information to validate the backup
            cursor = conn.cursor()
            cursor.execute("PRAGMA page_count")
            cursor.execute("PRAGMA page_size")
    except sqlite3.DatabaseError:
        raise sqlite3.DatabaseError("file is not a database")
        
    # Copy backup file to database
    shutil.copy2(backup_path, engine.url.database)
    return True 

