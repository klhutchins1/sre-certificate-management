"""
Database engine creation and configuration for IMS.

Handles:
- Engine instantiation
- Path normalization
- Network path detection
"""

import logging
import os
import sqlite3
from datetime import datetime
from sqlalchemy import Engine, create_engine, text
from pathlib import Path, WindowsPath
from ..models import Base
from ..settings import Settings

logger = logging.getLogger(__name__)

def is_network_path(path: Path) -> bool:
    """
    Check if a path is a network (UNC) path.

    Args:
        path (Path): Path to check (can be local or network).

    Returns:
        bool: True if path is a network (UNC) path, False otherwise.

    Edge Cases:
        - Returns False for empty or malformed paths.
        - Handles both Windows (\\server\share) and Unix (//server/share) UNC formats.

    Example:
        >>> is_network_path(Path('\\\server\share'))
        True
        >>> is_network_path(Path('/local/path'))
        False
    """
    path_str = str(path)
    return path_str.startswith('\\') or path_str.startswith('//')

def normalize_path(path: str) -> Path:
    """
    Normalize a path string to a Path object, handling network and local paths.

    Args:
        path (str): Path string to normalize (can be relative, absolute, or UNC).

    Returns:
        Path: Normalized path object (WindowsPath for UNC, absolute Path otherwise).

    Edge Cases:
        - Preserves UNC format for network shares.
        - Resolves local paths to absolute.
        - Handles both Windows and Unix path formats.

    Example:
        >>> normalize_path('data/certificates.db')
        WindowsPath('C:/.../data/certificates.db')
        >>> normalize_path('\\\server\share\file.db')
        WindowsPath('\\\server\share\file.db')
    """
    path_obj = Path(str(path))
    if is_network_path(path_obj):
        return WindowsPath(str(path_obj))
    return path_obj.absolute()


def get_engine(db_path: str) -> 'Engine':
    """
    Create and return a SQLAlchemy engine for the given path.

    Args:
        db_path (str): Path to the SQLite database file.

    Returns:
        Engine: SQLAlchemy engine instance.
    """
    db_path = normalize_path(db_path)
    return create_engine(f"sqlite:///{db_path}")

def init_database(db_path=None):
    """Initialize the database and perform migrations."""
    try:
        # Get database path from parameter or settings
        if db_path is None:
            settings = Settings()
            db_path = settings.get("paths.database", "data/certificates.db")
            logger.info(f"Got path from settings: {db_path}")
        
        # Convert to Path object without resolving
        db_path = normalize_path(db_path)
        logger.info(f"Using path: {db_path}")
        
        # Check for invalid characters in path first
        invalid_chars = '<>"|?*'  # Remove ':' from invalid chars since it's valid in Windows paths
        if any(char in str(db_path) for char in invalid_chars):
            raise Exception(f"Invalid database path: {db_path}")
        
        # Get parent directory and create if it doesn't exist
        parent_dir = db_path.parent
        logger.info(f"Parent directory: {parent_dir}")

        # Check if parent exists but is not a directory
        if parent_dir.exists() and not parent_dir.is_dir():
            raise Exception(f"Path exists but is not a directory: {parent_dir}")

        # Check if parent's parent exists
        if not parent_dir.parent.exists():
            raise Exception(f"Parent directory's parent does not exist: {parent_dir.parent}")

        try:
            # Create all parent directories
            parent_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created parent directory: {parent_dir}")
        except PermissionError:
            raise Exception(f"No write permission to create directory: {parent_dir}")
        except Exception as e:
            raise Exception(f"Failed to create directory {parent_dir}: {str(e)}")

        # Verify directory is writable
        if not os.access(str(parent_dir), os.W_OK):
            raise Exception(f"No write permission for database directory: {parent_dir}")
        
        # Handle existing database file
        if db_path.exists():
            logger.info(f"Database file exists at: {db_path}")
            if not os.access(str(db_path), os.W_OK):
                raise Exception(f"No write permission for database file: {db_path}")
            
            # Validate existing database
            try:
                # First try to open with sqlite3 to check if it's a valid database
                with sqlite3.connect(str(db_path)) as conn:
                    cursor = conn.cursor()
                    cursor.execute("PRAGMA page_count")
                    cursor.execute("PRAGMA page_size")
                
                # If we get here, it's a valid SQLite database
                test_engine = create_engine(f"sqlite:///{db_path}")
                with test_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                test_engine.dispose()
            except sqlite3.DatabaseError as e:
                logger.warning(f"Invalid or corrupted database: {str(e)}")
                # Instead of removing the file and continuing, raise the exception
                raise sqlite3.DatabaseError("file is not a database")
            except Exception as e:
                logger.error(f"Failed to validate database: {str(e)}")
                raise sqlite3.DatabaseError("file is not a database")
        else:
            logger.info(f"Database file does not exist at: {db_path}")
        
        # Create new database engine
        logger.info(f"Creating database engine at: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create tables and update schema
        logger.info("Creating database tables...")
        Base.metadata.create_all(engine)
        
        # Perform migrations
        from .schema import migrate_database, sync_default_ignore_patterns
        migrate_database(engine)
        
        # Sync default ignore patterns
        sync_default_ignore_patterns(engine)
        
        # Verify database is functional
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        
        # Verify file was created
        if not db_path.exists():
            logger.error(f"Database file was not created at: {db_path}")
            # Try to find the file in the current directory
            current_dir = Path.cwd()
            logger.info(f"Checking current directory: {current_dir}")
            for file in current_dir.glob("*.db"):
                logger.info(f"Found database file: {file}")
            raise Exception(f"Database file was not created at: {db_path}")
        
        return engine
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise
