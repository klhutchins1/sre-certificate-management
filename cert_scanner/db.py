"""
Database management module for the Certificate Management System.

This module provides the core database functionality for the application, including:
- Database initialization and connection management
- Schema creation and updates
- Session handling and thread safety
- Backup and restore operations
- Database health checks and maintenance

The module uses SQLAlchemy as the ORM and SQLite as the database engine.
All database operations are thread-safe and include proper error handling.
The module supports automatic schema updates and database validation.
"""

#------------------------------------------------------------------------------
# Imports and Configuration
#------------------------------------------------------------------------------

# Standard library imports
import os
import logging
import threading
import shutil
from datetime import datetime
from pathlib import Path, WindowsPath
import sqlite3
import random
import json

# Third-party imports
import streamlit as st
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

# Local application imports
from .models import Base
from .settings import Settings

#------------------------------------------------------------------------------
# Logging Configuration
#------------------------------------------------------------------------------

# Configure logging for database operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------
# Database Configuration
#------------------------------------------------------------------------------

# Thread-safe lock for database operations
db_lock = threading.Lock()

def _is_network_path(path: Path) -> bool:
    """
    Check if a path is a network path.
    
    Args:
        path: Path to check
        
    Returns:
        bool: True if path is a network path
    """
    path_str = str(path)
    return path_str.startswith('\\\\') or path_str.startswith('//')

def _normalize_path(path: str) -> Path:
    """
    Normalize a path string to a Path object.
    
    Args:
        path: Path string to normalize
        
    Returns:
        Path: Normalized path object
        
    This function handles:
    - Network share paths (\\server\share)
    - Local paths
    - Relative paths
    """
    # Convert string to Path object
    path_obj = Path(str(path))
    
    # Handle network paths
    if _is_network_path(path_obj):
        # For network paths, we want to preserve the UNC format
        return WindowsPath(str(path_obj))
    
    # For local paths, resolve to absolute
    return path_obj.absolute()

#------------------------------------------------------------------------------
# Schema Management
#------------------------------------------------------------------------------

def update_database_schema(engine):
    """
    Update database schema to include new tables and columns.
    
    This function performs the following operations:
    1. Inspects existing database schema
    2. Compares with defined models
    3. Creates missing tables
    4. Adds missing columns to existing tables
    
    Args:
        engine: SQLAlchemy engine instance
        
    Returns:
        bool: True if update successful, False otherwise
        
    Note:
        This operation is non-destructive and preserves existing data
    """
    try:
        logger.info("Checking for missing tables and columns...")
        try:
            inspector = inspect(engine)
            existing_tables = inspector.get_table_names()
        except Exception as e:
            logger.error(f"Failed to inspect database: {str(e)}")
            return False
        
        # Get all table names from our models
        model_tables = set(Base.metadata.tables.keys())
        
        # Find and create missing tables
        missing_tables = model_tables - set(existing_tables)
        if missing_tables:
            logger.info(f"Creating missing tables: {missing_tables}")
            for table_name in missing_tables:
                if table_name in Base.metadata.tables:
                    Base.metadata.tables[table_name].create(engine)
        
        # Update existing tables with missing columns
        for table_name in existing_tables:
            if table_name in Base.metadata.tables:
                model_columns = {c.name: c for c in Base.metadata.tables[table_name].columns}
                try:
                    existing_columns = {c['name']: c for c in inspector.get_columns(table_name)}
                    # Validate table structure
                    for col_name, col_info in existing_columns.items():
                        if col_name not in model_columns:
                            logger.error(f"Invalid column {col_name} in table {table_name}")
                            return False
                except Exception as e:
                    logger.error(f"Failed to get columns for table {table_name}: {str(e)}")
                    return False
                
                # Add missing columns
                missing_columns = set(model_columns.keys()) - set(existing_columns.keys())
                if missing_columns:
                    logger.info(f"Adding missing columns to {table_name}: {missing_columns}")
                    try:
                        with engine.begin() as connection:
                            for column_name in missing_columns:
                                column = model_columns[column_name]
                                nullable = 'NOT NULL' if not column.nullable else ''
                                
                                # Handle default values
                                default = ''
                                if column.server_default is not None:
                                    default = f"DEFAULT {column.server_default.arg}"
                                elif column.default is not None:
                                    if isinstance(column.default.arg, str):
                                        default = f"DEFAULT '{column.default.arg}'"
                                    else:
                                        default = f"DEFAULT {column.default.arg}"
                                
                                # For SQLite, we need to handle NOT NULL with DEFAULT in a specific way
                                if not column.nullable and default:
                                    # First add the column without NOT NULL
                                    sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column.type} {default}"
                                    connection.execute(text(sql.strip()))
                                    
                                    # Then update any NULL values with the default
                                    sql = f"UPDATE {table_name} SET {column_name} = {column.server_default.arg} WHERE {column_name} IS NULL"
                                    connection.execute(text(sql.strip()))
                                else:
                                    sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column.type} {nullable} {default}"
                                    connection.execute(text(sql.strip()))
                    except Exception as e:
                        logger.error(f"Failed to add columns to table {table_name}: {str(e)}")
                        return False
        
        logger.info("Database schema updated successfully")
        return True
            
    except Exception as e:
        logger.error(f"Failed to update database schema: {str(e)}")
        return False

#------------------------------------------------------------------------------
# Database Initialization
#------------------------------------------------------------------------------

def migrate_database(engine):
    """Perform database migrations to update schema."""
    try:
        inspector = inspect(engine)
        current_time = datetime.now().isoformat()
        
        # Create new tables if they don't exist
        if 'ignored_domains' not in inspector.get_table_names():
            logger.info("Creating ignored_domains table")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE ignored_domains (
                        id INTEGER PRIMARY KEY,
                        pattern TEXT NOT NULL UNIQUE,
                        reason TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT
                    )
                """))
                conn.commit()
        
        if 'ignored_certificates' not in inspector.get_table_names():
            logger.info("Creating ignored_certificates table")
            with engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE ignored_certificates (
                        id INTEGER PRIMARY KEY,
                        pattern TEXT NOT NULL UNIQUE,
                        reason TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT
                    )
                """))
                conn.commit()
        
        # Check if domain_dns_records table needs updating
        if 'domain_dns_records' in inspector.get_table_names():
            # Check if we need to update the unique constraint
            constraints = inspector.get_unique_constraints('domain_dns_records')
            needs_update = True
            for constraint in constraints:
                if 'value' in constraint['column_names']:
                    needs_update = False
                    break
            
            if needs_update:
                logger.info("Updating domain_dns_records table with new unique constraint")
                with engine.connect() as conn:
                    # Create new table with updated constraint
                    conn.execute(text("""
                        CREATE TABLE domain_dns_records_new (
                            id INTEGER PRIMARY KEY,
                            domain_id INTEGER REFERENCES domains(id),
                            record_type VARCHAR NOT NULL,
                            name VARCHAR NOT NULL,
                            value VARCHAR NOT NULL,
                            ttl INTEGER DEFAULT 3600,
                            priority INTEGER,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            UNIQUE (domain_id, record_type, name, value)
                        )
                    """))
                    
                    # Copy existing data
                    conn.execute(text("""
                        INSERT INTO domain_dns_records_new
                        SELECT DISTINCT id, domain_id, record_type, name, value, ttl, priority, created_at, updated_at
                        FROM domain_dns_records
                    """))
                    
                    # Drop old table
                    conn.execute(text("DROP TABLE domain_dns_records"))
                    
                    # Rename new table
                    conn.execute(text("ALTER TABLE domain_dns_records_new RENAME TO domain_dns_records"))
                    
                    conn.commit()
                    logger.info("Successfully updated domain_dns_records table")
        
        # Check if certificates table exists and perform existing migrations
        if 'certificates' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('certificates')]
            
            # Add chain_valid column if it doesn't exist
            if 'chain_valid' not in columns:
                logger.info("Adding chain_valid column to certificates table")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN chain_valid BOOLEAN DEFAULT FALSE"))
                    conn.commit()
            
            # Add created_at column if it doesn't exist
            if 'created_at' not in columns:
                logger.info("Adding created_at column to certificates table")
                with engine.connect() as conn:
                    # Add column with NULL default first
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN created_at DATETIME"))
                    # Then update with current timestamp
                    conn.execute(text(f"UPDATE certificates SET created_at = '{current_time}' WHERE created_at IS NULL"))
                    conn.commit()
            
            # Add updated_at column if it doesn't exist
            if 'updated_at' not in columns:
                logger.info("Adding updated_at column to certificates table")
                with engine.connect() as conn:
                    # Add column with NULL default first
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN updated_at DATETIME"))
                    # Then update with current timestamp
                    conn.execute(text(f"UPDATE certificates SET updated_at = '{current_time}' WHERE updated_at IS NULL"))
                    conn.commit()
            
            # Add sans_scanned column if it doesn't exist
            if 'sans_scanned' not in columns:
                logger.info("Adding sans_scanned column to certificates table")
                with engine.connect() as conn:
                    conn.execute(text("ALTER TABLE certificates ADD COLUMN sans_scanned BOOLEAN DEFAULT FALSE"))
                    conn.commit()
            
            # Handle JSON field migration
            with engine.connect() as conn:
                # Get all certificates
                result = conn.execute(text("SELECT id, issuer, subject, san FROM certificates"))
                for row in result:
                    try:
                        # Convert string fields to JSON if they're not already
                        issuer = row.issuer
                        subject = row.subject
                        san = row.san
                        
                        # Convert issuer
                        if issuer and not issuer.startswith('{'):
                            try:
                                issuer_dict = eval(issuer)
                                issuer = json.dumps(issuer_dict)
                            except:
                                logger.warning(f"Invalid issuer data for certificate {row.id}: {issuer}")
                                issuer = json.dumps({})
                        
                        # Convert subject
                        if subject and not subject.startswith('{'):
                            try:
                                subject_dict = eval(subject)
                                subject = json.dumps(subject_dict)
                            except:
                                logger.warning(f"Invalid subject data for certificate {row.id}: {subject}")
                                subject = json.dumps({})
                        
                        # Convert SAN
                        if san and not san.startswith('['):
                            try:
                                san_list = eval(san)
                                san = json.dumps(san_list if isinstance(san_list, list) else [])
                            except:
                                logger.warning(f"Invalid SAN data for certificate {row.id}: {san}")
                                san = json.dumps([])
                        
                        # Update the record
                        conn.execute(
                            text("UPDATE certificates SET issuer = :issuer, subject = :subject, san = :san WHERE id = :id"),
                            {"id": row.id, "issuer": issuer, "subject": subject, "san": san}
                        )
                    except Exception as e:
                        logger.error(f"Error migrating certificate {row.id}: {str(e)}")
                        raise
                
                conn.commit()
        
        logger.info("Database migration completed successfully")
    except Exception as e:
        logger.error(f"Failed to migrate database: {str(e)}")
        raise

def init_database(db_path=None):
    """Initialize the database and perform migrations."""
    try:
        # Get database path from parameter or settings
        if db_path is None:
            settings = Settings()
            db_path = settings.get("paths.database", "data/certificates.db")
            logger.info(f"Got path from settings: {db_path}")
        
        # Convert to Path object without resolving
        db_path = _normalize_path(db_path)
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
                test_engine = create_engine(f"sqlite:///{db_path}")
                with test_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                test_engine.dispose()
            except Exception as e:
                logger.warning(f"Removing invalid or corrupted database: {str(e)}")
                try:
                    db_path.unlink()
                except Exception as e:
                    logger.error(f"Failed to remove corrupted database: {str(e)}")
                    raise Exception(f"Failed to remove corrupted database: {str(e)}")
        else:
            logger.info(f"Database file does not exist at: {db_path}")
        
        # Create new database engine
        logger.info(f"Creating database engine at: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create tables and update schema
        logger.info("Creating database tables...")
        Base.metadata.create_all(engine)
        
        # Perform migrations
        migrate_database(engine)
        
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

#------------------------------------------------------------------------------
# Session Management
#------------------------------------------------------------------------------

# Create global engine instance
settings = Settings()
db_path = settings.get("paths.database", "data/certificates.db")
engine = create_engine(f"sqlite:///{db_path}")

def get_session(engine=None) -> Session:
    """Get a database session.
    
    Args:
        engine: Optional SQLAlchemy engine. If None, returns None.
        
    Returns:
        Session: A new database session if engine is valid, None otherwise.
    """
    if engine is None:
        return None
        
    try:
        # Try to create a connection to verify engine is valid
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return sessionmaker(
            bind=engine,
            expire_on_commit=False,  # Prevent stale data issues
            autoflush=True,  # Enable automatic flushing
            autocommit=False  # Keep transactions explicit
        )()
    except Exception:
        return None

class SessionManager:
    """
    Context manager for safe database session handling.
    
    Provides automatic session creation and cleanup with proper
    error handling and transaction management.
    
    Usage:
        with SessionManager(engine) as session:
            # Perform database operations
            session.query(...)
    """
    def __init__(self, engine):
        self.engine = engine
        self.session = None

    def __enter__(self):
        if not self.engine:
            return None
        self.session = sessionmaker(bind=self.engine, expire_on_commit=False)()
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            if exc_type is not None:
                self.session.rollback()
            self.session.close()

#------------------------------------------------------------------------------
# Database Maintenance
#------------------------------------------------------------------------------

def reset_database(engine):
    """
    Reset the database by dropping and recreating all tables.
    
    WARNING: This operation will delete all data in the database.
    
    Args:
        engine: SQLAlchemy engine instance
        
    Returns:
        bool: True if reset successful, False otherwise
    """
    try:
        logger.info("Dropping all tables...")
        Base.metadata.drop_all(engine)
        logger.info("Creating new tables...")
        Base.metadata.create_all(engine)
        logger.info("Database reset completed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to reset database: {str(e)}")
        return False

def check_database():
    """
    Check if the database exists and is properly initialized.
    
    Returns:
        bool: True if database is valid and accessible, False otherwise
    """
    try:
        settings = Settings()
        db_path = _normalize_path(settings.get("paths.database", "data/certificates.db"))
        
        if not db_path.exists():
            return False
        
        # Try to open and validate the database
        try:
            engine = create_engine(f"sqlite:///{db_path}")
            with engine.connect() as conn:
                # Check if we can execute a simple query
                conn.execute(text("SELECT 1"))
                
                # Check if required tables exist
                inspector = inspect(engine)
                existing_tables = inspector.get_table_names()
                required_tables = set(Base.metadata.tables.keys())
                
                if not required_tables.issubset(set(existing_tables)):
                    return False
            
            engine.dispose()
            return True
        except Exception:
            return False
    except Exception:
        return False

#------------------------------------------------------------------------------
# Backup and Restore
#------------------------------------------------------------------------------

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
        backup_path = _normalize_path(str(backup_dir)).resolve()
        
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
        
        # Verify we can write to the backup file location
        try:
            # Create a test file to verify write permissions
            test_file = backup_file.with_suffix('.test')
            with open(str(test_file), 'w') as f:
                f.write('test')
            test_file.unlink()
        except PermissionError:
            raise Exception(f"No write permission for backup file: {backup_file}")
        except Exception as e:
            raise Exception(f"Failed to verify write permission for backup file: {str(e)}")
        
        # Create backup using shutil
        try:
            shutil.copy2(source_path, str(backup_file))
        except PermissionError:
            raise Exception(f"No write permission for backup file: {backup_file}")
        except Exception as e:
            raise Exception(f"Failed to create backup file: {str(e)}")
        
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