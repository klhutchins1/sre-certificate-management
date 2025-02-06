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
from pathlib import Path

# Third-party imports
import streamlit as st
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

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

# Define default database path relative to the application root
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'certificates.db')

# Thread-safe lock for database operations
db_lock = threading.Lock()

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
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
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
                existing_columns = {c['name']: c for c in inspector.get_columns(table_name)}
                
                # Add missing columns
                missing_columns = set(model_columns.keys()) - set(existing_columns.keys())
                if missing_columns:
                    logger.info(f"Adding missing columns to {table_name}: {missing_columns}")
                    with engine.begin() as connection:
                        for column_name in missing_columns:
                            column = model_columns[column_name]
                            nullable = 'NOT NULL' if not column.nullable else ''
                            default = f"DEFAULT {column.default.arg}" if column.default is not None else ''
                            sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column.type} {nullable} {default}"
                            connection.execute(text(sql.strip()))
        
        logger.info("Database schema updated successfully")
        return True
            
    except Exception as e:
        logger.error(f"Failed to update database schema: {str(e)}")
        return False

#------------------------------------------------------------------------------
# Database Initialization
#------------------------------------------------------------------------------

def init_database(db_path=None):
    """
    Initialize the database connection and create tables if they don't exist.
    
    This function performs the following steps:
    1. Validates and normalizes the database path
    2. Checks directory permissions
    3. Validates existing database or creates new one
    4. Initializes database schema
    5. Verifies required tables
    
    Args:
        db_path (str, optional): Custom database path. Defaults to None.
        
    Returns:
        SQLAlchemy engine instance
        
    Raises:
        Exception: If database initialization fails
    """
    try:
        # Get database path from parameter or settings
        if db_path is None:
            settings = Settings()
            db_path = Path(settings.get("paths.database", "data/certificates.db"))
        else:
            db_path = Path(db_path)
        
        # Validate path format and characters
        try:
            invalid_chars = '<>:"|?*'
            if any(char in str(db_path) for char in invalid_chars):
                raise Exception(f"Invalid database path: Path contains invalid characters")
            
            db_path = db_path.absolute()
        except Exception as e:
            raise Exception(f"Invalid database path: {db_path} - {str(e)}")

        # Verify directory permissions
        parent_dir = db_path.parent
        if parent_dir.exists():
            if not parent_dir.is_dir():
                raise Exception(f"Invalid database path: {parent_dir} is not a directory")
            if not os.access(parent_dir, os.W_OK):
                raise Exception(f"No write permission for database directory: {parent_dir}")
        else:
            try:
                parent_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise Exception(f"Cannot create database directory at {parent_dir}: {str(e)}")

        # Validate existing database or remove if corrupted
        if db_path.exists():
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
                    raise
                raise Exception(f"Database at {db_path} is corrupted.")
        
        # Initialize database engine
        logger.info(f"Using database at: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create schema and verify tables
        logger.info("Creating database tables...")
        Base.metadata.create_all(engine)
        
        with engine.connect() as conn:
            tables = inspect(engine).get_table_names()
            logger.info(f"Created tables: {', '.join(tables)}")
            
            required_tables = ['certificates', 'hosts', 'certificate_bindings', 
                             'certificate_tracking', 'certificate_scans', 'host_ips']
            missing_tables = [table for table in required_tables if table not in tables]
            if missing_tables:
                raise Exception(f"Failed to create tables: {', '.join(missing_tables)}")
        
        # Update schema if needed
        update_database_schema(engine)
        
        return engine
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

#------------------------------------------------------------------------------
# Session Management
#------------------------------------------------------------------------------

def get_session(engine):
    """
    Create a new database session.
    
    Args:
        engine: SQLAlchemy engine instance
        
    Returns:
        SQLAlchemy session object or None if engine is invalid
    """
    if not engine:
        return None
    return sessionmaker(bind=engine, expire_on_commit=False)()

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
        db_path = Path(settings.get("paths.database", "data/certificates.db"))
        
        if not db_path.exists():
            return False
            
        try:
            engine = create_engine(f"sqlite:///{db_path}")
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
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
    Create a backup of the database.
    
    Creates a timestamped copy of the database file in the specified directory.
    
    Args:
        engine: SQLAlchemy engine instance
        backup_dir (str): Directory to store the backup
        
    Returns:
        str: Path to the created backup file
        
    Raises:
        Exception: If backup operation fails
    """
    try:
        db_path = engine.url.database
        
        if not os.path.exists(backup_dir):
            raise Exception("Failed to create database backup: Backup directory does not exist.")
        
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"backup_{timestamp}.db")
        
        with db_lock:
            shutil.copy2(db_path, backup_path)
        
        logger.info(f"Database backup created at: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create database backup: {str(e)}")
        raise

def restore_database(backup_path, engine):
    """
    Restore database from a backup file.
    
    WARNING: This operation will overwrite the current database.
    
    Args:
        backup_path (str): Path to the backup file
        engine: SQLAlchemy engine instance
        
    Returns:
        bool: True if restore successful
        
    Raises:
        Exception: If restore operation fails
    """
    try:
        db_path = engine.url.database
        
        engine.dispose()
        
        with db_lock:
            shutil.copy2(backup_path, db_path)
        
        logger.info(f"Database restored from backup: {backup_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to restore database from backup: {str(e)}")
        raise 