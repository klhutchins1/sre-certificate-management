import streamlit as st
import logging
import os
import threading
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base
from sqlalchemy import inspect
from pathlib import Path
from sqlalchemy import text
from .settings import Settings
import shutil
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'certificates.db')

# Lock for thread-safe database operations
db_lock = threading.Lock()

def update_database_schema(engine):
    """Update database schema to include new tables and columns"""
    try:
        logger.info("Checking for missing tables and columns...")
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        # Get all table names from our models
        model_tables = set(Base.metadata.tables.keys())
        
        # Find missing tables
        missing_tables = model_tables - set(existing_tables)
        
        if missing_tables:
            logger.info(f"Creating missing tables: {missing_tables}")
            # Create only the missing tables
            for table_name in missing_tables:
                if table_name in Base.metadata.tables:
                    Base.metadata.tables[table_name].create(engine)
        
        # Check for missing columns in existing tables
        for table_name in existing_tables:
            if table_name in Base.metadata.tables:
                model_columns = {c.name: c for c in Base.metadata.tables[table_name].columns}
                existing_columns = {c['name']: c for c in inspector.get_columns(table_name)}
                
                # Find missing columns
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

def init_database(db_path=None):
    """Initialize the database connection and create tables if they don't exist"""
    try:
        # Get database path from parameter or settings
        if db_path is None:
            settings = Settings()
            db_path = Path(settings.get("paths.database", "data/certificates.db"))
        else:
            db_path = Path(db_path)
        
        # Validate the path format and characters
        try:
            # Check for invalid characters in the path
            invalid_chars = '<>:"|?*'
            if any(char in str(db_path) for char in invalid_chars):
                raise Exception(f"Invalid database path: Path contains invalid characters")
            
            # Try to get the absolute path to validate it
            db_path = db_path.absolute()
        except Exception as e:
            raise Exception(f"Invalid database path: {db_path} - {str(e)}")

        # Check if we have write permissions to the parent directory
        parent_dir = db_path.parent
        if parent_dir.exists():
            if not parent_dir.is_dir():
                raise Exception(f"Invalid database path: {parent_dir} is not a directory")
            if not os.access(parent_dir, os.W_OK):
                raise Exception(f"No write permission for database directory: {parent_dir}")
        else:
            # Only try to create directories if we have a valid path
            try:
                parent_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise Exception(f"Cannot create database directory at {parent_dir}: {str(e)}")

        # If database exists but is corrupted or empty, remove it
        if db_path.exists():
            try:
                # Test if database is valid
                test_engine = create_engine(f"sqlite:///{db_path}")
                with test_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                test_engine.dispose()
            except Exception as e:
                logger.warning(f"Removing invalid or corrupted database: {str(e)}")
                try:
                    db_path.unlink()  # Remove the corrupted file
                except Exception as e:
                    logger.error(f"Failed to remove corrupted database: {str(e)}")
                    raise
                raise Exception(f"Database at {db_path} is corrupted.")  # Raise an exception if the database is corrupted
        
        # Create new database engine
        logger.info(f"Using database at: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create tables and update schema
        logger.info("Creating database tables...")
        Base.metadata.create_all(engine)
        
        # Verify tables were created
        with engine.connect() as conn:
            tables = inspect(engine).get_table_names()
            logger.info(f"Created tables: {', '.join(tables)}")
            
            # Verify each required table exists
            required_tables = ['certificates', 'hosts', 'certificate_bindings', 'certificate_tracking', 'certificate_scans', 'host_ips']
            missing_tables = [table for table in required_tables if table not in tables]
            if missing_tables:
                raise Exception(f"Failed to create tables: {', '.join(missing_tables)}")
        
        # Update schema if needed
        update_database_schema(engine)
        
        return engine
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

def get_session(engine):
    """Create a new database session"""
    if not engine:
        return None
    return sessionmaker(bind=engine, expire_on_commit=False)()

def reset_database(engine):
    """Reset the database by dropping and recreating all tables"""
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
    """Check if the database exists and is initialized."""
    try:
        settings = Settings()
        db_path = Path(settings.get("paths.database", "data/certificates.db"))
        
        # Check if file exists and is a valid SQLite database
        if not db_path.exists():
            return False
            
        # Try to connect to verify it's a valid database
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

class SessionManager:
    """Context manager for database sessions"""
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

def backup_database(engine, backup_dir):
    """Create a backup of the database"""
    try:
        # Get the database path from the engine URL
        db_path = engine.url.database
        
        # Check if the backup directory exists
        if not os.path.exists(backup_dir):
            raise Exception("Failed to create database backup: Backup directory does not exist.")
        
        # Create backup directory if it doesn't exist
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"backup_{timestamp}.db")
        
        # Copy the database file
        with db_lock:
            shutil.copy2(db_path, backup_path)
        
        logger.info(f"Database backup created at: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Failed to create database backup: {str(e)}")
        raise

def restore_database(backup_path, engine):
    """Restore database from a backup"""
    try:
        # Get the current database path from the engine URL
        db_path = engine.url.database
        
        # Close all connections
        engine.dispose()
        
        # Restore the database file
        with db_lock:
            shutil.copy2(backup_path, db_path)
        
        logger.info(f"Database restored from backup: {backup_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to restore database from backup: {str(e)}")
        raise 