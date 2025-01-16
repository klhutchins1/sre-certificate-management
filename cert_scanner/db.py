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
from .settings import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'certificates.db')

# Lock for thread-safe database operations
db_lock = threading.Lock()

def update_database_schema(engine):
    """Update database schema to include new tables"""
    try:
        logger.info("Checking for missing tables...")
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
            logger.info("Database schema updated successfully")
            return True
        else:
            logger.debug("No missing tables found")
            return True
            
    except Exception as e:
        logger.error(f"Failed to update database schema: {str(e)}")
        return False

def init_database():
    """Initialize the database connection and create tables if they don't exist"""
    try:
        # Get database path from settings
        db_path = Path(settings.get("paths.database", "data/certificates.db"))
        
        # Ensure the database directory exists
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # If database exists but is corrupted, remove it
        if db_path.exists():
            try:
                # Test if database is valid
                engine = create_engine(f"sqlite:///{db_path}")
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
            except Exception as e:
                logger.error(f"Existing database is corrupted, removing: {str(e)}")
                db_path.unlink()
        
        # Create database engine
        logger.info(f"Using database at: {db_path}")
        engine = create_engine(f"sqlite:///{db_path}")
        
        # Create tables
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
    """Check if the database exists and is properly initialized"""
    try:
        if not os.path.exists(DB_PATH):
            logger.warning("Database file does not exist")
            return False
            
        engine = create_engine(f'sqlite:///{DB_PATH}', echo=False)
        with engine.connect() as conn:
            # Try to query the database
            result = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in result]
            logger.info(f"Found tables: {tables}")
            return True
    except Exception as e:
        logger.error(f"Database check failed: {str(e)}")
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