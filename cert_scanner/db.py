import streamlit as st
import logging
import os
import threading
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base
from sqlalchemy import inspect

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'certificates.db')

# Lock for thread-safe database operations
db_lock = threading.Lock()

def init_database():
    """Initialize the database connection and create tables if they don't exist"""
    with db_lock:
        try:
            logger.info("Initializing database connection...")
            
            # Create data directory if it doesn't exist
            os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
            logger.info(f"Using database at: {DB_PATH}")
            
            # Create database connection
            engine = create_engine(f'sqlite:///{DB_PATH}', echo=False, pool_pre_ping=True)
            
            # Check if tables exist before creating them
            inspector = inspect(engine)
            existing_tables = inspector.get_table_names()
            
            if not existing_tables:
                logger.info("Creating database tables...")
                Base.metadata.create_all(engine)
            else:
                logger.debug(f"Using existing tables: {existing_tables}")
            
            # Test the connection
            with engine.connect() as conn:
                logger.debug("Database connection successful")
            
            return engine
            
        except Exception as e:
            logger.error(f"Database initialization failed: {str(e)}")
            st.error(f"Failed to initialize database: {str(e)}")
            return None

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