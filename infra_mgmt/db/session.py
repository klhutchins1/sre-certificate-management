"""
Session management for IMS.

Handles:
- Session creation
- Context management
"""

from requests import Session
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session
from ..settings import Settings

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

