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

