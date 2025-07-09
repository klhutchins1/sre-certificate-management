"""
Session management for IMS.

Handles:
- Session creation
- Context management
- Cache integration for file-share optimization
"""

from requests import Session
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session
from ..settings import Settings
from .engine import get_cache_manager, is_cache_enabled
from .enhanced_session import CachedSessionFactory

# Create global engine instance
settings = Settings()
db_path = settings.get("paths.database", "data/certificates.db")
engine = create_engine(f"sqlite:///{db_path}")

# Global cached session factory
_cached_session_factory = None

def _get_cached_session_factory():
    """Get or create the cached session factory."""
    global _cached_session_factory
    if _cached_session_factory is None and is_cache_enabled():
        cache_manager = get_cache_manager()
        if cache_manager:
            _cached_session_factory = CachedSessionFactory(cache_manager)
    return _cached_session_factory

def get_session(engine=None, use_cache: bool = True) -> Session:
    """Get a database session.
    
    Args:
        engine: Optional SQLAlchemy engine. If None, uses global engine.
        use_cache: Whether to use cache if available (default: True)
        
    Returns:
        Session: A new database session if engine is valid, None otherwise.
    """
    if engine is None:
        engine = getattr(settings, '_engine', None)
        if engine is None:
            return None
    
    # Try to use cached session if available
    if use_cache and is_cache_enabled():
        cached_factory = _get_cached_session_factory()
        if cached_factory:
            try:
                return cached_factory(use_cache=True)
            except Exception:
                # Fall back to direct session if cache fails
                pass
    
    # Fall back to direct session
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

