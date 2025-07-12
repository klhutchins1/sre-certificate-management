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

def get_session(engine_param=None, use_cache: bool = True) -> Session:
    """Get a database session.
    
    Args:
        engine_param: Optional SQLAlchemy engine. If None, uses appropriate engine.
        use_cache: Whether to use cache if available (default: True)
        
    Returns:
        Session: A new database session if engine is valid, None otherwise.
    """
    # Determine which engine to use
    target_engine = engine_param
    
    # Try to use cached session if available and no specific engine requested
    if target_engine is None and use_cache and is_cache_enabled():
        cached_factory = _get_cached_session_factory()
        if cached_factory:
            try:
                return cached_factory(use_cache=True)
            except Exception as e:
                # Log the error and fall back
                import logging
                logging.warning(f"Failed to create cached session: {e}")
    
    # If no engine specified, try to get from cache manager first, then global
    if target_engine is None:
        cache_manager = get_cache_manager()
        if cache_manager and use_cache:
            # Use cache manager's local engine for reads
            target_engine = cache_manager.local_engine
        else:
            # Fall back to global engine
            target_engine = globals().get('engine')
    
    if target_engine is None:
        return None
    
    # Create direct session
    try:
        # Try to create a connection to verify engine is valid
        with target_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return sessionmaker(
            bind=target_engine,
            expire_on_commit=False,  # Prevent stale data issues
            autoflush=True,  # Enable automatic flushing
            autocommit=False  # Keep transactions explicit
        )()
    except Exception:
        return None

