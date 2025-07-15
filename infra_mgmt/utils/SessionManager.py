from sqlalchemy.orm import sessionmaker
import sys

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
        
        # Try to use cache manager's session if available
        try:
            from ..db.engine import get_cache_manager, is_cache_enabled
            from ..db.session import get_session
            
            if is_cache_enabled():
                # Use the cache-aware session creation
                self.session = get_session(engine_param=self.engine, use_cache=True)
                if self.session:
                    return self.session
        except Exception as e:
            # Log warning but continue with fallback
            import logging
            logging.warning(f"Failed to create cache-aware session: {e}")
        
        # Fallback to direct session creation
        self.session = sessionmaker(bind=self.engine, expire_on_commit=False)()
        
        # Mark session for tracking even in fallback mode
        try:
            self.session._ims_cache_tracking = True
        except Exception:
            pass
            
        return self.session

    def __exit__(self, exc_type, *_):
        if self.session:
            if exc_type is not None:
                self.session.rollback()
            self.session.close()

