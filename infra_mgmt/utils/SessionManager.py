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
        self.session = sessionmaker(bind=self.engine, expire_on_commit=False)()
        return self.session

    def __exit__(self, exc_type, *_):
        if self.session:
            if exc_type is not None:
                self.session.rollback()
            self.session.close()

