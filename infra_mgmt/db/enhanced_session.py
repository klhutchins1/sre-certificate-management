"""
Enhanced Session Manager with caching support.

This module provides an enhanced session manager that integrates with the cache manager
to provide transparent caching for database operations. It automatically tracks write
operations and manages the sync process.
"""

import logging
from contextlib import contextmanager
from typing import Optional, Any
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import event
from sqlalchemy.exc import SQLAlchemyError

from .cache_manager import DatabaseCacheManager
from ..exceptions import DatabaseError

logger = logging.getLogger(__name__)

class EnhancedSessionManager:
    """
    Enhanced session manager with caching and sync support.
    
    This class provides a transparent interface for database operations that
    automatically uses local caching when available and tracks write operations
    for background sync.
    """
    
    def __init__(self, cache_manager: DatabaseCacheManager):
        """
        Initialize the enhanced session manager.
        
        Args:
            cache_manager: The database cache manager instance
        """
        self.cache_manager = cache_manager
        self._setup_session_events()
    
    def _setup_session_events(self):
        """Setup SQLAlchemy event listeners for tracking write operations."""
        @event.listens_for(Session, 'after_flush')
        def after_flush(session, context):
            """Track write operations after flush."""
            try:
                # Only track if this is a cached session (to avoid duplicate tracking)
                if hasattr(session, '_ims_cache_tracking') or True:  # Track all for now
                    for obj in session.new:
                        self._track_write_operation(obj, 'INSERT')
                        logger.debug(f"Tracked INSERT for {obj.__class__.__name__}")
                    for obj in session.dirty:
                        self._track_write_operation(obj, 'UPDATE') 
                        logger.debug(f"Tracked UPDATE for {obj.__class__.__name__}")
                    for obj in session.deleted:
                        self._track_write_operation(obj, 'DELETE')
                        logger.debug(f"Tracked DELETE for {obj.__class__.__name__}")
            except Exception as e:
                logger.warning(f"Failed to track write operation: {str(e)}")
        
        @event.listens_for(Session, 'after_commit')
        def after_commit(session):
            """Log commit events for debugging."""
            logger.debug(f"Session committed - tracking active: {getattr(session, '_ims_cache_tracking', False)}")
    
    def _track_write_operation(self, obj: Any, operation: str):
        """Track a write operation for sync."""
        try:
            table_name = obj.__tablename__
            record_id = getattr(obj, 'id', None)
            
            if table_name and record_id:
                self.cache_manager.add_pending_write(table_name, record_id, operation)
                
        except Exception as e:
            logger.warning(f"Failed to track {operation} operation: {str(e)}")
    
    @contextmanager
    def session_scope(self, use_cache: bool = True):
        """
        Provide a transactional scope around a series of operations.
        
        Args:
            use_cache: Whether to use local cache (default: True)
            
        Yields:
            Session: SQLAlchemy session for database operations
            
        Raises:
            DatabaseError: If session creation fails
        """
        session = None
        try:
            session = self.cache_manager.get_session(use_cache=use_cache)
            yield session
            session.commit()
        except Exception as e:
            if session:
                session.rollback()
            logger.error(f"Session operation failed: {str(e)}")
            raise DatabaseError(f"Database operation failed: {str(e)}")
        finally:
            if session:
                session.close()
    
    def get_session(self, use_cache: bool = True) -> Session:
        """
        Get a database session.
        
        Args:
            use_cache: Whether to use local cache (default: True)
            
        Returns:
            Session: SQLAlchemy session for database operations
            
        Raises:
            DatabaseError: If session creation fails
        """
        try:
            return self.cache_manager.get_session(use_cache=use_cache)
        except Exception as e:
            logger.error(f"Failed to get session: {str(e)}")
            raise DatabaseError(f"Failed to create database session: {str(e)}")
    
    def force_sync(self):
        """Force an immediate sync operation."""
        return self.cache_manager.force_sync()
    
    def get_sync_status(self):
        """Get current sync status."""
        return self.cache_manager.get_sync_status()
    
    def clear_cache(self):
        """Clear the local cache."""
        self.cache_manager.clear_cache()

class CachedSessionFactory:
    """
    Factory for creating cached database sessions.
    
    This class provides a convenient way to create database sessions that
    automatically use caching when available.
    """
    
    def __init__(self, cache_manager: DatabaseCacheManager):
        """
        Initialize the session factory.
        
        Args:
            cache_manager: The database cache manager instance
        """
        self.cache_manager = cache_manager
        self.session_manager = EnhancedSessionManager(cache_manager)
    
    def __call__(self, use_cache: bool = True) -> Session:
        """
        Create a new database session.
        
        Args:
            use_cache: Whether to use local cache (default: True)
            
        Returns:
            Session: SQLAlchemy session
        """
        session = self.session_manager.get_session(use_cache=use_cache)
        if session:
            # Mark session for tracking
            session._ims_cache_tracking = True
        return session
    
    @contextmanager
    def session_scope(self, use_cache: bool = True):
        """
        Provide a transactional scope around a series of operations.
        
        Args:
            use_cache: Whether to use local cache (default: True)
            
        Yields:
            Session: SQLAlchemy session for database operations
        """
        with self.session_manager.session_scope(use_cache=use_cache) as session:
            yield session
    
    def force_sync(self):
        """Force an immediate sync operation."""
        return self.cache_manager.force_sync()
    
    def get_sync_status(self):
        """Get current sync status."""
        return self.cache_manager.get_sync_status() 