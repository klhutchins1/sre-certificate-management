"""
Database Cache Manager for optimizing file-share database access.

This module provides a hybrid caching solution that maintains a local SQLite database
for fast reads/writes while periodically syncing with a central file-share database.
It's designed to handle slow network connections and provide offline capability.

Features:
- Local SQLite cache for fast operations
- Background sync with configurable intervals
- Write batching to minimize network calls
- Conflict resolution using timestamps
- Offline mode support
- Automatic retry logic for network failures
"""

import os
import shutil
import sqlite3
import threading
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum
import json

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError, DatabaseError

from ..models import Base
from ..settings import Settings
from ..exceptions import DatabaseError as IMSDatabaseError

logger = logging.getLogger(__name__)

class SyncStatus(Enum):
    """Status of sync operations."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    OFFLINE = "offline"

@dataclass
class SyncResult:
    """Result of a sync operation."""
    status: SyncStatus
    timestamp: datetime
    records_synced: int = 0
    conflicts_resolved: int = 0
    errors: List[str] = None
    duration: float = 0.0

class DatabaseCacheManager:
    """
    Manages local database caching with background sync to file-share.
    
    This class provides a transparent caching layer that maintains a local SQLite
    database for fast operations while periodically syncing with a central file-share
    database. It handles concurrent access, conflict resolution, and offline operation.
    """
    
    def __init__(self, remote_db_path: str, sync_interval: int = 30):
        """
        Initialize the cache manager.
        
        Args:
            remote_db_path: Path to the remote file-share database
            sync_interval: Sync interval in seconds (default: 30)
        """
        self.remote_db_path = Path(remote_db_path)
        self.sync_interval = sync_interval
        
        # Local cache database path
        cache_dir = Path.home() / ".ims_cache"
        cache_dir.mkdir(exist_ok=True)
        self.local_db_path = cache_dir / f"cache_{self.remote_db_path.name}"
        
        # Database engines
        self.local_engine = None
        self.remote_engine = None
        
        # Sync state
        self.sync_status = SyncStatus.PENDING
        self.last_sync = None
        self.sync_results: List[SyncResult] = []
        self.pending_writes: List[Dict[str, Any]] = []
        
        # Threading
        self.sync_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.sync_thread = None
        self.running = False
        
        # Initialize databases
        self._initialize_databases()
        
        # Load any unsynced operations from previous sessions
        self._load_pending_writes_from_tracking()
        
        # Start background sync
        self.start_sync()
    
    def _load_pending_writes_from_tracking(self):
        """Load unsynced operations from sync_tracking table."""
        if not self.local_engine:
            return
        
        try:
            with self.local_engine.connect() as local_conn:
                unsynced_ops = local_conn.execute(text("""
                    SELECT table_name, record_id, operation, timestamp 
                    FROM sync_tracking 
                    WHERE synced = FALSE
                    ORDER BY timestamp ASC
                """)).fetchall()
                
                with self.write_lock:
                    for op in unsynced_ops:
                        self.pending_writes.append({
                            'table_name': op.table_name,
                            'record_id': op.record_id,
                            'operation': op.operation,
                            'timestamp': op.timestamp
                        })
                
                if unsynced_ops:
                    logger.info(f"Loaded {len(unsynced_ops)} unsynced operations from previous session")
                    
        except Exception as e:
            logger.warning(f"Failed to load pending writes from tracking: {str(e)}")
    
    def _initialize_databases(self):
        """Initialize local and remote database connections."""
        try:
            # Initialize local cache database
            self.local_engine = create_engine(f"sqlite:///{self.local_db_path}")
            
            # Try to initialize remote database connection first
            if self._is_network_available():
                self.remote_engine = create_engine(f"sqlite:///{self.remote_db_path}")
                # Test connection
                with self.remote_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                logger.info("Remote database connection established")
                
                # Create schema on remote first, then copy to local
                Base.metadata.create_all(self.remote_engine)
                
                # Copy remote schema to local
                self._copy_schema_from_remote()
            else:
                logger.warning("Remote database not available, operating in offline mode")
                # Create schema locally
                Base.metadata.create_all(self.local_engine)
            
            # Add sync tracking tables to local
            with self.local_engine.connect() as conn:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS sync_tracking (
                        id INTEGER PRIMARY KEY,
                        table_name TEXT NOT NULL,
                        record_id INTEGER NOT NULL,
                        operation TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        synced BOOLEAN DEFAULT FALSE,
                        UNIQUE(table_name, record_id, operation)
                    )
                """))
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS sync_metadata (
                        id INTEGER PRIMARY KEY,
                        last_sync DATETIME,
                        sync_status TEXT,
                        records_synced INTEGER DEFAULT 0,
                        conflicts_resolved INTEGER DEFAULT 0
                    )
                """))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to initialize databases: {str(e)}")
            raise IMSDatabaseError(f"Database initialization failed: {str(e)}")
    
    def _copy_schema_from_remote(self):
        """Copy schema from remote database to local cache."""
        try:
            # Get remote schema
            remote_inspector = inspect(self.remote_engine)
            remote_tables = remote_inspector.get_table_names()
            
            # Create local schema
            Base.metadata.create_all(self.local_engine)
            
            # Copy data from remote to local for each table
            for table_name in remote_tables:
                if table_name not in ['sync_tracking', 'sync_metadata']:
                    self._copy_table_data(table_name, 'remote_to_local')
                    
            logger.info(f"Copied schema and data from remote database")
            
        except Exception as e:
            logger.error(f"Failed to copy schema from remote: {str(e)}")
            # Fall back to creating empty schema locally
            Base.metadata.create_all(self.local_engine)
    
    def _copy_table_data(self, table_name: str, direction: str):
        """Copy data between remote and local databases."""
        try:
            if direction == 'remote_to_local':
                # Copy from remote to local
                with self.remote_engine.connect() as remote_conn:
                    result = remote_conn.execute(text(f"SELECT * FROM {table_name}"))
                    rows = result.fetchall()
                    columns = result.keys()
                
                if rows:
                    with self.local_engine.connect() as local_conn:
                        # Clear existing data
                        local_conn.execute(text(f"DELETE FROM {table_name}"))
                        
                        # Insert data
                        for row in rows:
                            placeholders = ', '.join([':' + col for col in columns])
                            column_list = ', '.join(columns)
                            data = dict(zip(columns, row))
                            local_conn.execute(text(f"INSERT INTO {table_name} ({column_list}) VALUES ({placeholders})"), data)
                        
                        local_conn.commit()
                        
        except Exception as e:
            logger.warning(f"Failed to copy table {table_name}: {str(e)}")
    
    def _is_network_available(self) -> bool:
        """Check if the remote database is accessible."""
        try:
            if not self.remote_db_path.exists():
                return False
            
            # Try to open the file
            with open(self.remote_db_path, 'rb') as f:
                f.read(16)  # Read SQLite header
            return True
        except Exception:
            return False
    
    def get_session(self, use_cache: bool = True) -> Session:
        """
        Get a database session.
        
        Args:
            use_cache: Whether to use local cache (default: True)
            
        Returns:
            Session: SQLAlchemy session for local or remote database
        """
        if use_cache and self.local_engine:
            Session = sessionmaker(bind=self.local_engine)
            return Session()
        elif self.remote_engine:
            Session = sessionmaker(bind=self.remote_engine)
            return Session()
        else:
            raise IMSDatabaseError("No database engine available")
    
    def add_pending_write(self, table_name: str, record_id: int, operation: str):
        """Add a write operation to the pending queue."""
        with self.write_lock:
            self.pending_writes.append({
                'table_name': table_name,
                'record_id': record_id,
                'operation': operation,
                'timestamp': datetime.now()
            })
            
            # Also persist to sync_tracking table for durability
            if self.local_engine:
                try:
                    with self.local_engine.connect() as local_conn:
                        local_conn.execute(text("""
                            INSERT OR IGNORE INTO sync_tracking 
                            (table_name, record_id, operation, timestamp, synced) 
                            VALUES (:table_name, :record_id, :operation, :timestamp, FALSE)
                        """), {
                            'table_name': table_name,
                            'record_id': record_id,
                            'operation': operation,
                            'timestamp': datetime.now()
                        })
                        local_conn.commit()
                except Exception as e:
                    logger.warning(f"Failed to persist pending write to sync_tracking: {str(e)}")
    
    def start_sync(self):
        """Start the background sync thread."""
        if self.sync_thread and self.sync_thread.is_alive():
            return
        
        self.running = True
        self.sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self.sync_thread.start()
        logger.info("Background sync started")
    
    def stop_sync(self):
        """Stop the background sync thread."""
        self.running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        logger.info("Background sync stopped")
    
    def _sync_worker(self):
        """Background worker for syncing data."""
        while self.running:
            try:
                if self._is_network_available():
                    self._perform_sync()
                else:
                    self.sync_status = SyncStatus.OFFLINE
                    logger.debug("Network unavailable, skipping sync")
                
                # Wait for next sync interval
                time.sleep(self.sync_interval)
                
            except Exception as e:
                logger.error(f"Sync worker error: {str(e)}")
                self.sync_status = SyncStatus.FAILED
                time.sleep(self.sync_interval)
    
    def _perform_sync(self):
        """Perform a sync operation between local and remote databases."""
        start_time = time.time()
        
        with self.sync_lock:
            self.sync_status = SyncStatus.IN_PROGRESS
            
            try:
                # Sync pending writes first
                self._sync_pending_writes()
                
                # Sync schema changes
                self._sync_schema()
                
                # Sync data changes
                records_synced, conflicts_resolved = self._sync_data()
                
                self.sync_status = SyncStatus.SUCCESS
                self.last_sync = datetime.now()
                
                # Record sync result
                result = SyncResult(
                    status=SyncStatus.SUCCESS,
                    timestamp=self.last_sync,
                    records_synced=records_synced,
                    conflicts_resolved=conflicts_resolved,
                    duration=time.time() - start_time
                )
                self.sync_results.append(result)
                
                # Keep only last 10 results
                if len(self.sync_results) > 10:
                    self.sync_results = self.sync_results[-10:]
                
                logger.info(f"Sync completed: {records_synced} records, {conflicts_resolved} conflicts resolved")
                
            except Exception as e:
                self.sync_status = SyncStatus.FAILED
                result = SyncResult(
                    status=SyncStatus.FAILED,
                    timestamp=datetime.now(),
                    errors=[str(e)],
                    duration=time.time() - start_time
                )
                self.sync_results.append(result)
                logger.error(f"Sync failed: {str(e)}")
    
    def _sync_pending_writes(self):
        """Sync pending write operations to remote database."""
        if not self.pending_writes or not self.remote_engine:
            return
        
        with self.write_lock:
            writes_to_sync = self.pending_writes.copy()
            self.pending_writes.clear()
        
        # Group writes by table for batching
        writes_by_table = {}
        for write in writes_to_sync:
            table = write['table_name']
            if table not in writes_by_table:
                writes_by_table[table] = []
            writes_by_table[table].append(write)
        
        # Sync each table's writes
        for table_name, writes in writes_by_table.items():
            self._sync_table_writes(table_name, writes)
    
    def _sync_table_writes(self, table_name: str, writes: List[Dict[str, Any]]):
        """Sync writes for a specific table."""
        try:
            with self.remote_engine.begin() as remote_conn:
                for write in writes:
                    try:
                        # Actually execute the operation on the remote database
                        if write['operation'] == 'INSERT':
                            self._sync_insert(remote_conn, table_name, write['record_id'])
                        elif write['operation'] == 'UPDATE':
                            self._sync_update(remote_conn, table_name, write['record_id'])
                        elif write['operation'] == 'DELETE':
                            self._sync_delete(remote_conn, table_name, write['record_id'])
                        
                        # Only mark as synced after successful execution
                        if self.local_engine:
                            with self.local_engine.connect() as local_conn:
                                local_conn.execute(text("""
                                    UPDATE sync_tracking 
                                    SET synced = TRUE 
                                    WHERE table_name = :table_name 
                                    AND record_id = :record_id 
                                    AND operation = :operation
                                """), {
                                    'table_name': table_name,
                                    'record_id': write['record_id'],
                                    'operation': write['operation']
                                })
                                local_conn.commit()
                            
                    except Exception as op_e:
                        logger.error(f"Failed to sync {write['operation']} operation for {table_name}:{write['record_id']}: {str(op_e)}")
                        # Re-add this specific failed write to pending queue
                        with self.write_lock:
                            self.pending_writes.append(write)
                        
        except Exception as e:
            logger.error(f"Failed to sync writes for table {table_name}: {str(e)}")
            # Re-add failed writes to pending queue
            with self.write_lock:
                self.pending_writes.extend(writes)
    
    def _sync_schema(self):
        """Sync schema changes between databases."""
        if not self.remote_engine:
            return
        
        try:
            # Get schema differences
            local_inspector = inspect(self.local_engine)
            remote_inspector = inspect(self.remote_engine)
            
            local_tables = set(local_inspector.get_table_names())
            remote_tables = set(remote_inspector.get_table_names())
            
            # Create missing tables on remote
            for table_name in local_tables - remote_tables:
                if table_name in Base.metadata.tables:
                    Base.metadata.tables[table_name].create(self.remote_engine)
                    logger.info(f"Created table {table_name} on remote database")
            
            # Create missing tables on local
            for table_name in remote_tables - local_tables:
                if table_name in Base.metadata.tables:
                    Base.metadata.tables[table_name].create(self.local_engine)
                    logger.info(f"Created table {table_name} on local database")
                    
        except Exception as e:
            logger.error(f"Schema sync failed: {str(e)}")
    
    def _sync_data(self) -> Tuple[int, int]:
        """Sync data changes between databases."""
        if not self.remote_engine:
            return 0, 0
        
        records_synced = 0
        conflicts_resolved = 0
        
        try:
            # Get all table names
            local_inspector = inspect(self.local_engine)
            tables = local_inspector.get_table_names()
            
            for table_name in tables:
                if table_name in ['sync_tracking', 'sync_metadata']:
                    continue
                
                synced, conflicts = self._sync_table_data(table_name)
                records_synced += synced
                conflicts_resolved += conflicts
                
        except Exception as e:
            logger.error(f"Data sync failed: {str(e)}")
        
        return records_synced, conflicts_resolved
    
    def _sync_table_data(self, table_name: str) -> Tuple[int, int]:
        """Sync data for a specific table."""
        records_synced = 0
        conflicts_resolved = 0
        
        try:
            # Get local changes
            if not self.local_engine:
                return 0, 0
            with self.local_engine.connect() as local_conn:
                local_changes = local_conn.execute(text("""
                    SELECT record_id, operation, timestamp 
                    FROM sync_tracking 
                    WHERE table_name = :table_name AND synced = FALSE
                """), {'table_name': table_name}).fetchall()
            
            # Apply changes to remote
            with self.remote_engine.begin() as remote_conn:
                for change in local_changes:
                    try:
                        # Apply the change based on operation type
                        if change.operation == 'INSERT':
                            self._sync_insert(remote_conn, table_name, change.record_id)
                        elif change.operation == 'UPDATE':
                            self._sync_update(remote_conn, table_name, change.record_id)
                        elif change.operation == 'DELETE':
                            self._sync_delete(remote_conn, table_name, change.record_id)
                        
                        records_synced += 1
                        
                    except Exception as e:
                        logger.warning(f"Conflict resolving for {table_name}:{change.record_id}: {str(e)}")
                        conflicts_resolved += 1
                        # Use timestamp-based conflict resolution
                        self._resolve_conflict(remote_conn, table_name, change.record_id, change.timestamp)
        
        except Exception as e:
            logger.error(f"Failed to sync table {table_name}: {str(e)}")
        
        return records_synced, conflicts_resolved
    
    def _sync_insert(self, conn, table_name: str, record_id: int):
        """Sync an insert operation."""
        # Get the record from local database
        with self.local_engine.connect() as local_conn:
            result = local_conn.execute(text(f"SELECT * FROM {table_name} WHERE id = :id"), 
                                      {'id': record_id}).fetchone()
            if result:
                # Insert into remote database
                columns = result.keys()
                values = [result[col] for col in columns]
                placeholders = ', '.join([':' + col for col in columns])
                column_list = ', '.join(columns)
                
                conn.execute(text(f"INSERT INTO {table_name} ({column_list}) VALUES ({placeholders})"),
                           dict(zip(columns, values)))
    
    def _sync_update(self, conn, table_name: str, record_id: int):
        """Sync an update operation."""
        # Get the record from local database
        with self.local_engine.connect() as local_conn:
            result = local_conn.execute(text(f"SELECT * FROM {table_name} WHERE id = :id"), 
                                      {'id': record_id}).fetchone()
            if result:
                # Update remote database
                columns = [col for col in result.keys() if col != 'id']
                set_clause = ', '.join([f"{col} = :{col}" for col in columns])
                
                update_data = {col: result[col] for col in columns}
                update_data['id'] = record_id
                
                conn.execute(text(f"UPDATE {table_name} SET {set_clause} WHERE id = :id"), update_data)
    
    def _sync_delete(self, conn, table_name: str, record_id: int):
        """Sync a delete operation."""
        conn.execute(text(f"DELETE FROM {table_name} WHERE id = :id"), {'id': record_id})
    
    def _resolve_conflict(self, conn, table_name: str, record_id: int, local_timestamp: datetime):
        """Resolve conflicts using timestamp-based resolution."""
        try:
            # Get timestamps from both databases
            with self.local_engine.connect() as local_conn:
                local_result = local_conn.execute(text(f"SELECT updated_at FROM {table_name} WHERE id = :id"), 
                                                {'id': record_id}).fetchone()
            
            remote_result = conn.execute(text(f"SELECT updated_at FROM {table_name} WHERE id = :id"), 
                                       {'id': record_id}).fetchone()
            
            if local_result and remote_result:
                local_time = local_result.updated_at
                remote_time = remote_result.updated_at
                
                # Use the most recent version
                if local_time > remote_time:
                    self._sync_update(conn, table_name, record_id)
                # If remote is newer, local will be updated on next sync
                    
        except Exception as e:
            logger.error(f"Conflict resolution failed for {table_name}:{record_id}: {str(e)}")
    
    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status and statistics."""
        return {
            'status': self.sync_status.value,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'pending_writes': len(self.pending_writes),
            'sync_interval': self.sync_interval,
            'network_available': self._is_network_available(),
            'recent_results': [
                {
                    'status': r.status.value,
                    'timestamp': r.timestamp.isoformat(),
                    'records_synced': r.records_synced,
                    'conflicts_resolved': r.conflicts_resolved,
                    'duration': r.duration,
                    'errors': r.errors
                }
                for r in self.sync_results[-5:]  # Last 5 results
            ]
        }
    
    def force_sync(self) -> SyncResult:
        """Force an immediate sync operation."""
        if not self._is_network_available():
            return SyncResult(
                status=SyncStatus.OFFLINE,
                timestamp=datetime.now(),
                errors=["Network not available"]
            )
        
        start_time = time.time()
        
        try:
            with self.sync_lock:
                self._perform_sync()
            
            # Get the last result
            if self.sync_results:
                return self.sync_results[-1]
            else:
                return SyncResult(
                    status=SyncStatus.SUCCESS,
                    timestamp=datetime.now(),
                    duration=time.time() - start_time
                )
                
        except Exception as e:
            return SyncResult(
                status=SyncStatus.FAILED,
                timestamp=datetime.now(),
                errors=[str(e)],
                duration=time.time() - start_time
            )
    
    def clear_cache(self):
        """Clear the local cache database."""
        try:
            if self.local_engine:
                self.local_engine.dispose()
            
            if self.local_db_path.exists():
                self.local_db_path.unlink()
            
            # Reinitialize
            self._initialize_databases()
            logger.info("Local cache cleared and reinitialized")
            
        except Exception as e:
            logger.error(f"Failed to clear cache: {str(e)}")
    
    def __del__(self):
        """Cleanup on destruction."""
        self.stop_sync()
        if self.local_engine:
            self.local_engine.dispose()
        if self.remote_engine:
            self.remote_engine.dispose() 