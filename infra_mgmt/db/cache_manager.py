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
        self.db_operation_queue = []
        self.db_queue_lock = threading.Lock()
        self.sync_thread = None
        self.db_worker_thread = None
        self.running = False
        
        # Debug tracking
        self.sync_counter = 0
        self.last_sync_caller = None
        
        # Enhanced session manager for tracking
        self.enhanced_session_manager = None
        
        # Initialize databases
        self._initialize_databases()
        
        # Initialize enhanced session manager after databases are ready
        self._setup_enhanced_session_manager()
        
        # Load any unsynced operations from previous sessions
        self._load_pending_writes_from_tracking()
        
        # Start background sync and database worker
        self.start_sync()
        self.start_db_worker()
    
    def _setup_enhanced_session_manager(self):
        """Setup the enhanced session manager for operation tracking."""
        try:
            from .enhanced_session import EnhancedSessionManager
            self.enhanced_session_manager = EnhancedSessionManager(self)
            logger.info("Enhanced session manager initialized for operation tracking")
        except Exception as e:
            logger.warning(f"Failed to initialize enhanced session manager: {e}")
    
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
            # Initialize local cache database with WAL mode and connection pooling
            self.local_engine = create_engine(
                f"sqlite:///{self.local_db_path}",
                pool_pre_ping=True,
                pool_recycle=300,
                pool_timeout=10,
                max_overflow=10,
                connect_args={
                    "check_same_thread": False,
                    "timeout": 30,
                    "isolation_level": None
                }
            )
            
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
            
            # Add sync tracking tables to local and enable WAL mode
            with self.local_engine.connect() as conn:
                # Enable WAL mode for better concurrent access
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA synchronous=NORMAL"))
                conn.execute(text("PRAGMA cache_size=10000"))
                conn.execute(text("PRAGMA temp_store=memory"))
                
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
            SessionClass = sessionmaker(bind=self.local_engine)
            session = SessionClass()
            # Mark session for tracking
            session._ims_cache_tracking = True
            return session
        elif self.remote_engine:
            SessionClass = sessionmaker(bind=self.remote_engine)
            session = SessionClass()
            # Mark session for tracking
            session._ims_cache_tracking = True
            return session
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
                self._queue_database_operation('persist_sync_tracking', table_name, record_id, operation)
    
    def _retry_database_operation(self, operation_func, *args, max_retries=5, **kwargs):
        """Retry database operations with exponential backoff."""
        import time
        
        for attempt in range(max_retries):
            try:
                return operation_func(*args, **kwargs)
            except Exception as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 0.05  # 0.05, 0.1, 0.2, 0.4, 0.8 seconds
                    logger.debug(f"Database locked, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.warning(f"Database operation failed after {attempt + 1} attempts: {str(e)}")
                    break
    
    def _persist_sync_tracking(self, table_name: str, record_id: int, operation: str):
        """Persist operation to sync_tracking table."""
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
    
    def _mark_sync_completed(self, table_name: str, record_id: int, operation: str):
        """Mark an operation as completed in sync_tracking table."""
        with self.local_engine.connect() as local_conn:
            local_conn.execute(text("""
                UPDATE sync_tracking 
                SET synced = TRUE 
                WHERE table_name = :table_name 
                AND record_id = :record_id 
                AND operation = :operation
            """), {
                'table_name': table_name,
                'record_id': record_id,
                'operation': operation
            })
            local_conn.commit()
    
    def _queue_database_operation(self, operation_type: str, *args, **kwargs):
        """Queue a database operation for serial execution."""
        with self.db_queue_lock:
            self.db_operation_queue.append({
                'operation_type': operation_type,
                'args': args,
                'kwargs': kwargs,
                'timestamp': datetime.now()
            })
    
    def start_db_worker(self):
        """Start the database operation worker thread."""
        if self.db_worker_thread and self.db_worker_thread.is_alive():
            return
        
        self.db_worker_thread = threading.Thread(target=self._db_worker, daemon=True)
        self.db_worker_thread.start()
        logger.info("Database operation worker started")
    
    def _db_worker(self):
        """Background worker for processing database operations."""
        while self.running:
            try:
                operations_to_process = []
                
                # Get operations from queue
                with self.db_queue_lock:
                    if self.db_operation_queue:
                        operations_to_process = self.db_operation_queue.copy()
                        self.db_operation_queue.clear()
                
                # Process operations
                for operation in operations_to_process:
                    try:
                        self._execute_database_operation(operation)
                    except Exception as e:
                        logger.error(f"Failed to execute database operation {operation['operation_type']}: {str(e)}")
                
                # Sleep briefly to prevent tight loop
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Database worker error: {str(e)}")
                time.sleep(1)
    
    def _execute_database_operation(self, operation):
        """Execute a single database operation with retry logic."""
        operation_type = operation['operation_type']
        args = operation['args']
        kwargs = operation['kwargs']
        
        if operation_type == 'persist_sync_tracking':
            self._retry_database_operation(self._persist_sync_tracking, *args, **kwargs)
        elif operation_type == 'mark_sync_completed':
            self._retry_database_operation(self._mark_sync_completed, *args, **kwargs)
        else:
            logger.warning(f"Unknown database operation type: {operation_type}")
    
    def _wait_for_database_queue(self, max_wait_time=2.0):
        """Wait for database operation queue to be processed."""
        import time
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            with self.db_queue_lock:
                queue_size = len(self.db_operation_queue)
            
            if queue_size == 0:
                break
            
            logger.debug(f"Waiting for database queue to clear ({queue_size} operations)")
            time.sleep(0.1)
        
        # Final check
        with self.db_queue_lock:
            final_queue_size = len(self.db_operation_queue)
        
        if final_queue_size > 0:
            logger.warning(f"Database queue still has {final_queue_size} operations after waiting")
    
    def start_sync(self):
        """Start the background sync thread."""
        # Stop any existing sync thread first
        if self.sync_thread and self.sync_thread.is_alive():
            logger.warning("Sync thread already running, not starting another")
            return
        
        self.running = True
        self.sync_thread = threading.Thread(target=self._sync_worker, daemon=True, name="CacheSync")
        self.sync_thread.start()
        logger.info(f"Background sync started (thread: {self.sync_thread.name})")
    
    def stop_sync(self):
        """Stop the background sync and database worker threads."""
        self.running = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        if self.db_worker_thread:
            self.db_worker_thread.join(timeout=5)
        logger.info("Background sync and database worker stopped")
    
    def _sync_worker(self):
        """Background worker for syncing data."""
        last_sync_time = 0
        min_sync_interval = 5  # Minimum 5 seconds between syncs
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check if enough time has passed since last sync
                if current_time - last_sync_time < min_sync_interval:
                    time.sleep(0.5)
                    continue
                
                if self._is_network_available():
                    # Check if there's anything to sync before running
                    has_pending_writes = len(self.pending_writes) > 0
                    
                    with self.db_queue_lock:
                        has_queue_operations = len(self.db_operation_queue) > 0
                    
                    # Only run sync if there's something to sync or it's been a while
                    if has_pending_writes or has_queue_operations or (current_time - last_sync_time > self.sync_interval):
                        self._perform_sync("background_worker")
                        last_sync_time = current_time
                    else:
                        # No work to do, sleep briefly
                        time.sleep(1)
                else:
                    if self.sync_status != SyncStatus.OFFLINE:
                        self.sync_status = SyncStatus.OFFLINE
                        logger.debug("Network unavailable, going offline")
                    time.sleep(self.sync_interval)
                
            except Exception as e:
                logger.error(f"Sync worker error: {str(e)}")
                self.sync_status = SyncStatus.FAILED
                time.sleep(self.sync_interval)
    
    def _perform_sync(self, caller="unknown"):
        """Perform a sync operation between local and remote databases."""
        import threading
        import traceback
        
        current_thread = threading.current_thread().name
        self.sync_counter += 1
        sync_id = self.sync_counter
        
        # Get caller info for debugging
        caller_info = f"{caller}:{current_thread}"
        stack = traceback.format_stack()
        caller_stack = [line.strip() for line in stack[-3:-1]]  # Get last 2 stack frames
        
        # Prevent concurrent sync operations
        if not self.sync_lock.acquire(blocking=False):
            logger.debug(f"Sync #{sync_id} already in progress, skipping (caller: {caller_info})")
            return
        
        try:
            if self.sync_status == SyncStatus.IN_PROGRESS:
                logger.debug(f"Sync #{sync_id} already in progress, skipping (caller: {caller_info})")
                return
                
            start_time = time.time()
            self.sync_status = SyncStatus.IN_PROGRESS
            self.last_sync_caller = caller_info
            logger.debug(f"Starting sync #{sync_id} (caller: {caller_info})")
            
            # Wait for database queue to be processed first
            self._wait_for_database_queue()
            
            try:
                # Sync pending writes first
                pending_writes_synced = self._sync_pending_writes()
                
                # Sync schema changes
                self._sync_schema()
                
                # Sync data changes from sync_tracking table
                tracking_synced, conflicts_resolved = self._sync_data()
                
                # Total records synced
                total_synced = pending_writes_synced + tracking_synced
                
                self.sync_status = SyncStatus.SUCCESS
                self.last_sync = datetime.now()
                
                # Record sync result
                result = SyncResult(
                    status=SyncStatus.SUCCESS,
                    timestamp=self.last_sync,
                    records_synced=total_synced,
                    conflicts_resolved=conflicts_resolved,
                    duration=time.time() - start_time
                )
                self.sync_results.append(result)
                
                # Keep only last 10 results
                if len(self.sync_results) > 10:
                    self.sync_results = self.sync_results[-10:]
                
                # Only log INFO for actual sync work, DEBUG for empty syncs
                if total_synced > 0 or conflicts_resolved > 0:
                    logger.info(f"Sync #{sync_id} completed: {total_synced} records, {conflicts_resolved} conflicts resolved (caller: {caller_info})")
                else:
                    # Don't log empty syncs at all to reduce noise
                    logger.debug(f"Sync #{sync_id} completed: {total_synced} records, {conflicts_resolved} conflicts resolved (caller: {caller_info})")
                
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
                
        finally:
            self.sync_lock.release()
    
    def _sync_pending_writes(self):
        """Sync pending write operations to remote database."""
        if not self.pending_writes or not self.remote_engine:
            return 0
        
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
        
        total_synced = 0
        # Sync each table's writes
        for table_name, writes in writes_by_table.items():
            synced_count = self._sync_table_writes(table_name, writes)
            total_synced += synced_count
        
        return total_synced
    
    def _sync_table_writes(self, table_name: str, writes: List[Dict[str, Any]]):
        """Sync writes for a specific table."""
        synced_count = 0
        failed_writes = []
        
        try:
            if not self.remote_engine:
                return 0
                
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
                        
                        synced_count += 1
                        
                        # Only mark as synced after successful execution
                        if self.local_engine:
                            self._queue_database_operation(
                                'mark_sync_completed', 
                                table_name, 
                                write['record_id'], 
                                write['operation']
                            )
                            
                    except Exception as op_e:
                        logger.error(f"Failed to sync {write['operation']} operation for {table_name}:{write['record_id']}: {str(op_e)}")
                        # Add to failed writes list
                        failed_writes.append(write)
                        
        except Exception as e:
            logger.error(f"Failed to sync writes for table {table_name}: {str(e)}")
            # Add all writes to failed list
            failed_writes.extend(writes)
        
        # Re-add failed writes to pending queue
        if failed_writes:
            with self.write_lock:
                self.pending_writes.extend(failed_writes)
        
        return synced_count
    
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
        import threading
        
        with self.db_queue_lock:
            queue_size = len(self.db_operation_queue)
        
        # Count active threads
        active_threads = threading.active_count()
        thread_names = [t.name for t in threading.enumerate()]
        
        return {
            'status': self.sync_status.value,
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'pending_writes': len(self.pending_writes),
            'database_queue_size': queue_size,
            'sync_interval': self.sync_interval,
            'network_available': self._is_network_available(),
            'active_threads': active_threads,
            'thread_names': thread_names,
            'sync_thread_alive': self.sync_thread.is_alive() if self.sync_thread else False,
            'db_worker_alive': self.db_worker_thread.is_alive() if self.db_worker_thread else False,
            'sync_counter': self.sync_counter,
            'last_sync_caller': self.last_sync_caller,
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
        logger.info("Force sync requested")
        
        try:
            # Directly call _perform_sync which has its own locking
            self._perform_sync("force_sync")
            
            # Get the last result
            if self.sync_results:
                result = self.sync_results[-1]
                logger.info(f"Force sync completed: {result.records_synced} records, {result.conflicts_resolved} conflicts")
                return result
            else:
                result = SyncResult(
                    status=SyncStatus.SUCCESS,
                    timestamp=datetime.now(),
                    duration=time.time() - start_time
                )
                logger.info("Force sync completed with no results")
                return result
                
        except Exception as e:
            result = SyncResult(
                status=SyncStatus.FAILED,
                timestamp=datetime.now(),
                errors=[str(e)],
                duration=time.time() - start_time
            )
            logger.error(f"Force sync failed: {str(e)}")
            return result
    
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