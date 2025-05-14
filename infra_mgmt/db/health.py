"""
Database health checks for IMS.

Handles:
- Health validation
- Corruption checks
"""

import sqlite3

from sqlalchemy import create_engine, inspect, text

from infra_mgmt.models import Base
from ..settings import Settings
from .engine import normalize_path

def check_database():
    """
    Check if the database exists and is properly initialized.
    
    Returns:
        bool: True if database is valid and accessible, False otherwise
    """
    try:
        settings = Settings()
        db_path = normalize_path(settings.get("paths.database", "data/certificates.db"))
        print(f"[DEBUG] Checking database path: {db_path}")
        print(f"[DEBUG] File exists: {db_path.exists()}")
        if db_path.exists():
            print(f"[DEBUG] File size: {db_path.stat().st_size}")
            with open(db_path, 'rb') as f:
                header = f.read(16)
                print(f"[DEBUG] File header: {header}")
        
        if not db_path.exists():
            return False
        
        # Check file size and header for valid SQLite format
        if db_path.stat().st_size < 100:
            return False
        with open(db_path, 'rb') as f:
            if f.read(16) != b'SQLite format 3\x00':
                return False
        
        # Try to open and validate the database
        try:
            # First try to open with sqlite3 to check if it's a valid database
            with sqlite3.connect(str(db_path)) as conn:
                # Try to read some basic information to validate the database
                cursor = conn.cursor()
                cursor.execute("PRAGMA page_count")
                cursor.execute("PRAGMA page_size")
            
            # If we get here, it's a valid SQLite database
            engine = create_engine(f"sqlite:///{db_path}")
            with engine.connect() as conn:
                # Check if we can execute a simple query
                conn.execute(text("SELECT 1"))
                
                # Check if required tables exist
                inspector = inspect(engine)
                existing_tables = inspector.get_table_names()
                required_tables = set(Base.metadata.tables.keys())
                
                if not required_tables.issubset(set(existing_tables)):
                    return False
            
            engine.dispose()
            return True
        except Exception:
            return False
    except Exception:
        return False


