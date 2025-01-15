from sqlalchemy import create_engine
from cert_scanner.models import Base
import os
import time
import sqlite3
from sqlalchemy.pool import NullPool
import platform
if platform.system() == 'Windows':
    import msvcrt
else:
    import fcntl

# Use NullPool to prevent connection pooling issues
engine = create_engine('sqlite:///certificates.db', poolclass=NullPool)

class FileLock:
    def __init__(self, lock_file):
        self.lock_file = lock_file
        self.fd = None

    def __enter__(self):
        if platform.system() == 'Windows':
            while True:
                try:
                    self.fd = os.open(self.lock_file, os.O_RDWR | os.O_CREAT | os.O_EXCL)
                    break
                except OSError:
                    time.sleep(0.1)
        else:
            self.fd = open(self.lock_file, 'w')
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd:
            if platform.system() == 'Windows':
                os.close(self.fd)
                os.unlink(self.lock_file)
            else:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                self.fd.close()

def with_db_lock(func):
    """Decorator to ensure database operations are atomic"""
    def wrapper(*args, **kwargs):
        lock_file = 'db.lock'
        with FileLock(lock_file):
            return func(*args, **kwargs)
    return wrapper

@with_db_lock
def check_schema_version():
    """Check if the database schema matches our models"""
    try:
        # Try to get table info from the database
        conn = sqlite3.connect('certificates.db')
        cursor = conn.cursor()
        
        # Get list of tables and their schemas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing_tables = set(row[0] for row in cursor.fetchall())
        
        # Get expected tables from our models
        expected_tables = set(table.name for table in Base.metadata.tables.values())
        
        conn.close()
        return existing_tables == expected_tables
    except Exception:
        return False

@with_db_lock
def reset_db():
    """Delete and recreate the database"""
    try:
        # Try to dispose of any existing connections
        engine.dispose()
        
        # Drop all tables if they exist
        Base.metadata.drop_all(engine)
        
        # Create new tables
        Base.metadata.create_all(engine)
        print("Database reset completed")
        return True
    except Exception as e:
        print(f"Error creating database: {e}")
        return False

@with_db_lock
def init_db():
    """Initialize the database if it doesn't exist"""
    try:
        if not os.path.exists('certificates.db'):
            Base.metadata.create_all(engine)
            print("New database created")
            return True
        
        if not check_schema_version():
            print("Schema mismatch, resetting database")
            return reset_db()
        
        print("Database schema is up to date")
        return True
    except Exception as e:
        print(f"Error initializing database: {e}")
        return False

if __name__ == "__main__":
    init_db() 