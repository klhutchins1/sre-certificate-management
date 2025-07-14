import pytest
import tempfile
import shutil
import gc
import time
import os

# Import compatibility fixes before SQLAlchemy
try:
    from infra_mgmt.compatibility import ensure_compatibility
    ensure_compatibility()
except ImportError:
    # If compatibility module not available, continue anyway
    pass

from sqlalchemy.orm import Session, close_all_sessions
from infra_mgmt.models import Base
from infra_mgmt.db.schema import migrate_database, sync_default_ignore_patterns
import logging

logger = logging.getLogger(__name__)

# Shared fixture for cleaning up temp directories
def cleanup_temp_dir(temp_dir):
    try:
        close_all_sessions()
        gc.collect()
        time.sleep(0.1)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"Warning: Failed to clean up temporary directory {temp_dir}: {e}")

@pytest.fixture
def test_db():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    engine = None
    try:
        db_url = f"sqlite:///{db_path}"
        from sqlalchemy import create_engine
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        migrate_database(engine)
        sync_default_ignore_patterns(engine)
        yield engine
    finally:
        try:
            if engine:
                engine.dispose()
            close_all_sessions()
            if os.path.exists(db_path):
                try:
                    if engine:
                        Base.metadata.drop_all(engine)
                except Exception:
                    pass
            cleanup_temp_dir(temp_dir)
        except Exception as e:
            logger.debug(f"Error during test database cleanup: {str(e)}")

@pytest.fixture
def test_session(test_db):
    session = None
    try:
        session = Session(test_db)
        yield session
    finally:
        if session:
            session.close() 