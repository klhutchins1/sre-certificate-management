#!/usr/bin/env python3
"""
Performance Test Script for Database Cache Optimization

This script demonstrates the performance improvements achieved by the cache system
when accessing databases on slow file-shares.
"""

import time
import tempfile
import shutil
from pathlib import Path

# Import compatibility fixes before SQLAlchemy
try:
    from infra_mgmt.compatibility import ensure_compatibility
    ensure_compatibility()
except ImportError:
    # If compatibility module not available, continue anyway
    pass

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_test_database(db_path: str, num_records: int = 1000):
    """Create a test database with sample data."""
    engine = create_engine(f"sqlite:///{db_path}")
    
    # Create test table
    with engine.connect() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS test_data (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                value INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """))
        
        # Insert test data
        for i in range(num_records):
            conn.execute(text("""
                INSERT INTO test_data (name, value) 
                VALUES (:name, :value)
            """), {
                'name': f'Record_{i}',
                'value': i
            })
        
        conn.commit()
    
    return engine

def benchmark_direct_access(db_path: str, num_operations: int = 100):
    """Test direct database access performance."""
    logger.info(f"Testing direct access to {db_path}")
    
    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)
    
    # Test read operations
    start_time = time.time()
    for i in range(num_operations):
        with Session() as session:
            result = session.execute(text("SELECT COUNT(*) FROM test_data")).scalar()
            if i % 10 == 0:
                logger.debug(f"Read {i}: {result} records")
    
    read_time = time.time() - start_time
    
    # Test write operations
    start_time = time.time()
    for i in range(num_operations):
        with Session() as session:
            session.execute(text("""
                INSERT INTO test_data (name, value) 
                VALUES (:name, :value)
            """), {
                'name': f'Test_Write_{i}',
                'value': i
            })
            session.commit()
    
    write_time = time.time() - start_time
    
    return {
        'read_time': read_time,
        'write_time': write_time,
        'read_ops_per_sec': num_operations / read_time,
        'write_ops_per_sec': num_operations / write_time
    }

def force_enable_cache_for_testing(db_path: str):
    """Force enable cache for testing by temporarily making the path appear as network path."""
    import os
    from infra_mgmt.settings import Settings
    from infra_mgmt.db.cache_manager import DatabaseCacheManager
    import infra_mgmt.db.engine as engine_module
    
    # Get the settings instance
    settings = Settings()
    
    # Store original path
    original_path = settings.get("paths.database")
    
    # Temporarily set the test path as the database path
    settings.update("paths.database", db_path)
    
    # Manually create cache manager for testing (bypass network path check)
    if engine_module._cache_manager is None:
        sync_interval = settings.get("database.sync_interval", 30)
        engine_module._cache_manager = DatabaseCacheManager(db_path, sync_interval)
    
    return original_path

def restore_original_db_path(original_path: str):
    """Restore the original database path."""
    from infra_mgmt.settings import Settings
    settings = Settings()
    settings.update("paths.database", original_path)

def benchmark_cached_access(db_path: str, num_operations: int = 100):
    """Test cached database access performance."""
    logger.info(f"Testing cached access to {db_path}")
    
    # Force enable cache for testing
    original_path = force_enable_cache_for_testing(db_path)
    
    try:
        from infra_mgmt.db.session import get_session
        from infra_mgmt.db.engine import is_cache_enabled, get_cache_manager
        
        # Force enable cache for testing (override network path check)
        logger.info(f"Cache enabled: {is_cache_enabled()}")
        cache_manager = get_cache_manager()
        logger.info(f"Cache manager available: {cache_manager is not None}")
        
        # Ensure test table exists and is populated in the cached DB
        # Use cache manager's local engine directly for testing
        if cache_manager and cache_manager.local_engine:
            from sqlalchemy.orm import sessionmaker
            Session = sessionmaker(bind=cache_manager.local_engine)
            session = Session()
            logger.info(f"Session created: {session is not None}")
            
            if session:
                try:
                    session.execute(text("""
                        CREATE TABLE IF NOT EXISTS test_data (
                            id INTEGER PRIMARY KEY,
                            name TEXT,
                            value INTEGER,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                    session.execute(text("DELETE FROM test_data"))
                    for i in range(num_operations):
                        session.execute(text("""
                            INSERT INTO test_data (name, value) VALUES (:name, :value)
                        """), {"name": f"test_{i}", "value": i})
                    session.commit()
                    logger.info(f"Test table created and populated with {num_operations} records")
                finally:
                    session.close()
            else:
                logger.error("Failed to create session for table setup")
                return None
        else:
            logger.error("Cache manager or local engine not available")
            return None
        
        # Test read operations
        start_time = time.time()
        successful_reads = 0
        for i in range(num_operations):
            session = Session()
            if session:
                try:
                    result = session.execute(text("SELECT COUNT(*) FROM test_data")).scalar()
                    successful_reads += 1
                    if i % 10 == 0:
                        logger.debug(f"Read {i}: {result} records")
                except Exception as e:
                    logger.error(f"Read operation {i} failed: {e}")
                finally:
                    session.close()
            else:
                logger.error(f"Failed to create session for read operation {i}")
        
        read_time = time.time() - start_time
        logger.info(f"Successful reads: {successful_reads}/{num_operations}")
        
        # Test write operations
        start_time = time.time()
        successful_writes = 0
        for i in range(num_operations):
            session = Session()
            if session:
                try:
                    session.execute(text("""
                        INSERT INTO test_data (name, value) VALUES (:name, :value)
                    """), {"name": f"cached_test_{i}", "value": i + num_operations})
                    session.commit()
                    successful_writes += 1
                except Exception as e:
                    logger.error(f"Write operation {i} failed: {e}")
                finally:
                    session.close()
            else:
                logger.error(f"Failed to create session for write operation {i}")
        
        write_time = time.time() - start_time
        logger.info(f"Successful writes: {successful_writes}/{num_operations}")
        
        return {
            'read_time': read_time,
            'write_time': write_time,
            'read_ops_per_sec': successful_reads / read_time if read_time > 0 else 0,
            'write_ops_per_sec': successful_writes / write_time if write_time > 0 else 0,
            'successful_reads': successful_reads,
            'successful_writes': successful_writes
        }
        
    except Exception as e:
        logger.error(f"Cached test failed: {str(e)}")
        return None
    finally:
        # Restore original database path
        restore_original_db_path(original_path)

def simulate_network_latency(db_path: str, latency_ms: int = 100):
    """Simulate network latency by adding delays."""
    logger.info(f"Simulating {latency_ms}ms network latency")
    
    import time
    
    def delayed_operation():
        time.sleep(latency_ms / 1000.0)
    
    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)
    
    # Test with simulated latency
    start_time = time.time()
    for i in range(10):
        with Session() as session:
            result = session.execute(text("SELECT COUNT(*) FROM test_data")).scalar()
            delayed_operation()  # Simulate network delay
    
    total_time = time.time() - start_time
    
    return {
        'total_time': total_time,
        'avg_time_per_op': total_time / 10,
        'simulated_latency': latency_ms
    }

def main():
    """Run performance comparison tests."""
    print("=" * 60)
    print("Database Cache Performance Test")
    print("=" * 60)
    
    # Create temporary test database
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_file:
        test_db_path = tmp_file.name
    
    try:
        # Create test data
        logger.info("Creating test database...")
        create_test_database(test_db_path, num_records=1000)
        
        # Test direct access
        print("\n1. Testing Direct Database Access")
        print("-" * 40)
        direct_results = benchmark_direct_access(test_db_path, num_operations=50)
        
        if direct_results:
            print(f"Read Operations: {direct_results['read_ops_per_sec']:.2f} ops/sec")
            print(f"Write Operations: {direct_results['write_ops_per_sec']:.2f} ops/sec")
            print(f"Average Read Time: {direct_results['read_time']/50*1000:.2f} ms")
            print(f"Average Write Time: {direct_results['write_time']/50*1000:.2f} ms")
        
        # Test cached access
        print("\n2. Testing Cached Database Access")
        print("-" * 40)
        cached_results = benchmark_cached_access(test_db_path, num_operations=50)
        
        if cached_results:
            print(f"Read Operations: {cached_results['read_ops_per_sec']:.2f} ops/sec")
            print(f"Write Operations: {cached_results['write_ops_per_sec']:.2f} ops/sec")
            print(f"Average Read Time: {cached_results['read_time']/50*1000:.2f} ms")
            print(f"Average Write Time: {cached_results['write_time']/50*1000:.2f} ms")
            print(f"Successful Reads: {cached_results.get('successful_reads', 0)}/50")
            print(f"Successful Writes: {cached_results.get('successful_writes', 0)}/50")
        
        # Simulate network latency
        print("\n3. Simulating Network Latency (100ms)")
        print("-" * 40)
        latency_results = simulate_network_latency(test_db_path, latency_ms=100)
        
        if latency_results:
            print(f"Total Time: {latency_results['total_time']:.2f} seconds")
            print(f"Average Time per Operation: {latency_results['avg_time_per_op']*1000:.2f} ms")
        
        # Performance comparison
        if direct_results and cached_results:
            print("\n4. Performance Comparison")
            print("-" * 40)
            
            read_improvement = cached_results['read_ops_per_sec'] / direct_results['read_ops_per_sec']
            write_improvement = cached_results['write_ops_per_sec'] / direct_results['write_ops_per_sec']
            
            print(f"Read Performance Improvement: {read_improvement:.1f}x")
            print(f"Write Performance Improvement: {write_improvement:.1f}x")
            
            if read_improvement > 1:
                print("✅ Cache provides faster read performance")
            else:
                print("⚠️ Cache read performance needs investigation")
            
            if write_improvement > 1:
                print("✅ Cache provides faster write performance")
            else:
                print("⚠️ Cache write performance needs investigation")
        
        print("\n" + "=" * 60)
        print("Test completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        print(f"\n❌ Test failed: {str(e)}")
    
    finally:
        # Cleanup
        try:
            # Stop cache manager and close connections
            from infra_mgmt.db.engine import _cache_manager
            if _cache_manager:
                _cache_manager.stop_sync()
                if _cache_manager.local_engine:
                    _cache_manager.local_engine.dispose()
                if _cache_manager.remote_engine:
                    _cache_manager.remote_engine.dispose()
            
            # Reset cache manager
            import infra_mgmt.db.engine as engine_module
            engine_module._cache_manager = None
            
            # Wait for connections to close and retry cleanup
            import time
            for attempt in range(3):
                time.sleep(0.2)
                try:
                    if Path(test_db_path).exists():
                        Path(test_db_path).unlink()
                        logger.info("Test database cleaned up")
                        break
                except Exception as e:
                    if attempt == 2:  # Last attempt
                        logger.warning(f"Failed to cleanup test database after 3 attempts: {str(e)}")
                        # Schedule final cleanup attempt
                        import threading
                        def final_cleanup():
                            time.sleep(1.0)  # Wait 1 second
                            try:
                                if Path(test_db_path).exists():
                                    Path(test_db_path).unlink()
                                    logger.info("Final cleanup successful")
                            except Exception:
                                pass  # Silently fail on final attempt
                        
                        cleanup_thread = threading.Thread(target=final_cleanup, daemon=True)
                        cleanup_thread.start()
                    else:
                        logger.debug(f"Cleanup attempt {attempt + 1} failed, retrying...")
                        
        except Exception as e:
            logger.warning(f"Failed to cleanup test database: {str(e)}")

if __name__ == "__main__":
    main() 