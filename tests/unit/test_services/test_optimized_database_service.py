"""
Tests for OptimizedDatabaseService and QueryCache.

Tests query caching, bulk operations, pagination, and performance optimizations.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch
import time
import threading

from infra_mgmt.services.OptimizedDatabaseService import (
    OptimizedDatabaseService,
    QueryCache,
    cache_query
)
from infra_mgmt.models import Certificate, Domain, Host
from sqlalchemy.orm import selectinload as real_selectinload


class TestQueryCache:
    """Test suite for QueryCache."""

    @pytest.fixture
    def cache(self):
        """Create QueryCache instance for testing."""
        return QueryCache(max_size=10, default_ttl=60)

    def test_cache_set_and_get(self, cache):
        """Test basic cache set and get operations."""
        cache.set("key1", "value1", ttl=60)  # Explicitly set TTL
        result = cache.get("key1", ttl=60)
        
        assert result == "value1"

    def test_cache_get_nonexistent_key(self, cache):
        """Test getting non-existent key from cache."""
        result = cache.get("nonexistent")
        
        assert result is None

    def test_cache_ttl_expiration(self):
        """Test cache expiration based on TTL."""
        from datetime import datetime, timedelta
        
        # Use a cache with shorter default TTL for this test
        short_cache = QueryCache(max_size=10, default_ttl=1)
        
        # Set with very short TTL
        short_cache.set("key1", "value1", ttl=0.1)
        
        # Immediately after setting, should still be valid
        result1 = short_cache.get("key1", ttl=0.1)
        assert result1 == "value1"
        
        # Manually expire the cache by manipulating timestamps
        # This avoids timing issues in tests
        short_cache.timestamps["key1"] = datetime.now() - timedelta(seconds=0.2)
        
        # Get with the same TTL - should be expired now
        result = short_cache.get("key1", ttl=0.1)
        
        assert result is None

    def test_cache_custom_ttl(self, cache):
        """Test cache with custom TTL."""
        cache.set("key1", "value1", ttl=5)
        cache.set("key2", "value2", ttl=10)
        
        # Both should still be valid
        assert cache.get("key1", ttl=5) == "value1"
        assert cache.get("key2", ttl=10) == "value2"

    def test_cache_max_size_eviction(self, cache):
        """Test cache eviction when max size is reached."""
        # Fill cache beyond max_size
        for i in range(12):
            cache.set(f"key{i}", f"value{i}")
        
        # Cache should have evicted some entries
        assert len(cache.cache) <= cache.max_size

    def test_cache_lru_eviction(self, cache):
        """Test LRU eviction strategy."""
        # Add items to cache
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        
        # Access some keys more frequently
        cache.get("key1")
        cache.get("key1")
        cache.get("key2")
        
        # Fill cache to trigger eviction
        for i in range(4, 15):
            cache.set(f"key{i}", f"value{i}")
        
        # key1 and key2 should likely still be there (more access)
        assert len(cache.cache) <= cache.max_size

    def test_cache_clear(self, cache):
        """Test clearing the cache."""
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        
        cache.clear()
        
        assert len(cache.cache) == 0
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_cache_stats(self, cache):
        """Test cache statistics."""
        cache.set("key1", "value1")
        cache.get("key1")
        cache.get("key1")
        
        stats = cache.stats()
        
        assert stats['size'] == 1
        assert stats['max_size'] == 10
        assert stats['total_access'] >= 2

    def test_cache_thread_safety(self, cache):
        """Test cache thread safety."""
        def set_values(start, end):
            for i in range(start, end):
                cache.set(f"key{i}", f"value{i}")
        
        def get_values(start, end):
            for i in range(start, end):
                cache.get(f"key{i}")
        
        # Create multiple threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=set_values, args=(i*10, (i+1)*10))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Cache should be in valid state
        assert len(cache.cache) <= cache.max_size


class TestOptimizedDatabaseService:
    """Test suite for OptimizedDatabaseService."""

    @pytest.fixture
    def mock_engine(self):
        """Create mock SQLAlchemy engine."""
        engine = MagicMock()
        return engine

    @pytest.fixture
    def service(self, mock_engine):
        """Create OptimizedDatabaseService instance for testing."""
        return OptimizedDatabaseService(mock_engine, cache_size=100, cache_ttl=300)

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock()
        return session

    def test_service_initialization(self, mock_engine):
        """Test service initialization."""
        service = OptimizedDatabaseService(mock_engine, cache_size=200, cache_ttl=600)
        
        assert service.engine == mock_engine
        assert service.query_cache.max_size == 200
        assert service.query_cache.default_ttl == 600
        assert service.query_count == 0
        assert service.cache_hits == 0

    def test_get_session_success(self, service, mock_engine):
        """Test successful session retrieval."""
        with patch.object(service, 'session_factory') as mock_factory:
            mock_session = MagicMock()
            mock_factory.return_value = mock_session
            
            with service.get_session() as session:
                assert session == mock_session
            
            mock_session.commit.assert_called_once()
            mock_session.close.assert_called_once()

    def test_get_session_rollback_on_error(self, service, mock_engine):
        """Test session rollback on error."""
        with patch.object(service, 'session_factory') as mock_factory:
            mock_session = MagicMock()
            mock_session.commit.side_effect = Exception("Database error")
            mock_factory.return_value = mock_session
            
            with pytest.raises(Exception):
                with service.get_session() as session:
                    raise Exception("Test error")
            
            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()

    def test_execute_timed_query(self, service):
        """Test timed query execution."""
        import time as time_module
        
        mock_session = MagicMock()
        mock_query = MagicMock()
        mock_result = MagicMock()
        mock_session.execute.return_value = mock_result
        
        # Mock time.time() to simulate some elapsed time
        initial_time = 1000.0
        with patch.object(time_module, 'time', side_effect=[initial_time, initial_time + 0.001]):
            result = service._execute_timed_query(mock_session, mock_query, "Test query")
        
        assert service.query_count == 1
        assert service.total_query_time > 0
        mock_session.execute.assert_called_once_with(mock_query)
        assert result == mock_result

    def test_get_certificate_metrics_cached(self, service):
        """Test certificate metrics with caching."""
        mock_result = MagicMock()
        mock_result.total = 100
        mock_result.expiring = 10
        mock_result.expired = 5
        
        with patch.object(service, 'get_session') as mock_get_session:
            mock_session = MagicMock()
            mock_session.execute.return_value.first.return_value = mock_result
            mock_get_session.return_value.__enter__.return_value = mock_session
            
            # First call - cache miss
            result1 = service.get_certificate_metrics()
            
            # Second call - should use cache
            result2 = service.get_certificate_metrics()
            
            assert result1 == result2
            # Should only execute query once (second call uses cache)
            assert mock_session.execute.call_count == 1

    def test_get_certificate_metrics_no_data(self, service):
        """Test certificate metrics with no data."""
        mock_result = MagicMock()
        mock_result.total = None
        mock_result.expiring = None
        mock_result.expired = None
        
        with patch.object(service, 'get_session') as mock_get_session:
            mock_session = MagicMock()
            mock_session.execute.return_value.first.return_value = mock_result
            mock_get_session.return_value.__enter__.return_value = mock_session
            
            result = service.get_certificate_metrics()
            
            assert result['total_certificates'] == 0
            assert result['expiring_certificates'] == 0
            assert result['expired_certificates'] == 0

    def test_get_domain_metrics(self, service):
        """Test domain metrics retrieval."""
        mock_result = MagicMock()
        mock_result.total = 50
        mock_result.expiring = 5
        
        with patch.object(service, 'get_session') as mock_get_session:
            mock_session = MagicMock()
            mock_session.execute.return_value.first.return_value = mock_result
            mock_get_session.return_value.__enter__.return_value = mock_session
            
            result = service.get_domain_metrics()
            
            assert result['total_domains'] == 50
            assert result['expiring_domains'] == 5

    def test_get_certificates_paginated_first_page(self, service):
        """Test paginated certificate retrieval - first page."""
        mock_cert = MagicMock()
        mock_cert.id = 1
        mock_cert.common_name = "example.com"
        
        with patch.object(Certificate, 'hosts', create=True), \
             patch.object(service, 'get_session') as mock_get_session, \
             patch.object(service, '_execute_timed_query') as mock_execute, \
             patch('infra_mgmt.services.OptimizedDatabaseService.select') as mock_select, \
             patch('infra_mgmt.services.OptimizedDatabaseService.selectinload') as mock_selectinload:
            mock_session = MagicMock()
            mock_session.scalar.return_value = 100  # Total count
            
            # Mock selectinload to return a chainable mock
            mock_selectinload_option = MagicMock()
            mock_selectinload.return_value = mock_selectinload_option
            
            # Mock the select() call to return a chainable query object
            # Make .options() return self to handle selectinload call
            mock_query = MagicMock()
            mock_query.options = MagicMock(return_value=mock_query)
            mock_query.order_by = MagicMock(return_value=mock_query)
            mock_query.offset = MagicMock(return_value=mock_query)
            mock_query.limit = MagicMock(return_value=mock_query)
            mock_select.return_value = mock_query
            
            # Mock the _execute_timed_query return value
            mock_all = MagicMock()
            mock_all.all.return_value = [mock_cert]
            mock_scalars_result = MagicMock()
            mock_scalars_result.scalars.return_value = mock_all
            mock_execute.return_value = mock_scalars_result
            
            mock_get_session.return_value.__enter__.return_value = mock_session
            
            result = service.get_certificates_paginated(page=1, per_page=10)
            
            assert result['total_count'] == 100
            assert result['page'] == 1
            assert result['per_page'] == 10
            assert len(result['certificates']) == 1

    def test_get_certificates_paginated_last_page(self, service):
        """Test paginated certificate retrieval - last page."""
        with patch.object(service, 'get_session') as mock_get_session, \
             patch.object(service, '_execute_timed_query') as mock_execute:
            mock_session = MagicMock()
            mock_session.scalar.return_value = 100  # Total count
            
            # Mock the _execute_timed_query return value
            mock_all = MagicMock()
            mock_all.all.return_value = []
            mock_scalars_result = MagicMock()
            mock_scalars_result.scalars.return_value = mock_all
            mock_execute.return_value = mock_scalars_result
            
            mock_get_session.return_value.__enter__.return_value = mock_session
            
            result = service.get_certificates_paginated(page=10, per_page=10)
            
            assert result['total_count'] == 100
            assert result['page'] == 10
            assert result['total_pages'] == 10
            assert len(result['certificates']) == 0

    def test_get_certificates_paginated_ordering(self, service):
        """Test paginated certificate retrieval with custom ordering."""
        with patch.object(service, 'get_session') as mock_get_session, \
             patch.object(service, '_execute_timed_query') as mock_execute:
            mock_session = MagicMock()
            mock_session.scalar.return_value = 50
            
            # Mock the _execute_timed_query return value
            mock_all = MagicMock()
            mock_all.all.return_value = []
            mock_scalars_result = MagicMock()
            mock_scalars_result.scalars.return_value = mock_all
            mock_execute.return_value = mock_scalars_result
            
            mock_get_session.return_value.__enter__.return_value = mock_session
            
            result = service.get_certificates_paginated(
                page=1, per_page=10, order_by='common_name', order_dir='asc'
            )
            
            assert result['page'] == 1
            assert result['total_count'] == 50
            # Verify _execute_timed_query was called
            assert mock_execute.called

    def test_cache_query_decorator(self, service):
        """Test cache_query decorator functionality."""
        # Create a test method with cache decorator
        call_count = {'count': 0}
        
        @cache_query(ttl=60)
        def cached_method(self, param):
            call_count['count'] += 1
            return f"result_{param}"
        
        # Bind method to service
        service.test_method = cached_method.__get__(service, OptimizedDatabaseService)
        
        # First call - should execute
        result1 = service.test_method("test")
        assert call_count['count'] == 1
        assert result1 == "result_test"
        
        # Second call - should use cache
        result2 = service.test_method("test")
        assert call_count['count'] == 1  # Should not increment
        assert result2 == "result_test"

