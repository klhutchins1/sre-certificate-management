"""
Tests for SearchService.

Tests search functionality across certificates, hosts, and IP addresses
with various filters.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock
from sqlalchemy.orm import Session

from infra_mgmt.services.SearchService import SearchService
from infra_mgmt.models import Certificate, Host, HostIP, CertificateBinding


class TestSearchService:
    """Test suite for SearchService."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock(spec=Session)
        return session

    @pytest.fixture
    def sample_certificate(self):
        """Create sample certificate for testing."""
        cert = Mock(spec=Certificate)
        cert.id = 1
        cert.common_name = "example.com"
        cert.serial_number = "123456"
        cert._subject = "CN=example.com"
        cert._san = "*.example.com"
        cert.valid_until = datetime.now() + timedelta(days=90)
        cert.certificate_bindings = []
        return cert

    @pytest.fixture
    def sample_host(self):
        """Create sample host for testing."""
        host = Mock(spec=Host)
        host.id = 1
        host.name = "server1.example.com"
        host.host_type = "Server"
        host.environment = "Production"
        host.ip_addresses = []
        host.certificate_bindings = []
        return host

    def test_perform_search_all_types(self, mock_session, sample_certificate, sample_host):
        """Test search across all types."""
        # Setup certificate query chain - for "All" filters, no status/platform filters are applied
        # Chain: query(Certificate).options(...).filter(or_(...)).all()
        # The .all() call should return the actual list
        cert_query_all_result = [sample_certificate]
        cert_query_all = MagicMock()
        cert_query_all.all.return_value = cert_query_all_result
        cert_query_options = MagicMock()
        cert_query_options.options.return_value = cert_query_all
        cert_query = MagicMock()
        cert_query.options.return_value = cert_query_options
        # For "All" filters, only one filter() call is made (the search filter)
        cert_query_options.filter.return_value = cert_query_all
        
        # Setup host query chain
        host_query_all_result = [sample_host]
        host_query_all = MagicMock()
        host_query_all.all.return_value = host_query_all_result
        host_query_options = MagicMock()
        host_query_options.options.return_value = host_query_all
        host_query = MagicMock()
        host_query.options.return_value = host_query_options
        # For "All" filters, only one filter() call is made (the search filter)
        host_query_options.filter.return_value = host_query_all
        
        # Track calls to return correct query
        def query_side_effect(model):
            # Use model name string matching to avoid SQLAlchemy comparison issues
            model_name = getattr(model, '__name__', str(model))
            if 'Certificate' in model_name:
                return cert_query
            elif 'Host' in model_name:
                return host_query
            return MagicMock()
        
        mock_session.query.side_effect = query_side_effect
        
        results = SearchService.perform_search(
            mock_session, "example", "All", "All", "All"
        )
        
        assert 'certificates' in results
        assert 'hosts' in results
        # Verify the results are lists (not MagicMock objects)
        assert isinstance(results['certificates'], list)
        assert isinstance(results['hosts'], list)
        assert len(results['certificates']) == 1
        assert len(results['hosts']) == 1

    def test_perform_search_certificates_only(self, mock_session, sample_certificate):
        """Test search for certificates only."""
        cert_query = MagicMock()
        cert_query.filter.return_value.all.return_value = [sample_certificate]
        
        mock_session.query.return_value.options.return_value = cert_query
        
        results = SearchService.perform_search(
            mock_session, "example", "Certificates", "All", "All"
        )
        
        assert 'certificates' in results
        assert len(results['certificates']) == 1
        assert 'hosts' not in results

    def test_perform_search_hosts_only(self, mock_session, sample_host):
        """Test search for hosts only."""
        # Setup host query chain properly - for "Hosts" type with "All" filters
        # Chain: query(Host).options(...).filter(or_(...)).all()
        host_query_all_result = [sample_host]
        host_query_all = MagicMock()
        host_query_all.all.return_value = host_query_all_result
        host_query_options = MagicMock()
        host_query_options.options.return_value = host_query_all
        host_query = MagicMock()
        host_query.options.return_value = host_query_options
        # For "All" filters, only one filter() call is made (the search filter)
        host_query_options.filter.return_value = host_query_all
        
        def query_side_effect(model):
            # Use model name string matching to avoid SQLAlchemy comparison issues
            model_name = getattr(model, '__name__', str(model))
            if 'Host' in model_name:
                return host_query
            return MagicMock()
        
        mock_session.query.side_effect = query_side_effect
        
        results = SearchService.perform_search(
            mock_session, "server1", "Hosts", "All", "All"
        )
        
        assert 'hosts' in results
        assert isinstance(results['hosts'], list)
        assert len(results['hosts']) == 1
        assert 'certificates' not in results

    def test_perform_search_valid_status_filter(self, mock_session, sample_certificate):
        """Test search with valid certificate status filter."""
        cert_query = MagicMock()
        cert_query.filter.return_value.filter.return_value.all.return_value = [sample_certificate]
        
        mock_session.query.return_value.options.return_value = cert_query
        
        results = SearchService.perform_search(
            mock_session, "example", "Certificates", "Valid", "All"
        )
        
        # Verify filter was applied
        assert cert_query.filter.called

    def test_perform_search_expired_status_filter(self, mock_session):
        """Test search with expired certificate status filter."""
        expired_cert = Mock(spec=Certificate)
        expired_cert.id = 1
        expired_cert.common_name = "expired.com"
        expired_cert.serial_number = "123"
        expired_cert._subject = "CN=expired.com"
        expired_cert._san = ""
        expired_cert.valid_until = datetime.now() - timedelta(days=1)
        expired_cert.certificate_bindings = []
        
        cert_query = MagicMock()
        cert_query.filter.return_value.filter.return_value.all.return_value = [expired_cert]
        
        mock_session.query.return_value.options.return_value = cert_query
        
        results = SearchService.perform_search(
            mock_session, "expired", "Certificates", "Expired", "All"
        )
        
        assert len(results['certificates']) == 1

    def test_perform_search_platform_filter(self, mock_session, sample_certificate):
        """Test search with platform filter."""
        cert_query = MagicMock()
        cert_query.join.return_value.filter.return_value.filter.return_value.all.return_value = [sample_certificate]
        
        mock_session.query.return_value.options.return_value = cert_query
        
        results = SearchService.perform_search(
            mock_session, "example", "Certificates", "All", "F5"
        )
        
        # Verify join was called for platform filter
        assert cert_query.join.called

    def test_perform_search_empty_query(self, mock_session):
        """Test search with empty query string."""
        cert_query = MagicMock()
        cert_query.filter.return_value.all.return_value = []
        
        mock_session.query.return_value.options.return_value = cert_query
        
        results = SearchService.perform_search(
            mock_session, "", "All", "All", "All"
        )
        
        assert 'certificates' in results or len(results.get('certificates', [])) == 0

    def test_perform_search_no_results(self, mock_session):
        """Test search that returns no results."""
        cert_query = MagicMock()
        cert_query.filter.return_value.all.return_value = []
        
        mock_session.query.return_value.options.return_value = cert_query
        
        results = SearchService.perform_search(
            mock_session, "nonexistent", "All", "All", "All"
        )
        
        assert 'certificates' in results
        assert len(results.get('certificates', [])) == 0

    def test_perform_search_with_ip_address(self, mock_session, sample_host):
        """Test search for IP addresses."""
        ip_address = Mock(spec=HostIP)
        ip_address.ip_address = "192.168.1.1"
        sample_host.ip_addresses = [ip_address]
        
        # Setup host query chain for IP address search
        host_query_all_result = [sample_host]
        host_query_all = MagicMock()
        host_query_all.all.return_value = host_query_all_result
        host_query_options = MagicMock()
        host_query_options.options.return_value = host_query_all
        host_query = MagicMock()
        host_query.options.return_value = host_query_options
        # For "All" filters with IP search, only one filter() call is made (the search filter)
        host_query_options.filter.return_value = host_query_all
        
        def query_side_effect(model):
            # Use model name string matching to avoid SQLAlchemy comparison issues
            model_name = getattr(model, '__name__', str(model))
            if 'Host' in model_name:
                return host_query
            return MagicMock()
        
        mock_session.query.side_effect = query_side_effect
        
        results = SearchService.perform_search(
            mock_session, "192.168.1.1", "IP Addresses", "All", "All"
        )
        
        assert 'hosts' in results
        assert isinstance(results['hosts'], list)
        assert len(results['hosts']) == 1

