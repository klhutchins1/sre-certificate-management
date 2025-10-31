"""
Tests for ViewDataService.

Tests view data aggregation for certificates, dashboard, domains, hosts, applications, and search.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch
import pandas as pd

from infra_mgmt.services.ViewDataService import ViewDataService
from infra_mgmt.models import Certificate, Domain, Host, HostIP, Application, CertificateBinding, IgnoredDomain
from infra_mgmt.services.DashboardService import DashboardService
from infra_mgmt.services.SearchService import SearchService


class TestViewDataService:
    """Test suite for ViewDataService."""

    @pytest.fixture
    def view_data_service(self):
        """Create ViewDataService instance for testing."""
        return ViewDataService()

    @pytest.fixture
    def mock_engine(self):
        """Create mock SQLAlchemy engine."""
        engine = MagicMock()
        return engine

    @pytest.fixture
    def sample_certificate(self):
        """Create sample certificate for testing."""
        cert = Mock(spec=Certificate)
        cert.id = 1
        cert.common_name = "example.com"
        cert.serial_number = "123456"
        cert.valid_from = datetime.now() - timedelta(days=90)
        cert.valid_until = datetime.now() + timedelta(days=90)
        cert.certificate_bindings = []
        return cert

    def test_get_certificate_list_view_data_success(self, view_data_service, mock_engine, sample_certificate):
        """Test successful retrieval of certificate list view data."""
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.return_value.count.return_value = 10
            mock_session.query.return_value.filter.return_value.count.return_value = 8
            mock_session.query.return_value.all.return_value = [sample_certificate]
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_certificate_list_view_data(mock_engine)
            
            assert result['success'] is True
            assert 'data' in result
            assert 'df' in result['data']
            assert 'column_config' in result['data']
            assert 'metrics' in result['data']
            assert result['data']['metrics']['total_certs'] == 10

    def test_get_certificate_list_view_data_metrics_error(self, view_data_service, mock_engine):
        """Test error handling when fetching metrics fails."""
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.side_effect = Exception("Database error")
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_certificate_list_view_data(mock_engine)
            
            assert result['success'] is False
            assert 'error' in result

    def test_get_certificate_list_view_data_table_error(self, view_data_service, mock_engine):
        """Test error handling when fetching table data fails."""
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.side_effect = [
                MagicMock(count=lambda: 10),  # total_certs query
                MagicMock(count=lambda: 8),   # valid_certs query
                MagicMock(count=lambda: 5),   # total_bindings query
                Exception("Database error")   # certificates.all() query
            ]
            
            def query_side_effect(*args):
                if len([x for x in mock_session.query.side_effect if isinstance(x, Exception)]) > 0:
                    raise Exception("Database error")
                return MagicMock(count=lambda: 10)
            
            mock_session.query = MagicMock(side_effect=[
                MagicMock(count=lambda: 10),
                MagicMock(count=lambda: 8),
                MagicMock(count=lambda: 5),
                MagicMock(all=MagicMock(side_effect=Exception("Database error")))
            ])
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_certificate_list_view_data(mock_engine)
            
            assert result['success'] is False
            assert 'error' in result

    def test_get_dashboard_view_data_success(self, view_data_service, mock_engine):
        """Test successful retrieval of dashboard view data."""
        mock_metrics = {
            'total_certs': 10,
            'expiring_certs': 2,
            'root_domains': []
        }
        mock_cert_timeline = []
        mock_domain_timeline = []
        
        with patch.object(view_data_service, 'session_scope') as mock_scope, \
             patch.object(DashboardService, 'get_dashboard_metrics', return_value=mock_metrics), \
             patch.object(DashboardService, 'get_certificate_timeline_data', return_value=mock_cert_timeline), \
             patch.object(DashboardService, 'get_domain_timeline_data', return_value=mock_domain_timeline):
            
            mock_session = MagicMock()
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_dashboard_view_data(mock_engine)
            
            assert result['success'] is True
            assert 'data' in result
            assert 'metrics' in result['data']
            assert 'cert_timeline' in result['data']
            assert 'domain_timeline' in result['data']

    def test_get_dashboard_view_data_error(self, view_data_service, mock_engine):
        """Test error handling in get_dashboard_view_data."""
        with patch.object(view_data_service, 'session_scope') as mock_scope, \
             patch.object(DashboardService, 'get_dashboard_metrics', side_effect=Exception("Database error")):
            
            mock_session = MagicMock()
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_dashboard_view_data(mock_engine)
            
            assert result['success'] is False
            assert 'error' in result

    def test_get_domain_list_view_data_success(self, view_data_service, mock_engine):
        """Test successful retrieval of domain list view data."""
        domain1 = Mock(spec=Domain)
        domain1.domain_name = "example.com"
        domain1.is_active = True
        domain1.expiration_date = datetime.now() + timedelta(days=60)
        domain1.certificates = []
        domain1.dns_records = []
        domain1.subdomains = []
        
        ignored = Mock(spec=IgnoredDomain)
        ignored.pattern = "*.test.com"
        
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.side_effect = [
                MagicMock(options=MagicMock(return_value=MagicMock(order_by=MagicMock(return_value=MagicMock(all=lambda: [domain1]))))),
                MagicMock(all=lambda: [ignored])
            ]
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_domain_list_view_data(mock_engine)
            
            assert result['success'] is True
            assert 'data' in result
            assert 'visible_domains' in result['data']
            assert 'metrics' in result['data']
            assert 'ignored_patterns' in result['data']

    def test_get_domain_list_view_data_error(self, view_data_service, mock_engine):
        """Test error handling in get_domain_list_view_data."""
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.side_effect = Exception("Database error")
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_domain_list_view_data(mock_engine)
            
            assert result['success'] is False
            assert 'error' in result

    def test_get_host_list_view_data_success(self, view_data_service, mock_engine):
        """Test successful retrieval of host list view data."""
        host = Mock(spec=Host)
        host.id = 1
        host.name = "server1.example.com"
        host.host_type = "Server"
        host.environment = "Production"
        host.description = "Test server"
        host.last_seen = datetime.now()
        
        ip1 = Mock(spec=HostIP)
        ip1.ip_address = "192.168.1.1"
        ip2 = Mock(spec=HostIP)
        ip2.ip_address = "192.168.1.2"
        host.ip_addresses = [ip1, ip2]
        host.certificate_bindings = []
        
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.return_value.all.return_value = [host]
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_host_list_view_data(mock_engine)
            
            assert result['success'] is True
            assert 'data' in result
            assert 'df' in result['data']
            assert 'column_config' in result['data']
            assert 'metrics' in result['data']
            assert result['data']['metrics']['total_hosts'] == 1

    def test_get_host_list_view_data_error(self, view_data_service, mock_engine):
        """Test error handling in get_host_list_view_data."""
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.side_effect = Exception("Database error")
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_host_list_view_data(mock_engine)
            
            assert result['success'] is False
            assert 'error' in result

    def test_get_applications_list_view_data_success(self, view_data_service, mock_engine):
        """Test successful retrieval of applications list view data."""
        app = Mock(spec=Application)
        app.id = 1
        app.name = "Test App"
        app.app_type = "Web"
        app.description = "Test Description"
        app.owner = "Test Owner"
        
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.return_value.all.return_value = [app]
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_applications_list_view_data(mock_engine)
            
            assert result['success'] is True
            assert 'data' in result
            assert 'df' in result['data']
            assert 'column_config' in result['data']

    def test_get_applications_list_view_data_error(self, view_data_service, mock_engine):
        """Test error handling in get_applications_list_view_data."""
        with patch.object(view_data_service, 'session_scope') as mock_scope:
            mock_session = MagicMock()
            mock_session.query.side_effect = Exception("Database error")
            
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_applications_list_view_data(mock_engine)
            
            assert result['success'] is False
            assert 'error' in result

    def test_get_search_view_data_success(self, view_data_service, mock_engine, sample_certificate):
        """Test successful retrieval of search view data."""
        host = Mock(spec=Host)
        host.id = 1
        host.name = "server1.example.com"
        host.host_type = "Server"
        host.environment = "Production"
        host.description = "Test server"
        host.last_seen = datetime.now()
        
        mock_search_results = {
            'certificates': [sample_certificate],
            'hosts': [host]
        }
        
        with patch.object(view_data_service, 'session_scope') as mock_scope, \
             patch.object(SearchService, 'perform_search', return_value=mock_search_results):
            
            mock_session = MagicMock()
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_search_view_data(
                mock_engine, "example", "All", "All", "All"
            )
            
            assert result['success'] is True
            assert 'data' in result
            assert 'df' in result['data']
            assert 'column_config' in result['data']

    def test_get_search_view_data_error(self, view_data_service, mock_engine):
        """Test error handling in get_search_view_data."""
        with patch.object(view_data_service, 'session_scope') as mock_scope, \
             patch.object(SearchService, 'perform_search', side_effect=Exception("Database error")):
            
            mock_session = MagicMock()
            mock_scope.return_value.__enter__.return_value = mock_session
            
            result = view_data_service.get_search_view_data(
                mock_engine, "example", "All", "All", "All"
            )
            
            assert result['success'] is False
            assert 'error' in result


