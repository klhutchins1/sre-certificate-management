"""
Tests for DashboardService.

Tests all dashboard-related functionality including metrics, domain hierarchy,
and timeline data generation.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch
from sqlalchemy.orm import Session

from infra_mgmt.services.DashboardService import DashboardService
from infra_mgmt.models import Certificate, Domain, Host, Application


class TestDashboardService:
    """Test suite for DashboardService."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock(spec=Session)
        return session

    def test_get_root_domain_simple(self):
        """Test get_root_domain with simple domain."""
        result = DashboardService.get_root_domain("example.com")
        assert result == "example.com"

    def test_get_root_domain_subdomain(self):
        """Test get_root_domain with subdomain."""
        result = DashboardService.get_root_domain("www.example.com")
        assert result == "example.com"

    def test_get_root_domain_multi_level(self):
        """Test get_root_domain with multi-level subdomain."""
        result = DashboardService.get_root_domain("api.v1.example.com")
        assert result == "example.com"

    def test_get_root_domain_short(self):
        """Test get_root_domain with short domain."""
        result = DashboardService.get_root_domain("ex.co")
        assert result == "ex.co"

    def test_get_domain_hierarchy_single_root(self, mock_session):
        """Test domain hierarchy with single root domain."""
        domains = [Mock(domain_name="example.com")]
        hierarchy = DashboardService.get_domain_hierarchy(domains)
        assert "example.com" in hierarchy
        assert len(hierarchy["example.com"]) == 0

    def test_get_domain_hierarchy_with_subdomains(self, mock_session):
        """Test domain hierarchy with subdomains."""
        root = Mock(domain_name="example.com")
        sub1 = Mock(domain_name="www.example.com")
        sub2 = Mock(domain_name="api.example.com")
        domains = [root, sub1, sub2]
        
        hierarchy = DashboardService.get_domain_hierarchy(domains)
        assert "example.com" in hierarchy
        assert len(hierarchy["example.com"]) == 2

    def test_get_root_domains_no_domains(self, mock_session):
        """Test get_root_domains with no domains."""
        mock_session.query.return_value.all.return_value = []
        result = DashboardService.get_root_domains(mock_session)
        assert result == []

    def test_get_root_domains_with_domains(self, mock_session):
        """Test get_root_domains with existing domains."""
        now = datetime.now()
        domain1 = Mock(domain_name="example.com")
        domain1.registration_date = None
        domain1.expiration_date = None
        domain1.updated_at = None
        
        mock_session.query.return_value.all.return_value = [domain1]
        result = DashboardService.get_root_domains(mock_session, [domain1])
        assert len(result) == 1
        assert domain1.registration_date is not None
        assert domain1.expiration_date is not None

    def test_get_dashboard_metrics_no_data(self, mock_session):
        """Test dashboard metrics with empty database."""
        from sqlalchemy import func, select
        
        # Mock certificate query (select with func.count)
        cert_mock = MagicMock()
        cert_mock.total_certs = 0
        cert_mock.expiring_certs = 0
        mock_session.execute.return_value.first.return_value = cert_mock
        
        # Mock count queries - session.query(func.count(...)).scalar()
        call_count = [0]
        def query_side_effect(*args):
            call_count[0] += 1
            mock_query = MagicMock()
            
            # Check if it's a func.count() call by checking if args[0] is callable
            # We can't compare SQLAlchemy models directly (triggers operators)
            if args and hasattr(args[0], '__call__'):
                # It's a function call like func.count()
                mock_query.scalar.return_value = 0
                return mock_query
            
            # For model queries, check by call order
            # 4th call is the Domain list query
            if call_count[0] == 4:
                mock_query.options.return_value.all.return_value = []
            else:
                mock_query.scalar.return_value = 0
            
            return mock_query
        
        mock_session.query.side_effect = query_side_effect
        
        metrics = DashboardService.get_dashboard_metrics(mock_session)
        
        assert metrics['total_certs'] == 0
        assert metrics['expiring_certs'] == 0
        assert metrics['total_domains'] == 0
        assert metrics['total_root_domains'] == 0
        assert metrics['total_apps'] == 0
        assert metrics['total_hosts'] == 0

    def test_get_dashboard_metrics_with_data(self, mock_session):
        """Test dashboard metrics with sample data."""
        from sqlalchemy import func
        
        # Mock certificate query
        cert_mock = MagicMock()
        cert_mock.total_certs = 10
        cert_mock.expiring_certs = 2
        mock_session.execute.return_value.first.return_value = cert_mock
        
        # Create mock domains
        domain1 = Mock(domain_name="example.com")
        domain1.expiration_date = datetime.now() + timedelta(days=20)
        domain2 = Mock(domain_name="test.com")
        domain2.expiration_date = datetime.now() + timedelta(days=50)
        
        # Track query calls to return appropriate mocks
        # The actual calls are:
        # 1. query(func.count(func.distinct(Domain.id))).scalar()
        # 2. query(func.count(func.distinct(Application.id))).scalar()
        # 3. query(func.count(func.distinct(Host.id))).scalar()
        # 4. query(Domain).options(...).all()
        query_calls = [0]
        def query_side_effect(*args):
            query_calls[0] += 1
            mock_query = MagicMock()
            
            # Count queries use func.count() which is a SQLAlchemy function
            # Check if first arg is a SQLAlchemy function by checking for 'count' in name or type
            is_count_query = False
            if args:
                arg = args[0]
                # Check various ways func.count might appear
                if (hasattr(arg, '__name__') and 'count' in str(arg.__name__).lower()):
                    is_count_query = True
                elif (hasattr(arg, '__class__') and 'function' in str(type(arg)).lower()):
                    is_count_query = True
                elif str(type(arg)) == "<class 'sqlalchemy.sql.functions.Function'>":
                    is_count_query = True
            
            if is_count_query:
                # It's a func.count() query
                if query_calls[0] == 1:  # Domain count
                    mock_query.scalar.return_value = 2
                elif query_calls[0] == 2:  # App count
                    mock_query.scalar.return_value = 5
                elif query_calls[0] == 3:  # Host count
                    mock_query.scalar.return_value = 3
                else:
                    mock_query.scalar.return_value = 0
                return mock_query
            
            # Model queries (Domain, Application, Host) - 4th call should be Domain
            if query_calls[0] == 4:
                # This is the Domain list query
                mock_query.options.return_value.all.return_value = [domain1, domain2]
            else:
                # Fallback
                mock_query.scalar.return_value = 0
            
            return mock_query
        
        mock_session.query.side_effect = query_side_effect
        
        metrics = DashboardService.get_dashboard_metrics(mock_session)
        
        assert metrics['total_certs'] == 10
        assert metrics['expiring_certs'] == 2
        # total_domains comes from scalar() which we set to 2
        assert metrics['total_domains'] == 2
        assert metrics['total_apps'] == 5
        assert metrics['total_hosts'] == 3
        assert 'total_root_domains' in metrics
        # root_domains should have 2 domains (domain1 and domain2 are both root domains)
        assert len(metrics['root_domains']) == 2

    def test_get_certificate_timeline_data(self, mock_session):
        """Test certificate timeline data retrieval."""
        now = datetime.now()
        
        # Create mock certificate objects with required attributes
        cert1 = Mock()
        cert1.id = 1
        cert1.common_name = "example.com"
        cert1.serial_number = "1234567890ABCDEF"
        cert1.valid_from = now
        cert1.valid_until = now + timedelta(days=90)
        
        cert2 = Mock()
        cert2.id = 2
        cert2.common_name = "test.com"
        cert2.serial_number = "FEDCBA0987654321"
        cert2.valid_from = now
        cert2.valid_until = now + timedelta(days=180)
        
        mock_query = MagicMock()
        mock_query.order_by.return_value.limit.return_value.all.return_value = [cert1, cert2]
        mock_session.query.return_value = mock_query
        
        timeline = DashboardService.get_certificate_timeline_data(mock_session, limit=100)
        
        assert len(timeline) == 2
        assert timeline[0]['Name'] == "example.com"
        assert timeline[0]['Start'] == now
        assert timeline[0]['End'] == now + timedelta(days=90)
        assert timeline[1]['Name'] == "test.com"
        assert timeline[1]['Start'] == now
        assert timeline[1]['End'] == now + timedelta(days=180)
    
    def test_get_certificate_timeline_data_with_duplicates(self, mock_session):
        """Test certificate timeline data with duplicate common names."""
        now = datetime.now()
        
        # Create certificates with the same common name but different validity periods
        cert1 = Mock()
        cert1.id = 1
        cert1.common_name = "example.com"
        cert1.serial_number = "1111111111111111"
        cert1.valid_from = now
        cert1.valid_until = now + timedelta(days=90)
        
        cert2 = Mock()
        cert2.id = 2
        cert2.common_name = "example.com"  # Same CN as cert1
        cert2.serial_number = "2222222222222222"
        cert2.valid_from = now + timedelta(days=100)
        cert2.valid_until = now + timedelta(days=200)
        
        mock_query = MagicMock()
        mock_query.order_by.return_value.limit.return_value.all.return_value = [cert1, cert2]
        mock_session.query.return_value = mock_query
        
        timeline = DashboardService.get_certificate_timeline_data(mock_session, limit=100)
        
        assert len(timeline) == 2
        # First occurrence should have no suffix
        assert timeline[0]['Name'] == "example.com"
        # Second occurrence should have serial number suffix
        assert timeline[1]['Name'] == "example.com (22222222...)"
        assert timeline[1]['Start'] == now + timedelta(days=100)
        assert timeline[1]['End'] == now + timedelta(days=200)
    
    def test_get_certificate_timeline_data_no_serial(self, mock_session):
        """Test certificate timeline data when serial number is missing."""
        now = datetime.now()
        
        cert1 = Mock()
        cert1.id = 1
        cert1.common_name = "example.com"
        cert1.serial_number = None  # No serial number
        cert1.valid_from = now
        cert1.valid_until = now + timedelta(days=90)
        
        mock_query = MagicMock()
        mock_query.order_by.return_value.limit.return_value.all.return_value = [cert1]
        mock_session.query.return_value = mock_query
        
        timeline = DashboardService.get_certificate_timeline_data(mock_session, limit=100)
        
        assert len(timeline) == 1
        assert timeline[0]['Name'] == "example.com"
        assert timeline[0]['Start'] == now
        assert timeline[0]['End'] == now + timedelta(days=90)

    def test_get_domain_timeline_data(self):
        """Test domain timeline data generation."""
        domain1 = Mock()
        domain1.domain_name = "example.com"
        domain1.registration_date = datetime(2020, 1, 1)
        domain1.expiration_date = datetime(2030, 1, 1)
        
        domain2 = Mock()
        domain2.domain_name = "test.com"
        domain2.registration_date = None
        domain2.expiration_date = None
        
        domains = [domain1, domain2]
        timeline = DashboardService.get_domain_timeline_data(domains)
        
        assert len(timeline) == 1  # Only domain1 has dates
        assert timeline[0]['Name'] == "example.com"
        assert timeline[0]['Start'] == datetime(2020, 1, 1)
        assert timeline[0]['End'] == datetime(2030, 1, 1)

    def test_get_domain_timeline_data_no_dates(self):
        """Test domain timeline with domains missing dates."""
        domain = Mock()
        domain.domain_name = "example.com"
        domain.registration_date = None
        domain.expiration_date = None
        
        timeline = DashboardService.get_domain_timeline_data([domain])
        assert len(timeline) == 0

