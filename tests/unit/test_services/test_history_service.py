"""
Tests for HistoryService.

Tests history retrieval, certificate tracking, and scan history functionality.
"""
import pytest
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch
from sqlalchemy.orm import Session

from infra_mgmt.services.HistoryService import HistoryService
from infra_mgmt.models import (
    Host, HostIP, CertificateBinding, Certificate,
    CertificateScan, CertificateTracking
)


class TestHistoryService:
    """Test suite for HistoryService."""

    @pytest.fixture
    def mock_engine(self):
        """Create mock SQLAlchemy engine."""
        engine = MagicMock()
        return engine

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock(spec=Session)
        return session

    @pytest.fixture
    def sample_host(self):
        """Create sample host for testing."""
        host = Mock(spec=Host)
        host.id = 1
        host.name = "server1.example.com"
        host.ip_addresses = []
        host.certificate_bindings = []
        return host

    @pytest.fixture
    def sample_ip(self, sample_host):
        """Create sample IP address for testing."""
        ip = Mock(spec=HostIP)
        ip.id = 1
        ip.ip_address = "192.168.1.1"
        ip.host = sample_host
        return ip

    def test_get_host_certificate_history_success(self, mock_engine, sample_host, sample_ip):
        """Test successful retrieval of host certificate history."""
        sample_host.ip_addresses = [sample_ip]
        
        with patch('infra_mgmt.services.HistoryService.SessionManager') as mock_sm:
            mock_sm.return_value.__enter__.return_value.query.return_value.options.return_value.all.return_value = [sample_host]
            
            result = HistoryService.get_host_certificate_history(mock_engine)
            
            assert result['success'] is True
            assert 'data' in result
            assert 'hosts' in result['data']
            assert 'host_options' in result['data']

    def test_get_host_certificate_history_error(self, mock_engine):
        """Test error handling in get_host_certificate_history."""
        with patch('infra_mgmt.services.HistoryService.SessionManager') as mock_sm:
            mock_sm.return_value.__enter__.side_effect = Exception("Database error")
            
            result = HistoryService.get_host_certificate_history(mock_engine)
            
            assert result['success'] is False
            assert 'error' in result

    def test_get_bindings_for_host_success(self, mock_engine, sample_host, sample_ip):
        """Test successful retrieval of bindings for a host."""
        binding = Mock(spec=CertificateBinding)
        binding.id = 1
        binding.certificate = Mock(spec=Certificate)
        
        with patch('infra_mgmt.services.HistoryService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_query = MagicMock()
            mock_query.options.return_value.filter.return_value.order_by.return_value.all.return_value = [binding]
            mock_session.query.return_value = mock_query
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = HistoryService.get_bindings_for_host(mock_engine, 1, 1)
            
            assert isinstance(result, list)
            assert len(result) == 1

    def test_get_bindings_for_host_error(self, mock_engine):
        """Test error handling in get_bindings_for_host."""
        with patch('infra_mgmt.services.HistoryService.SessionManager') as mock_sm:
            mock_sm.return_value.__enter__.side_effect = Exception("Database error")
            
            result = HistoryService.get_bindings_for_host(mock_engine, 1, 1)
            
            assert result == []

    def test_get_scan_history(self, mock_session):
        """Test retrieval of scan history."""
        scan1 = Mock(spec=CertificateScan)
        scan1.id = 1
        scan1.scan_date = datetime.now()
        scan1.certificate = Mock()
        scan1.host = Mock()
        
        scan2 = Mock(spec=CertificateScan)
        scan2.id = 2
        scan2.scan_date = datetime.now()
        scan2.certificate = Mock()
        scan2.host = Mock()
        
        # Properly chain the query methods
        mock_all = MagicMock()
        mock_all.all.return_value = [scan1, scan2]
        
        mock_order_by = MagicMock()
        mock_order_by.order_by.return_value = mock_all
        
        mock_options = MagicMock()
        mock_options.options.return_value = mock_order_by
        
        mock_outerjoin2 = MagicMock()
        mock_outerjoin2.outerjoin.return_value = mock_options
        
        mock_outerjoin1 = MagicMock()
        mock_outerjoin1.outerjoin.return_value = mock_outerjoin2
        
        mock_session.query.return_value = mock_outerjoin1
        
        result = HistoryService.get_scan_history(mock_session)
        
        assert len(result) == 2
        assert result[0].id == 1

    def test_get_cn_history(self, mock_session):
        """Test retrieval of common name history."""
        mock_query = MagicMock()
        # Need to properly chain the query methods
        mock_distinct = MagicMock()
        mock_order_by = MagicMock()
        mock_order_by.all.return_value = [
            ("example.com",),
            ("test.com",),
            (None,),  # Should be filtered
        ]
        mock_distinct.order_by.return_value = mock_order_by
        mock_query.distinct.return_value = mock_distinct
        mock_session.query.return_value = mock_query
        
        result = HistoryService.get_cn_history(mock_session)
        
        assert len(result) == 2
        assert "example.com" in result
        assert "test.com" in result

    def test_get_certificates_by_cn(self, mock_session):
        """Test retrieval of certificates by common name."""
        cert1 = Mock(spec=Certificate)
        cert1.id = 1
        cert1.common_name = "example.com"
        
        cert2 = Mock(spec=Certificate)
        cert2.id = 2
        cert2.common_name = "example.com"
        
        mock_query = MagicMock()
        mock_query.filter.return_value.order_by.return_value.all.return_value = [cert1, cert2]
        mock_session.query.return_value = mock_query
        
        result = HistoryService.get_certificates_by_cn(mock_session, "example.com")
        
        assert len(result) == 2
        assert result[0].common_name == "example.com"

    def test_add_certificate_tracking_entry_success(self, mock_session):
        """Test successful addition of certificate tracking entry."""
        planned_date = datetime.now().date()
        
        result = HistoryService.add_certificate_tracking_entry(
            mock_session, 1, "CHG001", planned_date, "planned", "Test notes"
        )
        
        assert result['success'] is True
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    def test_add_certificate_tracking_entry_error(self, mock_session):
        """Test error handling in add_certificate_tracking_entry."""
        from sqlalchemy.exc import SQLAlchemyError
        
        mock_session.add.side_effect = SQLAlchemyError("Database error")
        planned_date = datetime.now().date()
        
        result = HistoryService.add_certificate_tracking_entry(
            mock_session, 1, "CHG001", planned_date, "planned", "Test notes"
        )
        
        assert result['success'] is False
        assert 'error' in result
        mock_session.rollback.assert_called_once()

