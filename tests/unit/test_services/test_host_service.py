"""
Tests for HostService.

Tests host CRUD operations, IP management, and certificate binding operations.
"""
import pytest
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from infra_mgmt.services.HostService import HostService
from infra_mgmt.models import Host, HostIP, CertificateBinding
from infra_mgmt.utils.SessionManager import SessionManager


class TestHostService:
    """Test suite for HostService."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock(spec=Session)
        return session

    @pytest.fixture
    def mock_engine(self):
        """Create mock SQLAlchemy engine."""
        engine = MagicMock()
        return engine

    def test_add_host_with_ips_success(self, mock_session):
        """Test successful addition of host with IP addresses."""
        new_host = Mock(spec=Host)
        new_host.id = 1
        new_host.name = "server1.example.com"
        
        mock_session.add = MagicMock()
        mock_session.flush = MagicMock()
        mock_session.commit = MagicMock()
        
        # Mock the Host constructor to return our mock
        with patch('infra_mgmt.services.HostService.Host') as mock_host_class, \
             patch('infra_mgmt.services.HostService.HostIP') as mock_ip_class:
            mock_host_class.return_value = new_host
            mock_ip_class.return_value = Mock(spec=HostIP)
            
            result = HostService.add_host_with_ips(
                mock_session,
                "server1.example.com",
                "Server",
                "Production",
                "Test server",
                ["192.168.1.1", "192.168.1.2"]
            )
            
            assert result['success'] is True
            assert result['host_id'] == 1
            assert mock_session.add.call_count >= 3  # Host + 2 IPs
            mock_session.commit.assert_called_once()

    def test_add_host_with_ips_empty_ips(self, mock_session):
        """Test adding host with empty IP list."""
        new_host = Mock(spec=Host)
        new_host.id = 1
        
        with patch('infra_mgmt.services.HostService.Host') as mock_host_class:
            mock_host_class.return_value = new_host
            
            result = HostService.add_host_with_ips(
                mock_session,
                "server1.example.com",
                "Server",
                "Production",
                "Test server",
                []
            )
            
            assert result['success'] is True
            # Should only add host, no IPs
            assert mock_session.add.call_count == 1

    def test_add_host_with_ips_database_error(self, mock_session):
        """Test error handling when database operation fails."""
        mock_session.commit.side_effect = SQLAlchemyError("Database error")
        
        with patch('infra_mgmt.services.HostService.Host') as mock_host_class:
            mock_host_class.return_value = Mock(spec=Host)
            
            result = HostService.add_host_with_ips(
                mock_session,
                "server1.example.com",
                "Server",
                "Production",
                "Test server",
                ["192.168.1.1"]
            )
            
            assert result['success'] is False
            assert 'error' in result
            mock_session.rollback.assert_called_once()

    def test_update_binding_platform_success(self, mock_session):
        """Test successful update of binding platform."""
        binding = Mock(spec=CertificateBinding)
        binding.id = 1
        binding.platform = "F5"
        
        mock_session.get.return_value = binding
        
        result = HostService.update_binding_platform(mock_session, 1, "Akamai")
        
        assert result['success'] is True
        assert binding.platform == "Akamai"
        mock_session.commit.assert_called_once()

    def test_update_binding_platform_not_found(self, mock_session):
        """Test update binding platform when binding doesn't exist."""
        mock_session.get.return_value = None
        
        result = HostService.update_binding_platform(mock_session, 999, "F5")
        
        assert result['success'] is False
        assert 'error' in result
        assert 'not found' in result['error'].lower()

    def test_update_binding_platform_error(self, mock_session):
        """Test error handling in update_binding_platform."""
        binding = Mock(spec=CertificateBinding)
        mock_session.get.return_value = binding
        mock_session.commit.side_effect = SQLAlchemyError("Database error")
        
        result = HostService.update_binding_platform(mock_session, 1, "F5")
        
        assert result['success'] is False
        assert 'error' in result
        mock_session.rollback.assert_called_once()

    def test_delete_binding_success(self, mock_session):
        """Test successful deletion of binding."""
        binding = Mock(spec=CertificateBinding)
        binding.id = 1
        
        mock_session.get.return_value = binding
        
        result = HostService.delete_binding(mock_session, 1)
        
        assert result['success'] is True
        mock_session.delete.assert_called_once_with(binding)
        mock_session.commit.assert_called_once()

    def test_delete_binding_not_found(self, mock_session):
        """Test delete binding when binding doesn't exist."""
        mock_session.get.return_value = None
        
        result = HostService.delete_binding(mock_session, 999)
        
        assert result['success'] is False
        assert 'error' in result
        assert 'not found' in result['error'].lower()

    def test_delete_binding_error(self, mock_session):
        """Test error handling in delete_binding."""
        binding = Mock(spec=CertificateBinding)
        mock_session.get.return_value = binding
        mock_session.commit.side_effect = SQLAlchemyError("Database error")
        
        result = HostService.delete_binding(mock_session, 1)
        
        assert result['success'] is False
        assert 'error' in result
        mock_session.rollback.assert_called_once()

    def test_delete_host_by_id_success(self, mock_engine):
        """Test successful deletion of host by ID."""
        host = Mock(spec=Host)
        host.id = 1
        
        with patch('infra_mgmt.services.HostService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = host
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = HostService.delete_host_by_id(mock_engine, 1)
            
            assert result['success'] is True
            mock_session.delete.assert_called_once_with(host)
            mock_session.commit.assert_called_once()

    def test_delete_host_by_id_not_found(self, mock_engine):
        """Test delete host when host doesn't exist."""
        with patch('infra_mgmt.services.HostService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = None
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = HostService.delete_host_by_id(mock_engine, 999)
            
            assert result['success'] is False
            assert 'error' in result
            assert 'not found' in result['error'].lower()

    def test_delete_host_by_id_error(self, mock_engine):
        """Test error handling in delete_host_by_id."""
        host = Mock(spec=Host)
        
        with patch('infra_mgmt.services.HostService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = host
            mock_session.delete.side_effect = Exception("Database error")
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = HostService.delete_host_by_id(mock_engine, 1)
            
            assert result['success'] is False
            assert 'error' in result

