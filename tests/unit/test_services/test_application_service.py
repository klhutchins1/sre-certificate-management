"""
Tests for ApplicationService.

Tests application CRUD operations, certificate binding, and availability checks.
"""
import pytest
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch
from sqlalchemy.exc import SQLAlchemyError

from infra_mgmt.services.ApplicationService import ApplicationService
from infra_mgmt.models import Application, CertificateBinding, Certificate
from infra_mgmt.utils.SessionManager import SessionManager


class TestApplicationService:
    """Test suite for ApplicationService."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock()
        return session

    @pytest.fixture
    def mock_engine(self):
        """Create mock SQLAlchemy engine."""
        engine = MagicMock()
        return engine

    @pytest.fixture
    def sample_application(self):
        """Create sample application for testing."""
        app = Mock(spec=Application)
        app.id = 1
        app.name = "Test App"
        app.app_type = "Web"
        app.description = "Test Description"
        app.owner = "Test Owner"
        app.created_at = datetime.now()
        return app

    def test_add_application_success(self, mock_session, sample_application):
        """Test successful addition of application."""
        mock_session.query.return_value.filter.return_value.first.return_value = None
        
        with patch('infra_mgmt.services.ApplicationService.Application') as mock_app_class:
            mock_app_class.return_value = sample_application
            sample_application.id = 1
            
            result = ApplicationService.add_application(
                mock_session,
                "Test App",
                "Web",
                "Test Description",
                "Test Owner"
            )
            
            assert result['success'] is True
            assert result['app_id'] == 1
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()

    def test_add_application_duplicate_name(self, mock_session, sample_application):
        """Test adding application with duplicate name."""
        mock_session.query.return_value.filter.return_value.first.return_value = sample_application
        
        result = ApplicationService.add_application(
            mock_session,
            "Test App",
            "Web",
            "Test Description",
            "Test Owner"
        )
        
        assert result['success'] is False
        assert 'already exists' in result['error'].lower()
        mock_session.add.assert_not_called()

    def test_add_application_database_error(self, mock_session):
        """Test error handling when database operation fails."""
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_session.commit.side_effect = SQLAlchemyError("Database error")
        
        with patch('infra_mgmt.services.ApplicationService.Application'):
            result = ApplicationService.add_application(
                mock_session,
                "Test App",
                "Web",
                "Test Description",
                "Test Owner"
            )
            
            assert result['success'] is False
            assert 'error' in result
            mock_session.rollback.assert_called_once()

    def test_update_application_success(self, mock_engine, sample_application):
        """Test successful update of application."""
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = sample_application
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.update_application(
                mock_engine, 1, "Updated App", "API", "Updated Description", "New Owner"
            )
            
            assert result['success'] is True
            assert sample_application.name == "Updated App"
            assert sample_application.app_type == "API"
            assert sample_application.description == "Updated Description"
            assert sample_application.owner == "New Owner"
            mock_session.commit.assert_called_once()

    def test_update_application_not_found(self, mock_engine):
        """Test update application when application doesn't exist."""
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = None
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.update_application(
                mock_engine, 999, "Updated App", "API", "Updated Description", "New Owner"
            )
            
            assert result['success'] is False
            assert 'not found' in result['error'].lower()

    def test_update_application_error(self, mock_engine):
        """Test error handling in update_application."""
        app = Mock(spec=Application)
        
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = app
            mock_session.commit.side_effect = Exception("Database error")
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.update_application(
                mock_engine, 1, "Updated App", "API", "Updated Description", "New Owner"
            )
            
            assert result['success'] is False
            assert 'error' in result

    def test_delete_application_success(self, mock_engine, sample_application):
        """Test successful deletion of application."""
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = sample_application
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.delete_application(mock_engine, 1)
            
            assert result['success'] is True
            mock_session.delete.assert_called_once_with(sample_application)
            mock_session.commit.assert_called_once()

    def test_delete_application_not_found(self, mock_engine):
        """Test delete application when application doesn't exist."""
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = None
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.delete_application(mock_engine, 999)
            
            assert result['success'] is False
            assert 'not found' in result['error'].lower()

    def test_delete_application_error(self, mock_engine):
        """Test error handling in delete_application."""
        app = Mock(spec=Application)
        
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = app
            mock_session.delete.side_effect = Exception("Database error")
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.delete_application(mock_engine, 1)
            
            assert result['success'] is False
            assert 'error' in result

    def test_remove_binding_success(self, mock_engine):
        """Test successful removal of certificate binding."""
        binding = Mock(spec=CertificateBinding)
        binding.id = 1
        
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = binding
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.remove_binding(mock_engine, 1)
            
            assert result['success'] is True
            mock_session.delete.assert_called_once_with(binding)
            mock_session.commit.assert_called_once()

    def test_remove_binding_not_found(self, mock_engine):
        """Test remove binding when binding doesn't exist."""
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = None
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.remove_binding(mock_engine, 999)
            
            assert result['success'] is False
            assert 'not found' in result['error'].lower()

    def test_bind_certificates_success(self, mock_engine, sample_application):
        """Test successful binding of certificates to application."""
        cert1 = Mock(spec=Certificate)
        cert1.id = 1
        
        cert2 = Mock(spec=Certificate)
        cert2.id = 2
        
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm, \
             patch('infra_mgmt.services.ApplicationService.CertificateBinding') as mock_binding_class:
            mock_session = MagicMock()
            mock_session.get.side_effect = [sample_application, cert1, cert2]
            mock_binding = Mock(spec=CertificateBinding)
            mock_binding_class.return_value = mock_binding
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.bind_certificates(
                mock_engine, 1, [1, 2], "server"
            )
            
            assert result['success'] is True
            assert result['count'] == 2
            assert mock_session.add.call_count == 2
            mock_session.commit.assert_called_once()

    def test_bind_certificates_app_not_found(self, mock_engine):
        """Test bind certificates when application doesn't exist."""
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = None
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.bind_certificates(
                mock_engine, 999, [1, 2], "server"
            )
            
            assert result['success'] is False
            assert 'not found' in result['error'].lower()

    def test_bind_certificates_missing_cert(self, mock_engine, sample_application):
        """Test binding certificates where some certificates don't exist."""
        cert1 = Mock(spec=Certificate)
        cert1.id = 1
        
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm, \
             patch('infra_mgmt.services.ApplicationService.CertificateBinding') as mock_binding_class:
            mock_session = MagicMock()
            mock_session.get.side_effect = [sample_application, cert1, None]  # cert2 is None
            mock_binding = Mock(spec=CertificateBinding)
            mock_binding_class.return_value = mock_binding
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.bind_certificates(
                mock_engine, 1, [1, 2], "server"
            )
            
            assert result['success'] is True
            assert result['count'] == 1  # Only one certificate bound

    def test_get_available_certificates_success(self, mock_engine):
        """Test successful retrieval of available certificates."""
        cert1 = Mock(spec=Certificate)
        cert1.id = 1
        cert1.common_name = "example.com"
        
        cert2 = Mock(spec=Certificate)
        cert2.id = 2
        cert2.common_name = "test.com"
        
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_query = MagicMock()
            mock_query.join.return_value.filter.return_value.all.return_value = [cert1, cert2]
            mock_session.query.return_value = mock_query
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.get_available_certificates(mock_engine, 1)
            
            assert result['success'] is True
            assert 'data' in result
            assert len(result['data']) == 2

    def test_get_available_certificates_error(self, mock_engine):
        """Test error handling in get_available_certificates."""
        with patch('infra_mgmt.services.ApplicationService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.query.side_effect = Exception("Database error")
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = ApplicationService.get_available_certificates(mock_engine, 1)
            
            assert result['success'] is False
            assert 'error' in result


