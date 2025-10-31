"""
Tests for BaseService.

Tests base service functionality including session scope management
and result helper methods.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from contextlib import contextmanager

from infra_mgmt.services.BaseService import BaseService
from infra_mgmt.utils.SessionManager import SessionManager


class TestBaseService:
    """Test suite for BaseService."""

    @pytest.fixture
    def base_service(self):
        """Create BaseService instance for testing."""
        return BaseService()

    @pytest.fixture
    def mock_engine(self):
        """Create mock SQLAlchemy engine."""
        engine = MagicMock()
        return engine

    def test_result_success(self, base_service):
        """Test result helper method with success."""
        result = base_service.result(True, data={"key": "value"})
        
        assert result['success'] is True
        assert result['data'] == {"key": "value"}
        assert result['error'] is None

    def test_result_failure(self, base_service):
        """Test result helper method with failure."""
        result = base_service.result(False, error="Test error")
        
        assert result['success'] is False
        assert result['error'] == "Test error"
        assert result['data'] is None

    def test_result_no_data_or_error(self, base_service):
        """Test result helper method with no data or error."""
        result = base_service.result(True)
        
        assert result['success'] is True
        assert result['data'] is None
        assert result['error'] is None

    def test_session_scope_success(self, base_service, mock_engine):
        """Test session_scope context manager with successful operation."""
        mock_session = MagicMock()
        
        with patch('infra_mgmt.services.BaseService.SessionManager') as mock_sm:
            mock_sm.return_value.__enter__.return_value = mock_session
            mock_sm.return_value.__exit__.return_value = None
            
            with base_service.session_scope(mock_engine) as session:
                assert session == mock_session
                # Session should be returned
            
            # After context exit, commit should be called
            mock_session.commit.assert_called_once()
            mock_session.close.assert_called_once()

    def test_session_scope_exception(self, base_service, mock_engine):
        """Test session_scope context manager with exception."""
        mock_session = MagicMock()
        test_exception = Exception("Test error")
        mock_session.commit.side_effect = test_exception
        
        with patch('infra_mgmt.services.BaseService.SessionManager') as mock_sm:
            mock_sm.return_value.__enter__.return_value = mock_session
            mock_sm.return_value.__exit__.return_value = None
            
            with pytest.raises(Exception) as exc_info:
                with base_service.session_scope(mock_engine) as session:
                    raise test_exception
            
            assert exc_info.value == test_exception
            mock_session.rollback.assert_called_once()
            mock_session.close.assert_called_once()

    def test_session_scope_rollback_on_error(self, base_service, mock_engine):
        """Test session_scope performs rollback on error."""
        mock_session = MagicMock()
        
        with patch('infra_mgmt.services.BaseService.SessionManager') as mock_sm:
            mock_sm.return_value.__enter__.return_value = mock_session
            mock_sm.return_value.__exit__.return_value = None
            
            try:
                with base_service.session_scope(mock_engine) as session:
                    raise ValueError("Test error")
            except ValueError:
                pass
            
            mock_session.rollback.assert_called_once()

    def test_session_scope_always_closes(self, base_service, mock_engine):
        """Test session_scope always closes session even on error."""
        mock_session = MagicMock()
        
        with patch('infra_mgmt.services.BaseService.SessionManager') as mock_sm:
            mock_sm.return_value.__enter__.return_value = mock_session
            mock_sm.return_value.__exit__.return_value = None
            
            try:
                with base_service.session_scope(mock_engine) as session:
                    raise Exception("Test error")
            except Exception:
                pass
            
            # Session should be closed even after exception
            mock_session.close.assert_called_once()


