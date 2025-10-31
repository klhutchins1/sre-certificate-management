"""
Tests for IgnoreListUtil.

Tests ignore list matching for domains and certificates.
"""
import pytest
from unittest.mock import Mock, MagicMock

from infra_mgmt.utils.ignore_list import IgnoreListUtil
from infra_mgmt.models import IgnoredDomain, IgnoredCertificate


class TestIgnoreListUtil:
    """Test suite for IgnoreListUtil."""

    @pytest.fixture
    def mock_session(self):
        """Create mock database session."""
        session = MagicMock()
        return session

    @pytest.fixture
    def sample_ignored_domain(self):
        """Create sample ignored domain pattern."""
        ignored = Mock(spec=IgnoredDomain)
        ignored.pattern = "*.test.com"
        ignored.reason = "Test domain"
        ignored.matches = Mock(return_value=False)
        return ignored

    def test_is_domain_ignored_exact_match(self, mock_session):
        """Test exact domain match in ignore list."""
        ignored = Mock(spec=IgnoredDomain)
        ignored.pattern = "example.com"
        ignored.reason = "Test reason"
        ignored.matches = Mock(return_value=True)
        
        mock_session.query.return_value.all.return_value = [ignored]
        
        is_ignored, reason = IgnoreListUtil.is_domain_ignored(mock_session, "example.com")
        
        assert is_ignored is True
        assert reason == "Test reason"

    def test_is_domain_ignored_wildcard_match(self, mock_session):
        """Test wildcard domain match in ignore list."""
        ignored = Mock(spec=IgnoredDomain)
        ignored.pattern = "*.test.com"
        ignored.reason = "Wildcard match"
        ignored.matches = Mock(return_value=True)
        
        mock_session.query.return_value.all.return_value = [ignored]
        
        is_ignored, reason = IgnoreListUtil.is_domain_ignored(mock_session, "www.test.com")
        
        assert is_ignored is True
        assert reason == "Wildcard match"

    def test_is_domain_ignored_contains_match(self, mock_session):
        """Test contains pattern match (*test*)."""
        ignored = Mock(spec=IgnoredDomain)
        ignored.pattern = "*test*"
        ignored.reason = "Contains match"
        ignored.matches = Mock(return_value=False)
        
        mock_session.query.return_value.all.return_value = [ignored]
        
        is_ignored, reason = IgnoreListUtil.is_domain_ignored(mock_session, "mytestdomain.com")
        
        assert is_ignored is True
        assert reason == "Contains match"

    def test_is_domain_ignored_no_match(self, mock_session):
        """Test domain not in ignore list."""
        ignored = Mock(spec=IgnoredDomain)
        ignored.pattern = "*.test.com"
        ignored.matches = Mock(return_value=False)
        
        mock_session.query.return_value.all.return_value = [ignored]
        
        is_ignored, reason = IgnoreListUtil.is_domain_ignored(mock_session, "example.com")
        
        assert is_ignored is False
        assert reason is None

    def test_is_domain_ignored_empty_list(self, mock_session):
        """Test ignore list check with empty ignore list."""
        mock_session.query.return_value.all.return_value = []
        
        is_ignored, reason = IgnoreListUtil.is_domain_ignored(mock_session, "example.com")
        
        assert is_ignored is False
        assert reason is None

    def test_is_domain_ignored_error_handling(self, mock_session):
        """Test error handling in is_domain_ignored."""
        mock_session.query.side_effect = Exception("Database error")
        
        is_ignored, reason = IgnoreListUtil.is_domain_ignored(mock_session, "example.com")
        
        assert is_ignored is False
        assert reason is None

    def test_is_certificate_ignored_exact_match(self, mock_session):
        """Test exact certificate CN match in ignore list."""
        ignored = Mock(spec=IgnoredCertificate)
        ignored.pattern = "example.com"
        ignored.reason = "Test certificate"
        ignored.matches = Mock(return_value=True)
        
        mock_session.query.return_value.all.return_value = [ignored]
        
        is_ignored, reason = IgnoreListUtil.is_certificate_ignored(mock_session, "example.com")
        
        assert is_ignored is True
        assert reason == "Test certificate"

    def test_is_certificate_ignored_wildcard_match(self, mock_session):
        """Test wildcard certificate CN match."""
        ignored = Mock(spec=IgnoredCertificate)
        ignored.pattern = "*.example.com"
        ignored.reason = "Wildcard certificate"
        ignored.matches = Mock(return_value=True)
        
        mock_session.query.return_value.all.return_value = [ignored]
        
        is_ignored, reason = IgnoreListUtil.is_certificate_ignored(mock_session, "www.example.com")
        
        assert is_ignored is True
        assert reason == "Wildcard certificate"

    def test_is_certificate_ignored_no_match(self, mock_session):
        """Test certificate CN not in ignore list."""
        ignored = Mock(spec=IgnoredCertificate)
        ignored.pattern = "*.test.com"
        ignored.matches = Mock(return_value=False)
        
        mock_session.query.return_value.all.return_value = [ignored]
        
        is_ignored, reason = IgnoreListUtil.is_certificate_ignored(mock_session, "example.com")
        
        assert is_ignored is False
        assert reason is None

    def test_is_certificate_ignored_empty_list(self, mock_session):
        """Test certificate ignore check with empty ignore list."""
        mock_session.query.return_value.all.return_value = []
        
        is_ignored, reason = IgnoreListUtil.is_certificate_ignored(mock_session, "example.com")
        
        assert is_ignored is False
        assert reason is None

    def test_is_certificate_ignored_error_handling(self, mock_session):
        """Test error handling in is_certificate_ignored."""
        mock_session.query.side_effect = Exception("Database error")
        
        is_ignored, reason = IgnoreListUtil.is_certificate_ignored(mock_session, "example.com")
        
        assert is_ignored is False
        assert reason is None


