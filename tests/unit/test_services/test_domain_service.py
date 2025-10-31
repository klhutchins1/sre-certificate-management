"""
Tests for DomainService.

Tests domain CRUD operations, domain hierarchy, recursive deletion,
and ignore list functionality.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from infra_mgmt.services.DomainService import DomainService, VirtualDomain
from infra_mgmt.models import Domain, IgnoredDomain
from infra_mgmt.utils.SessionManager import SessionManager


class TestDomainService:
    """Test suite for DomainService."""

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

    def test_get_domain_hierarchy_single_domain(self):
        """Test domain hierarchy with single domain."""
        domain = Mock()
        domain.domain_name = "example.com"
        
        root_domains, hierarchy = DomainService.get_domain_hierarchy([domain])
        
        assert len(root_domains) == 1
        assert root_domains[0].domain_name == "example.com"
        assert len(hierarchy) == 0

    def test_get_domain_hierarchy_with_subdomains(self):
        """Test domain hierarchy with subdomains."""
        root = Mock()
        root.domain_name = "example.com"
        
        sub1 = Mock()
        sub1.domain_name = "www.example.com"
        
        sub2 = Mock()
        sub2.domain_name = "api.example.com"
        
        domains = [root, sub1, sub2]
        root_domains, hierarchy = DomainService.get_domain_hierarchy(domains)
        
        assert len(root_domains) == 1
        assert root_domains[0].domain_name == "example.com"
        assert len(hierarchy.get("example.com", [])) == 2

    def test_get_domain_hierarchy_multi_level(self):
        """Test domain hierarchy with multiple levels."""
        root = Mock()
        root.domain_name = "example.com"
        
        sub1 = Mock()
        sub1.domain_name = "www.example.com"
        
        sub2 = Mock()
        sub2.domain_name = "v1.api.example.com"
        
        domains = [root, sub1, sub2]
        root_domains, hierarchy = DomainService.get_domain_hierarchy(domains)
        
        # Should have at least one root domain (example.com)
        assert len(root_domains) >= 1
        # Root domain should be in the result
        assert any(d.domain_name == "example.com" for d in root_domains if hasattr(d, 'domain_name'))

    def test_get_root_domain_info(self):
        """Test getting root domain information."""
        root = Mock()
        root.domain_name = "example.com"
        
        sub = Mock()
        sub.domain_name = "www.example.com"
        
        domains = [root, sub]
        result = DomainService.get_root_domain_info("www.example.com", domains)
        
        assert result is not None
        assert result.domain_name == "example.com"

    def test_delete_domain_success(self, mock_session):
        """Test successful domain deletion."""
        domain = Mock(spec=Domain)
        domain.id = 1
        
        result = DomainService.delete_domain(mock_session, domain)
        
        assert result['success'] is True
        mock_session.delete.assert_called_once_with(domain)
        mock_session.commit.assert_called_once()

    def test_delete_domain_error(self, mock_session):
        """Test error handling in domain deletion."""
        domain = Mock(spec=Domain)
        mock_session.commit.side_effect = SQLAlchemyError("Database error")
        
        result = DomainService.delete_domain(mock_session, domain)
        
        assert result['success'] is False
        assert 'error' in result
        mock_session.rollback.assert_called_once()

    def test_add_to_ignore_list_success(self, mock_session):
        """Test successful addition to ignore list."""
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        
        result = DomainService.add_to_ignore_list(mock_session, "test.example.com")
        
        assert result['success'] is True
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    def test_add_to_ignore_list_already_exists(self, mock_session):
        """Test adding domain that's already in ignore list."""
        existing = Mock(spec=IgnoredDomain)
        mock_session.query.return_value.filter_by.return_value.first.return_value = existing
        
        result = DomainService.add_to_ignore_list(mock_session, "test.example.com")
        
        assert result['success'] is False
        assert 'already' in result['error'].lower()

    def test_add_to_ignore_list_error(self, mock_session):
        """Test error handling in add_to_ignore_list."""
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session.commit.side_effect = SQLAlchemyError("Database error")
        
        result = DomainService.add_to_ignore_list(mock_session, "test.example.com")
        
        assert result['success'] is False
        assert 'error' in result
        mock_session.rollback.assert_called_once()

    def test_delete_domain_by_id_success(self, mock_engine):
        """Test successful deletion of domain by ID."""
        domain = Mock(spec=Domain)
        domain.id = 1
        domain.domain_name = "example.com"
        
        with patch('infra_mgmt.services.DomainService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = domain
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = DomainService.delete_domain_by_id(mock_engine, 1, recursive=False)
            
            assert result['success'] is True
            assert result['deleted_count'] == 1
            mock_session.delete.assert_called_once_with(domain)

    def test_delete_domain_by_id_not_found(self, mock_engine):
        """Test delete domain when domain doesn't exist."""
        with patch('infra_mgmt.services.DomainService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = None
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = DomainService.delete_domain_by_id(mock_engine, 999, recursive=False)
            
            assert result['success'] is False
            assert 'not found' in result['error'].lower()

    def test_delete_domain_by_id_recursive(self, mock_engine):
        """Test recursive deletion of domain with children."""
        parent = Mock(spec=Domain)
        parent.id = 1
        parent.domain_name = "example.com"
        
        child1 = Mock(spec=Domain)
        child1.id = 2
        child1.domain_name = "www.example.com"
        
        child2 = Mock(spec=Domain)
        child2.id = 3
        child2.domain_name = "api.example.com"
        
        with patch('infra_mgmt.services.DomainService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            
            # Mock get to return parent twice (before and after commit)
            def get_side_effect(entity, id):
                if id == 1:
                    return parent
                return None
            
            mock_session.get.side_effect = get_side_effect
            
            # Mock query for children
            def filter_by_side_effect(**kwargs):
                mock_query = MagicMock()
                if kwargs.get('parent_domain_id') == 1:
                    mock_query.all.return_value = [child1, child2]
                else:
                    mock_query.all.return_value = []
                return mock_query
            
            mock_query_base = MagicMock()
            mock_query_base.filter_by.side_effect = filter_by_side_effect
            mock_session.query.return_value = mock_query_base
            
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = DomainService.delete_domain_by_id(mock_engine, 1, recursive=True)
            
            assert result['success'] is True
            assert result['deleted_count'] == 3  # Parent + 2 children

    def test_get_all_child_domains(self, mock_session):
        """Test getting all child domains recursively."""
        child1 = Mock(spec=Domain)
        child1.id = 2
        child1.domain_name = "www.example.com"
        
        child2 = Mock(spec=Domain)
        child2.id = 3
        child2.domain_name = "api.example.com"
        
        grandchild = Mock(spec=Domain)
        grandchild.id = 4
        grandchild.domain_name = "v1.api.example.com"
        
        # Create mock query chain properly
        def create_mock_query():
            mock_query = MagicMock()
            return mock_query
        
        # Set up filter_by to return different results based on domain_id
        call_count = [0]
        def filter_by_side_effect(**kwargs):
            call_count[0] += 1
            domain_id = kwargs.get('parent_domain_id')
            mock_query = MagicMock()
            if domain_id == 1:
                mock_query.all.return_value = [child1, child2]
            elif domain_id == 2:
                mock_query.all.return_value = []
            elif domain_id == 3:
                mock_query.all.return_value = [grandchild]
            elif domain_id == 4:
                mock_query.all.return_value = []
            else:
                mock_query.all.return_value = []
            return mock_query
        
        mock_query_base = MagicMock()
        mock_query_base.filter_by.side_effect = filter_by_side_effect
        mock_session.query.return_value = mock_query_base
        
        result = DomainService._get_all_child_domains(mock_session, 1)
        
        assert len(result) == 3  # child1, child2, grandchild

    def test_get_child_domains_for_display_success(self, mock_engine):
        """Test getting child domains for display."""
        domain = Mock(spec=Domain)
        domain.id = 1
        domain.domain_name = "example.com"
        
        child1 = Mock(spec=Domain)
        child1.domain_name = "www.example.com"
        
        child2 = Mock(spec=Domain)
        child2.domain_name = "api.example.com"
        
        with patch('infra_mgmt.services.DomainService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.get.return_value = domain
            
            # Mock the recursive query properly (same as test_get_all_child_domains)
            def filter_by_side_effect(**kwargs):
                mock_query = MagicMock()
                if kwargs.get('parent_domain_id') == 1:
                    mock_query.all.return_value = [child1, child2]
                else:
                    mock_query.all.return_value = []
                return mock_query
            
            mock_query_base = MagicMock()
            mock_query_base.filter_by.side_effect = filter_by_side_effect
            mock_session.query.return_value = mock_query_base
            
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = DomainService.get_child_domains_for_display(mock_engine, 1)
            
            assert result['success'] is True
            assert result['count'] == 2
            assert 'www.example.com' in result['children']
            assert 'api.example.com' in result['children']

    def test_add_to_ignore_list_by_name_success(self, mock_engine):
        """Test adding domain to ignore list by name."""
        with patch('infra_mgmt.services.DomainService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.query.return_value.filter_by.return_value.first.return_value = None
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = DomainService.add_to_ignore_list_by_name(mock_engine, "test.example.com")
            
            assert result['success'] is True
            mock_session.add.assert_called_once()

    def test_get_filtered_domain_hierarchy(self, mock_engine):
        """Test getting filtered domain hierarchy."""
        domain1 = Mock(spec=Domain)
        domain1.domain_name = "example.com"
        domain1.is_active = True
        domain1.expiration_date = datetime.now() + timedelta(days=60)
        
        domain2 = Mock(spec=Domain)
        domain2.domain_name = "test.com"
        domain2.is_active = True
        domain2.expiration_date = datetime.now() + timedelta(days=20)
        
        ignored = Mock(spec=IgnoredDomain)
        ignored.pattern = "*.ignored.com"
        
        with patch('infra_mgmt.services.DomainService.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.query.side_effect = [
                MagicMock(options=MagicMock(return_value=MagicMock(order_by=MagicMock(return_value=MagicMock(all=lambda: [domain1, domain2]))))),
                MagicMock(all=lambda: [ignored])
            ]
            mock_sm.return_value.__enter__.return_value = mock_session
            
            result = DomainService.get_filtered_domain_hierarchy(mock_engine, "")
            
            assert result['success'] is True
            assert 'data' in result
            assert 'metrics' in result['data']

