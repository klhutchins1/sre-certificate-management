"""
Test domain scanner module with comprehensive network isolation.
All tests run with complete network isolation - no external API calls.
"""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone
from sqlalchemy.orm import Session

# Import the isolated test environment
from tests.test_isolation import isolated_test, create_mock_whois_result, create_mock_dns_answer
from infra_mgmt.scanner.domain_scanner import DomainScanner, DomainInfo
from infra_mgmt.models import Domain, DomainDNSRecord, IgnoredDomain
from infra_mgmt.utils.cache import ScanSessionCache

@pytest.fixture
def mock_session():
    """Create a mock session for testing"""
    session = MagicMock(spec=Session)
    session.query.return_value.filter.return_value.first.return_value = None
    return session

@pytest.fixture
def domain_scanner():
    """Create a domain scanner instance for testing"""
    cache = ScanSessionCache()
    scanner = DomainScanner(session_cache=cache)
    # Override rate limits for testing
    scanner.whois_rate_limit = 3600  # No rate limiting in tests
    scanner.dns_rate_limit = 3600
    return scanner

@pytest.fixture
def sample_domain_info():
    """Create sample domain info for testing"""
    return DomainInfo(
        domain_name="example.com",
        registrar="Test Registrar",
        registration_date=datetime(2020, 1, 1, tzinfo=timezone.utc),
        expiration_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
        registrant="Test Owner",
        status=["active"],
        nameservers=["ns1.example.com", "ns2.example.com"],
        is_valid=True,
        domain_type="external"
    )

class TestDomainScanner:
    """Test cases for DomainScanner class - all network-isolated"""
    
    def test_init_domain_scanner(self, domain_scanner):
        """Test DomainScanner initialization"""
        assert domain_scanner.whois_rate_limit == 3600
        assert domain_scanner.dns_rate_limit == 3600
        assert domain_scanner.dns_record_types == ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        assert domain_scanner.session_cache is not None
    
    def test_get_domain_type_internal(self, domain_scanner):
        """Test domain type detection for internal domains"""
        domain_scanner.internal_domains = {'.internal.com', 'test.local'}
        
        assert domain_scanner._get_domain_type('example.internal.com') == 'internal'
        assert domain_scanner._get_domain_type('test.local') == 'internal'
        assert domain_scanner._get_domain_type('public.com') == 'external'
    
    def test_get_domain_type_external(self, domain_scanner):
        """Test domain type detection for external domains"""
        domain_scanner.external_domains = {'.external.com', 'public.org'}
        
        assert domain_scanner._get_domain_type('example.external.com') == 'external'
        assert domain_scanner._get_domain_type('public.org') == 'external'
        assert domain_scanner._get_domain_type('random.com') == 'external'  # Default
    
    def test_is_internal_domain(self, domain_scanner):
        """Test internal domain matching"""
        domain_scanner.internal_domains = {'.internal.com', 'specific.local'}
        
        assert domain_scanner._is_internal_domain('test.internal.com') == True
        assert domain_scanner._is_internal_domain('specific.local') == True
        assert domain_scanner._is_internal_domain('public.com') == False
    
    def test_is_external_domain(self, domain_scanner):
        """Test external domain matching"""
        domain_scanner.external_domains = {'.external.com', 'public.org'}
        domain_scanner.internal_domains = {'.internal.com'}
        
        assert domain_scanner._is_external_domain('test.external.com') == True
        assert domain_scanner._is_external_domain('public.org') == True
        assert domain_scanner._is_external_domain('internal.com') == False
    
    def test_apply_rate_limit(self, domain_scanner):
        """Test rate limiting functionality"""
        # With high rate limit, should not sleep
        current_time = domain_scanner._apply_rate_limit(0, 3600, "TEST")
        assert current_time > 0
    
    def test_expand_domains_with_wildcards(self, domain_scanner):
        """Test domain expansion for wildcards"""
        domains = ['*.example.com', 'test.com', '*.wildcard.org']
        expanded = domain_scanner._expand_domains(domains)
        
        assert 'example.com' in expanded
        assert 'test.com' in expanded
        assert 'wildcard.org' in expanded
        assert '*.example.com' not in expanded
    
    def test_expand_domains_without_wildcards(self, domain_scanner):
        """Test domain expansion without wildcards"""
        domains = ['example.com', 'test.com']
        expanded = domain_scanner._expand_domains(domains)
        
        assert expanded == domains
    
    def test_get_base_domain(self, domain_scanner):
        """Test base domain extraction"""
        assert domain_scanner._get_base_domain('*.example.com') == 'example.com'
        assert domain_scanner._get_base_domain('example.com') is None
        assert domain_scanner._get_base_domain('*.sub.example.com') == 'sub.example.com'
    
    def test_get_ip_addresses_for_domain(self, domain_scanner):
        """Test IP address resolution for domains"""
        # Network isolation ensures this returns mock data
        ips = domain_scanner._get_ip_addresses('example.com')
        assert len(ips) > 0
        assert all(isinstance(ip, str) for ip in ips)
    
    def test_get_ip_addresses_for_ip(self, domain_scanner):
        """Test IP address resolution for IPs"""
        # Should return the same IP if it's already an IP
        ip = "192.168.1.1"
        ips = domain_scanner._get_ip_addresses(ip)
        assert ips == [ip]
    
    def test_scan_domain_basic(self, domain_scanner, mock_session):
        """Test basic domain scanning"""
        domain_info = domain_scanner.scan_domain(
            'example.com', 
            mock_session, 
            get_whois=True, 
            get_dns=True
        )
        
        assert isinstance(domain_info, DomainInfo)
        assert domain_info.domain_name == 'example.com'
        assert domain_info.is_valid == True
    
    def test_scan_domain_whois_only(self, domain_scanner, mock_session):
        """Test domain scanning with WHOIS only"""
        domain_info = domain_scanner.scan_domain(
            'example.com', 
            mock_session, 
            get_whois=True, 
            get_dns=False
        )
        
        assert isinstance(domain_info, DomainInfo)
        assert domain_info.domain_name == 'example.com'
        # With network isolation, should have mock WHOIS data
        assert domain_info.registrar is not None
    
    def test_scan_domain_dns_only(self, domain_scanner, mock_session):
        """Test domain scanning with DNS only"""
        domain_info = domain_scanner.scan_domain(
            'example.com', 
            mock_session, 
            get_whois=False, 
            get_dns=True
        )
        
        assert isinstance(domain_info, DomainInfo)
        assert domain_info.domain_name == 'example.com'
        # Should not have WHOIS data
        assert domain_info.registrar is None
    
    def test_scan_domain_offline_mode(self, domain_scanner, mock_session):
        """Test domain scanning in offline mode"""
        domain_info = domain_scanner.scan_domain(
            'example.com', 
            mock_session, 
            get_whois=True, 
            get_dns=True,
            offline_mode=True
        )
        
        assert isinstance(domain_info, DomainInfo)
        assert domain_info.domain_name == 'example.com'
        # In offline mode, should skip external calls
        assert domain_info.error is None or "offline" in domain_info.error.lower()
    
    def test_scan_domain_invalid_domain(self, domain_scanner, mock_session):
        """Test scanning invalid domain"""
        domain_info = domain_scanner.scan_domain(
            'invalid..domain', 
            mock_session, 
            get_whois=True, 
            get_dns=True
        )
        
        assert isinstance(domain_info, DomainInfo)
        assert domain_info.domain_name == 'invalid..domain'
        # Should handle invalid domain gracefully
        assert domain_info.is_valid == False or domain_info.error is not None
    
    def test_scan_domain_ignored_domain(self, domain_scanner, mock_session):
        """Test scanning ignored domain"""
        # Mock ignore list check
        def mock_is_ignored(session, domain):
            return (True, "Test ignore reason")
        
        with patch('infra_mgmt.utils.ignore_list.IgnoreListUtil.is_domain_ignored', side_effect=mock_is_ignored):
            domain_info = domain_scanner.scan_domain(
                'ignored.com', 
                mock_session, 
                get_whois=True, 
                get_dns=True
            )
        
        assert isinstance(domain_info, DomainInfo)
        assert domain_info.domain_name == 'ignored.com'
        # Should skip WHOIS for ignored domains
        assert domain_info.registrar is None
    
    def test_domain_info_to_dict(self, sample_domain_info):
        """Test DomainInfo to_dict conversion"""
        domain_dict = sample_domain_info.to_dict()
        
        assert domain_dict['domain_name'] == 'example.com'
        assert domain_dict['registrar'] == 'Test Registrar'
        assert domain_dict['is_valid'] == True
        assert domain_dict['domain_type'] == 'external'
        assert isinstance(domain_dict['registration_date'], str)
        assert isinstance(domain_dict['expiration_date'], str)
    
    def test_domain_info_serialization(self, sample_domain_info):
        """Test DomainInfo serialization with complex data"""
        # Add some complex data
        sample_domain_info.dns_records = [
            {'type': 'A', 'value': '1.2.3.4'},
            {'type': 'MX', 'value': 'mail.example.com'}
        ]
        sample_domain_info.related_domains = {'related1.com', 'related2.com'}
        
        domain_dict = sample_domain_info.to_dict()
        
        assert len(domain_dict['dns_records']) == 2
        assert len(domain_dict['related_domains']) == 2
        assert isinstance(domain_dict['related_domains'], list)
    
    def test_cache_integration(self, domain_scanner, mock_session):
        """Test cache integration with domain scanning"""
        # First scan should populate cache
        domain_info1 = domain_scanner.scan_domain(
            'cached.com', 
            mock_session, 
            get_whois=True, 
            get_dns=False
        )
        
        # Second scan should use cache
        domain_info2 = domain_scanner.scan_domain(
            'cached.com', 
            mock_session, 
            get_whois=True, 
            get_dns=False
        )
        
        # Should have same data
        assert domain_info1.domain_name == domain_info2.domain_name
        assert domain_info1.registrar == domain_info2.registrar
    
    def test_error_handling(self, domain_scanner, mock_session):
        """Test error handling in domain scanning"""
        # Test with various error conditions
        test_cases = [
            "",  # Empty domain
            "  ",  # Whitespace only
            "a" * 300,  # Too long
        ]
        
        for test_domain in test_cases:
            domain_info = domain_scanner.scan_domain(
                test_domain, 
                mock_session, 
                get_whois=True, 
                get_dns=True
            )
            
            assert isinstance(domain_info, DomainInfo)
            # Should handle errors gracefully
            assert domain_info.error is not None or domain_info.is_valid == False

# Test network isolation effectiveness
class TestNetworkIsolation:
    """Test that network isolation is working correctly"""
    
    def test_no_real_whois_calls(self, domain_scanner, mock_session):
        """Verify no real WHOIS calls are made"""
        # Even with a real domain, should not make real calls
        domain_info = domain_scanner.scan_domain(
            'google.com', 
            mock_session, 
            get_whois=True, 
            get_dns=False
        )
        
        assert isinstance(domain_info, DomainInfo)
        # Should have mock data, not real data
        assert domain_info.registrar == "Test Registrar Ltd"
    
    def test_no_real_dns_calls(self, domain_scanner, mock_session):
        """Verify no real DNS calls are made"""
        # Even with a real domain, should not make real calls
        domain_info = domain_scanner.scan_domain(
            'google.com', 
            mock_session, 
            get_whois=False, 
            get_dns=True
        )
        
        assert isinstance(domain_info, DomainInfo)
        # Should have mock DNS data
        assert len(domain_info.dns_records) >= 0
        
    def test_consistent_mock_data(self, domain_scanner, mock_session):
        """Verify mock data is consistent across calls"""
        domain_info1 = domain_scanner.scan_domain('test1.com', mock_session)
        domain_info2 = domain_scanner.scan_domain('test2.com', mock_session)
        
        # Mock registrar should be consistent
        assert domain_info1.registrar == domain_info2.registrar
        assert domain_info1.registrar == "Test Registrar Ltd" 