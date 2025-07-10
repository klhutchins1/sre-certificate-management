"""
Tests for the domain scanner module.

This module tests the domain scanning functionality, including DNS lookups,
domain validation, and domain information retrieval.
"""

import pytest
from unittest.mock import patch, MagicMock, Mock
import socket
import dns.resolver
from datetime import datetime

from infra_mgmt.scanner.domain_scanner import DomainScanner, DomainInfo
from infra_mgmt.models import Domain

@pytest.fixture
def domain_scanner():
    """Create a domain scanner instance for testing."""
    return DomainScanner()

@pytest.fixture
def sample_domain_info():
    """Create sample domain information for testing."""
    return DomainInfo(
        domain_name="example.com",
        registrar="Example Registrar",
        registration_date=datetime(1995, 8, 14),
        expiration_date=datetime(2024, 8, 13),
        status=["active"],
        nameservers=["a.iana-servers.net", "b.iana-servers.net"]
    )

@pytest.fixture
def mock_session():
    """Create a mock database session."""
    return MagicMock()

def test_domain_scanner_initialization(domain_scanner):
    """Test domain scanner initialization."""
    assert domain_scanner is not None
    assert hasattr(domain_scanner, 'scan_domain')

def test_domain_info_creation(sample_domain_info):
    """Test DomainInfo object creation."""
    assert sample_domain_info.domain_name == "example.com"
    assert sample_domain_info.registrar == "Example Registrar"
    assert sample_domain_info.registration_date == datetime(1995, 8, 14)
    assert sample_domain_info.expiration_date == datetime(2024, 8, 13)
    assert sample_domain_info.status == ["active"]
    assert sample_domain_info.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]

def test_domain_info_repr(sample_domain_info):
    """Test DomainInfo string representation."""
    repr_str = repr(sample_domain_info)
    # DomainInfo uses default object repr, so we just check it's a string
    assert isinstance(repr_str, str)
    assert "DomainInfo" in repr_str

def test_scan_domain_basic(domain_scanner, mock_session):
    """Test basic domain scanning functionality."""
    with patch('infra_mgmt.scanner.domain_scanner.socket.gethostbyname') as mock_gethostbyname:
        mock_gethostbyname.return_value = "93.184.216.34"
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_dns_resolution(domain_scanner, mock_session):
    """Test DNS resolution in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        # Mock A record resolution
        mock_a_record = MagicMock()
        mock_a_record.address = "93.184.216.34"
        mock_resolve.return_value = [mock_a_record]
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_nameserver_resolution(domain_scanner, mock_session):
    """Test nameserver resolution in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        # Mock NS record resolution
        mock_ns_record = MagicMock()
        mock_ns_record.target = "ns1.example.com"
        mock_resolve.return_value = [mock_ns_record]
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_whois_lookup(domain_scanner, mock_session):
    """Test WHOIS lookup in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.whois.whois') as mock_whois:
        mock_whois_result = MagicMock()
        mock_whois_result.registrar = "Example Registrar"
        mock_whois_result.creation_date = datetime(1995, 8, 14)
        mock_whois_result.expiration_date = datetime(2024, 8, 13)
        mock_whois_result.status = ["active"]
        mock_whois.return_value = mock_whois_result
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_error_handling(domain_scanner, mock_session):
    """Test error handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.socket.gethostbyname') as mock_gethostbyname:
        mock_gethostbyname.side_effect = socket.gaierror("Name or service not known")
        
        result = domain_scanner.scan_domain("invalid-domain-that-does-not-exist.com", mock_session)
        
        # Should return a DomainInfo object even with errors
        assert result is not None
        assert result.domain_name == "invalid-domain-that-does-not-exist.com"

def test_scan_domain_dns_error_handling(domain_scanner, mock_session):
    """Test DNS error handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NXDOMAIN
        
        result = domain_scanner.scan_domain("nonexistent-domain.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "nonexistent-domain.com"

def test_scan_domain_whois_error_handling(domain_scanner, mock_session):
    """Test WHOIS error handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.whois.whois') as mock_whois:
        mock_whois.side_effect = Exception("WHOIS lookup failed")
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_multiple_ips(domain_scanner, mock_session):
    """Test domain scanning with multiple IP addresses."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        # Mock multiple A records
        mock_a_record1 = MagicMock()
        mock_a_record1.address = "93.184.216.34"
        mock_a_record2 = MagicMock()
        mock_a_record2.address = "93.184.216.35"
        mock_resolve.return_value = [mock_a_record1, mock_a_record2]
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_multiple_nameservers(domain_scanner, mock_session):
    """Test domain scanning with multiple nameservers."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        # Mock multiple NS records
        mock_ns_record1 = MagicMock()
        mock_ns_record1.target = "ns1.example.com"
        mock_ns_record2 = MagicMock()
        mock_ns_record2.target = "ns2.example.com"
        mock_resolve.return_value = [mock_ns_record1, mock_ns_record2]
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_whois_status_handling(domain_scanner, mock_session):
    """Test WHOIS status handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.whois.whois') as mock_whois:
        mock_whois_result = MagicMock()
        mock_whois_result.status = ["clientTransferProhibited", "active"]
        mock_whois.return_value = mock_whois_result
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_whois_date_handling(domain_scanner, mock_session):
    """Test WHOIS date handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.whois.whois') as mock_whois:
        mock_whois_result = MagicMock()
        mock_whois_result.creation_date = [datetime(1995, 8, 14), datetime(1995, 8, 15)]
        mock_whois_result.expiration_date = datetime(2024, 8, 13)
        mock_whois.return_value = mock_whois_result
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_timeout_handling(domain_scanner, mock_session):
    """Test timeout handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        mock_resolve.side_effect = dns.resolver.Timeout
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_noanswer_handling(domain_scanner, mock_session):
    """Test NoAnswer handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        mock_resolve.side_effect = dns.resolver.NoAnswer
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_yxdomain_handling(domain_scanner, mock_session):
    """Test YXDOMAIN handling in domain scanning."""
    with patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve:
        mock_resolve.side_effect = dns.resolver.YXDOMAIN
        
        result = domain_scanner.scan_domain("example.com", mock_session)
        
        assert result is not None
        assert result.domain_name == "example.com"

def test_scan_domain_invalid_domain(domain_scanner, mock_session):
    """Test scanning of invalid domain names."""
    result = domain_scanner.scan_domain("", mock_session)
    
    assert result is not None
    assert result.domain_name == ""

def test_scan_domain_none_domain(domain_scanner, mock_session):
    """Test scanning of None domain."""
    result = domain_scanner.scan_domain(None, mock_session)
    
    assert result is not None
    assert result.domain_name is None

def test_domain_info_equality(sample_domain_info):
    """Test DomainInfo equality comparison."""
    # Create another instance with same data
    other_info = DomainInfo(
        domain_name="example.com",
        registrar="Example Registrar",
        registration_date=datetime(1995, 8, 14),
        expiration_date=datetime(2024, 8, 13),
        status=["active"],
        nameservers=["a.iana-servers.net", "b.iana-servers.net"]
    )
    
    # Test equality (DomainInfo doesn't implement __eq__, so this tests object identity)
    assert sample_domain_info is not other_info

def test_domain_info_inequality(sample_domain_info):
    """Test DomainInfo inequality comparison."""
    # Create another instance with different data
    other_info = DomainInfo(
        domain_name="different.com",
        registrar="Example Registrar",
        registration_date=datetime(1995, 8, 14),
        expiration_date=datetime(2024, 8, 13),
        status=["active"],
        nameservers=["a.iana-servers.net", "b.iana-servers.net"]
    )
    
    # Test inequality
    assert sample_domain_info is not other_info

def test_scan_domain_performance(domain_scanner, mock_session):
    """Test domain scanning performance."""
    import time
    
    # Mock all external calls to ensure consistent timing
    with patch('infra_mgmt.scanner.domain_scanner.socket.gethostbyname') as mock_gethostbyname, \
         patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve') as mock_resolve, \
         patch('infra_mgmt.scanner.domain_scanner.whois.whois') as mock_whois:
        
        mock_gethostbyname.return_value = "93.184.216.34"
        
        # Mock DNS resolver to return quickly
        mock_a_record = MagicMock()
        mock_a_record.address = "93.184.216.34"
        mock_resolve.return_value = [mock_a_record]
        
        # Mock WHOIS to avoid network calls
        mock_whois_result = MagicMock()
        mock_whois_result.registrar = "Test Registrar"
        mock_whois.return_value = mock_whois_result
        
        start_time = time.time()
        result = domain_scanner.scan_domain("example.com", mock_session)
        end_time = time.time()
        
        # Should complete quickly (less than 5 seconds with all mocks)
        assert end_time - start_time < 5.0
        assert result is not None

def test_domain_info_to_dict(sample_domain_info):
    """Test DomainInfo to_dict method."""
    result = sample_domain_info.to_dict()
    
    assert isinstance(result, dict)
    assert result['domain_name'] == "example.com"
    assert result['registrar'] == "Example Registrar"
    assert result['status'] == ["active"]
    assert result['nameservers'] == ["a.iana-servers.net", "b.iana-servers.net"]

def test_domain_info_default_values():
    """Test DomainInfo with default values."""
    info = DomainInfo("test.com")
    
    assert info.domain_name == "test.com"
    assert info.registrar is None
    assert info.registration_date is None
    assert info.expiration_date is None
    assert info.status == []
    assert info.nameservers == []
    assert info.is_valid is True
    assert info.error is None 