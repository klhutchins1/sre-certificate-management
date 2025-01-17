import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import socket
import ssl
import OpenSSL.crypto
from cert_scanner.scanner import CertificateScanner, CertificateInfo

@pytest.fixture
def scanner():
    """Create a scanner instance with a mock logger"""
    logger = Mock()
    return CertificateScanner(logger=logger)

def test_get_base_domain(scanner):
    """Test extracting base domain from wildcard domain"""
    assert scanner._get_base_domain("*.google.com") == "google.com"
    assert scanner._get_base_domain("*.sub.google.com") == "sub.google.com"
    assert scanner._get_base_domain("google.com") is None
    assert scanner._get_base_domain("") is None

def test_expand_domains(scanner):
    """Test expanding domains list to include base domains"""
    domains = ["*.google.com", "example.com", "*.test.com"]
    expanded = scanner._expand_domains(domains)
    assert "google.com" in expanded
    assert "test.com" in expanded
    assert "example.com" in expanded
    assert "*.google.com" not in expanded
    assert "*.test.com" not in expanded
    assert len(expanded) == 3

@pytest.fixture
def mock_certificate():
    """Create a mock certificate for testing"""
    cert = OpenSSL.crypto.X509()
    
    # Set subject
    subject = cert.get_subject()
    subject.CN = b"test.com"
    
    # Set issuer
    issuer = cert.get_issuer()
    issuer.CN = b"Test CA"
    issuer.O = b"Test Organization"
    
    # Generate key pair for the certificate
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    cert.set_pubkey(key)
    
    # Set dates
    cert.gmtime_adj_notBefore(0)  # Valid from now
    cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
    
    # Set serial number
    cert.set_serial_number(12345)
    
    # Add SAN extension
    san_extension = OpenSSL.crypto.X509Extension(
        b"subjectAltName",
        False,
        b"DNS:test.com, DNS:www.test.com"
    )
    cert.add_extensions([san_extension])
    
    # Sign the certificate
    cert.sign(key, 'sha256')
    
    return cert

@patch('socket.socket')
@patch('ssl.create_default_context')
def test_get_certificate(mock_ssl_context, mock_socket, scanner):
    """Test retrieving certificate data"""
    # Mock SSL context and socket
    mock_context = Mock()
    mock_ssl_context.return_value = mock_context
    
    # Create a proper context manager mock
    mock_wrapped_socket = MagicMock()
    mock_context_manager = MagicMock()
    mock_context_manager.__enter__.return_value = mock_wrapped_socket
    mock_context.wrap_socket.return_value = mock_context_manager
    
    # Mock certificate data
    cert_data = b"mock certificate data"
    mock_wrapped_socket.getpeercert.return_value = cert_data
    
    # Test successful certificate retrieval
    result = scanner._get_certificate("test.com", 443)
    assert result == cert_data
    
    # Test connection error
    mock_wrapped_socket.connect.side_effect = ConnectionRefusedError()
    result = scanner._get_certificate("test.com", 443)
    assert result is None
    
    # Test timeout
    mock_wrapped_socket.connect.side_effect = socket.timeout()
    result = scanner._get_certificate("test.com", 443)
    assert result is None

@patch('socket.getaddrinfo')
def test_get_ip_addresses(mock_getaddrinfo, scanner):
    """Test IP address resolution"""
    # Mock getaddrinfo response
    mock_getaddrinfo.return_value = [
        (None, None, None, None, ('192.168.1.1', 443)),
        (None, None, None, None, ('192.168.1.2', 443))
    ]
    
    # Test hostname resolution
    ips = scanner._get_ip_addresses("test.com")
    assert len(ips) == 2
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips
    
    # Test IP address input
    ips = scanner._get_ip_addresses("192.168.1.1")
    assert len(ips) == 1
    assert ips[0] == "192.168.1.1"
    
    # Test failed resolution
    mock_getaddrinfo.side_effect = socket.gaierror()
    ips = scanner._get_ip_addresses("invalid.domain")
    assert len(ips) == 0

def test_process_certificate(scanner, mock_certificate):
    """Test processing certificate data"""
    # Convert mock certificate to binary
    cert_binary = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, mock_certificate)
    
    # Process certificate
    cert_info = scanner._process_certificate(cert_binary, "test.com", 443)
    
    # Verify certificate info
    assert isinstance(cert_info, CertificateInfo)
    assert cert_info.hostname == "test.com"
    assert cert_info.common_name == "test.com"
    assert cert_info.serial_number == "3039"  # hex of 12345
    assert "test.com" in cert_info.san
    assert "www.test.com" in cert_info.san
    assert cert_info.issuer.get("CN") == "Test CA"
    assert cert_info.issuer.get("O") == "Test Organization"

@patch('cert_scanner.scanner.CertificateScanner._get_certificate')
@patch('cert_scanner.scanner.CertificateScanner._process_certificate')
def test_scan_certificate(mock_process, mock_get_cert, scanner, mock_certificate):
    """Test complete certificate scanning"""
    # Mock certificate retrieval and processing
    mock_get_cert.return_value = b"mock certificate data"
    
    expected_info = CertificateInfo(
        hostname="test.com",
        ip_addresses=["192.168.1.1"],
        port=443,
        common_name="test.com",
        expiration_date=datetime.now(),
        serial_number="3039",
        thumbprint="dummy",
        san=["test.com"],
        issuer={"CN": "Test CA"},
        subject={"CN": "test.com"},
        valid_from=datetime.now()
    )
    mock_process.return_value = expected_info
    
    # Test successful scan
    result = scanner.scan_certificate("test.com")
    assert result == expected_info
    
    # Test wildcard domain
    result = scanner.scan_certificate("*.test.com")
    assert result is None
    
    # Test failed certificate retrieval
    mock_get_cert.return_value = None
    result = scanner.scan_certificate("test.com")
    assert result is None

def test_scan_domains(scanner):
    """Test scanning multiple domains"""
    with patch.object(scanner, 'scan_certificate') as mock_scan:
        # Mock successful scan
        mock_scan.return_value = Mock(spec=CertificateInfo)
        
        # Test with mix of normal and wildcard domains
        domains = ["*.google.com", "example.com", "*.test.com"]
        results = scanner.scan_domains(domains)
        
        # Should attempt to scan base domains and normal domains
        assert mock_scan.call_count == 3
        assert len(results) == 3
        
        # Verify it tried to scan the correct domains
        called_domains = [call.args[0] for call in mock_scan.call_args_list]
        assert "google.com" in called_domains
        assert "example.com" in called_domains
        assert "test.com" in called_domains 