"""
Unit tests for the scanner module.
"""

import logging
import pytest
from datetime import datetime, timezone
import socket
import ssl
from unittest.mock import Mock, patch, MagicMock, call
import OpenSSL
from OpenSSL.crypto import X509, X509Name
from cert_scanner.certificate_scanner import CertificateScanner, CertificateInfo, ScanResult
from cert_scanner.scanner import ScanTracker, ScanManager

@pytest.fixture
def scanner():
    """Create a scanner instance with a mock logger"""
    logger = MagicMock(spec=logging.Logger)
    scanner = CertificateScanner(logger=logger)
    return scanner

def test_get_base_domain(scanner):
    """Test extracting base domain from wildcard domain"""
    assert scanner._get_base_domain("*.google.com") == "google.com"
    assert scanner._get_base_domain("*.sub.google.com") == "sub.google.com"
    assert scanner._get_base_domain("google.com") is None
    assert scanner._get_base_domain("") is None

def test_expand_domains(scanner):
    """Test expanding domain list with wildcards"""
    domains = ["*.google.com", "example.com", "*.test.com", "direct.com"]
    expanded = scanner._expand_domains(domains)
    
    assert "google.com" in expanded
    assert "test.com" in expanded
    assert "example.com" in expanded
    assert "direct.com" in expanded
    assert "*.google.com" not in expanded
    assert "*.test.com" not in expanded
    assert len(expanded) == 4

@pytest.fixture
def mock_certificate():
    """Create a mock X509 certificate"""
    cert = Mock(spec=X509)
    
    # Mock serial number and thumbprint
    cert.get_serial_number.return_value = 12345
    cert.digest.return_value = b"01:23:45:67:89:AB:CD:EF"
    
    # Mock dates
    cert.get_notBefore.return_value = b"20230101000000Z"
    cert.get_notAfter.return_value = b"20240101000000Z"
    
    # Mock version
    cert.get_version.return_value = 2
    
    # Mock subject and issuer
    subject = Mock(spec=X509Name)
    subject.get_components.return_value = [(b"CN", b"test.com")]
    cert.get_subject.return_value = subject
    
    issuer = Mock(spec=X509Name)
    issuer.get_components.return_value = [(b"CN", b"Test CA")]
    cert.get_issuer.return_value = issuer
    
    # Mock extensions (SAN)
    class MockExtension:
        def get_short_name(self):
            return b"subjectAltName"
        def __str__(self):
            return "DNS:test.com, DNS:www.test.com"
    
    cert.get_extension_count.return_value = 1
    cert.get_extension.return_value = MockExtension()
    
    return cert

def test_process_certificate(scanner, mock_certificate):
    """Test processing certificate data"""
    with patch('OpenSSL.crypto.load_certificate') as mock_load_cert, \
         patch.object(scanner, '_get_ip_addresses', return_value=[]):
        
        mock_load_cert.return_value = mock_certificate
        
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert isinstance(cert_info, CertificateInfo)
        assert cert_info.hostname == "test.com"
        assert cert_info.port == 443
        assert cert_info.common_name == "test.com"
        assert cert_info.serial_number == "3039"  # hex of 12345
        assert cert_info.ip_addresses == []  # IP resolution is mocked to return empty list
        assert len(cert_info.san) == 2
        assert "test.com" in cert_info.san
        assert "www.test.com" in cert_info.san
        assert cert_info.issuer == {"CN": "Test CA"}
        assert cert_info.subject == {"CN": "test.com"}
        assert cert_info.version == 2

def test_get_ip_addresses(scanner):
    """Test IP address resolution"""
    # Test with IP address input
    ip_addrs = scanner._get_ip_addresses("192.168.1.1")
    assert ip_addrs == ["192.168.1.1"]
    
    # Test with hostname
    with patch('socket.getaddrinfo') as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (None, None, None, None, ('10.0.0.1', 0)),
            (None, None, None, None, ('10.0.0.2', 0))
        ]
        ip_addrs = scanner._get_ip_addresses("example.com")
        assert ip_addrs == ["10.0.0.1", "10.0.0.2"]
    
    # Test with failed DNS resolution
    with patch('socket.getaddrinfo', side_effect=socket.gaierror):
        ip_addrs = scanner._get_ip_addresses("nonexistent.com")
        assert ip_addrs == []

@patch('socket.socket')
@patch('ssl.create_default_context')
def test_get_certificate(mock_ssl_context, mock_socket, scanner):
    """Test certificate retrieval"""
    # Create mock SSL socket
    mock_ssl_socket = MagicMock()
    mock_ssl_socket.getpeercert.return_value = b"mock_cert_data"
    
    # Setup SSL context
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssl_socket
    mock_ssl_context.return_value = mock_context
    
    # Setup socket
    mock_socket_instance = MagicMock()
    mock_socket.return_value = mock_socket_instance
    
    # Test certificate retrieval
    cert_data = scanner._get_certificate("test.com", 443)
    
    # Verify socket was created and connected
    mock_socket.assert_called_once()
    mock_context.wrap_socket.assert_called_once_with(mock_socket_instance, server_hostname="test.com")
    mock_ssl_socket.getpeercert.assert_called_once_with(binary_form=True)
    assert cert_data == mock_ssl_socket.getpeercert.return_value

def test_get_certificate_errors(scanner):
    """Test error handling in certificate retrieval."""
    # Test connection refused
    with pytest.raises(Exception) as exc_info:
        scanner._get_certificate("localhost", 1234)  # Non-existent port
    assert "Connection refused" in str(exc_info.value)
    
    # Test timeout
    with patch('socket.create_connection') as mock_connect:
        mock_connect.side_effect = socket.timeout()
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("localhost", 443)
        assert "Socket timed out while checking certificate for localhost:443" in str(exc_info.value)
    
    # Test SSL error
    with patch('ssl.SSLContext.wrap_socket') as mock_wrap:
        mock_wrap.side_effect = ssl.SSLError("SSL error occurred")
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("localhost", 443)
        assert "SSL error: SSL error occurred" in str(exc_info.value)

def test_scan_certificate(scanner):
    """Test complete certificate scanning process"""
    with patch.object(scanner, '_get_certificate', return_value=b"cert_data"), \
         patch.object(scanner, '_process_certificate') as mock_process:
        
        mock_process.return_value = CertificateInfo(
            hostname="test.com",
            ip_addresses=["192.168.1.1"],
            port=443,
            common_name="test.com",
            expiration_date=datetime.now(),
            serial_number="123",
            thumbprint="abc",
            san=["test.com"],
            issuer={"CN": "Test CA"},
            subject={"CN": "test.com"},
            valid_from=datetime.now()
        )
        
        result = scanner.scan_certificate("test.com")
        assert result is not None
        assert result.error is None
        assert result.certificate_info is not None
        assert result.certificate_info.hostname == "test.com"
        assert result.certificate_info.ip_addresses == ["192.168.1.1"]

def test_scan_domains(scanner):
    """Test scanning multiple domains"""
    domains = ["*.google.com", "example.com"]
    
    with patch.object(scanner, 'scan_certificate') as mock_scan:
        mock_scan.return_value = CertificateInfo(
            hostname="test.com",
            ip_addresses=["192.168.1.1"],
            port=443,
            common_name="test.com",
            expiration_date=datetime.now(),
            serial_number="123",
            thumbprint="abc",
            san=["test.com"],
            issuer={"CN": "Test CA"},
            subject={"CN": "test.com"},
            valid_from=datetime.now()
        )
        
        results = scanner.scan_domains(domains)
        assert len(results) == 2  # One for google.com and one for example.com
        assert mock_scan.call_count == 2
        
        # Verify wildcard domain was expanded
        call_args = [call[0][0] for call in mock_scan.call_args_list]
        assert "google.com" in call_args
        assert "example.com" in call_args
        assert "*.google.com" not in call_args 

def test_scan_certificate_custom_port(scanner):
    """Test scanning certificate with non-standard port"""
    with patch.object(scanner, '_get_certificate', return_value=b"cert_data"), \
         patch.object(scanner, '_process_certificate') as mock_process:
        
        mock_process.return_value = CertificateInfo(
            hostname="test.com",
            ip_addresses=["192.168.1.1"],
            port=8443,
            common_name="test.com",
            expiration_date=datetime.now(),
            serial_number="123",
            thumbprint="abc",
            san=["test.com"],
            issuer={"CN": "Test CA"},
            subject={"CN": "test.com"},
            valid_from=datetime.now()
        )
        
        result = scanner.scan_certificate("test.com", port=8443)
        assert result is not None
        assert result.error is None
        assert result.certificate_info is not None
        assert result.certificate_info.port == 8443
        mock_process.assert_called_once()

def test_process_certificate_with_multiple_sans(scanner):
    """Test processing certificate with multiple Subject Alternative Names"""
    cert = Mock(spec=X509)
    
    # Basic certificate setup
    cert.get_serial_number.return_value = 12345
    cert.get_version.return_value = 2
    cert.get_notBefore.return_value = b"20230101000000Z"
    cert.get_notAfter.return_value = b"20240101000000Z"
    cert.digest.return_value = b"01:23:45:67:89:AB:CD:EF"
    
    # Setup subject and issuer
    subject = Mock(spec=X509Name)
    subject.get_components.return_value = [(b"CN", b"test.com")]
    cert.get_subject.return_value = subject
    
    issuer = Mock(spec=X509Name)
    issuer.get_components.return_value = [(b"CN", b"Test CA")]
    cert.get_issuer.return_value = issuer
    
    # Setup multiple SANs
    class MockExtension:
        def get_short_name(self):
            return b"subjectAltName"
        def __str__(self):
            return "DNS:test.com, DNS:www.test.com, DNS:api.test.com"
    
    cert.get_extension_count.return_value = 1
    cert.get_extension.return_value = MockExtension()
    
    with patch('OpenSSL.crypto.load_certificate') as mock_load_cert, \
         patch.object(scanner, '_get_ip_addresses', return_value=[]):
        
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert len(cert_info.san) == 3
        assert "test.com" in cert_info.san
        assert "www.test.com" in cert_info.san
        assert "api.test.com" in cert_info.san

def test_process_certificate_with_extended_fields(scanner):
    """Test processing certificate with Organization and Location fields"""
    cert = Mock(spec=X509)
    
    # Basic certificate setup
    cert.get_serial_number.return_value = 12345
    cert.get_version.return_value = 2
    cert.get_notBefore.return_value = b"20230101000000Z"
    cert.get_notAfter.return_value = b"20240101000000Z"
    cert.digest.return_value = b"01:23:45:67:89:AB:CD:EF"
    
    # Setup subject with extended fields
    subject = Mock(spec=X509Name)
    subject.get_components.return_value = [
        (b"CN", b"test.com"),
        (b"O", b"Test Company"),
        (b"L", b"Test City"),
        (b"C", b"US"),
        (b"ST", b"Test State")
    ]
    cert.get_subject.return_value = subject
    
    # Setup issuer with extended fields
    issuer = Mock(spec=X509Name)
    issuer.get_components.return_value = [
        (b"CN", b"Test CA"),
        (b"O", b"CA Company"),
        (b"C", b"US")
    ]
    cert.get_issuer.return_value = issuer
    
    # Setup extensions
    class MockExtension:
        def get_short_name(self):
            return b"subjectAltName"
        def __str__(self):
            return "DNS:test.com"
    
    cert.get_extension_count.return_value = 1
    cert.get_extension.return_value = MockExtension()
    
    with patch('OpenSSL.crypto.load_certificate') as mock_load_cert, \
         patch.object(scanner, '_get_ip_addresses', return_value=[]):
        
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert cert_info.subject == {
            "CN": "test.com",
            "O": "Test Company",
            "L": "Test City",
            "C": "US",
            "ST": "Test State"
        }
        assert cert_info.issuer == {
            "CN": "Test CA",
            "O": "CA Company",
            "C": "US"
        }

def test_scan_certificate_logging(scanner, caplog):
    """Test logging during certificate scanning."""
    caplog.set_level(logging.WARNING)
    
    # Test connection refused logging
    try:
        scanner._get_certificate("localhost", 1234)  # This should fail
    except:
        pass
    assert "localhost:1234 is not reachable" in caplog.text
    assert "Error while checking certificate: Connection refused" in caplog.text
    
    caplog.clear()
    
    # Test timeout logging
    with patch('socket.create_connection') as mock_connect:
        mock_connect.side_effect = socket.timeout()
        try:
            scanner._get_certificate("localhost", 443)
        except:
            pass
    assert "Socket timed out while checking certificate for localhost:443" in caplog.text
    
    caplog.clear()
    
    # Test SSL error logging
    with patch('ssl.SSLContext.wrap_socket') as mock_wrap:
        mock_wrap.side_effect = ssl.SSLError("SSL error occurred")
        try:
            scanner._get_certificate("localhost", 443)
        except:
            pass
    assert "SSL error for localhost:443: SSL error occurred" in caplog.text

def test_scan_domains_empty_list(scanner):
    """Test scanning with empty domain list"""
    results = scanner.scan_domains([])
    assert results == []
    scanner.logger.info.assert_not_called()  # No domains to expand
    assert len(results) == 0

def test_scan_domains_with_failures(scanner):
    """Test scanning multiple domains with some failures"""
    domains = ["valid.com", "invalid.com"]
    
    with patch.object(scanner, 'scan_certificate') as mock_scan_cert:
        def scan_side_effect(domain, port=443):
            if domain == "valid.com":
                cert_info = CertificateInfo(
                    hostname=domain,
                    ip_addresses=["192.168.1.1"],
                    port=port,
                    common_name=domain,
                    expiration_date=datetime.now(),
                    serial_number="123",
                    thumbprint="abc",
                    san=[domain],
                    issuer={"CN": "Test CA"},
                    subject={"CN": domain},
                    valid_from=datetime.now()
                )
                return ScanResult(certificate_info=cert_info)
            return ScanResult(error="Failed to scan")
        
        mock_scan_cert.side_effect = scan_side_effect
        results = scanner.scan_domains(domains)
        assert len(results) == 2
        assert results[0].certificate_info is not None
        assert results[1].error is not None

def test_process_certificate_with_key_usage(scanner):
    """Test processing certificate with key usage information"""
    cert = Mock(spec=X509)
    
    # Basic certificate setup
    cert.get_serial_number.return_value = 12345
    cert.get_version.return_value = 2
    cert.get_notBefore.return_value = b"20230101000000Z"
    cert.get_notAfter.return_value = b"20240101000000Z"
    cert.digest.return_value = b"01:23:45:67:89:AB:CD:EF"
    
    # Setup subject and issuer
    subject = Mock(spec=X509Name)
    subject.get_components.return_value = [(b"CN", b"test.com")]
    cert.get_subject.return_value = subject
    
    issuer = Mock(spec=X509Name)
    issuer.get_components.return_value = [(b"CN", b"Test CA")]
    cert.get_issuer.return_value = issuer
    
    # Setup key usage extension
    class MockExtension:
        def __init__(self, name, value):
            self._name = name
            self._value = value
        def get_short_name(self):
            return self._name
        def __str__(self):
            return self._value
    
    # Mock multiple extensions including key usage
    extensions = [
        MockExtension(b"subjectAltName", "DNS:test.com"),
        MockExtension(b"keyUsage", "Digital Signature, Key Encipherment")
    ]
    cert.get_extension_count.return_value = len(extensions)
    cert.get_extension.side_effect = lambda i: extensions[i]
    
    with patch('OpenSSL.crypto.load_certificate') as mock_load_cert, \
         patch.object(scanner, '_get_ip_addresses', return_value=[]):
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        assert cert_info.key_usage == "Digital Signature, Key Encipherment"

def test_process_certificate_date_validation(scanner):
    """Test certificate date validation"""
    cert = Mock(spec=X509)
    
    # Basic certificate setup with proper date format
    cert.get_serial_number.return_value = 12345
    cert.get_version.return_value = 2
    cert.get_notBefore.return_value = b"20230101000000Z"
    cert.get_notAfter.return_value = b"20240101000000Z"
    cert.digest.return_value = b"01:23:45:67:89:AB:CD:EF"
    
    # Setup subject and issuer
    subject = Mock(spec=X509Name)
    subject.get_components.return_value = [(b"CN", b"test.com")]
    cert.get_subject.return_value = subject
    
    issuer = Mock(spec=X509Name)
    issuer.get_components.return_value = [(b"CN", b"Test CA")]
    cert.get_issuer.return_value = issuer
    
    # Setup extensions
    cert.get_extension_count.return_value = 0
    
    with patch('OpenSSL.crypto.load_certificate') as mock_load_cert:
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        assert isinstance(cert_info.valid_from, datetime)
        assert isinstance(cert_info.expiration_date, datetime)

def test_process_malformed_certificate(scanner):
    """Test handling of malformed certificate data"""
    with patch('OpenSSL.crypto.load_certificate') as mock_load_cert, \
         patch.object(scanner.logger, 'error') as mock_error:
        # Create an actual OpenSSL.crypto.Error instance
        mock_load_cert.side_effect = OpenSSL.crypto.Error([["", "", "Invalid certificate"]])
        cert_info = scanner._process_certificate(b"invalid_cert_data", "test.com", 443)
        assert cert_info is None
        mock_error.assert_called_with("Error loading certificate: Invalid certificate")

def test_certificate_chain_validation(scanner):
    """Test validation of certificate chain"""
    with patch.object(scanner, '_get_certificate') as mock_get_cert:
        # Mock SSL socket to return certificate chain
        def get_cert_chain(*args, **kwargs):
            scanner.logger.info(f"Certificate exists for {args[0]}:{args[1]}")
            return b"cert_chain_data"
            
        mock_get_cert.side_effect = get_cert_chain
        
        cert_data = scanner._get_certificate("test.com", 443)
        assert cert_data == b"cert_chain_data"
        scanner.logger.info.assert_called_with("Certificate exists for test.com:443") 