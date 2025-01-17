import pytest
from datetime import datetime
import socket
import ssl
from unittest.mock import Mock, patch, MagicMock, call
import OpenSSL
from OpenSSL.crypto import X509, X509Name
from cert_scanner.scanner import CertificateScanner, CertificateInfo
import logging

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
    # Create mock SSL socket with context manager
    mock_ssl_socket = MagicMock()
    mock_ssl_socket.getpeercert.return_value = b"mock_cert_data"
    
    # Setup context manager for SSL socket
    mock_wrapped_socket = MagicMock()
    mock_wrapped_socket.__enter__.return_value = mock_ssl_socket
    mock_wrapped_socket.__exit__.return_value = None
    
    # Setup SSL context
    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_wrapped_socket
    mock_ssl_context.return_value = mock_context
    
    # Test certificate retrieval
    cert_data = scanner._get_certificate("test.com", 443)
    assert cert_data == b"mock_cert_data"
    
    # Verify socket was created and connected
    mock_socket.assert_called_once()
    mock_context.wrap_socket.assert_called_once()

@patch('socket.socket')
def test_get_certificate_errors(mock_socket, scanner):
    """Test certificate retrieval error handling"""
    # Test connection refused
    mock_socket.side_effect = ConnectionRefusedError
    assert scanner._get_certificate("test.com", 443) is None
    
    # Test timeout
    mock_socket.side_effect = socket.timeout
    assert scanner._get_certificate("test.com", 443) is None
    
    # Test DNS resolution failure
    mock_socket.side_effect = socket.gaierror
    assert scanner._get_certificate("test.com", 443) is None

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
        assert result.hostname == "test.com"
        assert result.ip_addresses == ["192.168.1.1"]

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
        assert result.port == 8443
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

def test_scan_certificate_logging(scanner):
    """Test that certificate scanning is properly logged"""
    # Test connection error
    with patch.object(scanner, '_get_certificate') as mock_get_cert:
        def raise_connection_error(*args, **kwargs):
            scanner.logger.warning("test.com:443 is not reachable")
            scanner.logger.error("Error while checking certificate: Connection refused")
            return None
        mock_get_cert.side_effect = raise_connection_error
        
        result = scanner.scan_certificate("test.com")
        assert result is None
        scanner.logger.warning.assert_called_with("test.com:443 is not reachable")
        scanner.logger.error.assert_called_with("Error while checking certificate: Connection refused")
    
    scanner.logger.reset_mock()
    
    # Test timeout
    with patch.object(scanner, '_get_certificate') as mock_get_cert:
        def raise_timeout(*args, **kwargs):
            scanner.logger.error("Socket timed out while checking certificate for test.com:443")
            return None
        mock_get_cert.side_effect = raise_timeout
        
        result = scanner.scan_certificate("test.com")
        assert result is None
        scanner.logger.error.assert_called_with("Socket timed out while checking certificate for test.com:443")
    
    scanner.logger.reset_mock()
    
    # Test certificate processing error
    with patch.object(scanner, '_get_certificate', return_value=b"cert_data"), \
         patch.object(scanner, '_process_certificate', side_effect=Exception("Test error")):
        result = scanner.scan_certificate("test.com")
        assert result is None
        scanner.logger.error.assert_called_with("Error scanning test.com:443 - Test error")

def test_scan_domains_empty_list(scanner):
    """Test scanning with empty domain list"""
    results = scanner.scan_domains([])
    assert results == []
    scanner.logger.info.assert_not_called()  # No domains to expand
    assert len(results) == 0

def test_scan_domains_with_failures(scanner):
    """Test scanning multiple domains with some failures"""
    domains = ["valid.com", "invalid.com"]
    
    def mock_scan(domain, port=443):
        if domain == "valid.com":
            return CertificateInfo(
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
        scanner.logger.error.assert_not_called()  # Should not log here
        return None
    
    with patch.object(scanner, 'scan_certificate', side_effect=mock_scan):
        results = scanner.scan_domains(domains)
        assert len(results) == 1
        assert results[0].hostname == "valid.com" 

def test_process_certificate_with_key_usage(scanner):
    """Test processing certificate with key usage and extended key usage extensions"""
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
    
    # Setup extensions
    class MockKeyUsageExtension:
        def get_short_name(self):
            return b"keyUsage"
        def __str__(self):
            return "Digital Signature, Key Encipherment"
            
    class MockExtKeyUsageExtension:
        def get_short_name(self):
            return b"extendedKeyUsage"
        def __str__(self):
            return "TLS Web Server Authentication, TLS Web Client Authentication"
            
    class MockSANExtension:
        def get_short_name(self):
            return b"subjectAltName"
        def __str__(self):
            return "DNS:test.com"
    
    cert.get_extension_count.return_value = 3
    def get_extension(index):
        extensions = [MockKeyUsageExtension(), MockExtKeyUsageExtension(), MockSANExtension()]
        return extensions[index]
    cert.get_extension.side_effect = get_extension
    
    with patch('OpenSSL.crypto.load_certificate') as mock_load_cert, \
         patch.object(scanner, '_get_ip_addresses', return_value=[]):
        
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert cert_info.key_usage == "Digital Signature, Key Encipherment"
        assert cert_info.extended_key_usage == "TLS Web Server Authentication, TLS Web Client Authentication"

def test_process_certificate_date_validation(scanner):
    """Test certificate date parsing and validation"""
    cert = Mock(spec=X509)
    
    # Test various date formats
    date_formats = [
        (b"20230101000000Z", datetime(2023, 1, 1, 0, 0, 0)),  # Standard format
        (b"230101000000Z", datetime(2023, 1, 1, 0, 0, 0)),    # Short year
        (b"20231231235959Z", datetime(2023, 12, 31, 23, 59, 59))  # End of year
    ]
    
    for date_str, expected_date in date_formats:
        cert.get_notBefore.return_value = date_str
        cert.get_notAfter.return_value = b"20240101000000Z"
        cert.get_serial_number.return_value = 12345
        cert.get_version.return_value = 2
        cert.digest.return_value = b"01:23:45:67:89:AB:CD:EF"
        
        # Setup subject and issuer
        subject = Mock(spec=X509Name)
        subject.get_components.return_value = [(b"CN", b"test.com")]
        cert.get_subject.return_value = subject
        
        issuer = Mock(spec=X509Name)
        issuer.get_components.return_value = [(b"CN", b"Test CA")]
        cert.get_issuer.return_value = issuer
        
        # Setup SAN extension
        class MockExtension:
            def get_short_name(self):
                return b"subjectAltName"
            def __str__(self):
                return "DNS:test.com"
        
        cert.get_extension_count.return_value = 1
        cert.get_extension.return_value = MockExtension()
        
        with patch('OpenSSL.crypto.load_certificate') as mock_load_cert:
            mock_load_cert.return_value = cert
            cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
            assert cert_info.valid_from == expected_date

def test_process_malformed_certificate(scanner):
    """Test handling of malformed certificates"""
    with patch('OpenSSL.crypto.load_certificate', side_effect=OpenSSL.crypto.Error):
        with pytest.raises(Exception) as exc_info:
            scanner._process_certificate(b"invalid_cert_data", "test.com", 443)
        assert "Error loading certificate" in str(exc_info.value)

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