"""
Unit tests for the scanner module.
"""

import logging
import pytest
from datetime import datetime, timezone
import socket
import ssl
from unittest.mock import Mock, patch, MagicMock, call
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from infra_mgmt.certificate_scanner import CertificateScanner, CertificateInfo, ScanResult
from infra_mgmt.scanner import ScanTracker, ScanManager

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
    """Create a mock x509.Certificate for testing."""
    cert = Mock(spec=x509.Certificate)
    cert.serial_number = 12345
    cert.not_valid_before_utc = datetime(2023, 1, 1, tzinfo=timezone.utc)
    cert.not_valid_after_utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    cert.signature_algorithm_oid = Mock(_name="sha256WithRSAEncryption")
    
    # Setup subject
    subject = Mock()
    subject.get_attributes_for_oid.return_value = [Mock(value="test.com")]
    cert.subject = subject
    
    # Setup issuer
    issuer = Mock()
    issuer.get_attributes_for_oid.return_value = [Mock(value="Test CA")]
    cert.issuer = issuer
    
    # Setup extensions for SAN
    san_extension = Mock()
    san_extension.value = [x509.DNSName("test.com"), x509.DNSName("www.test.com")]
    cert.extensions = Mock()
    cert.extensions.get_extension_for_oid.return_value = san_extension
    
    return cert

def test_process_certificate(scanner, mock_certificate):
    """Test processing a certificate."""
    with patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_load_cert.return_value = mock_certificate
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert cert_info is not None
        assert cert_info.serial_number == format(12345, 'x')
        assert cert_info.common_name == "test.com"
        assert cert_info.valid_from == datetime(2023, 1, 1, tzinfo=timezone.utc)
        assert cert_info.expiration_date == datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert cert_info.signature_algorithm == "sha256WithRSAEncryption"
        assert cert_info.subject == {"CN": "test.com"}
        assert cert_info.issuer == {"CN": "Test CA"}
        assert cert_info.san == ["test.com", "www.test.com"]
        assert not cert_info.validation_errors
        assert not cert_info.chain_valid  # Chain validation is done separately

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

def test_get_certificate(scanner):
    """Test getting a certificate from a host."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        
        cert_data = scanner._get_certificate("test.com", 443)
        assert cert_data == b"dummy_cert_data"
        assert scanner._last_cert_chain is True

def test_get_certificate_errors(scanner):
    """Test error handling when getting a certificate."""
    # Test connection refused
    with patch('socket.create_connection', side_effect=ConnectionRefusedError()):
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("test.com", 443)
        assert "Connection refused" in str(exc_info.value)
    
    # Test timeout
    with patch('socket.create_connection', side_effect=TimeoutError()):
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("test.com", 443)
        assert "Connection timed out" in str(exc_info.value)
    
    # Test SSL error
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket', side_effect=ssl.SSLError("SSL error")):
        mock_create_conn.return_value = Mock()
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("test.com", 443)
        assert "SSL error" in str(exc_info.value)
        assert scanner._last_cert_chain is False

def test_scan_certificate(scanner, mock_certificate):
    """Test scanning a certificate from a host."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        mock_load_cert.return_value = mock_certificate
        
        result = scanner.scan_certificate("test.com")
        
        assert isinstance(result, ScanResult)
        assert result.has_certificate
        assert result.is_valid
        assert result.status == "Valid certificate"
        assert not result.error
        assert not result.warnings
        
        cert_info = result.certificate_info
        assert cert_info is not None
        assert cert_info.serial_number == format(12345, 'x')
        assert cert_info.common_name == "test.com"
        assert cert_info.valid_from == datetime(2023, 1, 1, tzinfo=timezone.utc)
        assert cert_info.expiration_date == datetime(2024, 1, 1, tzinfo=timezone.utc)
        assert cert_info.signature_algorithm == "sha256WithRSAEncryption"
        assert cert_info.subject == {"CN": "test.com"}
        assert cert_info.issuer == {"CN": "Test CA"}
        assert cert_info.san == ["test.com", "www.test.com"]
        assert cert_info.chain_valid

def test_scan_certificate_errors(scanner):
    """Test error handling during certificate scanning."""
    # Test connection refused
    with patch('socket.create_connection', side_effect=ConnectionRefusedError()):
        result = scanner.scan_certificate("test.com")
        assert not result.has_certificate
        assert not result.is_valid
        assert "Connection refused" in result.error
    
    # Test timeout
    with patch('socket.create_connection', side_effect=TimeoutError()):
        result = scanner.scan_certificate("test.com")
        assert not result.has_certificate
        assert not result.is_valid
        assert "Connection timed out" in result.error
    
    # Test SSL error
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket', side_effect=ssl.SSLError("SSL error")):
        mock_create_conn.return_value = Mock()
        result = scanner.scan_certificate("test.com")
        assert not result.has_certificate
        assert not result.is_valid
        assert "SSL error" in result.error

def test_scan_domains(scanner, mock_certificate):
    """Test scanning multiple domains."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        mock_load_cert.return_value = mock_certificate
        
        domains = ["test1.com", "test2.com"]
        scanner.scan_domains(domains)
        
        # Check that all domains were processed
        assert scanner.total_domains == 2
        assert scanner.scanned_domains == 2
        assert scanner.queue_size == 0
        assert len(scanner.results) == 2
        
        # Check results for each domain
        for domain in domains:
            result = scanner.results.get(domain)
            assert result is not None
            assert result.has_certificate
            assert result.is_valid
            assert result.status == "Valid certificate"
            assert not result.error
            assert not result.warnings

def test_scan_certificate_custom_port(scanner, mock_certificate):
    """Test scanning a certificate with a custom port."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        mock_load_cert.return_value = mock_certificate
        
        result = scanner.scan_certificate("test.com", port=8443)
        
        assert isinstance(result, ScanResult)
        assert result.has_certificate
        assert result.is_valid
        assert result.status == "Valid certificate"
        
        # Verify that the custom port was used
        mock_create_conn.assert_called_once_with(("test.com", 8443), timeout=scanner.socket_timeout)

def test_process_certificate_with_multiple_sans(scanner):
    """Test processing a certificate with multiple SANs."""
    cert = Mock(spec=x509.Certificate)
    cert.serial_number = 12345
    cert.not_valid_before_utc = datetime(2023, 1, 1, tzinfo=timezone.utc)
    cert.not_valid_after_utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    cert.signature_algorithm_oid = Mock(_name="sha256WithRSAEncryption")
    
    # Setup subject
    subject = Mock()
    subject.get_attributes_for_oid.return_value = [Mock(value="test.com")]
    cert.subject = subject
    
    # Setup issuer
    issuer = Mock()
    issuer.get_attributes_for_oid.return_value = [Mock(value="Test CA")]
    cert.issuer = issuer
    
    # Setup extensions with multiple SANs
    san_extension = Mock()
    san_extension.value = [
        x509.DNSName("test.com"),
        x509.DNSName("www.test.com"),
        x509.DNSName("api.test.com"),
        x509.DNSName("admin.test.com")
    ]
    
    def get_extension_for_oid(oid):
        if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            return san_extension
        raise x509.extensions.ExtensionNotFound("Extension not found", oid)
    
    cert.extensions = Mock()
    cert.extensions.get_extension_for_oid.side_effect = get_extension_for_oid
    
    with patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert cert_info is not None
        assert len(cert_info.san) == 4
        assert "test.com" in cert_info.san
        assert "www.test.com" in cert_info.san
        assert "api.test.com" in cert_info.san
        assert "admin.test.com" in cert_info.san
        assert cert_info.common_name == "test.com"

def test_process_certificate_with_extended_fields(scanner):
    """Test processing a certificate with extended fields."""
    cert = Mock(spec=x509.Certificate)
    cert.serial_number = 12345
    cert.not_valid_before_utc = datetime(2023, 1, 1, tzinfo=timezone.utc)
    cert.not_valid_after_utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    cert.signature_algorithm_oid = Mock(_name="sha256WithRSAEncryption")
    
    # Setup subject with extended fields
    subject = Mock()
    subject_attrs = {
        x509.oid.NameOID.COMMON_NAME: [Mock(value="test.com")],
        x509.oid.NameOID.ORGANIZATION_NAME: [Mock(value="Test Company")],
        x509.oid.NameOID.LOCALITY_NAME: [Mock(value="Test City")],
        x509.oid.NameOID.COUNTRY_NAME: [Mock(value="US")],
        x509.oid.NameOID.STATE_OR_PROVINCE_NAME: [Mock(value="Test State")]
    }
    subject.get_attributes_for_oid.side_effect = lambda oid: subject_attrs.get(oid, [])
    cert.subject = subject
    
    # Setup issuer with extended fields
    issuer = Mock()
    issuer_attrs = {
        x509.oid.NameOID.COMMON_NAME: [Mock(value="Test CA")],
        x509.oid.NameOID.ORGANIZATION_NAME: [Mock(value="CA Company")],
        x509.oid.NameOID.COUNTRY_NAME: [Mock(value="US")]
    }
    issuer.get_attributes_for_oid.side_effect = lambda oid: issuer_attrs.get(oid, [])
    cert.issuer = issuer
    
    # Setup extensions
    san_extension = Mock()
    san_extension.value = [x509.DNSName("test.com")]
    
    def get_extension_for_oid(oid):
        if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            return san_extension
        raise x509.extensions.ExtensionNotFound("Extension not found", oid)
    
    cert.extensions = Mock()
    cert.extensions.get_extension_for_oid.side_effect = get_extension_for_oid
    
    with patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert cert_info is not None
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
        assert cert_info.common_name == "test.com"

def test_scan_certificate_logging(scanner, caplog, mock_certificate):
    """Test logging during certificate scanning."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        mock_load_cert.return_value = mock_certificate
        
        # Test successful scan logging
        result = scanner.scan_certificate("test.com")
        assert "Starting certificate scan for test.com:443" in caplog.text
        assert "Successfully processed certificate for test.com:443" in caplog.text
        
        # Test error logging
        caplog.clear()
        mock_create_conn.side_effect = ConnectionRefusedError()
        result = scanner.scan_certificate("test.com")
        assert "Error scanning test.com:443" in caplog.text
        assert "Connection refused" in caplog.text
        
        # Test SSL error logging
        caplog.clear()
        mock_create_conn.side_effect = None
        mock_wrap_socket.side_effect = ssl.SSLError("SSL error")
        result = scanner.scan_certificate("test.com")
        assert "Error scanning test.com:443" in caplog.text
        assert "SSL error" in caplog.text
        
        # Test timeout logging
        caplog.clear()
        mock_create_conn.side_effect = TimeoutError()
        result = scanner.scan_certificate("test.com")
        assert "Error scanning test.com:443" in caplog.text
        assert "Connection timed out" in caplog.text

def test_scan_domains_empty_list(scanner):
    """Test scanning with an empty domain list."""
    scanner.scan_domains([])
    assert scanner.total_domains == 0
    assert scanner.scanned_domains == 0
    assert scanner.queue_size == 0
    assert len(scanner.results) == 0

def test_scan_domains_with_failures(scanner, mock_certificate):
    """Test scanning domains with some failures."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        mock_load_cert.return_value = mock_certificate
        
        # Make the first domain succeed and the second fail
        mock_create_conn.side_effect = [Mock(), ConnectionRefusedError()]
        
        domains = ["test1.com", "test2.com"]
        scanner.scan_domains(domains)
        
        # Check overall stats
        assert scanner.total_domains == 2
        assert scanner.scanned_domains == 2
        assert scanner.queue_size == 0
        assert len(scanner.results) == 2
        
        # Check successful domain
        result1 = scanner.results.get("test1.com")
        assert result1 is not None
        assert result1.has_certificate
        assert result1.is_valid
        assert result1.status == "Valid certificate"
        
        # Check failed domain
        result2 = scanner.results.get("test2.com")
        assert result2 is not None
        assert not result2.has_certificate
        assert not result2.is_valid
        assert "Connection refused" in result2.error

def test_process_certificate_with_key_usage(scanner):
    """Test processing a certificate with key usage information."""
    cert = Mock(spec=x509.Certificate)
    cert.serial_number = 12345
    cert.not_valid_before_utc = datetime(2023, 1, 1, tzinfo=timezone.utc)
    cert.not_valid_after_utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    cert.signature_algorithm_oid = Mock(_name="sha256WithRSAEncryption")
    
    # Setup subject
    subject = Mock()
    subject.get_attributes_for_oid.return_value = [Mock(value="test.com")]
    cert.subject = subject
    
    # Setup issuer
    issuer = Mock()
    issuer.get_attributes_for_oid.return_value = [Mock(value="Test CA")]
    cert.issuer = issuer
    
    # Setup extensions
    key_usage = Mock()
    key_usage.digital_signature = True
    key_usage.content_commitment = True
    key_usage.key_encipherment = True
    key_usage.data_encipherment = False
    key_usage.key_agreement = False
    key_usage.key_cert_sign = True
    key_usage.crl_sign = False
    
    key_usage_ext = Mock()
    key_usage_ext.value = key_usage
    
    san_extension = Mock()
    san_extension.value = [x509.DNSName("test.com")]
    
    def get_extension_for_oid(oid):
        if oid == x509.oid.ExtensionOID.KEY_USAGE:
            return key_usage_ext
        if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            return san_extension
        raise x509.extensions.ExtensionNotFound("Extension not found", oid)
    
    cert.extensions = Mock()
    cert.extensions.get_extension_for_oid.side_effect = get_extension_for_oid
    
    with patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert cert_info is not None
        assert cert_info.key_usage == [
            "digitalSignature",
            "contentCommitment",
            "keyEncipherment",
            "keyCertSign"
        ]

def test_rate_limiting(scanner):
    """Test rate limiting functionality."""
    scanner.rate_limit = 30  # Set rate limit to 30 requests/minute
    
    with patch('time.sleep') as mock_sleep:
        # First request should not trigger rate limiting
        scanner._apply_rate_limit()
        mock_sleep.assert_not_called()
        
        # Second request within a minute should trigger rate limiting
        scanner._apply_rate_limit()
        mock_sleep.assert_called_once_with(2.0)  # 60 seconds / 30 requests = 2 seconds per request

def test_scan_stats(scanner, mock_certificate):
    """Test scanning statistics."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        mock_load_cert.return_value = mock_certificate
        
        # Initial stats should be zero
        assert scanner.total_domains == 0
        assert scanner.scanned_domains == 0
        assert scanner.queue_size == 0
        
        # Add domains and check stats
        domains = ["test1.com", "test2.com", "test3.com"]
        scanner.scan_domains(domains)
        
        # After scanning, stats should be updated
        assert scanner.total_domains == 3
        assert scanner.scanned_domains == 3
        assert scanner.queue_size == 0
        assert len(scanner.results) == 3
        
        # Check success rate
        successful_scans = sum(1 for result in scanner.results.values() if result.is_valid)
        assert successful_scans == 3
        
        # Check that all results are stored
        for domain in domains:
            assert domain in scanner.results
            result = scanner.results[domain]
            assert result.has_certificate
            assert result.is_valid
            assert result.status == "Valid certificate"

def test_scan_certificate_custom_port(scanner, mock_certificate):
    """Test scanning a certificate with a custom port."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_create_conn.return_value = mock_sock
        mock_wrap_socket.return_value = mock_ssl_sock
        mock_load_cert.return_value = mock_certificate
        
        result = scanner.scan_certificate("test.com", port=8443)
        
        assert isinstance(result, ScanResult)
        assert result.has_certificate
        assert result.is_valid
        assert result.status == "Valid certificate"
        
        # Verify that the custom port was used
        mock_create_conn.assert_called_once_with(("test.com", 8443), timeout=scanner.socket_timeout)

def test_process_certificate_with_key_usage(scanner):
    """Test processing a certificate with key usage information."""
    cert = Mock(spec=x509.Certificate)
    cert.serial_number = 12345
    cert.not_valid_before_utc = datetime(2023, 1, 1, tzinfo=timezone.utc)
    cert.not_valid_after_utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    cert.signature_algorithm_oid = Mock(_name="sha256WithRSAEncryption")
    
    # Setup subject
    subject = Mock()
    subject.get_attributes_for_oid.return_value = [Mock(value="test.com")]
    cert.subject = subject
    
    # Setup issuer
    issuer = Mock()
    issuer.get_attributes_for_oid.return_value = [Mock(value="Test CA")]
    cert.issuer = issuer
    
    # Setup extensions
    key_usage = Mock()
    key_usage.digital_signature = True
    key_usage.content_commitment = True
    key_usage.key_encipherment = True
    key_usage.data_encipherment = False
    key_usage.key_agreement = False
    key_usage.key_cert_sign = True
    key_usage.crl_sign = False
    
    key_usage_ext = Mock()
    key_usage_ext.value = key_usage
    
    san_extension = Mock()
    san_extension.value = [x509.DNSName("test.com")]
    
    def get_extension_for_oid(oid):
        if oid == x509.oid.ExtensionOID.KEY_USAGE:
            return key_usage_ext
        if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            return san_extension
        raise x509.extensions.ExtensionNotFound("Extension not found", oid)
    
    cert.extensions = Mock()
    cert.extensions.get_extension_for_oid.side_effect = get_extension_for_oid
    
    with patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert:
        mock_load_cert.return_value = cert
        cert_info = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
        
        assert cert_info is not None
        assert cert_info.key_usage == [
            "digitalSignature",
            "contentCommitment",
            "keyEncipherment",
            "keyCertSign"
        ] 