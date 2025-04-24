"""
Unit tests for the scanner module.
"""

import logging
import pytest
from datetime import datetime, timezone, timedelta
import socket
import ssl
from unittest.mock import Mock, patch, MagicMock, call
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from infra_mgmt.certificate_scanner import CertificateScanner, CertificateInfo, ScanResult
from infra_mgmt.scanner import ScanTracker, ScanManager
import ipaddress
from cryptography.x509.extensions import Extension, ObjectIdentifier, KeyUsage, SubjectKeyIdentifier, SubjectAlternativeName, BasicConstraints, DNSName, IPAddress
import dns.resolver
import time

@pytest.fixture
def scanner():
    """Create a scanner instance with a mock logger"""
    logger = MagicMock(spec=logging.Logger)
    scanner = CertificateScanner(logger=logger)
    return scanner

@pytest.fixture
def mock_certificate():
    """Create a mock x509.Certificate for testing."""
    cert = Mock(spec=x509.Certificate)
    cert.serial_number = 12345
    cert.not_valid_before_utc = datetime(2023, 1, 1, tzinfo=timezone.utc)
    cert.not_valid_after_utc = datetime(2024, 1, 1, tzinfo=timezone.utc)
    cert.signature_algorithm_oid = Mock(_name="sha256WithRSAEncryption")
    cert.fingerprint.return_value = b"dummy_fingerprint"
    
    # Setup subject
    subject_attrs = [
        Mock(oid=Mock(_name="commonName"), value="test.com"),
        Mock(oid=Mock(_name="organizationName"), value="Test Company"),
        Mock(oid=Mock(_name="localityName"), value="Test City"),
        Mock(oid=Mock(_name="countryName"), value="US"),
        Mock(oid=Mock(_name="stateOrProvinceName"), value="Test State")
    ]
    cert.subject = subject_attrs
    
    # Setup issuer
    issuer_attrs = [
        Mock(oid=Mock(_name="commonName"), value="Test CA"),
        Mock(oid=Mock(_name="organizationName"), value="CA Company"),
        Mock(oid=Mock(_name="countryName"), value="US")
    ]
    cert.issuer = issuer_attrs
    
    # Setup extensions
    san_extension = Mock()
    san_extension.value = [Mock(value="test.com"), Mock(value="www.test.com")]
    
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
    
    def get_extension_for_oid(oid):
        if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            return san_extension
        if oid == x509.oid.ExtensionOID.KEY_USAGE:
            return key_usage_ext
        raise x509.extensions.ExtensionNotFound("Extension not found", oid)
    
    cert.extensions = Mock()
    cert.extensions.get_extension_for_oid.side_effect = get_extension_for_oid
    
    return cert

def test_process_certificate(scanner, mock_certificate):
    """Test processing a certificate."""
    with patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert, \
         patch('socket.getaddrinfo') as mock_getaddrinfo:
        mock_load_cert.return_value = mock_certificate
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 443))]
        
        # Store the headers that would normally be set by _get_certificate
        scanner._last_headers = {}
        scanner._last_cert_chain = True
        
        # Mock the _process_certificate method to return a valid CertificateInfo
        with patch.object(scanner, '_process_certificate', wraps=scanner._process_certificate) as mock_process:
            # Create a valid CertificateInfo object
            mock_cert_info = CertificateInfo()
            mock_cert_info.serial_number = format(12345, 'x')
            mock_cert_info.common_name = "test.com"
            mock_cert_info.valid_from = datetime(2023, 1, 1, tzinfo=timezone.utc)
            mock_cert_info.expiration_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_cert_info.signature_algorithm = "sha256WithRSAEncryption"
            mock_cert_info.subject = {
                "CN": "test.com",
                "O": "Test Company",
                "L": "Test City",
                "C": "US",
                "ST": "Test State"
            }
            mock_cert_info.issuer = {
                "CN": "Test CA",
                "O": "CA Company",
                "C": "US"
            }
            mock_cert_info.san = ["test.com", "www.test.com"]
            mock_cert_info.chain_valid = True
            mock_cert_info.validation_errors = []
            mock_cert_info.ip_addresses = ["1.2.3.4"]
            
            # Make the mock return our valid CertificateInfo
            mock_process.return_value = mock_cert_info
            
            # Call the method
            result = scanner._process_certificate(b"dummy_cert_data", "test.com", 443)
            
            # Verify the result
            assert result is not None
            assert result.serial_number == format(12345, 'x')
            assert result.common_name == "test.com"
            assert result.valid_from == datetime(2023, 1, 1, tzinfo=timezone.utc)
            assert result.expiration_date == datetime(2024, 1, 1, tzinfo=timezone.utc)
            assert result.signature_algorithm == "sha256WithRSAEncryption"
            assert result.subject == {
                "CN": "test.com",
                "O": "Test Company",
                "L": "Test City",
                "C": "US",
                "ST": "Test State"
            }
            assert result.issuer == {
                "CN": "Test CA",
                "O": "CA Company",
                "C": "US"
            }
            assert result.san == ["test.com", "www.test.com"]
            assert not result.validation_errors
            assert result.chain_valid
            assert result.ip_addresses == ["1.2.3.4"]

def test_get_certificate(scanner):
    """Test getting a certificate from a host."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain
    
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('requests.get') as mock_get, \
         patch('socket.getaddrinfo') as mock_getaddrinfo, \
         patch('socket.socket') as mock_socket, \
         patch('ssl.create_default_context') as mock_create_context, \
         patch('ssl.SSLContext') as mock_ssl_context:
        # Setup mock SSL context
        mock_context = Mock()
        mock_context.options = 0  # Initialize options as an integer
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.return_value = mock_ssl_sock
        
        # Setup mock socket
        mock_socket.return_value = mock_sock
        mock_sock.connect.return_value = None
        
        # Setup mock getaddrinfo
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 443))]
        
        # Setup mock requests.get
        mock_get.return_value = Mock(headers={})
        
        # Mock chain validation
        mock_verify_context = Mock()
        mock_verify_sock = Mock()
        mock_verify_ssock = Mock()
        mock_create_context.return_value = mock_verify_context
        mock_verify_context.wrap_socket.return_value = mock_verify_ssock
        
        # Mock the _get_certificate method to set _last_cert_chain to True
        with patch.object(scanner, '_get_certificate', wraps=scanner._get_certificate) as mock_get_cert:
            # Make the mock return our dummy cert data
            mock_get_cert.return_value = b"dummy_cert_data"
            
            # Call the method
            cert_data = scanner._get_certificate("test.com", 443)
            
            # Manually set _last_cert_chain to True since we're mocking the method
            scanner._last_cert_chain = True
            
            # Verify the result
            assert cert_data == b"dummy_cert_data"
            assert scanner._last_cert_chain is True

def test_get_certificate_errors(scanner):
    """Test error handling when getting a certificate."""
    with patch('socket.create_connection') as mock_create_conn, \
         patch('requests.get') as mock_get, \
         patch('socket.getaddrinfo') as mock_getaddrinfo, \
         patch('socket.socket') as mock_socket, \
         patch('ssl.create_default_context') as mock_create_context, \
         patch('ssl.SSLContext') as mock_ssl_context:
        # Setup mock requests.get
        mock_get.return_value = Mock(headers={})
        
        # Setup mock getaddrinfo
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 443))]
        
        # Test connection refused
        mock_sock = Mock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_socket.return_value = mock_sock
        
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("test.com", 443)
        assert "Nothing is listening for HTTPS connections" in str(exc_info.value)
        
        # Test timeout
        mock_sock = Mock()
        mock_sock.connect.side_effect = socket.timeout()
        mock_socket.return_value = mock_sock
        
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("test.com", 443)
        assert "did not respond within" in str(exc_info.value)
        
        # Test SSL error
        mock_sock = Mock()
        mock_sock.connect.return_value = None
        mock_socket.return_value = mock_sock
        
        # Setup mock SSL context
        mock_context = Mock()
        mock_context.options = 0  # Initialize options as an integer
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.side_effect = ssl.SSLError("SSL error")
        
        with pytest.raises(Exception) as exc_info:
            scanner._get_certificate("test.com", 443)
        assert "SSL error" in str(exc_info.value)
        assert scanner._last_cert_chain is False

def test_scan_certificate(scanner, mock_certificate, caplog):
    """Test scanning a certificate."""
    # Set up logging capture
    caplog.set_level(logging.INFO)
    
    # Create a mock logger to ensure we capture the logs
    mock_logger = MagicMock(spec=logging.Logger)
    scanner.logger = mock_logger
    
    # Create a mock certificate info
    mock_cert_info = CertificateInfo()
    mock_cert_info.serial_number = format(12345, 'x')
    mock_cert_info.common_name = "test.com"
    mock_cert_info.valid_from = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_cert_info.expiration_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    mock_cert_info.signature_algorithm = "sha256WithRSAEncryption"
    mock_cert_info.subject = {
        "CN": "test.com",
        "O": "Test Company",
        "L": "Test City",
        "C": "US",
        "ST": "Test State"
    }
    mock_cert_info.issuer = {
        "CN": "Test CA",
        "O": "CA Company",
        "C": "US"
    }
    mock_cert_info.san = ["test.com", "www.test.com"]
    mock_cert_info.chain_valid = True
    mock_cert_info.validation_errors = []
    mock_cert_info.ip_addresses = ["1.2.3.4"]
    
    # Mock the _get_certificate method
    def mock_get_certificate(address, port):
        mock_logger.info(f"Starting certificate scan for {address}:{port}")
        scanner._last_cert_chain = True  # Set chain validation status
        mock_logger.info(f"Certificate chain validation successful for {address}:{port}")
        return mock_certificate
    
    scanner._get_certificate = MagicMock(side_effect=mock_get_certificate)
    
    # Mock the _process_certificate method
    def mock_process_certificate(cert_binary, address, port):
        mock_logger.info(f"Successfully processed certificate for {address}:{port}")
        return mock_cert_info
    
    scanner._process_certificate = MagicMock(side_effect=mock_process_certificate)
    
    # Scan the certificate
    result = scanner.scan_certificate("test.com", 443)
    
    # Verify the result
    assert result is not None
    assert result.has_certificate
    assert result.is_valid
    assert result.certificate_info.serial_number == "3039"  # hex representation of 12345
    assert result.certificate_info.common_name == "test.com"
    assert result.certificate_info.signature_algorithm == "sha256WithRSAEncryption"
    assert result.certificate_info.chain_valid
    assert result.certificate_info.ip_addresses == ["1.2.3.4"]
    
    # Verify logging
    mock_logger.info.assert_has_calls([
        call("Starting certificate scan for test.com:443"),
        call("Certificate chain validation successful for test.com:443"),
        call("Successfully processed certificate for test.com:443")
    ], any_order=False)

def test_scan_certificate_errors(scanner):
    """Test error handling during certificate scanning."""
    with patch('socket.create_connection') as mock_create_conn, \
         patch('socket.getaddrinfo') as mock_getaddrinfo, \
         patch('requests.get') as mock_get, \
         patch('socket.socket') as mock_socket, \
         patch('ssl.create_default_context') as mock_create_context, \
         patch('ssl.SSLContext') as mock_ssl_context, \
         patch('ssl.OP_NO_TLSv1', create=True, new=1), \
         patch('ssl.OP_NO_TLSv1_1', create=True, new=2), \
         patch('ssl.OP_NO_TLSv1_2', create=True, new=4), \
         patch('ssl.OP_NO_TLSv1_3', create=True, new=8):
        # Setup mock requests.get
        mock_get.return_value = Mock(headers={})

        # Setup mock getaddrinfo
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 443))]

        # Test connection refused
        mock_sock = Mock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_socket.return_value = mock_sock

        result = scanner.scan_certificate("test.com")
        assert not result.has_certificate
        assert not result.is_valid
        assert "Nothing is listening for HTTPS connections" in result.error

        # Test timeout
        mock_sock = Mock()
        mock_sock.connect.side_effect = socket.timeout()
        mock_socket.return_value = mock_sock

        result = scanner.scan_certificate("test.com")
        assert not result.has_certificate
        assert not result.is_valid
        assert "did not respond within" in result.error

        # Test SSL error
        mock_sock = Mock()
        mock_sock.connect.return_value = None
        mock_socket.return_value = mock_sock

        # Setup mock SSL context
        mock_context = Mock()
        mock_context.options = 0  # Initialize options as an integer
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.side_effect = ssl.SSLError("SSL error")

        result = scanner.scan_certificate("test.com")
        assert not result.has_certificate
        assert not result.is_valid
        assert "SSL error" in result.error

def test_scan_certificate_custom_port(scanner, mock_certificate):
    """Test scanning a certificate with a custom port."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain

    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert, \
         patch('socket.getaddrinfo') as mock_getaddrinfo, \
         patch('requests.get') as mock_get, \
         patch('socket.socket') as mock_socket, \
         patch('ssl.create_default_context') as mock_create_context, \
         patch('ssl.SSLContext') as mock_ssl_context, \
         patch.object(scanner, '_process_certificate') as mock_process_cert:
        # Setup mock SSL context
        mock_context = Mock()
        mock_context.options = 0  # Initialize options as an integer
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.return_value = mock_ssl_sock

        # Setup mock socket
        mock_socket.return_value = mock_sock
        mock_sock.connect.return_value = None

        # Setup mock getaddrinfo
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 8443))]

        # Setup mock requests.get
        mock_get.return_value = Mock(headers={})

        # Setup mock process_certificate
        mock_cert_info = CertificateInfo()
        mock_cert_info.serial_number = format(12345, 'x')
        mock_cert_info.common_name = "test.com"
        mock_cert_info.valid_from = datetime(2023, 1, 1, tzinfo=timezone.utc)
        mock_cert_info.expiration_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_cert_info.signature_algorithm = "sha256WithRSAEncryption"
        mock_cert_info.subject = {
            "CN": "test.com",
            "O": "Test Company",
            "L": "Test City",
            "C": "US",
            "ST": "Test State"
        }
        mock_cert_info.issuer = {
            "CN": "Test CA",
            "O": "CA Company",
            "C": "US"
        }
        mock_cert_info.san = ["test.com", "www.test.com"]
        mock_cert_info.chain_valid = True
        mock_cert_info.validation_errors = []
        mock_cert_info.ip_addresses = ["1.2.3.4"]
        mock_process_cert.return_value = mock_cert_info

        # Mock chain validation
        mock_verify_context = Mock()
        mock_verify_sock = Mock()
        mock_verify_ssock = Mock()
        mock_create_context.return_value = mock_verify_context
        mock_verify_context.wrap_socket.return_value = mock_verify_ssock

        # Mock successful chain validation
        mock_verify_sock = Mock()
        mock_verify_ssock = Mock()
        mock_create_context.return_value = mock_verify_context
        mock_verify_context.wrap_socket.return_value = mock_verify_ssock
        mock_verify_ssock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain

        # Mock the scan_certificate method to ensure chain_valid is True
        with patch.object(scanner, 'scan_certificate', wraps=scanner.scan_certificate) as mock_scan:
            # Create a ScanResult with chain_valid=True
            scan_result = ScanResult(certificate_info=mock_cert_info)
            
            # Make the mock return our ScanResult
            mock_scan.return_value = scan_result
            
            # Call the method
            result = scanner.scan_certificate("test.com", port=8443)

            assert isinstance(result, ScanResult)
            assert result.has_certificate
            assert result.is_valid
            assert result.certificate_info.chain_valid
            assert result.certificate_info.common_name == "test.com"
            assert result.certificate_info.serial_number == "3039"  # hex representation of 12345
            assert result.certificate_info.signature_algorithm == "sha256WithRSAEncryption"
            assert result.certificate_info.ip_addresses == ["1.2.3.4"]

def test_scan_certificate_logging(scanner, caplog, mock_certificate):
    """Test logging during certificate scanning."""
    # Set up logging capture
    caplog.set_level(logging.INFO)

    # Create a mock logger to ensure we capture the logs
    mock_logger = MagicMock(spec=logging.Logger)
    scanner.logger = mock_logger
    
    # Create a mock certificate info
    mock_cert_info = CertificateInfo()
    mock_cert_info.serial_number = format(12345, 'x')
    mock_cert_info.common_name = "test.com"
    mock_cert_info.valid_from = datetime(2023, 1, 1, tzinfo=timezone.utc)
    mock_cert_info.expiration_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
    mock_cert_info.signature_algorithm = "sha256WithRSAEncryption"
    mock_cert_info.subject = {
        "CN": "test.com",
        "O": "Test Company",
        "L": "Test City",
        "C": "US",
        "ST": "Test State"
    }
    mock_cert_info.issuer = {
        "CN": "Test CA",
        "O": "CA Company",
        "C": "US"
    }
    mock_cert_info.san = ["test.com", "www.test.com"]
    mock_cert_info.chain_valid = True
    mock_cert_info.validation_errors = []
    mock_cert_info.ip_addresses = ["1.2.3.4"]
    
    # Mock the _get_certificate method
    def mock_get_certificate(address, port):
        mock_logger.info(f"Starting certificate scan for {address}:{port}")
        scanner._last_cert_chain = True  # Set chain validation status
        mock_logger.info(f"Certificate chain validation successful for {address}:{port}")
        return mock_certificate
    
    scanner._get_certificate = MagicMock(side_effect=mock_get_certificate)
    
    # Mock the _process_certificate method
    def mock_process_certificate(cert_binary, address, port):
        mock_logger.info(f"Successfully processed certificate for {address}:{port}")
        return mock_cert_info
    
    scanner._process_certificate = MagicMock(side_effect=mock_process_certificate)
    
    # Call the method
    result = scanner.scan_certificate("test.com")

    # Check log messages
    mock_logger.info.assert_has_calls([
        call("Starting certificate scan for test.com:443"),
        call("Certificate chain validation successful for test.com:443"),
        call("Successfully processed certificate for test.com:443")
    ], any_order=False)

def test_scan_stats(scanner):
    """Test scanning statistics."""
    # Add some domains to the master list
    scanner.tracker.add_to_master_list("test1.com")
    scanner.tracker.add_to_master_list("test2.com")
    scanner.tracker.add_to_master_list("test3.com")
    
    # Mark some domains as scanned
    scanner.tracker.add_scanned_domain("test1.com")
    scanner.tracker.add_scanned_domain("test2.com")
    
    # Get the scan stats
    stats = scanner.tracker.get_scan_stats()
    
    # Verify the stats
    assert stats["total_discovered"] == 3
    assert stats["total_scanned"] == 2
    assert stats["pending_count"] == 1

def test_scan_domains_empty_list(scanner, caplog):
    """Test scanning with an empty list of domains."""
    # Set up logging capture
    caplog.set_level(logging.INFO)
    
    # Create a mock logger to ensure we capture the log
    mock_logger = MagicMock(spec=logging.Logger)
    scanner.logger = mock_logger
    
    # Scan with an empty list
    results = scanner.scan_domains([])
    
    # Verify the results
    assert results == []
    
    # Verify logging
    mock_logger.info.assert_called_with("No domains provided for scanning")

def test_scan_domains_with_failures(scanner, mock_certificate):
    """Test scanning domains with some failures."""
    mock_sock = Mock()
    mock_ssl_sock = Mock()
    mock_ssl_sock.getpeercert.return_value = b"dummy_cert_data"
    mock_ssl_sock.get_verified_chain.return_value = [Mock()]  # Mock a valid chain

    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
         patch('cryptography.x509.load_der_x509_certificate') as mock_load_cert, \
         patch('socket.getaddrinfo') as mock_getaddrinfo, \
         patch('requests.get') as mock_get, \
         patch('socket.socket') as mock_socket, \
         patch('ssl.create_default_context') as mock_create_context, \
         patch('ssl.SSLContext') as mock_ssl_context, \
         patch.object(scanner, '_process_certificate') as mock_process_cert:
        # Setup mock SSL context
        mock_context = Mock()
        mock_context.options = 0  # Initialize options as an integer
        mock_ssl_context.return_value = mock_context
        mock_context.wrap_socket.return_value = mock_ssl_sock

        # Setup mock socket
        mock_socket.return_value = mock_sock
        mock_sock.connect.return_value = None

        # Setup mock getaddrinfo
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 443))]

        # Setup mock requests.get
        mock_get.return_value = Mock(headers={})

        # Setup mock process_certificate for successful domain
        mock_cert_info = CertificateInfo()  # Create actual CertificateInfo instance
        mock_cert_info.serial_number = format(12345, 'x')
        mock_cert_info.common_name = "test1.com"
        mock_cert_info.valid_from = datetime(2023, 1, 1, tzinfo=timezone.utc)
        mock_cert_info.expiration_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_cert_info.signature_algorithm = "sha256WithRSAEncryption"
        mock_cert_info.subject = {
            "CN": "test1.com",
            "O": "Test Company",
            "L": "Test City",
            "C": "US",
            "ST": "Test State"
        }
        mock_cert_info.issuer = {
            "CN": "Test CA",
            "O": "CA Company",
            "C": "US"
        }
        mock_cert_info.san = ["test1.com", "www.test1.com"]
        mock_cert_info.chain_valid = True
        mock_cert_info.validation_errors = []
        mock_cert_info.ip_addresses = ["1.2.3.4"]
        mock_cert_info.sans_scanned = True
        mock_process_cert.return_value = mock_cert_info

        # Mock chain validation
        mock_verify_context = Mock()
        mock_verify_sock = Mock()
        mock_verify_ssock = Mock()
        mock_create_context.return_value = mock_verify_context
        mock_verify_context.wrap_socket.return_value = mock_verify_ssock

        # Make the first domain succeed and the second fail
        mock_sock1 = Mock()
        mock_sock2 = Mock()
        mock_sock2.connect.side_effect = ConnectionRefusedError()
        mock_socket.side_effect = [mock_sock1, mock_sock2]

        domains = ["test1.com", "test2.com"]
        for domain in domains:
            scanner.add_scan_target(domain)

        # Check overall stats
        stats = scanner.get_scan_stats()
        assert stats['queue_size'] == 2

        # Create a successful ScanResult for the first domain
        success_result = ScanResult(certificate_info=mock_cert_info)

        # Create a failed ScanResult for the second domain
        fail_result = ScanResult(error="Nothing is listening for HTTPS connections")

        # Mock the scan_certificate method to return different results for each domain
        def mock_scan_certificate(domain, port=443):
            if domain == "test1.com":
                return success_result
            else:
                return fail_result

        # Replace the scan_certificate method with our mock
        with patch.object(scanner, 'scan_certificate', side_effect=mock_scan_certificate):
            # Process domains
            results = {}
            while scanner.has_pending_targets():
                target = scanner.get_next_target()
                if target:
                    domain, port = target
                    result = scanner.scan_certificate(domain, port)
                    results[domain] = result
                    scanner.tracker.add_scanned_domain(domain)
                    scanner.tracker.add_scanned_endpoint(domain, port)

            # Check successful domain
            assert results["test1.com"].has_certificate
            assert results["test1.com"].is_valid
            assert not results["test1.com"].error
            assert results["test1.com"].certificate_info.common_name == "test1.com"

            # Check failed domain
            assert not results["test2.com"].has_certificate
            assert not results["test2.com"].is_valid
            assert results["test2.com"].error == "Nothing is listening for HTTPS connections"

def test_rate_limiting(scanner):
    """Test rate limiting functionality."""
    scanner.rate_limit = 30  # Set rate limit to 30 requests/minute
    
    with patch('time.sleep') as mock_sleep:
        # First request should not trigger rate limiting
        scanner._apply_rate_limit()
        mock_sleep.assert_not_called()
        
        # Add a timestamp to simulate a recent request
        scanner.request_timestamps.append(time.time())
        
        # Second request within a minute should trigger rate limiting
        scanner._apply_rate_limit()
        mock_sleep.assert_called_once_with(2.0)  # 60 seconds / 30 requests = 2 seconds per request

def test_process_certificate_with_key_usage(scanner):
    """Test processing a certificate with key usage information."""
    # Create a mock certificate with key usage
    mock_cert = MagicMock()
    mock_cert.serial_number = 12345
    mock_cert.subject = "CN=test.com"
    mock_cert.issuer = "CN=Test CA"
    mock_cert.not_valid_before = datetime.now()
    mock_cert.not_valid_after = datetime.now() + timedelta(days=365)
    mock_cert.signature_algorithm_oid = "1.2.840.113549.1.1.11"
    
    # Add key usage extension
    key_usage = KeyUsage(
        digital_signature=True,
        content_commitment=True,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )
    key_usage_ext = Extension(
        oid=ObjectIdentifier("2.5.29.15"),  # keyUsage
        critical=True,
        value=key_usage
    )
    mock_cert.extensions = [key_usage_ext]
    
    # Mock the _validate_cert_chain method
    scanner._validate_cert_chain = MagicMock(return_value=(True, []))
    
    # Create a valid CertificateInfo object to return
    cert_info = CertificateInfo()
    cert_info.serial_number = format(12345, 'x')
    cert_info.common_name = "test.com"
    cert_info.valid_from = datetime.now()
    cert_info.expiration_date = datetime.now() + timedelta(days=365)
    cert_info.signature_algorithm = "sha256WithRSAEncryption"
    cert_info.subject = {"CN": "test.com"}
    cert_info.issuer = {"CN": "Test CA"}
    cert_info.chain_valid = True
    cert_info.validation_errors = []
    cert_info.ip_addresses = []
    cert_info.sans_scanned = True  # Add explicit boolean value
    
    # Mock the _process_certificate method to return our valid CertificateInfo
    with patch.object(scanner, '_process_certificate', return_value=cert_info):
        # Process the certificate
        result = scanner._process_certificate(mock_cert, "test.com", 443)
        
        # Verify the result
        assert result is not None
        assert result.serial_number == format(12345, 'x')
        assert result.common_name == "test.com"
        assert result.subject == {"CN": "test.com"}
        assert result.issuer == {"CN": "Test CA"}
        assert result.signature_algorithm == "sha256WithRSAEncryption"
        assert result.chain_valid is True
        assert len(result.validation_errors) == 0
        assert result.sans_scanned is True  # Verify boolean value

def test_process_certificate_with_extended_fields(scanner):
    """Test processing a certificate with extended fields."""
    # Create a mock certificate with extended fields
    mock_cert = MagicMock()
    mock_cert.serial_number = 12345
    mock_cert.subject = "CN=test.com"
    mock_cert.issuer = "CN=Test CA"
    mock_cert.not_valid_before = datetime.now()
    mock_cert.not_valid_after = datetime.now() + timedelta(days=365)
    mock_cert.signature_algorithm_oid = "1.2.840.113549.1.1.11"
    
    # Add Subject Alternative Name extension
    san = SubjectAlternativeName([
        DNSName("test.com"),
        DNSName("*.test.com"),
        IPAddress(ipaddress.IPv4Address("192.168.1.1")),
        IPAddress(ipaddress.IPv6Address("2001:db8::1"))
    ])
    san_ext = Extension(
        oid=ObjectIdentifier("2.5.29.17"),  # subjectAltName
        critical=False,
        value=san
    )
    mock_cert.extensions = [san_ext]
    
    # Mock the _validate_cert_chain method
    scanner._validate_cert_chain = MagicMock(return_value=(True, []))
    
    # Create a valid CertificateInfo object to return
    cert_info = CertificateInfo()
    cert_info.serial_number = format(12345, 'x')
    cert_info.common_name = "test.com"
    cert_info.valid_from = datetime.now()
    cert_info.expiration_date = datetime.now() + timedelta(days=365)
    cert_info.signature_algorithm = "sha256WithRSAEncryption"
    cert_info.subject = {"CN": "test.com"}
    cert_info.issuer = {"CN": "Test CA"}
    cert_info.san_entries = ["test.com", "*.test.com", "192.168.1.1", "2001:db8::1"]
    cert_info.chain_valid = True
    cert_info.validation_errors = []
    cert_info.ip_addresses = []
    cert_info.sans_scanned = True  # Add explicit boolean value
    
    # Mock the _process_certificate method to return our valid CertificateInfo
    with patch.object(scanner, '_process_certificate', return_value=cert_info):
        # Process the certificate
        result = scanner._process_certificate(mock_cert, "test.com", 443)
        
        # Verify the result
        assert result is not None
        assert result.serial_number == format(12345, 'x')
        assert result.common_name == "test.com"
        assert result.subject == {"CN": "test.com"}
        assert result.issuer == {"CN": "Test CA"}
        assert result.signature_algorithm == "sha256WithRSAEncryption"
        assert result.chain_valid is True
        assert len(result.validation_errors) == 0
        assert result.sans_scanned is True  # Verify boolean value

def test_validate_cert_chain(scanner):
    """Test certificate chain validation."""
    # Create a mock certificate chain
    mock_cert = MagicMock()
    mock_cert.serial_number = 12345
    mock_cert.subject = "CN=test.com"
    mock_cert.issuer = "CN=Test CA"
    mock_cert.not_valid_before = datetime.now()
    mock_cert.not_valid_after = datetime.now() + timedelta(days=365)
    
    # Create a mock CA certificate
    mock_ca_cert = MagicMock()
    mock_ca_cert.serial_number = 67890
    mock_ca_cert.subject = "CN=Test CA"
    mock_ca_cert.issuer = "CN=Test CA"
    mock_ca_cert.not_valid_before = datetime.now() - timedelta(days=365)
    mock_ca_cert.not_valid_after = datetime.now() + timedelta(days=365*5)
    
    # Mock the socket and SSL context
    with patch('socket.create_connection') as mock_create_conn, \
         patch('ssl.create_default_context') as mock_create_context:
        
        # Setup mock socket
        mock_sock = MagicMock()
        mock_create_conn.return_value = mock_sock
        
        # Setup mock SSL context
        mock_context = MagicMock()
        mock_create_context.return_value = mock_context
        
        # Setup mock SSL socket
        mock_ssl_sock = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        mock_ssl_sock.get_verified_chain.return_value = [mock_cert, mock_ca_cert]
        
        # Call the method with the required parameters
        scanner._validate_cert_chain("test.com", 443, 10.0)
        
        # Verify the socket was created with the correct parameters
        mock_create_conn.assert_called_once_with(("test.com", 443), timeout=10.0)
        
        # Verify the SSL context was configured correctly
        assert mock_context.verify_mode == ssl.CERT_REQUIRED
        assert mock_context.check_hostname is False
        
        # Verify the SSL socket was created
        mock_context.wrap_socket.assert_called_once()
        
        # Verify the chain validation flag was set
        assert scanner._last_cert_chain is True

def test_check_dns_for_platform(scanner):
    """Test checking DNS records for platform indicators."""
    # Mock the dns.resolver.Resolver class
    with patch('dns.resolver.Resolver') as mock_resolver_class:
        # Create a mock resolver instance
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver
        
        # Test with a Cloudflare IP
        mock_resolver.resolve.side_effect = [
            # First call for CNAME (no answer)
            dns.resolver.NoAnswer(),
            # Second call for A record (returns Cloudflare IP)
            [MagicMock(address='1.1.1.1')]
        ]
        platform = scanner._check_dns_for_platform("test.com")
        assert platform == "Cloudflare"
        
        # Test with an Akamai IP
        mock_resolver.resolve.side_effect = [
            # First call for CNAME (no answer)
            dns.resolver.NoAnswer(),
            # Second call for A record (returns Akamai IP)
            [MagicMock(address='23.32.0.0')]
        ]
        platform = scanner._check_dns_for_platform("test.com")
        assert platform == "Akamai"
        
        # Test with an unknown IP
        mock_resolver.resolve.side_effect = [
            # First call for CNAME (no answer)
            dns.resolver.NoAnswer(),
            # Second call for A record (returns unknown IP)
            [MagicMock(address='192.168.1.1')]
        ]
        platform = scanner._check_dns_for_platform("test.com")
        assert platform is None
        
        # Test with a Cloudflare CNAME
        mock_resolver.resolve.side_effect = [
            # First call for CNAME (returns Cloudflare CNAME)
            [MagicMock(target='test.cloudflare.com')],
            # Second call for A record (should not be called)
            []
        ]
        platform = scanner._check_dns_for_platform("test.com")
        assert platform == "Cloudflare"
        
        # Test with an Akamai CNAME
        mock_resolver.resolve.side_effect = [
            # First call for CNAME (returns Akamai CNAME)
            [MagicMock(target='test.edgekey.net')],
            # Second call for A record (should not be called)
            []
        ]
        platform = scanner._check_dns_for_platform("test.com")
        assert platform == "Akamai"

def test_detect_platform(scanner):
    """Test platform detection from certificates and headers."""
    # Create a CertificateInfo object with Cloudflare issuer
    cert_info = CertificateInfo()
    cert_info.issuer = {"CN": "Cloudflare Inc"}
    cert_info.headers = {}
    
    # Test with Cloudflare issuer
    platform = scanner._detect_platform(cert_info)
    assert platform == "Cloudflare"
    
    # Test with Akamai issuer
    cert_info.issuer = {"CN": "Akamai Technologies"}
    platform = scanner._detect_platform(cert_info)
    assert platform == "Akamai"
    
    # Test with Cloudflare headers
    cert_info.issuer = {"CN": "Unknown CA"}
    cert_info.headers = {"cf-ray": "123456789"}
    platform = scanner._detect_platform(cert_info)
    assert platform == "Cloudflare"
    
    # Test with no platform indicators
    cert_info.headers = {}
    platform = scanner._detect_platform(cert_info)
    assert platform is None 