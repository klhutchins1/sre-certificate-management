import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
from infra_mgmt.scanner import ScanManager, ScanProcessor
from infra_mgmt.scanner.certificate_scanner import CertificateInfo, ScanResult
from infra_mgmt.models import Domain, Certificate, Host, HostIP, CertificateBinding, CertificateScan
from infra_mgmt.db.session import get_session

@pytest.fixture
def mock_session():
    """Create a mock database session."""
    session = MagicMock()
    session.query.return_value.filter_by.return_value.first.return_value = None
    return session

@pytest.fixture
def mock_status_container():
    """Create a mock status container."""
    container = MagicMock()
    container.text = MagicMock()
    container.progress = MagicMock()
    return container

@pytest.fixture
def mock_cert_info():
    """Create a mock certificate info."""
    return CertificateInfo(
        serial_number="123456",
        thumbprint="abcdef",
        common_name="test.example.com",
        valid_from=datetime.now(timezone.utc),
        expiration_date=datetime.now(timezone.utc),
        subject={"CN": "test.example.com"},
        issuer={"CN": "Test CA"},
        san=["test.example.com"],
        ip_addresses=["192.168.1.1"]
    )

@pytest.fixture
def mock_scan_result(mock_cert_info):
    """Create a mock scan result."""
    return ScanResult(certificate_info=mock_cert_info)

@pytest.fixture
def scan_manager():
    """Create a ScanManager instance."""
    manager = ScanManager()
    # Mock the certificate scanner
    manager.infra_mgmt = MagicMock()
    manager.domain_scanner = MagicMock()
    manager.subdomain_scanner = MagicMock()
    return manager

def test_scan_manager_initialization(scan_manager):
    """Test ScanManager initialization."""
    assert hasattr(scan_manager, 'infra_mgmt')
    assert hasattr(scan_manager, 'domain_scanner')
    assert hasattr(scan_manager, 'subdomain_scanner')
    assert hasattr(scan_manager, 'scan_results')
    # Allow extra keys in scan_results, but required keys must be present and empty
    for key in ['success', 'error', 'warning', 'no_cert']:
        assert key in scan_manager.scan_results
        assert scan_manager.scan_results[key] == []

def test_process_scan_target(scan_manager):
    """Test processing a scan target."""
    target = "example.com:443"
    is_valid, hostname, port, error = scan_manager.process_scan_target(target)
    assert is_valid
    assert hostname == "example.com"
    assert port == 443
    assert error is None

def test_process_scan_target_invalid(scan_manager):
    """Test processing an invalid scan target."""
    target = "invalid:port"
    is_valid, hostname, port, error = scan_manager.process_scan_target(target)
    assert not is_valid
    assert error is not None

def test_scan_target_success(scan_manager, mock_session, mock_status_container, mock_scan_result):
    """Test successful target scanning."""
    # Configure mocks
    scan_manager.infra_mgmt.scan_certificate.return_value = mock_scan_result
    scan_manager.domain_scanner.scan_domain.return_value = MagicMock()
    # Ensure the query chain returns None so commit() is called
    mock_session.query.return_value.filter_by.return_value.first.return_value = None

    # Patch upsert_certificate_and_binding to call session.commit()
    with patch('infra_mgmt.utils.certificate_db.CertificateDBUtil.upsert_certificate_and_binding') as mock_upsert:
        def upsert_side_effect(session, *args, **kwargs):
            session.commit()
        mock_upsert.side_effect = upsert_side_effect

        # Test the scan
        result = scan_manager.scan_target(
            session=mock_session,
            domain="example.com",
            port=443,
            status_container=mock_status_container
        )
        assert result is True
        assert "example.com:443" in scan_manager.scan_results["success"]
        mock_session.commit.assert_called()

def test_scan_target_error(scan_manager, mock_session, mock_status_container):
    """Test error handling during target scanning."""
    # Configure mock to raise an error
    scan_manager.infra_mgmt.scan_certificate.side_effect = Exception("Scan failed")
    # Patch the logger attribute directly to suppress noisy output
    scan_manager.logger.exception = lambda *a, **k: None
    scan_manager.logger.error = lambda *a, **k: None
    scan_manager.logger.warning = lambda *a, **k: None
    # Test the scan (should raise Exception)
    with pytest.raises(Exception, match="Scan failed"):
        scan_manager.scan_target(
            session=mock_session,
            domain="example.com",
            port=443,
            status_container=mock_status_container
        )
    mock_session.rollback.assert_called()

def test_scan_target_no_certificate(scan_manager, mock_session, mock_status_container):
    """Test handling when no certificate is found."""
    # Configure mock to return None for certificate and domain info
    scan_manager.infra_mgmt.scan_certificate.return_value = None
    scan_manager.domain_scanner.scan_domain.return_value = None

    # Test the scan
    result = scan_manager.scan_target(
        session=mock_session,
        domain="example.com",
        port=443,
        status_container=mock_status_container
    )
    # Should return True (scan completed, but nothing found)
    assert result is True
    # Should record in error (with a message starting with the domain:port)
    assert any(e.startswith("example.com:443") for e in scan_manager.scan_results["error"])

def test_scan_target_with_subdomains(scan_manager, mock_session, mock_status_container, mock_scan_result):
    """Test scanning with subdomain discovery."""
    # Configure mocks
    scan_manager.infra_mgmt.scan_certificate.return_value = mock_scan_result
    scan_manager.subdomain_scanner.scan_and_process_subdomains.return_value = [
        {"domain": "sub.example.com"}
    ]
    
    # Test the scan
    result = scan_manager.scan_target(
        session=mock_session,
        domain="example.com",
        port=443,
        check_subdomains=True,
        status_container=mock_status_container
    )
    
    assert result is True
    scan_manager.subdomain_scanner.scan_and_process_subdomains.assert_called_once()

def test_get_scan_stats(scan_manager):
    """Test scan statistics calculation."""
    # Add some test results
    scan_manager.scan_results["success"].append("success.com:443")
    scan_manager.scan_results["error"].append("error.com:443")
    scan_manager.scan_results["warning"].append("warning.com:443")
    scan_manager.infra_mgmt.get_scan_stats.return_value = {}
    stats = scan_manager.get_scan_stats()
    assert stats["success_count"] == 1
    assert stats["error_count"] == 1
    assert stats["warning_count"] == 1 