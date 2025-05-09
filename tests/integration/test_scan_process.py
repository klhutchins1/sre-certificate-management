import pytest
from unittest.mock import MagicMock
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.scanner import ScanManager
from infra_mgmt.models import Base, Domain, Certificate, Host, HostIP, CertificateBinding, CertificateScan
from infra_mgmt.scanner.certificate_scanner import CertificateInfo, ScanResult
from infra_mgmt.db.session import get_session

@pytest.fixture
def test_db():
    """Create an in-memory test database."""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def test_session(test_db):
    """Create a test database session."""
    session = get_session()
    yield session
    session.close()

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
        valid_from=datetime.now(),
        expiration_date=datetime.now(),
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
    """Create a ScanManager instance with mocked components."""
    manager = ScanManager()
    manager.infra_mgmt = MagicMock()
    manager.domain_scanner = MagicMock()
    manager.subdomain_scanner = MagicMock()
    return manager

def test_full_scan_process(scan_manager, test_session, mock_status_container, mock_scan_result):
    """Test the complete scanning process flow."""
    # Configure mocks
    scan_manager.infra_mgmt.scan_certificate.return_value = mock_scan_result
    scan_manager.domain_scanner.scan_domain.return_value = MagicMock()
    
    # Process test targets
    targets = [
        ("example.com", 443),
        ("test.com", 443)
    ]
    
    results = []
    for domain, port in targets:
        result = scan_manager.scan_target(
            session=test_session,
            domain=domain,
            port=port,
            status_container=mock_status_container
        )
        results.append(result)
    
    # Verify scan completion
    assert all(results)  # All scans should succeed
    assert len(scan_manager.scan_results["success"]) == len(targets)
    
    # Verify database entries
    for domain, port in targets:
        cert = test_session.query(Certificate).join(CertificateBinding).join(Host).filter(
            Host.name == domain
        ).first()
        assert cert is not None
        assert cert.common_name == "test.example.com"  # From mock_cert_info

def test_scan_process_with_errors(scan_manager, test_session, mock_status_container):
    """Test scanning process with error handling."""
    # Configure mock to fail for specific domain
    def mock_scan(domain, port):
        if domain == "invalid.domain":
            return None
        return mock_scan_result
    
    scan_manager.infra_mgmt.scan_certificate.side_effect = mock_scan
    
    # Process targets
    targets = [
        ("example.com", 443),
        ("invalid.domain", 443),
        ("test.com", 443)
    ]
    
    results = []
    for domain, port in targets:
        result = scan_manager.scan_target(
            session=test_session,
            domain=domain,
            port=port,
            status_container=mock_status_container
        )
        results.append(result)
    
    # Verify error handling
    assert len(scan_manager.scan_results["success"]) == 2  # Two should succeed
    assert len(scan_manager.scan_results["error"]) == 1   # One should fail

def test_scan_process_with_subdomains(scan_manager, test_session, mock_status_container, mock_scan_result):
    """Test scanning process with subdomain discovery."""
    # Configure mocks
    scan_manager.infra_mgmt.scan_certificate.return_value = mock_scan_result
    scan_manager.subdomain_scanner.scan_and_process_subdomains.return_value = [
        {"domain": "sub1.example.com"},
        {"domain": "sub2.example.com"}
    ]
    
    # Process target with subdomain scanning
    result = scan_manager.scan_target(
        session=test_session,
        domain="example.com",
        port=443,
        check_subdomains=True,
        status_container=mock_status_container
    )
    
    # Verify results
    assert result is True
    assert "example.com:443" in scan_manager.scan_results["success"]
    scan_manager.subdomain_scanner.scan_and_process_subdomains.assert_called_once()
    
    # Verify subdomains were added to queue
    assert scan_manager.infra_mgmt.tracker.queue_size() == 2  # Two subdomains should be queued

def test_scan_process_database_integration(scan_manager, test_session, mock_status_container, mock_scan_result):
    """Test scanning process integration with database operations."""
    # Configure mocks
    scan_manager.infra_mgmt.scan_certificate.return_value = mock_scan_result
    scan_manager.domain_scanner.scan_domain.return_value = MagicMock()
    
    # Process target
    result = scan_manager.scan_target(
        session=test_session,
        domain="example.com",
        port=443,
        status_container=mock_status_container
    )
    
    # Verify scan success
    assert result is True
    assert "example.com:443" in scan_manager.scan_results["success"]
    
    # Verify database entries
    cert = test_session.query(Certificate).first()
    assert cert is not None
    assert cert.serial_number == "123456"  # From mock_cert_info
    
    host = test_session.query(Host).first()
    assert host is not None
    assert host.name == "example.com"
    
    binding = test_session.query(CertificateBinding).first()
    assert binding is not None
    assert binding.certificate_id == cert.id
    assert binding.host_id == host.id 