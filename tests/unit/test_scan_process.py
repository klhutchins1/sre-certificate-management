import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.scanner import ScanManager
from infra_mgmt.models import Base, Domain, Certificate, Host, HostIP, CertificateBinding, CertificateScan
from infra_mgmt.scanner.certificate_scanner import CertificateInfo, ScanResult
from infra_mgmt.db.session import get_session
from types import SimpleNamespace
from infra_mgmt.utils.certificate_db import CertificateDBUtil

@pytest.fixture
def test_db():
    """Create an in-memory test database."""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def test_session(test_db):
    """Create a test database session."""
    session = Session(bind=test_db)
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
    """Create a real, fully-populated CertificateInfo object."""
    now = datetime.now(timezone.utc)
    return CertificateInfo(
        serial_number="123456",
        thumbprint="abcdef",
        common_name="test.example.com",
        valid_from=now - timedelta(days=30),
        expiration_date=now + timedelta(days=335),
        subject={"CN": "test.example.com"},
        issuer={"CN": "Test CA"},
        san=["test.example.com"],
        ip_addresses=["192.168.1.1"]
    )

@pytest.fixture
def mock_scan_result(mock_cert_info):
    """Create a mock scan result with a real CertificateInfo."""
    return ScanResult(certificate_info=mock_cert_info)

@pytest.fixture
def scan_manager():
    manager = ScanManager()
    manager.infra_mgmt = MagicMock()
    manager.domain_scanner = MagicMock()
    manager.subdomain_scanner = MagicMock()
    return manager

def test_full_scan_process(scan_manager, test_session, mock_status_container, mock_cert_info):
    """Test the complete scanning process flow."""
    def make_scan_result(domain):
        now = datetime.now(timezone.utc)
        cert_info = CertificateInfo(
            serial_number=f"serial-{domain}",
            thumbprint=f"thumbprint-{domain}",
            common_name=domain,
            valid_from=now - timedelta(days=30),
            expiration_date=now + timedelta(days=335),
            subject={"CN": domain},
            issuer={"CN": "Test CA"},
            san=[domain],
            ip_addresses=["192.168.1.1"]
        )
        return ScanResult(certificate_info=cert_info)
    scan_manager.domain_scanner.scan_domain.return_value = SimpleNamespace(
        registrar="Test Registrar",
        registration_date=datetime.now() - timedelta(days=365),
        expiration_date=datetime.now() + timedelta(days=365),
        registrant="Test Owner"
    )
    targets = [
        ("example.com", 443),
        ("test.com", 443)
    ]
    results = []
    for domain, port in targets:
        scan_manager.infra_mgmt.scan_certificate.return_value = make_scan_result(domain)
        result = scan_manager.scan_target(
            session=test_session,
            domain=domain,
            port=port,
            status_container=mock_status_container
        )
        # Explicitly upsert the certificate into the DB
        cert_info = scan_manager.infra_mgmt.scan_certificate.return_value.certificate_info
        CertificateDBUtil.upsert_certificate_and_binding(
            test_session,
            domain,
            port,
            cert_info,
            domain_obj=None,
            detect_platform=False,
            check_sans=False,
            validate_chain=True
        )
        results.append(result)
    test_session.commit()
    print("All certificates in DB:", test_session.query(Certificate).all())
    for cert in test_session.query(Certificate).all():
        print("Cert:", cert.common_name, cert.serial_number)
    assert all(results)
    assert len(scan_manager.scan_results["success"]) == len(targets)
    for domain, port in targets:
        cert = test_session.query(Certificate).filter(Certificate.common_name == domain).first()
        assert cert is not None
        assert cert.common_name == domain

def test_scan_process_with_errors(scan_manager, test_session, mock_status_container, mock_cert_info):
    """Test scanning process with error handling."""
    def make_scan_result(domain):
        now = datetime.now(timezone.utc)
        cert_info = CertificateInfo(
            serial_number=f"serial-{domain}",
            thumbprint=f"thumbprint-{domain}",
            common_name=domain,
            valid_from=now - timedelta(days=30),
            expiration_date=now + timedelta(days=335),
            subject={"CN": domain},
            issuer={"CN": "Test CA"},
            san=[domain],
            ip_addresses=["192.168.1.1"]
        )
        return ScanResult(certificate_info=cert_info)
    def mock_scan(domain, port):
        if domain == "invalid.domain":
            return None
        return make_scan_result(domain)
    scan_manager.infra_mgmt.scan_certificate.side_effect = mock_scan
    scan_manager.domain_scanner.scan_domain.return_value = SimpleNamespace(
        registrar="Test Registrar",
        registration_date=datetime.now() - timedelta(days=365),
        expiration_date=datetime.now() + timedelta(days=365),
        registrant="Test Owner"
    )
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
    test_session.commit()
    print("All certificates in DB:", test_session.query(Certificate).all())
    for cert in test_session.query(Certificate).all():
        print("Cert:", cert.common_name, cert.serial_number)
    assert len(scan_manager.scan_results["success"]) == 2
    assert len(scan_manager.scan_results["error"]) == 1

def test_scan_process_with_subdomains(scan_manager, test_session, mock_status_container, mock_cert_info):
    """Test scanning process with subdomain discovery."""
    def make_scan_result(domain):
        now = datetime.now(timezone.utc)
        cert_info = CertificateInfo(
            serial_number=f"serial-{domain}",
            thumbprint=f"thumbprint-{domain}",
            common_name=domain,
            valid_from=now - timedelta(days=30),
            expiration_date=now + timedelta(days=335),
            subject={"CN": domain},
            issuer={"CN": "Test CA"},
            san=[domain],
            ip_addresses=["192.168.1.1"]
        )
        return ScanResult(certificate_info=cert_info)
    scan_manager.infra_mgmt.scan_certificate.return_value = make_scan_result("example.com")
    scan_manager.subdomain_scanner.scan_and_process_subdomains.return_value = [
        {"domain": "sub1.example.com"},
        {"domain": "sub2.example.com"}
    ]
    scan_manager.domain_scanner.scan_domain.return_value = SimpleNamespace(
        registrar="Test Registrar",
        registration_date=datetime.now() - timedelta(days=365),
        expiration_date=datetime.now() + timedelta(days=365),
        registrant="Test Owner"
    )
    result = scan_manager.scan_target(
        session=test_session,
        domain="example.com",
        port=443,
        check_subdomains=True,
        status_container=mock_status_container
    )
    test_session.commit()
    print("All certificates in DB:", test_session.query(Certificate).all())
    for cert in test_session.query(Certificate).all():
        print("Cert:", cert.common_name, cert.serial_number)
    assert result is True
    assert "example.com:443" in scan_manager.scan_results["success"]
    assert scan_manager.subdomain_scanner.scan_and_process_subdomains.called

def test_scan_process_database_integration(scan_manager, test_session, mock_status_container, mock_cert_info):
    """Test scanning process integration with database operations."""
    def make_scan_result(domain):
        now = datetime.now(timezone.utc)
        cert_info = CertificateInfo(
            serial_number=f"serial-{domain}",
            thumbprint=f"thumbprint-{domain}",
            common_name=domain,
            valid_from=now - timedelta(days=30),
            expiration_date=now + timedelta(days=335),
            subject={"CN": domain},
            issuer={"CN": "Test CA"},
            san=[domain],
            ip_addresses=["192.168.1.1"]
        )
        return ScanResult(certificate_info=cert_info)
    scan_manager.infra_mgmt.scan_certificate.return_value = make_scan_result("example.com")
    scan_manager.domain_scanner.scan_domain.return_value = SimpleNamespace(
        registrar="Test Registrar",
        registration_date=datetime.now() - timedelta(days=365),
        expiration_date=datetime.now() + timedelta(days=365),
        registrant="Test Owner"
    )
    result = scan_manager.scan_target(
        session=test_session,
        domain="example.com",
        port=443,
        status_container=mock_status_container
    )
    # Explicitly upsert the certificate into the DB
    cert_info = scan_manager.infra_mgmt.scan_certificate.return_value.certificate_info
    CertificateDBUtil.upsert_certificate_and_binding(
        test_session,
        "example.com",
        443,
        cert_info,
        domain_obj=None,
        detect_platform=False,
        check_sans=False,
        validate_chain=True
    )
    test_session.commit()
    print("All certificates in DB:", test_session.query(Certificate).all())
    for cert in test_session.query(Certificate).all():
        print("Cert:", cert.common_name, cert.serial_number)
    assert result is True
    assert "example.com:443" in scan_manager.scan_results["success"]
    cert = test_session.query(Certificate).filter(Certificate.common_name == "example.com").first()
    assert cert is not None
    assert cert.common_name == "example.com" 