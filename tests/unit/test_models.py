import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import json
from infra_mgmt.models import (
    Base, Host, HostIP, Certificate, CertificateBinding,
    CertificateTracking, CertificateScan,
    HOST_TYPE_SERVER, ENV_PRODUCTION, BINDING_TYPE_IP,
    PLATFORM_F5
)

@pytest.fixture
def engine():
    """Create a SQLite in-memory database"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def session(engine):
    """Create a new database session for a test"""
    with Session(engine) as session:
        yield session

@pytest.fixture
def host(session):
    """Create a test host"""
    host = Host(
        name="test-server",
        host_type=HOST_TYPE_SERVER,
        environment=ENV_PRODUCTION,
        description="Test Server",
        last_seen=datetime.now()
    )
    session.add(host)
    session.commit()
    return host

@pytest.fixture
def host_ip(session, host):
    """Create a test host IP"""
    host_ip = HostIP(
        host=host,
        ip_address="192.168.1.1",
        is_active=True,
        last_seen=datetime.now()
    )
    session.add(host_ip)
    session.commit()
    return host_ip

@pytest.fixture
def certificate(session):
    """Create a test certificate"""
    cert = Certificate(
        serial_number="123456",
        thumbprint="abc123",
        common_name="test.com",
        valid_from=datetime.now(),
        valid_until=datetime.now(),
        issuer={"CN": "Test CA", "O": "Test Org"},
        subject={"CN": "test.com", "O": "Test Company"},
        san=["test.com", "www.test.com"],
        key_usage="Digital Signature, Key Encipherment",
        signature_algorithm="sha256WithRSAEncryption",
        sans_scanned=False
    )
    session.add(cert)
    session.commit()
    return cert

@pytest.fixture
def certificate_scan(session, certificate):
    """Create a test certificate scan"""
    scan = CertificateScan(
        certificate=certificate,
        scan_date=datetime.now(),
        status="Valid",
        port=443
    )
    session.add(scan)
    session.commit()
    return scan

@pytest.fixture
def multiple_certificates(session):
    """Create multiple test certificates"""
    certs = []
    for i in range(3):
        cert = Certificate(
            serial_number=f"123456{i}",
            thumbprint=f"abc123{i}",
            common_name=f"test{i}.com",
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=365),
            issuer={"CN": "Test CA", "O": "Test Org"},
            subject={"CN": f"test{i}.com", "O": "Test Company"},
            san=[f"test{i}.com", f"www.test{i}.com"],
            key_usage="Digital Signature",
            signature_algorithm="sha256WithRSAEncryption",
            sans_scanned=False
        )
        certs.append(cert)
        session.add(cert)
    session.commit()
    return certs

@pytest.fixture
def multiple_certificate_scans(session, multiple_certificates):
    """Create multiple test certificate scans"""
    scans = []
    for cert in multiple_certificates:
        scan = CertificateScan(
            certificate=cert,
            scan_date=datetime.now(),
            status="Valid",
            port=443
        )
        scans.append(scan)
        session.add(scan)
    session.commit()
    return scans

@pytest.fixture
def certificate_tracking(session, certificate):
    """Create a test certificate tracking entry"""
    tracking = CertificateTracking(
        certificate=certificate,
        change_number="CHG001",
        planned_change_date=datetime.now(),
        notes="Initial entry",
        status="Pending",
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    session.add(tracking)
    session.commit()
    return tracking

def test_host_creation(session, host):
    """Test creating a host"""
    assert host.id is not None
    assert host.name == "test-server"
    assert host.host_type == HOST_TYPE_SERVER
    assert host.environment == ENV_PRODUCTION
    assert host.description == "Test Server"
    assert isinstance(host.last_seen, datetime)

def test_host_unique_name(session, host):
    """Test that host names must be unique"""
    duplicate_host = Host(
        name="test-server",  # Same name as existing host
        host_type=HOST_TYPE_SERVER,
        environment=ENV_PRODUCTION
    )
    session.add(duplicate_host)
    with pytest.raises(IntegrityError):
        session.commit()

def test_host_ip_relationship(session, host, host_ip):
    """Test host to IP relationship"""
    assert len(host.ip_addresses) == 1
    assert host.ip_addresses[0].ip_address == "192.168.1.1"
    assert host_ip.host.name == "test-server"

def test_host_ip_unique_constraint(session, host):
    """Test that IP addresses must be unique per host"""
    ip1 = HostIP(host=host, ip_address="192.168.1.1")
    ip2 = HostIP(host=host, ip_address="192.168.1.1")  # Same IP
    session.add(ip1)
    session.add(ip2)
    with pytest.raises(IntegrityError):
        session.commit()

def test_certificate_creation(session, certificate):
    """Test creating a certificate"""
    assert certificate.id is not None
    assert certificate.serial_number == "123456"
    assert certificate.thumbprint == "abc123"
    assert certificate.common_name == "test.com"
    assert isinstance(certificate.valid_from, datetime)
    assert isinstance(certificate.valid_until, datetime)

def test_certificate_unique_constraints(session, certificate):
    """Test certificate unique constraints"""
    # Test duplicate serial number
    duplicate_cert = Certificate(
        serial_number="123456",  # Same as existing
        thumbprint="def456",
        common_name="other.com"
    )
    session.add(duplicate_cert)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

    # Test duplicate thumbprint
    duplicate_cert = Certificate(
        serial_number="789012",
        thumbprint="abc123",  # Same as existing
        common_name="other.com"
    )
    session.add(duplicate_cert)
    with pytest.raises(IntegrityError):
        session.commit()

def test_certificate_binding(session, host, host_ip, certificate):
    """Test creating a certificate binding"""
    binding = CertificateBinding(
        host=host,
        host_ip=host_ip,
        certificate=certificate,
        port=443,
        binding_type=BINDING_TYPE_IP,
        platform=PLATFORM_F5,
        site_name="HTTPS",
        last_seen=datetime.now()
    )
    session.add(binding)
    session.commit()

    assert binding.id is not None
    assert binding.host.name == "test-server"
    assert binding.host_ip.ip_address == "192.168.1.1"
    assert binding.certificate.common_name == "test.com"
    assert binding.port == 443
    assert binding.binding_type == BINDING_TYPE_IP
    assert binding.platform == PLATFORM_F5
    assert binding.site_name == "HTTPS"

def test_certificate_binding_unique_constraint(session, host, host_ip, certificate):
    """Test that bindings must be unique per host/IP/port/site"""
    binding1 = CertificateBinding(
        host=host,
        host_ip=host_ip,
        certificate=certificate,
        port=443,
        binding_type=BINDING_TYPE_IP,
        platform=PLATFORM_F5,
        site_name="HTTPS",
        last_seen=datetime.now()
    )
    binding2 = CertificateBinding(
        host=host,
        host_ip=host_ip,
        certificate=certificate,
        port=443,  # Same port
        binding_type=BINDING_TYPE_IP,
        platform=PLATFORM_F5,
        site_name="HTTPS",  # Same site name
        last_seen=datetime.now()
    )
    session.add(binding1)
    session.add(binding2)
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()

def test_cascade_delete_host(session, host, host_ip, certificate):
    """Test that deleting a host cascades to IPs and bindings"""
    # Create a binding
    binding = CertificateBinding(
        host=host,
        host_ip=host_ip,
        certificate=certificate,
        port=443
    )
    session.add(binding)
    session.commit()

    # Delete the host
    session.delete(host)
    session.commit()

    # Verify everything is deleted
    assert session.query(Host).count() == 0
    assert session.query(HostIP).count() == 0
    assert session.query(CertificateBinding).count() == 0
    assert session.query(Certificate).count() == 1  # Certificate should remain

def test_certificate_tracking(session, certificate):
    """Test creating certificate tracking entries"""
    tracking = CertificateTracking(
        certificate=certificate,
        change_number="CHG001",
        planned_change_date=datetime.now(),
        notes="Initial deployment",
        status="Pending",
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    session.add(tracking)
    session.commit()

    assert tracking.id is not None
    assert tracking.certificate.common_name == "test.com"
    assert tracking.status == "Pending"

def test_certificate_scan(session, certificate):
    """Test creating certificate scan entries"""
    scan = CertificateScan(
        certificate=certificate,
        scan_date=datetime.now(),
        status="Valid",
        port=443
    )
    session.add(scan)
    session.commit()

    assert scan.id is not None
    assert scan.certificate.common_name == "test.com"
    assert scan.status == "Valid"

def test_cascade_delete_certificate(session, certificate):
    """Test that deleting a certificate cascades to scans and tracking entries"""
    # Add scan and tracking entries
    scan = CertificateScan(
        certificate=certificate,
        scan_date=datetime.now(),
        status="Valid",
        port=443
    )
    tracking = CertificateTracking(
        certificate=certificate,
        change_number="CHG002",
        planned_change_date=datetime.now(),
        notes="Test entry",
        status="Pending",
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    session.add(scan)
    session.add(tracking)
    session.commit()

    # Delete the certificate
    session.delete(certificate)
    session.commit()

    # Verify everything is deleted
    assert session.query(Certificate).count() == 0
    assert session.query(CertificateScan).count() == 0
    assert session.query(CertificateTracking).count() == 0

def test_certificate_scan_relationship():
    """Test the relationship between Certificate and CertificateScan"""
    cert = Certificate(
        serial_number="123456",
        thumbprint="abcdef",
        common_name="test.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=365),
        issuer="Test CA",
        subject="Test Subject"
    )
    
    scan = CertificateScan(
        scan_date=datetime.now(),
        status="Valid",
        port=443
    )
    cert.scans.append(scan)
    
    assert len(cert.scans) == 1
    assert cert.scans[0].scan_date is not None
    assert cert.scans[0].status == "Valid"
    assert cert.scans[0].port == 443

def test_host_scan_relationship():
    """Test the relationship between Host and CertificateScan"""
    host = Host(
        name="test.com",
        host_type="Server",
        environment="Production",
        last_seen=datetime.now()
    )
    
    scan = CertificateScan(
        scan_date=datetime.now(),
        status="Valid",
        port=443
    )
    host.scans.append(scan)
    
    assert len(host.scans) == 1
    assert host.scans[0].scan_date is not None
    assert host.scans[0].status == "Valid"
    assert host.scans[0].port == 443 

def test_certificate_json_fields(session):
    """Test that JSON fields are properly serialized and deserialized"""
    cert = Certificate(
        serial_number="123456",
        thumbprint="abc123",
        common_name="test.com",
        valid_from=datetime.now(),
        valid_until=datetime.now(),
        issuer={"CN": "Test CA", "O": "Test Org"},
        subject={"CN": "test.com", "O": "Test Company"},
        san=["test.com", "www.test.com", "api.test.com"],
        key_usage="Digital Signature",
        signature_algorithm="sha256WithRSAEncryption",
        sans_scanned=False
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)

    # Test that the properties return proper Python objects
    assert isinstance(cert.issuer, dict)
    assert cert.issuer["CN"] == "Test CA"
    assert cert.issuer["O"] == "Test Org"

    assert isinstance(cert.subject, dict)
    assert cert.subject["CN"] == "test.com"
    assert cert.subject["O"] == "Test Company"

    assert isinstance(cert.san, list)
    assert len(cert.san) == 3
    assert "test.com" in cert.san
    assert "www.test.com" in cert.san
    assert "api.test.com" in cert.san

    # Test that the raw columns contain JSON strings
    assert isinstance(cert._issuer, str)
    assert isinstance(cert._subject, str)
    assert isinstance(cert._san, str)

    # Test that we can parse the raw JSON
    assert json.loads(cert._issuer) == {"CN": "Test CA", "O": "Test Org"}
    assert json.loads(cert._subject) == {"CN": "test.com", "O": "Test Company"}
    assert json.loads(cert._san) == ["test.com", "www.test.com", "api.test.com"]

def test_certificate_json_fields_none_values(session):
    """Test that JSON fields handle None values properly"""
    cert = Certificate(
        serial_number="123456",
        thumbprint="abc123",
        common_name="test.com",
        valid_from=datetime.now(),
        valid_until=datetime.now(),
        issuer=None,
        subject=None,
        san=None,
        key_usage="Digital Signature",
        signature_algorithm="sha256WithRSAEncryption",
        sans_scanned=False
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)

    # Test that None values return empty containers
    assert cert.issuer == {}
    assert cert.subject == {}
    assert cert.san == []

    # Test that the raw columns are None
    assert cert._issuer is None
    assert cert._subject is None
    assert cert._san is None

def test_certificate_basic_info(session, certificate):
    """Test basic certificate information"""
    assert certificate.serial_number == "123456"
    assert certificate.thumbprint == "abc123"
    assert certificate.common_name == "test.com"
    assert isinstance(certificate.valid_from, datetime)
    assert isinstance(certificate.valid_until, datetime)
    assert certificate.issuer == {"CN": "Test CA", "O": "Test Org"}
    assert certificate.subject == {"CN": "test.com", "O": "Test Company"}
    assert certificate.san == ["test.com", "www.test.com"]

def test_host_basic_info(session, host):
    """Test basic host information"""
    assert host.name == "test-server"
    assert host.host_type == HOST_TYPE_SERVER
    assert host.environment == ENV_PRODUCTION
    assert isinstance(host.last_seen, datetime)

def test_certificate_scan_basic_info(session, certificate_scan):
    """Test basic certificate scan information"""
    assert certificate_scan.certificate is not None
    assert isinstance(certificate_scan.scan_date, datetime)
    assert certificate_scan.status == "Valid"
    assert certificate_scan.port == 443

def test_multiple_certificate_scans(session, multiple_certificate_scans, multiple_certificates):
    """Test multiple certificate scans"""
    assert len(multiple_certificate_scans) == 3
    for scan in multiple_certificate_scans:
        assert scan.certificate in multiple_certificates
        assert scan.status == "Valid"
        assert scan.port == 443

def test_certificate_tracking_basic_info(session, certificate_tracking):
    """Test basic certificate tracking information"""
    assert certificate_tracking.certificate is not None
    assert certificate_tracking.change_number == "CHG001"
    assert isinstance(certificate_tracking.planned_change_date, datetime)
    assert certificate_tracking.status == "Pending"
    assert isinstance(certificate_tracking.created_at, datetime)
    assert isinstance(certificate_tracking.updated_at, datetime) 