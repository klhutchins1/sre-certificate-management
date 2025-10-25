"""
Tests for proxy override functionality in certificate management.
"""
import pytest
from datetime import datetime, date, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate, CertificateBinding, Host, HostIP
from infra_mgmt.services.CertificateService import CertificateService
from infra_mgmt.constants import HOST_TYPE_SERVER, ENV_PRODUCTION, BINDING_TYPE_IP, PLATFORM_F5
import json

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
def certificate(session, host_ip):
    """Create a test certificate with proxy detection"""
    cert = Certificate(
        serial_number="proxy_serial_123",
        thumbprint="proxy_thumbprint_456",
        common_name="example.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=90),
        issuer=json.dumps({"commonName": "Proxy CA", "organizationName": "Proxy Corp"}),
        subject=json.dumps({"commonName": "example.com"}),
        san=json.dumps(["example.com", "www.example.com"]),
        proxied=True,
        proxy_info=json.dumps({"detected": "short_validity_period", "confidence": 0.8})
    )
    session.add(cert)
    session.commit()
    return cert

@pytest.fixture
def certificate_binding(session, certificate, host_ip):
    """Create a test certificate binding"""
    binding = CertificateBinding(
        certificate=certificate,
        host_ip=host_ip,
        port=443,
        binding_type=BINDING_TYPE_IP,
        platform=PLATFORM_F5
    )
    session.add(binding)
    session.commit()
    return binding

class TestProxyOverrideModel:
    """Test the new proxy override fields in the Certificate model."""
    
    def test_certificate_has_proxy_override_fields(self, session, certificate):
        """Test that certificate has all the new proxy override fields."""
        assert hasattr(certificate, 'real_serial_number')
        assert hasattr(certificate, 'real_thumbprint')
        assert hasattr(certificate, 'real_issuer')
        assert hasattr(certificate, 'real_subject')
        assert hasattr(certificate, 'real_valid_from')
        assert hasattr(certificate, 'real_valid_until')
        assert hasattr(certificate, 'override_notes')
        assert hasattr(certificate, 'override_created_at')
    
    def test_proxy_override_fields_are_nullable(self, session):
        """Test that proxy override fields can be null."""
        cert = Certificate(
            serial_number="test_serial",
            thumbprint="test_thumbprint",
            common_name="test.com",
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=90),
            issuer=json.dumps({"commonName": "Test CA"}),
            subject=json.dumps({"commonName": "test.com"})
        )
        session.add(cert)
        session.commit()
        
        # All override fields should be None by default
        assert cert.real_serial_number is None
        assert cert.real_thumbprint is None
        assert cert.real_issuer is None
        assert cert.real_subject is None
        assert cert.real_valid_from is None
        assert cert.real_valid_until is None
        assert cert.override_notes is None
        assert cert.override_created_at is None
    
    def test_proxy_override_fields_can_be_set(self, session, certificate):
        """Test that proxy override fields can be set with real certificate data."""
        real_serial = "real_serial_789"
        real_thumbprint = "real_thumbprint_012"
        real_issuer = {"commonName": "Real CA", "organizationName": "Real Corp"}
        real_subject = {"commonName": "example.com", "organizationName": "Real Org"}
        real_valid_from = datetime.now() + timedelta(days=1)
        real_valid_until = datetime.now() + timedelta(days=365)
        override_notes = "Certificate behind Cloudflare proxy"
        
        certificate.real_serial_number = real_serial
        certificate.real_thumbprint = real_thumbprint
        certificate.real_issuer = json.dumps(real_issuer)
        certificate.real_subject = json.dumps(real_subject)
        certificate.real_valid_from = real_valid_from
        certificate.real_valid_until = real_valid_until
        certificate.override_notes = override_notes
        certificate.override_created_at = datetime.now()
        
        session.commit()
        session.refresh(certificate)
        
        assert certificate.real_serial_number == real_serial
        assert certificate.real_thumbprint == real_thumbprint
        assert json.loads(certificate.real_issuer) == real_issuer
        assert json.loads(certificate.real_subject) == real_subject
        assert certificate.real_valid_from == real_valid_from
        assert certificate.real_valid_until == real_valid_until
        assert certificate.override_notes == override_notes
        assert certificate.override_created_at is not None
    
    def test_real_issuer_dict_property(self, session, certificate):
        """Test the real_issuer_dict hybrid property."""
        real_issuer = {"commonName": "Real CA", "organizationName": "Real Corp"}
        certificate.real_issuer = json.dumps(real_issuer)
        session.commit()
        
        assert certificate.real_issuer_dict == real_issuer
    
    def test_real_subject_dict_property(self, session, certificate):
        """Test the real_subject_dict hybrid property."""
        real_subject = {"commonName": "example.com", "organizationName": "Real Org"}
        certificate.real_subject = json.dumps(real_subject)
        session.commit()
        
        assert certificate.real_subject_dict == real_subject
    
    def test_real_issuer_dict_none(self, session, certificate):
        """Test real_issuer_dict when real_issuer is None."""
        assert certificate.real_issuer_dict == {}
    
    def test_real_subject_dict_none(self, session, certificate):
        """Test real_subject_dict when real_subject is None."""
        assert certificate.real_subject_dict == {}

class TestProxyOverrideService:
    """Test the CertificateService proxy override methods."""
    
    def test_update_proxy_override_success(self, session, certificate):
        """Test successful proxy override update."""
        service = CertificateService()
        
        real_serial = "real_serial_789"
        real_thumbprint = "real_thumbprint_012"
        real_issuer = {"commonName": "Real CA", "organizationName": "Real Corp"}
        real_subject = {"commonName": "example.com", "organizationName": "Real Org"}
        real_valid_from = datetime.now() + timedelta(days=1)
        real_valid_until = datetime.now() + timedelta(days=365)
        override_notes = "Certificate behind Cloudflare proxy"
        
        result = service.update_proxy_override(
            certificate.id, real_serial, real_thumbprint,
            json.dumps(real_issuer), json.dumps(real_subject),
            real_valid_from, real_valid_until, override_notes, session
        )
        
        assert result['success'] is True
        
        # Verify the certificate was updated
        session.refresh(certificate)
        assert certificate.real_serial_number == real_serial
        assert certificate.real_thumbprint == real_thumbprint
        assert json.loads(certificate.real_issuer) == real_issuer
        assert json.loads(certificate.real_subject) == real_subject
        assert certificate.real_valid_from == real_valid_from
        assert certificate.real_valid_until == real_valid_until
        assert certificate.override_notes == override_notes
        assert certificate.override_created_at is not None
    
    def test_update_proxy_override_certificate_not_found(self, session):
        """Test update_proxy_override when certificate doesn't exist."""
        service = CertificateService()
        
        result = service.update_proxy_override(
            99999, "serial", "thumbprint", "{}", "{}",
            datetime.now(), datetime.now() + timedelta(days=30), "notes", session
        )
        
        assert result['success'] is False
        assert "Certificate not found" in result['error']
    
    def test_clear_proxy_override_success(self, session, certificate):
        """Test successful proxy override clearing."""
        # First set some override data
        certificate.real_serial_number = "test_serial"
        certificate.real_thumbprint = "test_thumbprint"
        certificate.real_issuer = '{"commonName": "Test CA"}'
        certificate.real_subject = '{"commonName": "test.com"}'
        certificate.real_valid_from = datetime.now()
        certificate.real_valid_until = datetime.now() + timedelta(days=30)
        certificate.override_notes = "Test notes"
        certificate.override_created_at = datetime.now()
        session.commit()
        
        service = CertificateService()
        result = service.clear_proxy_override(certificate.id, session)
        
        assert result['success'] is True
        
        # Verify the certificate override data was cleared
        session.refresh(certificate)
        assert certificate.real_serial_number is None
        assert certificate.real_thumbprint is None
        assert certificate.real_issuer is None
        assert certificate.real_subject is None
        assert certificate.real_valid_from is None
        assert certificate.real_valid_until is None
        assert certificate.override_notes is None
        assert certificate.override_created_at is None
    
    def test_clear_proxy_override_certificate_not_found(self, session):
        """Test clear_proxy_override when certificate doesn't exist."""
        service = CertificateService()
        
        result = service.clear_proxy_override(99999, session)
        
        assert result['success'] is False
        assert "Certificate not found" in result['error']

class TestProxyOverrideIntegration:
    """Integration tests for proxy override functionality."""
    
    def test_proxy_certificate_workflow(self, session, certificate):
        """Test the complete workflow of handling a proxy certificate."""
        # Initially, certificate has proxy data
        assert certificate.proxied is True
        assert certificate.serial_number == "proxy_serial_123"
        assert certificate.thumbprint == "proxy_thumbprint_456"
        assert certificate.real_serial_number is None
        
        # Update with real certificate data
        service = CertificateService()
        real_serial = "real_serial_789"
        real_thumbprint = "real_thumbprint_012"
        real_issuer = {"commonName": "Let's Encrypt", "organizationName": "Let's Encrypt"}
        real_subject = {"commonName": "example.com"}
        real_valid_from = datetime.now() + timedelta(days=1)
        real_valid_until = datetime.now() + timedelta(days=90)
        override_notes = "Certificate behind Cloudflare proxy - real cert from Let's Encrypt"
        
        result = service.update_proxy_override(
            certificate.id, real_serial, real_thumbprint,
            json.dumps(real_issuer), json.dumps(real_subject),
            real_valid_from, real_valid_until, override_notes, session
        )
        
        assert result['success'] is True
        
        # Verify both proxy and real data are preserved
        session.refresh(certificate)
        assert certificate.proxied is True  # Still marked as proxied
        assert certificate.serial_number == "proxy_serial_123"  # Original proxy data
        assert certificate.thumbprint == "proxy_thumbprint_456"
        assert certificate.real_serial_number == real_serial  # Real data
        assert certificate.real_thumbprint == real_thumbprint
        assert json.loads(certificate.real_issuer) == real_issuer
        assert json.loads(certificate.real_subject) == real_subject
        assert certificate.override_notes == override_notes
    
    def test_proxy_override_data_retrieval(self, session, certificate):
        """Test that proxy override data can be retrieved correctly."""
        # Set override data
        real_issuer = {"commonName": "Real CA", "organizationName": "Real Corp"}
        real_subject = {"commonName": "example.com", "organizationName": "Real Org"}
        
        certificate.real_issuer = json.dumps(real_issuer)
        certificate.real_subject = json.dumps(real_subject)
        session.commit()
        
        # Test hybrid properties
        assert certificate.real_issuer_dict == real_issuer
        assert certificate.real_subject_dict == real_subject
        
        # Test that we can access both proxy and real data
        assert certificate.issuer is not None  # Original proxy issuer
        assert certificate.subject is not None  # Original proxy subject
        assert certificate.real_issuer_dict == real_issuer  # Real issuer
        assert certificate.real_subject_dict == real_subject  # Real subject
