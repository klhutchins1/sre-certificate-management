#!/usr/bin/env python3
"""
Simple tests for Enhanced Certificate Deduplication System

This test suite focuses on the core deduplication functionality without
complex imports that might cause dependency issues.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate
from infra_mgmt.utils.certificate_db import CertificateDBUtil
import json

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
def mock_cert_info():
    """Create a mock CertificateInfo object."""
    now = datetime.now(timezone.utc)
    cert_info = MagicMock()
    cert_info.serial_number = "test_serial_123"
    cert_info.thumbprint = "test_thumbprint_456"
    cert_info.common_name = "example.com"
    cert_info.valid_from = now - timedelta(days=30)
    cert_info.expiration_date = now + timedelta(days=365)
    cert_info.subject = {"CN": "example.com"}
    cert_info.issuer = {"CN": "Test CA"}
    cert_info.san = ["example.com", "www.example.com"]
    cert_info.ip_addresses = ["192.168.1.1"]
    cert_info.proxied = False
    cert_info.proxy_info = None
    cert_info.key_usage = None  # Add missing attribute
    cert_info.extended_key_usage = None  # Add missing attribute
    cert_info.signature_algorithm = "sha256"  # Add missing attribute
    cert_info.public_key_algorithm = "rsa"  # Add missing attribute
    cert_info.public_key_size = 2048  # Add missing attribute
    cert_info.chain_valid = True  # Add missing attribute
    cert_info.chain_errors = []  # Add missing attribute
    return cert_info

@pytest.fixture
def proxy_cert_info():
    """Create a mock proxy CertificateInfo object."""
    now = datetime.now(timezone.utc)
    cert_info = MagicMock()
    cert_info.serial_number = "proxy_serial_789"
    cert_info.thumbprint = "proxy_thumbprint_012"
    cert_info.common_name = "example.com"
    cert_info.valid_from = now - timedelta(days=30)
    cert_info.expiration_date = now + timedelta(days=365)
    cert_info.subject = {"CN": "example.com"}
    cert_info.issuer = {"CN": "Corporate Proxy CA"}
    cert_info.san = ["example.com", "www.example.com"]
    cert_info.ip_addresses = ["192.168.1.1"]
    cert_info.proxied = True
    cert_info.proxy_info = "Detected as proxy certificate"
    cert_info.key_usage = None  # Add missing attribute
    cert_info.extended_key_usage = None  # Add missing attribute
    cert_info.signature_algorithm = "sha256"  # Add missing attribute
    cert_info.public_key_algorithm = "rsa"  # Add missing attribute
    cert_info.public_key_size = 2048  # Add missing attribute
    cert_info.chain_valid = True  # Add missing attribute
    cert_info.chain_errors = []  # Add missing attribute
    return cert_info

@pytest.fixture
def existing_certificate(test_session):
    """Create an existing certificate in the database."""
    now = datetime.now(timezone.utc)
    cert = Certificate(
        serial_number="existing_serial_123",
        thumbprint="existing_thumbprint_456",
        common_name="example.com",
        valid_from=now - timedelta(days=30),
        valid_until=now + timedelta(days=365),
        issuer=json.dumps({"CN": "Test CA"}),
        subject=json.dumps({"CN": "example.com"}),
        san=json.dumps(["example.com", "www.example.com"]),
        proxied=False,
        proxy_info=None,
        created_at=now - timedelta(days=1),
        updated_at=now - timedelta(days=1)
    )
    test_session.add(cert)
    test_session.commit()
    return cert

class TestEnhancedDeduplicationIntegration:
    """Test the enhanced deduplication integration with CertificateDBUtil."""
    
    def test_enhanced_deduplication_new_certificate(self, test_session, mock_cert_info):
        """Test enhanced deduplication with a new certificate."""
        # Mock the enhanced deduplication to return new certificate
        with patch('infra_mgmt.utils.certificate_db.enhanced_deduplicate_certificate') as mock_enhanced:
            mock_enhanced.return_value = (True, None, "New certificate")
            
            result = CertificateDBUtil.upsert_certificate_and_binding(
                test_session,
                "example.com",
                443,
                mock_cert_info
            )
            
            # Verify a new certificate was created
            assert result is not None
            assert result.common_name == "example.com"
            mock_enhanced.assert_called_once()
    
    def test_enhanced_deduplication_existing_certificate(self, test_session, existing_certificate, mock_cert_info):
        """Test enhanced deduplication with an existing certificate."""
        # Mock the enhanced deduplication to return existing certificate
        with patch('infra_mgmt.utils.certificate_db.enhanced_deduplicate_certificate') as mock_enhanced:
            mock_enhanced.return_value = (False, existing_certificate, "Certificate deduplicated")
            
            result = CertificateDBUtil.upsert_certificate_and_binding(
                test_session,
                "example.com",
                443,
                mock_cert_info
            )
            
            # Verify the existing certificate was returned
            assert result.id == existing_certificate.id
            mock_enhanced.assert_called_once()
    
    def test_enhanced_deduplication_proxy_certificate(self, test_session, proxy_cert_info):
        """Test enhanced deduplication with a proxy certificate."""
        # Mock the enhanced deduplication to return new proxy certificate
        with patch('infra_mgmt.utils.certificate_db.enhanced_deduplicate_certificate') as mock_enhanced:
            mock_enhanced.return_value = (True, None, "Proxy certificate detected")
            
            result = CertificateDBUtil.upsert_certificate_and_binding(
                test_session,
                "example.com",
                443,
                proxy_cert_info
            )
            
            # Verify a new proxy certificate was created
            assert result is not None
            assert result.common_name == "example.com"
            assert result.proxied is True
            mock_enhanced.assert_called_once()
    
    def test_enhanced_deduplication_proxy_merge(self, test_session, existing_certificate, proxy_cert_info):
        """Test enhanced deduplication merging proxy certificates."""
        # Set up existing certificate as proxy
        existing_certificate.proxied = True
        existing_certificate.proxy_info = "Previously detected proxy certificate"
        test_session.commit()
        
        # Mock the enhanced deduplication to return existing proxy certificate
        with patch('infra_mgmt.utils.certificate_db.enhanced_deduplicate_certificate') as mock_enhanced:
            mock_enhanced.return_value = (False, existing_certificate, "Proxy certificate merged")
            
            result = CertificateDBUtil.upsert_certificate_and_binding(
                test_session,
                "example.com",
                443,
                proxy_cert_info
            )
            
            # Verify the existing proxy certificate was returned
            assert result.id == existing_certificate.id
            mock_enhanced.assert_called_once()

class TestProxyCertificateDeduplication:
    """Test the proxy certificate deduplication functionality."""
    
    def test_proxy_certificate_identity_creation(self):
        """Test creating a ProxyCertificateIdentity."""
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateIdentity
        
        now = datetime.now(timezone.utc)
        identity = ProxyCertificateIdentity(
            issuer_cn="Corporate Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365),
            san=["example.com", "www.example.com"]
        )
        
        assert identity.issuer_cn == "corporate proxy ca"  # Case is normalized
        assert identity.common_name == "example.com"
        assert identity.expiration_date == now + timedelta(days=365)
        assert identity.san == ["example.com", "www.example.com"]
    
    def test_proxy_certificate_identity_equality(self):
        """Test ProxyCertificateIdentity equality comparison."""
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateIdentity
        
        now = datetime.now(timezone.utc)
        identity1 = ProxyCertificateIdentity(
            issuer_cn="Corporate Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365)
        )
        
        identity2 = ProxyCertificateIdentity(
            issuer_cn="Corporate Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365)
        )
        
        assert identity1 == identity2
    
    def test_proxy_certificate_identity_inequality(self):
        """Test ProxyCertificateIdentity inequality comparison."""
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateIdentity
        
        now = datetime.now(timezone.utc)
        identity1 = ProxyCertificateIdentity(
            issuer_cn="Corporate Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365)
        )
        
        identity2 = ProxyCertificateIdentity(
            issuer_cn="Different Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365)
        )
        
        assert identity1 != identity2

class TestProxyCertificateDeduplicator:
    """Test the ProxyCertificateDeduplicator class."""
    
    def test_is_proxy_ca_detection(self, test_session):
        """Test proxy CA detection logic."""
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateDeduplicator
        
        deduplicator = ProxyCertificateDeduplicator(test_session)
        
        # Test known proxy CAs
        assert deduplicator.is_proxy_ca("Corporate Proxy CA") is True
        assert deduplicator.is_proxy_ca("BlueCoat ProxySG CA") is True
        assert deduplicator.is_proxy_ca("Zscaler Root CA") is True
        assert deduplicator.is_proxy_ca("Forcepoint SSL CA") is True
        
        # Test non-proxy CAs
        assert deduplicator.is_proxy_ca("Let's Encrypt") is False
        assert deduplicator.is_proxy_ca("DigiCert") is False
        assert deduplicator.is_proxy_ca("Google Trust Services") is False
    
    def test_get_proxy_certificate_identity(self, test_session, proxy_cert_info):
        """Test extracting proxy certificate identity."""
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateDeduplicator
        
        deduplicator = ProxyCertificateDeduplicator(test_session)
        
        identity = deduplicator.get_proxy_certificate_identity(proxy_cert_info)
        
        assert identity is not None
        assert identity.issuer_cn == "corporate proxy ca"  # Case is normalized
        assert identity.common_name == "example.com"
        assert identity.expiration_date == proxy_cert_info.expiration_date
        assert identity.san == ["example.com", "www.example.com"]

class TestRealWorldScenarios:
    """Test real-world scenarios for certificate deduplication."""
    
    def test_duplicate_scan_same_domain(self, test_session, existing_certificate, mock_cert_info):
        """Test scanning the same domain twice (should deduplicate)."""
        # Mock the enhanced deduplication to return existing certificate for second scan
        with patch('infra_mgmt.utils.certificate_db.enhanced_deduplicate_certificate') as mock_enhanced:
            # First call deduplicates to existing certificate
            # Second call also deduplicates to existing certificate
            mock_enhanced.side_effect = [
                (False, existing_certificate, "Certificate deduplicated"),  # First call
                (False, existing_certificate, "Certificate deduplicated")  # Second call
            ]
            
            # First scan - should deduplicate to existing certificate
            result1 = CertificateDBUtil.upsert_certificate_and_binding(
                test_session, "example.com", 443, mock_cert_info
            )
            
            # Second scan with same certificate - should also deduplicate
            mock_cert_info.serial_number = "different_serial_456"
            mock_cert_info.thumbprint = "different_thumbprint_789"
            
            result2 = CertificateDBUtil.upsert_certificate_and_binding(
                test_session, "example.com", 443, mock_cert_info
            )
            
            # Should return the same certificate (the existing one)
            assert result1.id == result2.id
            assert result1.id == existing_certificate.id
            
            # Should only have one certificate in database (the existing one)
            cert_count = test_session.query(Certificate).filter_by(common_name="example.com").count()
            assert cert_count == 1
    
    def test_mixed_certificate_types(self, test_session, mock_cert_info, proxy_cert_info):
        """Test handling mixed certificate types (normal and proxy)."""
        # Set the common name for the normal certificate
        mock_cert_info.common_name = "normal.com"
        
        # Create normal certificate
        result1 = CertificateDBUtil.upsert_certificate_and_binding(
            test_session, "normal.com", 443, mock_cert_info
        )
        
        # Create proxy certificate with different domain
        proxy_cert_info.common_name = "proxy.com"
        result2 = CertificateDBUtil.upsert_certificate_and_binding(
            test_session, "proxy.com", 443, proxy_cert_info
        )
        
        # Should create both certificates
        assert result1.common_name == "normal.com"
        assert result2.common_name == "proxy.com"
        assert result1.proxied is False
        assert result2.proxied is True
        
        # Verify both are in database
        normal_cert = test_session.query(Certificate).filter_by(common_name="normal.com").first()
        proxy_cert = test_session.query(Certificate).filter_by(common_name="proxy.com").first()
        
        assert normal_cert is not None
        assert proxy_cert is not None
        assert normal_cert.proxied is False
        assert proxy_cert.proxied is True
