#!/usr/bin/env python3
"""
Tests for Enhanced Certificate Deduplication System

This test suite covers the enhanced proxy certificate deduplication functionality
that is integrated into the live application.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate, Host, HostIP, CertificateBinding, CertificateScan
from infra_mgmt.scanner.certificate_scanner import CertificateInfo
from infra_mgmt.utils.certificate_db import CertificateDBUtil
from infra_mgmt.utils.proxy_certificate_deduplication import (
    enhanced_deduplicate_certificate,
    deduplicate_proxy_certificate,
    ProxyCertificateDeduplicator,
    ProxyCertificateIdentity
)
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
    now = datetime.now(timezone.utc)  # Use timezone-aware datetime
    return CertificateInfo(
        serial_number="test_serial_123",
        thumbprint="test_thumbprint_456",
        common_name="example.com",
        valid_from=now - timedelta(days=30),
        expiration_date=now + timedelta(days=365),
        subject={"CN": "example.com"},
        issuer={"CN": "Test CA"},
        san=["example.com", "www.example.com"],
        ip_addresses=["192.168.1.1"]
    )

@pytest.fixture
def proxy_cert_info():
    """Create a mock proxy CertificateInfo object."""
    # Use a fixed expiration date for consistent testing (with timezone for CertificateInfo)
    expiration_date = datetime.now(timezone.utc) + timedelta(days=365)
    return CertificateInfo(
        serial_number="proxy_serial_789",
        thumbprint="proxy_thumbprint_012",
        common_name="example.com",
        valid_from=expiration_date - timedelta(days=395),  # 30 days before expiration
        expiration_date=expiration_date,
        subject={"CN": "example.com"},
        issuer={"CN": "Corporate Proxy CA"},
        san=["example.com", "www.example.com"],
        ip_addresses=["192.168.1.1"],
        proxied=True,
        proxy_info="Detected as proxy certificate"
    )

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

@pytest.fixture
def existing_proxy_certificate(test_session):
    """Create an existing proxy certificate in the database."""
    # Use the same fixed expiration date as proxy_cert_info (without timezone for database storage)
    expiration_date = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=365)
    cert = Certificate(
        serial_number="existing_proxy_serial_789",
        thumbprint="existing_proxy_thumbprint_012",
        common_name="example.com",
        valid_from=expiration_date - timedelta(days=395),  # 30 days before expiration
        valid_until=expiration_date,
        issuer=json.dumps({"CN": "Corporate Proxy CA"}),
        subject=json.dumps({"CN": "example.com"}),
        san=json.dumps(["example.com", "www.example.com"]),
        proxied=True,
        proxy_info="Previously detected proxy certificate",
        created_at=expiration_date - timedelta(days=396),  # 1 day before valid_from
        updated_at=expiration_date - timedelta(days=396)
    )
    test_session.add(cert)
    test_session.commit()
    return cert

class TestProxyCertificateIdentity:
    """Test the ProxyCertificateIdentity class."""
    
    def test_proxy_certificate_identity_creation(self):
        """Test creating a ProxyCertificateIdentity."""
        now = datetime.now(timezone.utc)
        identity = ProxyCertificateIdentity(
            issuer_cn="Corporate Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365),
            san=["example.com", "www.example.com"]
        )
        
        assert identity.issuer_cn == "corporate proxy ca"
        assert identity.common_name == "example.com"
        assert identity.expiration_date == now + timedelta(days=365)
        assert identity.san == ["example.com", "www.example.com"]
    
    def test_proxy_certificate_identity_equality(self):
        """Test ProxyCertificateIdentity equality comparison."""
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
        deduplicator = ProxyCertificateDeduplicator(test_session)
        
        identity = deduplicator.get_proxy_certificate_identity(proxy_cert_info)
        
        assert identity is not None
        assert identity.issuer_cn == "corporate proxy ca"
        assert identity.common_name == "example.com"
        assert identity.expiration_date == proxy_cert_info.expiration_date
        assert identity.san == ["example.com", "www.example.com"]
    
    def test_find_existing_proxy_certificate(self, test_session, existing_proxy_certificate, proxy_cert_info):
        """Test finding existing proxy certificates."""
        deduplicator = ProxyCertificateDeduplicator(test_session)
        
        identity = deduplicator.get_proxy_certificate_identity(proxy_cert_info)
        existing_cert = deduplicator.find_existing_proxy_certificate(identity)
        
        assert existing_cert is not None
        assert existing_cert.id == existing_proxy_certificate.id
        assert existing_cert.common_name == "example.com"
    
    def test_merge_proxy_certificate_data(self, test_session, existing_proxy_certificate, proxy_cert_info):
        """Test merging proxy certificate data."""
        deduplicator = ProxyCertificateDeduplicator(test_session)
        
        # Test merging new proxy info
        deduplicator.merge_proxy_certificate_data(existing_proxy_certificate, proxy_cert_info)
        
        # Commit the session to persist changes
        test_session.commit()
        
        # Verify the existing certificate was updated
        test_session.refresh(existing_proxy_certificate)
        assert existing_proxy_certificate.proxied is True
        assert "Previously detected proxy certificate" in existing_proxy_certificate.proxy_info
        assert "Additional proxy detection" in existing_proxy_certificate.proxy_info

class TestEnhancedDeduplication:
    """Test the enhanced deduplication system."""
    
    def test_enhanced_deduplication_new_certificate(self, test_session, mock_cert_info):
        """Test enhanced deduplication with a new certificate."""
        should_save_new, existing_cert, reason = enhanced_deduplicate_certificate(
            test_session, mock_cert_info, "example.com", 443
        )
        
        assert should_save_new is True
        assert existing_cert is None
        assert "No existing certificate found" in reason
    
    def test_enhanced_deduplication_proxy_certificate_new(self, test_session, proxy_cert_info):
        """Test enhanced deduplication with a new proxy certificate."""
        should_save_new, existing_cert, reason = enhanced_deduplicate_certificate(
            test_session, proxy_cert_info, "example.com", 443
        )
        
        assert should_save_new is True
        assert existing_cert is None
        assert "No existing proxy certificate found" in reason
    
    def test_enhanced_deduplication_proxy_certificate_existing(self, test_session, existing_proxy_certificate, proxy_cert_info):
        """Test enhanced deduplication with an existing proxy certificate."""
        should_save_new, existing_cert, reason = enhanced_deduplicate_certificate(
            test_session, proxy_cert_info, "example.com", 443
        )
        
        assert should_save_new is False
        assert existing_cert is not None
        assert existing_cert.id == existing_proxy_certificate.id
        assert "merging to avoid duplicates" in reason
    
    def test_enhanced_deduplication_fallback_to_normal(self, test_session, existing_certificate, mock_cert_info):
        """Test enhanced deduplication fallback to normal deduplication."""
        # Mock the normal deduplication to return a match
        with patch('infra_mgmt.utils.certificate_deduplication.deduplicate_certificate') as mock_normal:
            mock_normal.return_value = (False, existing_certificate, "Normal deduplication match")
            
            should_save_new, existing_cert, reason = enhanced_deduplicate_certificate(
                test_session, mock_cert_info, "example.com", 443
            )
            
            assert should_save_new is False
            assert existing_cert is not None
            assert existing_cert.id == existing_certificate.id
            assert "Normal deduplication match" in reason

class TestCertificateDBUtilIntegration:
    """Test the integration of enhanced deduplication with CertificateDBUtil."""
    
    def test_upsert_certificate_with_deduplication(self, test_session, existing_certificate, mock_cert_info):
        """Test that CertificateDBUtil uses enhanced deduplication."""
        # Create a certificate with the same logical identity as existing
        mock_cert_info.common_name = "example.com"
        mock_cert_info.expiration_date = existing_certificate.valid_until
        mock_cert_info.issuer = {"CN": "Test CA"}
        
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
    
    def test_upsert_certificate_with_proxy_deduplication(self, test_session, existing_proxy_certificate, proxy_cert_info):
        """Test that CertificateDBUtil handles proxy certificate deduplication."""
        # Mock the enhanced deduplication to return existing proxy certificate
        with patch('infra_mgmt.utils.certificate_db.enhanced_deduplicate_certificate') as mock_enhanced:
            mock_enhanced.return_value = (False, existing_proxy_certificate, "Proxy certificate merged")
            
            result = CertificateDBUtil.upsert_certificate_and_binding(
                test_session,
                "example.com",
                443,
                proxy_cert_info
            )
            
            # Verify the existing proxy certificate was returned
            assert result.id == existing_proxy_certificate.id
            mock_enhanced.assert_called_once()
    
    def test_upsert_certificate_new_certificate(self, test_session, mock_cert_info):
        """Test that CertificateDBUtil creates new certificates when no duplicates exist."""
        # Mock the enhanced deduplication to return new certificate
        with patch('infra_mgmt.utils.certificate_db.enhanced_deduplicate_certificate') as mock_enhanced:
            mock_enhanced.return_value = (True, None, "New certificate")
            
            # Set the common name for the test
            mock_cert_info.common_name = "newdomain.com"
            
            result = CertificateDBUtil.upsert_certificate_and_binding(
                test_session,
                "newdomain.com",
                443,
                mock_cert_info
            )
            
            # Verify a new certificate was created
            assert result is not None
            assert result.common_name == "newdomain.com"
            mock_enhanced.assert_called_once()

class TestProxyCertificateDeduplicationIntegration:
    """Test the proxy certificate deduplication integration."""
    
    def test_deduplicate_proxy_certificate_new(self, test_session, proxy_cert_info):
        """Test deduplicating a new proxy certificate."""
        should_save_new, existing_cert, reason = deduplicate_proxy_certificate(
            test_session, proxy_cert_info, "example.com", 443
        )
        
        assert should_save_new is True
        assert existing_cert is None
        assert "No existing proxy certificate found" in reason
    
    def test_deduplicate_proxy_certificate_existing(self, test_session, existing_proxy_certificate, proxy_cert_info):
        """Test deduplicating an existing proxy certificate."""
        should_save_new, existing_cert, reason = deduplicate_proxy_certificate(
            test_session, proxy_cert_info, "example.com", 443
        )
        
        assert should_save_new is False
        assert existing_cert is not None
        assert existing_cert.id == existing_proxy_certificate.id
        assert "merging to avoid duplicates" in reason
    
    def test_deduplicate_proxy_certificate_commit_on_merge(self, test_session, existing_proxy_certificate, proxy_cert_info):
        """Test that session is committed when merging proxy certificates."""
        initial_proxy_info = existing_proxy_certificate.proxy_info
        
        should_save_new, existing_cert, reason = deduplicate_proxy_certificate(
            test_session, proxy_cert_info, "example.com", 443
        )
        
        # Verify the session was committed and changes persisted
        test_session.refresh(existing_proxy_certificate)
        assert existing_proxy_certificate.proxy_info != initial_proxy_info
        assert "Detected as proxy certificate" in existing_proxy_certificate.proxy_info

class TestRealWorldScenarios:
    """Test real-world scenarios for certificate deduplication."""
    
    def test_duplicate_scan_same_domain(self, test_session, existing_certificate, mock_cert_info):
        """Test scanning the same domain twice (should deduplicate)."""
        # First scan - should create certificate
        mock_cert_info.common_name = "example.com"
        mock_cert_info.expiration_date = existing_certificate.valid_until
        mock_cert_info.issuer = {"CN": "Test CA"}
        
        result1 = CertificateDBUtil.upsert_certificate_and_binding(
            test_session, "example.com", 443, mock_cert_info
        )
        
        # Second scan with same certificate - should deduplicate
        mock_cert_info.serial_number = "different_serial_456"
        mock_cert_info.thumbprint = "different_thumbprint_789"
        
        result2 = CertificateDBUtil.upsert_certificate_and_binding(
            test_session, "example.com", 443, mock_cert_info
        )
        
        # Should return the same certificate
        assert result1.id == result2.id
        
        # Should only have one certificate in database
        cert_count = test_session.query(Certificate).filter_by(common_name="example.com").count()
        assert cert_count == 1
    
    def test_proxy_certificate_renewal(self, test_session, existing_proxy_certificate, proxy_cert_info):
        """Test proxy certificate renewal scenario."""
        # Simulate certificate renewal with new serial/thumbprint but same logical identity
        proxy_cert_info.serial_number = "renewed_serial_999"
        proxy_cert_info.thumbprint = "renewed_thumbprint_888"
        proxy_cert_info.proxy_info = "Renewed proxy certificate"
        
        result = CertificateDBUtil.upsert_certificate_and_binding(
            test_session, "example.com", 443, proxy_cert_info
        )
        
        # Should return existing certificate with updated proxy info
        assert result.id == existing_proxy_certificate.id
        test_session.refresh(existing_proxy_certificate)
        assert "Renewed proxy certificate" in existing_proxy_certificate.proxy_info
    
    def test_mixed_certificate_types(self, test_session, mock_cert_info, proxy_cert_info):
        """Test handling mixed certificate types (normal and proxy)."""
        # Set the common names for the test
        mock_cert_info.common_name = "normal.com"
        proxy_cert_info.common_name = "proxy.com"
        
        # Create normal certificate
        result1 = CertificateDBUtil.upsert_certificate_and_binding(
            test_session, "normal.com", 443, mock_cert_info
        )
        
        # Create proxy certificate
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
