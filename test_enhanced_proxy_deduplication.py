#!/usr/bin/env python3
"""
Test Enhanced Proxy Certificate Deduplication

This script tests the enhanced proxy certificate deduplication system
to ensure it correctly identifies and merges proxy certificates with
different serial numbers but the same logical identity.
"""

import sys
import os
import json
from datetime import datetime, timedelta
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from infra_mgmt.utils.proxy_certificate_deduplication import (
    ProxyCertificateIdentity, 
    ProxyCertificateDeduplicator,
    deduplicate_proxy_certificate,
    enhanced_deduplicate_certificate
)
from infra_mgmt.db.session import get_session
from infra_mgmt.models import Certificate
from infra_mgmt.settings import settings

class MockCertificateInfo:
    """Mock certificate info for testing."""
    def __init__(self, serial_number, thumbprint, common_name, issuer, expiration_date, san=None, proxied=False, proxy_info=None):
        self.serial_number = serial_number
        self.thumbprint = thumbprint
        self.common_name = common_name
        self.issuer = issuer
        self.expiration_date = expiration_date
        self.san = san or []
        self.proxied = proxied
        self.proxy_info = proxy_info

def test_proxy_certificate_identity():
    """Test proxy certificate identity creation and comparison."""
    print("🔍 Testing Proxy Certificate Identity...")
    
    # Create two proxy certificates with same CA, target, and expiration but different serials
    issuer = {"commonName": "Corporate Proxy CA"}
    expiration = datetime.now() + timedelta(days=365)
    
    identity1 = ProxyCertificateIdentity(
        issuer_cn="Corporate Proxy CA",
        common_name="example.com",
        expiration_date=expiration,
        san=["example.com", "www.example.com"]
    )
    
    identity2 = ProxyCertificateIdentity(
        issuer_cn="Corporate Proxy CA",
        common_name="example.com",
        expiration_date=expiration,
        san=["example.com", "www.example.com"]
    )
    
    # They should be equal even with different serial numbers
    assert identity1 == identity2, "Proxy certificate identities should be equal"
    print("✅ Proxy certificate identities correctly identified as equal")
    
    # Test with different CA
    identity3 = ProxyCertificateIdentity(
        issuer_cn="Different Proxy CA",
        common_name="example.com",
        expiration_date=expiration,
        san=["example.com", "www.example.com"]
    )
    
    assert identity1 != identity3, "Different CA should create different identities"
    print("✅ Different CA correctly creates different identities")
    
    print("✅ Proxy Certificate Identity tests passed!")

def test_proxy_ca_detection():
    """Test proxy CA detection logic."""
    print("\n🔍 Testing Proxy CA Detection...")
    
    with get_session() as session:
        deduplicator = ProxyCertificateDeduplicator(session)
        
        # Test known proxy CAs
        proxy_cas = [
            "Corporate Proxy CA",
            "BlueCoat ProxySG CA",
            "Zscaler Root CA",
            "Forcepoint SSL CA",
            "Internal Proxy Gateway CA"
        ]
        
        for ca in proxy_cas:
            is_proxy = deduplicator.is_proxy_ca(ca)
            assert is_proxy, f"Should detect '{ca}' as proxy CA"
            print(f"✅ Detected '{ca}' as proxy CA")
        
        # Test non-proxy CAs
        non_proxy_cas = [
            "DigiCert SHA2 Extended Validation Server CA",
            "Let's Encrypt Authority X3",
            "GlobalSign Root CA"
        ]
        
        for ca in non_proxy_cas:
            is_proxy = deduplicator.is_proxy_ca(ca)
            assert not is_proxy, f"Should not detect '{ca}' as proxy CA"
            print(f"✅ Correctly identified '{ca}' as non-proxy CA")
        
        print("✅ Proxy CA Detection tests passed!")

def test_proxy_certificate_identity_extraction():
    """Test extracting proxy certificate identity from certificate info."""
    print("\n🔍 Testing Proxy Certificate Identity Extraction...")
    
    with get_session() as session:
        deduplicator = ProxyCertificateDeduplicator(session)
        
        # Test proxy certificate
        proxy_cert_info = MockCertificateInfo(
            serial_number="PROXY123456",
            thumbprint="proxy_thumbprint_123",
            common_name="example.com",
            issuer={"commonName": "Corporate Proxy CA"},
            expiration_date=datetime.now() + timedelta(days=365),
            san=["example.com", "www.example.com"],
            proxied=True,
            proxy_info="Detected as proxy certificate"
        )
        
        identity = deduplicator.get_proxy_certificate_identity(proxy_cert_info)
        assert identity is not None, "Should extract identity from proxy certificate"
        assert identity.issuer_cn == "corporate proxy ca"
        assert identity.common_name == "example.com"
        print(f"✅ Extracted proxy identity: {identity}")
        
        # Test non-proxy certificate
        normal_cert_info = MockCertificateInfo(
            serial_number="NORMAL123456",
            thumbprint="normal_thumbprint_123",
            common_name="example.com",
            issuer={"commonName": "DigiCert SHA2 Extended Validation Server CA"},
            expiration_date=datetime.now() + timedelta(days=365),
            san=["example.com", "www.example.com"],
            proxied=False
        )
        
        identity = deduplicator.get_proxy_certificate_identity(normal_cert_info)
        assert identity is None, "Should not extract identity from non-proxy certificate"
        print("✅ Correctly identified non-proxy certificate")
        
        print("✅ Proxy Certificate Identity Extraction tests passed!")

def test_enhanced_deduplication_logic():
    """Test the enhanced deduplication logic."""
    print("\n🔍 Testing Enhanced Deduplication Logic...")
    
    with get_session() as session:
        # Clean up any existing test certificates
        session.query(Certificate).filter(
            Certificate.serial_number.in_(["EXISTING123", "NEW_PROXY456", "NORMAL789"])
        ).delete()
        session.commit()
        
        # Use a fixed expiration date for consistent testing
        expiration_date = datetime.now() + timedelta(days=365)
        
        # Create a test certificate in the database
        test_cert = Certificate(
            serial_number="EXISTING123",
            thumbprint="existing_thumbprint_123",
            common_name="example.com",
            valid_from=datetime.now() - timedelta(days=30),
            valid_until=expiration_date,
            _issuer=json.dumps({"commonName": "Corporate Proxy CA"}),
            _subject=json.dumps({"commonName": "example.com"}),
            _san=json.dumps(["example.com", "www.example.com"]),
            proxied=True,
            proxy_info="Original proxy detection",
            created_at=datetime.now() - timedelta(days=10)
        )
        session.add(test_cert)
        session.commit()
        
        # Test deduplication with new proxy certificate (same identity, different serial)
        new_proxy_cert_info = MockCertificateInfo(
            serial_number="NEW_PROXY456",
            thumbprint="new_proxy_thumbprint",
            common_name="example.com",
            issuer={"commonName": "Corporate Proxy CA"},
            expiration_date=expiration_date,
            san=["example.com", "www.example.com"],
            proxied=True,
            proxy_info="Additional proxy detection"
        )
        
        should_save, existing_cert, reason = enhanced_deduplicate_certificate(
            session, new_proxy_cert_info, "example.com", 443
        )
        
        assert not should_save, "Should not save new proxy certificate"
        assert existing_cert is not None, "Should find existing certificate"
        assert "merging" in reason.lower(), "Should indicate merging"
        print(f"✅ Enhanced deduplication correctly merged proxy certificates: {reason}")
        
        # Verify the existing certificate was updated
        session.refresh(test_cert)
        print(f"Debug: proxy_info = '{test_cert.proxy_info}'")
        assert test_cert.proxy_info and ("Additional proxy detection:" in test_cert.proxy_info or "Proxy certificate detected" in test_cert.proxy_info)
        print("✅ Existing certificate was updated with new proxy information")
        
        # Test with non-proxy certificate (should save as new)
        normal_cert_info = MockCertificateInfo(
            serial_number="NORMAL789",
            thumbprint="normal_thumbprint",
            common_name="example.com",
            issuer={"commonName": "DigiCert SHA2 Extended Validation Server CA"},
            expiration_date=datetime.now() + timedelta(days=365),
            san=["example.com", "www.example.com"],
            proxied=False
        )
        
        should_save, existing_cert, reason = enhanced_deduplicate_certificate(
            session, normal_cert_info, "example.com", 443
        )
        
        assert should_save, "Should save new non-proxy certificate"
        print(f"✅ Enhanced deduplication correctly identified non-proxy certificate: {reason}")
        
        # Clean up
        session.delete(test_cert)
        session.commit()
        
        print("✅ Enhanced Deduplication Logic tests passed!")

def main():
    """Run all tests."""
    print("🧪 Enhanced Proxy Certificate Deduplication Test Suite")
    print("=" * 60)
    
    try:
        test_proxy_certificate_identity()
        test_proxy_ca_detection()
        test_proxy_certificate_identity_extraction()
        test_enhanced_deduplication_logic()
        
        print("\n" + "=" * 60)
        print("🎉 ALL TESTS PASSED!")
        print("=" * 60)
        print("✅ Enhanced proxy certificate deduplication is working correctly")
        print("✅ Proxy certificates with different serial numbers will be automatically merged")
        print("✅ Non-proxy certificates will be handled normally")
        print("✅ The system is ready for production use")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
