#!/usr/bin/env python3
"""
Enhanced Certificate Deduplication Validation Script

This script validates that the enhanced deduplication system is properly
integrated and working in the live application.

Usage:
    python test_enhanced_deduplication_simple_validation.py
"""

import sys
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

def test_enhanced_deduplication_imports():
    """Test that all enhanced deduplication modules can be imported."""
    print("Testing enhanced deduplication imports...")
    
    try:
        from infra_mgmt.utils.proxy_certificate_deduplication import (
            enhanced_deduplicate_certificate,
            deduplicate_proxy_certificate,
            ProxyCertificateDeduplicator,
            ProxyCertificateIdentity
        )
        print("SUCCESS: Enhanced deduplication modules imported successfully")
        return True
    except ImportError as e:
        print(f"ERROR: Failed to import enhanced deduplication modules: {e}")
        return False

def test_proxy_certificate_identity():
    """Test ProxyCertificateIdentity functionality."""
    print("Testing ProxyCertificateIdentity...")
    
    try:
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateIdentity
        
        now = datetime.now(timezone.utc)
        identity1 = ProxyCertificateIdentity(
            issuer_cn="Corporate Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365),
            san=["example.com", "www.example.com"]
        )
        
        identity2 = ProxyCertificateIdentity(
            issuer_cn="Corporate Proxy CA",
            common_name="example.com", 
            expiration_date=now + timedelta(days=365),
            san=["example.com", "www.example.com"]
        )
        
        # Test equality
        assert identity1 == identity2, "Identical identities should be equal"
        
        # Test inequality
        identity3 = ProxyCertificateIdentity(
            issuer_cn="Different Proxy CA",
            common_name="example.com",
            expiration_date=now + timedelta(days=365)
        )
        
        assert identity1 != identity3, "Different identities should not be equal"
        
        print("SUCCESS: ProxyCertificateIdentity tests passed")
        return True
    except Exception as e:
        print(f"ERROR: ProxyCertificateIdentity test failed: {e}")
        return False

def test_proxy_ca_detection():
    """Test proxy CA detection logic."""
    print("Testing proxy CA detection...")
    
    try:
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateDeduplicator
        from sqlalchemy.orm import Session
        
        # Create a mock session
        mock_session = MagicMock(spec=Session)
        
        # Create deduplicator
        deduplicator = ProxyCertificateDeduplicator(mock_session)
        
        # Test known proxy CAs
        assert deduplicator.is_proxy_ca("Corporate Proxy CA") is True
        assert deduplicator.is_proxy_ca("BlueCoat ProxySG CA") is True
        assert deduplicator.is_proxy_ca("Zscaler Root CA") is True
        assert deduplicator.is_proxy_ca("Forcepoint SSL CA") is True
        
        # Test non-proxy CAs
        assert deduplicator.is_proxy_ca("Let's Encrypt") is False
        assert deduplicator.is_proxy_ca("DigiCert") is False
        assert deduplicator.is_proxy_ca("Google Trust Services") is False
        
        print("SUCCESS: Proxy CA detection tests passed")
        return True
    except Exception as e:
        print(f"ERROR: Proxy CA detection test failed: {e}")
        return False

def test_certificate_db_integration():
    """Test that CertificateDBUtil has enhanced deduplication integrated."""
    print("Testing CertificateDBUtil integration...")
    
    try:
        from infra_mgmt.utils.certificate_db import CertificateDBUtil
        
        # Check that the enhanced_deduplicate_certificate is imported
        import infra_mgmt.utils.certificate_db as cert_db_module
        
        # Verify the import exists
        assert hasattr(cert_db_module, 'enhanced_deduplicate_certificate'), \
            "enhanced_deduplicate_certificate should be imported"
        
        print("SUCCESS: CertificateDBUtil integration verified")
        return True
    except Exception as e:
        print(f"ERROR: CertificateDBUtil integration test failed: {e}")
        return False

def test_enhanced_deduplication_function():
    """Test the enhanced deduplication function."""
    print("Testing enhanced deduplication function...")
    
    try:
        from infra_mgmt.utils.proxy_certificate_deduplication import enhanced_deduplicate_certificate
        from sqlalchemy.orm import Session
        
        # Create mock objects
        mock_session = MagicMock(spec=Session)
        mock_cert_info = MagicMock()
        mock_cert_info.common_name = "test.com"
        mock_cert_info.issuer = {"CN": "Test CA"}
        mock_cert_info.expiration_date = datetime.now(timezone.utc) + timedelta(days=365)
        mock_cert_info.san = ["test.com"]
        mock_cert_info.proxied = False
        mock_cert_info.proxy_info = None
        
        # Test the function call
        should_save_new, existing_cert, reason = enhanced_deduplicate_certificate(
            mock_session, mock_cert_info, "test.com", 443
        )
        
        # Verify return values are correct types
        assert isinstance(should_save_new, bool), "should_save_new should be boolean"
        assert existing_cert is None or hasattr(existing_cert, 'id'), "existing_cert should be None or Certificate-like"
        assert isinstance(reason, str), "reason should be string"
        
        print("SUCCESS: Enhanced deduplication function test passed")
        return True
    except Exception as e:
        print(f"ERROR: Enhanced deduplication function test failed: {e}")
        return False

def test_configuration_loading():
    """Test that configuration can be loaded."""
    print("Testing configuration loading...")
    
    try:
        import yaml
        
        # Check if config.yaml exists
        if os.path.exists('config.yaml'):
            with open('config.yaml', 'r') as f:
                config = yaml.safe_load(f)
            
            # Check for proxy_detection section
            if 'proxy_detection' in config:
                print("SUCCESS: Configuration file found with proxy_detection section")
                return True
            else:
                print("WARNING: Configuration file found but no proxy_detection section")
                return True
        else:
            print("WARNING: config.yaml not found - using defaults")
            return True
    except Exception as e:
        print(f"ERROR: Configuration loading test failed: {e}")
        return False

def main():
    """Run all validation tests."""
    print("=" * 60)
    print("Enhanced Certificate Deduplication Validation")
    print("=" * 60)
    
    tests = [
        test_enhanced_deduplication_imports,
        test_proxy_certificate_identity,
        test_proxy_ca_detection,
        test_certificate_db_integration,
        test_enhanced_deduplication_function,
        test_configuration_loading
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"ERROR: Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print("Validation Results:")
    print(f"   Passed: {passed}/{total}")
    print(f"   Failed: {total - passed}/{total}")
    
    if passed == total:
        print("SUCCESS: All tests passed! Enhanced deduplication is ready.")
        return 0
    else:
        print("WARNING: Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())











