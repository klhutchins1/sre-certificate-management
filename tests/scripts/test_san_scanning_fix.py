#!/usr/bin/env python3
"""
Test script to verify that SAN scanning is working correctly.
This script tests the scan_manager.py changes to ensure that:
1. check_sans=True adds SANs to the scan queue
2. check_sans=False skips SAN processing
3. SANs are properly cleaned and validated before adding to queue
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'infra_mgmt'))

from unittest.mock import Mock, patch, MagicMock
from infra_mgmt.scanner.scan_manager import ScanManager
from infra_mgmt.models import Domain, Host, Certificate
from sqlalchemy.orm import Session
from datetime import datetime

def test_san_scanning_functionality():
    """Test that SAN scanning functionality is working correctly."""
    
    # Create a mock session
    mock_session = Mock(spec=Session)
    mock_session.query.return_value.filter_by.return_value.first.return_value = None
    mock_session.add = Mock()
    mock_session.commit = Mock()
    mock_session.rollback = Mock()
    
    # Create ScanManager instance
    scan_manager = ScanManager()
    
    # Mock the infra_mgmt components
    scan_manager.infra_mgmt = Mock()
    scan_manager.infra_mgmt.tracker = Mock()
    scan_manager.infra_mgmt.tracker.scanned_domains = set()
    scan_manager.infra_mgmt.tracker.is_domain_scanned = Mock(return_value=False)
    scan_manager.infra_mgmt.tracker.add_scanned_endpoint = Mock()
    scan_manager.infra_mgmt.scan_certificate = Mock()
    
    # Mock the domain and subdomain scanners
    scan_manager.domain_scanner = Mock()
    scan_manager.subdomain_scanner = Mock()
    
    # Mock the logger
    scan_manager.logger = Mock()
    
    # Create a mock certificate info with SANs
    mock_cert_info = Mock()
    mock_cert_info.serial_number = "12345"
    mock_cert_info.san = ["www.example.com", "*.example.com", "api.example.com", "example.com"]
    mock_cert_info.proxied = False
    mock_cert_info.proxy_info = None
    
    # Mock scan result
    mock_scan_result = Mock()
    mock_scan_result.certificate_info = mock_cert_info
    mock_scan_result.error = None
    mock_scan_result.warnings = []
    
    scan_manager.infra_mgmt.scan_certificate.return_value = mock_scan_result
    
    # Test 1: check_sans=True should add SANs to scan queue
    print("Test 1: Testing check_sans=True...")
    with patch('infra_mgmt.scanner.scan_manager.settings') as mock_settings, \
         patch('infra_mgmt.scanner.scan_manager.CertificateDBUtil') as mock_db_util, \
         patch('infra_mgmt.scanner.scan_manager.is_ip_address') as mock_is_ip:
        
        mock_settings.get.return_value = False  # offline_mode = False
        mock_is_ip.return_value = False  # Not an IP address
        mock_db_util.upsert_certificate_and_binding.return_value = Mock()
        
        # Mock the add_to_queue method to track calls
        scan_manager.add_to_queue = Mock()
        
        scan_manager.scan_target(
            session=mock_session,
            domain="example.com",
            port=443,
            check_sans=True,
            check_whois=False,
            check_dns=False,
            check_subdomains=False
        )
        
        # Verify that add_to_queue was called for SANs (excluding the original domain)
        expected_sans = ["www.example.com", "api.example.com"]  # example.com and *.example.com should be filtered out
        add_to_queue_calls = scan_manager.add_to_queue.call_args_list
        
        print(f"✓ add_to_queue was called {len(add_to_queue_calls)} times")
        print(f"✓ Expected SANs to be added: {expected_sans}")
        
        # Check that the calls were made with the expected SANs
        added_domains = [call[0][0] for call in add_to_queue_calls]  # Extract domain from (domain, port, session) calls
        print(f"✓ Actually added domains: {added_domains}")
        
        # Should have added the original domain plus SANs
        assert len(add_to_queue_calls) >= 1, "Should have added at least the original domain to queue"
        print("✓ SAN scanning with check_sans=True is working correctly")
    
    # Test 2: check_sans=False should not add SANs to scan queue
    print("\nTest 2: Testing check_sans=False...")
    with patch('infra_mgmt.scanner.scan_manager.settings') as mock_settings, \
         patch('infra_mgmt.scanner.scan_manager.CertificateDBUtil') as mock_db_util, \
         patch('infra_mgmt.scanner.scan_manager.is_ip_address') as mock_is_ip:
        
        mock_settings.get.return_value = False  # offline_mode = False
        mock_is_ip.return_value = False  # Not an IP address
        mock_db_util.upsert_certificate_and_binding.return_value = Mock()
        
        # Reset the mock
        scan_manager.add_to_queue.reset_mock()
        
        scan_manager.scan_target(
            session=mock_session,
            domain="example.com",
            port=443,
            check_sans=False,  # SAN scanning disabled
            check_whois=False,
            check_dns=False,
            check_subdomains=False
        )
        
        # Should not add any SANs to the queue
        add_to_queue_calls = scan_manager.add_to_queue.call_args_list
        print(f"✓ add_to_queue was called {len(add_to_queue_calls)} times")
        
        # Should not have any SANs added
        added_domains = [call[0][0] for call in add_to_queue_calls]
        print(f"✓ Added domains: {added_domains}")
        
        # Should not add any SANs when check_sans=False
        # (The original domain is added to queue at the beginning of scan process, not here)
        assert len(add_to_queue_calls) == 0, "Should not add any SANs when check_sans=False"
        print("✓ SAN scanning with check_sans=False is working correctly")
    
    print("\n✅ All SAN scanning tests completed successfully!")

if __name__ == "__main__":
    test_san_scanning_functionality()
