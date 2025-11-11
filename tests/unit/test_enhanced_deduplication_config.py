#!/usr/bin/env python3
"""
Test configuration for Enhanced Certificate Deduplication

This module provides test configuration and utilities for testing
the enhanced certificate deduplication system.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from infra_mgmt.settings import Settings

@pytest.fixture
def mock_settings_with_proxy_detection():
    """Mock settings with proxy detection enabled."""
    with patch('infra_mgmt.utils.proxy_certificate_deduplication.settings') as mock_settings:
        mock_settings.get.side_effect = lambda key, default=None: {
            "proxy_detection.enabled": True,
            "proxy_detection.ca_subjects": ["Corporate Proxy CA", "BlueCoat ProxySG CA", "Zscaler Root CA"],
            "proxy_detection.ca_fingerprints": [],
            "proxy_detection.ca_serials": [],
            "proxy_detection.bypass_external": False,
            "proxy_detection.bypass_patterns": ["*.github.com", "*.google.com"],
            "proxy_detection.proxy_hostnames": ["proxy", "firewall", "gateway", "bluecoat", "zscaler", "forcepoint"],
            "proxy_detection.enable_hostname_validation": True,
            "proxy_detection.enable_authenticity_validation": True,
            "proxy_detection.warn_on_proxy_detection": True
        }.get(key, default)
        yield mock_settings

@pytest.fixture
def mock_settings_without_proxy_detection():
    """Mock settings with proxy detection disabled."""
    with patch('infra_mgmt.utils.proxy_certificate_deduplication.settings') as mock_settings:
        mock_settings.get.side_effect = lambda key, default=None: {
            "proxy_detection.enabled": False,
            "proxy_detection.ca_subjects": [],
            "proxy_detection.ca_fingerprints": [],
            "proxy_detection.ca_serials": [],
            "proxy_detection.bypass_external": False,
            "proxy_detection.bypass_patterns": [],
            "proxy_detection.proxy_hostnames": [],
            "proxy_detection.enable_hostname_validation": False,
            "proxy_detection.enable_authenticity_validation": False,
            "proxy_detection.warn_on_proxy_detection": False
        }.get(key, default)
        yield mock_settings

@pytest.fixture
def mock_certificate_info_factory():
    """Factory for creating mock CertificateInfo objects."""
    def create_cert_info(
        serial_number="test_serial",
        thumbprint="test_thumbprint",
        common_name="example.com",
        issuer_cn="Test CA",
        expiration_days=365,
        is_proxy=False,
        proxy_info=None
    ):
        now = datetime.now(timezone.utc)
        cert_info = MagicMock()
        cert_info.serial_number = serial_number
        cert_info.thumbprint = thumbprint
        cert_info.common_name = common_name
        cert_info.valid_from = now - timedelta(days=30)
        cert_info.expiration_date = now + timedelta(days=expiration_days)
        cert_info.subject = {"CN": common_name}
        cert_info.issuer = {"CN": issuer_cn}
        cert_info.san = [common_name, f"www.{common_name}"]
        cert_info.ip_addresses = ["192.168.1.1"]
        cert_info.proxied = is_proxy
        cert_info.proxy_info = proxy_info
        return cert_info
    return create_cert_info

@pytest.fixture
def mock_certificate_factory():
    """Factory for creating mock Certificate database objects."""
    def create_certificate(
        cert_id=1,
        serial_number="test_serial",
        thumbprint="test_thumbprint",
        common_name="example.com",
        issuer_cn="Test CA",
        expiration_days=365,
        is_proxy=False,
        proxy_info=None,
        created_days_ago=1
    ):
        now = datetime.now(timezone.utc)
        cert = MagicMock()
        cert.id = cert_id
        cert.serial_number = serial_number
        cert.thumbprint = thumbprint
        cert.common_name = common_name
        cert.valid_from = now - timedelta(days=30)
        cert.valid_until = now + timedelta(days=expiration_days)
        cert.issuer = f'{{"CN": "{issuer_cn}"}}'
        cert.subject = f'{{"CN": "{common_name}"}}'
        cert.san = f'["{common_name}", "www.{common_name}"]'
        cert.proxied = is_proxy
        cert.proxy_info = proxy_info
        cert.created_at = now - timedelta(days=created_days_ago)
        cert.updated_at = now - timedelta(days=created_days_ago)
        return cert
    return create_certificate

class TestEnhancedDeduplicationConfig:
    """Test configuration for enhanced deduplication."""
    
    def test_proxy_detection_enabled(self, mock_settings_with_proxy_detection):
        """Test that proxy detection is enabled in configuration."""
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateDeduplicator
        from sqlalchemy.orm import Session
        
        # Create a mock session
        mock_session = MagicMock(spec=Session)
        
        # Create deduplicator
        deduplicator = ProxyCertificateDeduplicator(mock_session)
        
        # Test proxy CA detection
        assert deduplicator.is_proxy_ca("Corporate Proxy CA") is True
        assert deduplicator.is_proxy_ca("BlueCoat ProxySG CA") is True
        assert deduplicator.is_proxy_ca("Zscaler Root CA") is True
        assert deduplicator.is_proxy_ca("Let's Encrypt") is False
    
    def test_proxy_detection_disabled(self, mock_settings_without_proxy_detection):
        """Test that proxy detection is disabled in configuration."""
        from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateDeduplicator
        from sqlalchemy.orm import Session
        
        # Create a mock session
        mock_session = MagicMock(spec=Session)
        
        # Create deduplicator
        deduplicator = ProxyCertificateDeduplicator(mock_session)
        
        # Test proxy CA detection (should all be False when disabled)
        assert deduplicator.is_proxy_ca("Corporate Proxy CA") is False
        assert deduplicator.is_proxy_ca("BlueCoat ProxySG CA") is False
        assert deduplicator.is_proxy_ca("Zscaler Root CA") is False
        assert deduplicator.is_proxy_ca("Let's Encrypt") is False
    
    def test_certificate_info_factory(self, mock_certificate_info_factory):
        """Test the certificate info factory."""
        cert_info = mock_certificate_info_factory(
            serial_number="factory_serial",
            thumbprint="factory_thumbprint",
            common_name="factory.com",
            issuer_cn="Factory CA",
            is_proxy=True,
            proxy_info="Factory proxy detection"
        )
        
        assert cert_info.serial_number == "factory_serial"
        assert cert_info.thumbprint == "factory_thumbprint"
        assert cert_info.common_name == "factory.com"
        assert cert_info.issuer["CN"] == "Factory CA"
        assert cert_info.proxied is True
        assert cert_info.proxy_info == "Factory proxy detection"
    
    def test_certificate_factory(self, mock_certificate_factory):
        """Test the certificate factory."""
        cert = mock_certificate_factory(
            cert_id=999,
            serial_number="factory_serial",
            thumbprint="factory_thumbprint",
            common_name="factory.com",
            issuer_cn="Factory CA",
            is_proxy=True,
            proxy_info="Factory proxy detection"
        )
        
        assert cert.id == 999
        assert cert.serial_number == "factory_serial"
        assert cert.thumbprint == "factory_thumbprint"
        assert cert.common_name == "factory.com"
        assert cert.proxied is True
        assert cert.proxy_info == "Factory proxy detection"









