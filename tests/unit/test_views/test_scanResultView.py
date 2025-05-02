import pytest
from infra_mgmt.scanner.certificate_scanner import ScanResult

@pytest.fixture
def test_scan_result(mock_cert_info):
    """Create a test scan result with timezone-aware datetime"""
    return ScanResult(
        certificate_info=mock_cert_info,
        ip_addresses=['192.168.1.1'],
        warnings=[]
    ) 