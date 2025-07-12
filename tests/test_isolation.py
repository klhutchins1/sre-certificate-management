"""
Test Isolation Module for Infrastructure Management System

This module provides comprehensive isolation for all tests to prevent external API calls.
It mocks all network-related operations including:
- WHOIS queries
- DNS lookups
- HTTP/HTTPS requests
- SSL/TLS connections
- Certificate transparency lookups
- Subprocess calls to external tools

Usage:
    from tests.test_isolation import isolated_test
    
    @isolated_test
    def test_my_function():
        # Test code here will not make external calls
        pass
"""

import sys
import os
import socket
import subprocess
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, Mock
import functools
from typing import Dict, Any, List, Optional
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Mock external modules at import time to prevent ImportError
def _mock_external_modules():
    """Mock external modules that might not be installed"""
    
    # Mock dns module
    if 'dns' not in sys.modules:
        dns_mock = MagicMock()
        dns_mock.resolver = MagicMock()
        dns_mock.resolver.resolve = MagicMock()
        dns_mock.resolver.query = MagicMock()
        dns_mock.resolver.Resolver = MagicMock()
        dns_mock.resolver.NXDOMAIN = Exception("NXDOMAIN")
        dns_mock.resolver.NoAnswer = Exception("NoAnswer")
        dns_mock.resolver.Timeout = Exception("Timeout")
        dns_mock.resolver.YXDOMAIN = Exception("YXDOMAIN")
        sys.modules['dns'] = dns_mock
        sys.modules['dns.resolver'] = dns_mock.resolver
    
    # Mock whois module
    if 'whois' not in sys.modules:
        whois_mock = MagicMock()
        whois_mock.whois = MagicMock()
        whois_mock.query = MagicMock()
        whois_mock.parser = MagicMock()
        whois_mock.parser.PywhoisError = Exception("PywhoisError")
        sys.modules['whois'] = whois_mock
        sys.modules['whois.parser'] = whois_mock.parser
    
    # Mock requests module
    if 'requests' not in sys.modules:
        requests_mock = MagicMock()
        requests_mock.get = MagicMock()
        requests_mock.post = MagicMock()
        requests_mock.put = MagicMock()
        requests_mock.delete = MagicMock()
        requests_mock.head = MagicMock()
        requests_mock.patch = MagicMock()
        requests_mock.Session = MagicMock()
        sys.modules['requests'] = requests_mock
    
    # Mock urllib3 module
    if 'urllib3' not in sys.modules:
        urllib3_mock = MagicMock()
        urllib3_mock.disable_warnings = MagicMock()
        urllib3_mock.exceptions = MagicMock()
        urllib3_mock.exceptions.InsecureRequestWarning = Warning
        urllib3_mock.PoolManager = MagicMock()
        sys.modules['urllib3'] = urllib3_mock
        sys.modules['urllib3.exceptions'] = urllib3_mock.exceptions
    
    # Mock other network-related modules
    if 'ipaddress' not in sys.modules:
        ipaddress_mock = MagicMock()
        ipaddress_mock.ip_address = MagicMock()
        sys.modules['ipaddress'] = ipaddress_mock

# Call the mock function at import time
_mock_external_modules()

class MockWhoisResult:
    """Mock WHOIS result object that mimics python-whois behavior"""
    def __init__(self, domain: str = "example.com"):
        self.domain = domain
        self.registrar = "Test Registrar Ltd"
        self.registrant_name = "Test Owner"
        self.registrant = "Test Owner"
        self.name = "Test Owner"
        self.org = "Test Organization"
        self.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        self.expiration_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        self.status = ["active", "clientTransferProhibited"]
        self.name_servers = ["ns1.example.com", "ns2.example.com"]
        self.nameservers = ["ns1.example.com", "ns2.example.com"]
        self.updated_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
        self.country = "US"
        
    def __bool__(self):
        return True

class MockDNSAnswer:
    """Mock DNS answer object"""
    def __init__(self, address: str = "1.2.3.4", ttl: int = 300):
        self.address = address
        self.ttl = ttl
        self.target = address
        self.preference = 10  # For MX records
        self.exchange = "mail.example.com"  # For MX records
        
    def __str__(self):
        return self.address

class MockHTTPResponse:
    """Mock HTTP response object"""
    def __init__(self, status_code: int = 200, json_data: Any = None, text: str = ""):
        self.status_code = status_code
        self.text = text or "Mock HTTP Response"
        self.content = (text or "Mock HTTP Response").encode()
        self.headers = {"Content-Type": "application/json"}
        self._json_data = json_data or []
        
    def json(self):
        return self._json_data
        
    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code} Error")

class MockSubprocessResult:
    """Mock subprocess result"""
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout or "Mock subprocess output"
        self.stderr = stderr
        self.args = []

class MockSocket:
    """Mock socket object"""
    def __init__(self):
        self.family = socket.AF_INET
        self.type = socket.SOCK_STREAM
        
    def connect(self, address):
        pass
        
    def close(self):
        pass
        
    def recv(self, bufsize):
        return b"Mock socket data"
        
    def send(self, data):
        return len(data)
        
    def settimeout(self, timeout):
        pass

class MockSSLContext:
    """Mock SSL context"""
    def __init__(self):
        self.check_hostname = True
        self.verify_mode = True
        
    def wrap_socket(self, sock, server_hostname=None):
        return MockSocket()

class NetworkIsolationManager:
    """Manager for network isolation patches"""
    
    def __init__(self):
        self.patches = []
        self.active = False
        
    def create_patches(self) -> List[Any]:
        """Create all network isolation patches"""
        patches = []
        
        # Basic network operations
        patches.extend([
            patch('socket.socket', return_value=MockSocket()),
            patch('socket.create_connection', return_value=MockSocket()),
            patch('socket.getaddrinfo', return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 443))
            ]),
            patch('socket.gethostbyname', return_value='1.2.3.4'),
            patch('socket.gethostbyaddr', return_value=('example.com', [], ['1.2.3.4'])),
        ])
        
        # SSL/TLS operations
        patches.extend([
            patch('ssl.create_default_context', return_value=MockSSLContext()),
            patch('ssl.SSLContext', return_value=MockSSLContext()),
        ])
        
        # HTTP requests
        mock_response = MockHTTPResponse()
        patches.extend([
            patch('requests.get', return_value=mock_response),
            patch('requests.post', return_value=mock_response),
            patch('requests.put', return_value=mock_response),
            patch('requests.delete', return_value=mock_response),
            patch('requests.head', return_value=mock_response),
            patch('requests.patch', return_value=mock_response),
            patch('requests.request', return_value=mock_response),
            patch('requests.Session.get', return_value=mock_response),
            patch('requests.Session.post', return_value=mock_response),
            patch('urllib.request.urlopen', return_value=mock_response),
            patch('urllib3.PoolManager.request', return_value=mock_response),
        ])
        
        # DNS operations
        mock_dns_answer = MockDNSAnswer()
        patches.extend([
            patch('dns.resolver.resolve', return_value=[mock_dns_answer]),
            patch('dns.resolver.query', return_value=[mock_dns_answer]),
            patch('dns.resolver.Resolver.resolve', return_value=[mock_dns_answer]),
            patch('dns.resolver.Resolver.query', return_value=[mock_dns_answer]),
        ])
        
        # WHOIS operations
        mock_whois_result = MockWhoisResult()
        patches.extend([
            patch('whois.whois', return_value=mock_whois_result),
            patch('whois.query', return_value=mock_whois_result),
        ])
        
        # Subprocess operations
        mock_subprocess_result = MockSubprocessResult()
        patches.extend([
            patch('subprocess.run', return_value=mock_subprocess_result),
            patch('subprocess.Popen', return_value=Mock()),
            patch('subprocess.check_output', return_value=b"Mock output"),
            patch('subprocess.check_call', return_value=0),
            patch('subprocess.call', return_value=0),
            patch('os.system', return_value=0),
        ])
        
        # Time operations (to speed up tests)
        patches.extend([
            patch('time.sleep', return_value=None),
            patch('time.time', return_value=1609459200.0),  # Fixed timestamp
        ])
        
        # IP address operations
        patches.extend([
            patch('ipaddress.ip_address', side_effect=lambda x: x if x.replace('.', '').isdigit() else ValueError(f"Invalid IP: {x}")),
        ])
        
        # Application-specific patches
        patches.extend(self._create_app_specific_patches())
        
        return patches
    
    def _create_app_specific_patches(self) -> List[Any]:
        """Create application-specific patches for our modules"""
        patches = []
        
        # Mock responses for different modules
        mock_whois_result = MockWhoisResult()
        mock_dns_answer = MockDNSAnswer()
        mock_http_response = MockHTTPResponse()
        
        # Domain scanner patches
        patches.extend([
            patch('infra_mgmt.scanner.domain_scanner.whois.whois', return_value=mock_whois_result),
            patch('infra_mgmt.scanner.domain_scanner.dns.resolver.resolve', return_value=[mock_dns_answer]),
            patch('infra_mgmt.scanner.domain_scanner.socket.getaddrinfo', return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.2.3.4', 443))
            ]),
        ])
        
        # Subdomain scanner patches
        patches.extend([
            patch('infra_mgmt.scanner.subdomain_scanner.requests.get', return_value=mock_http_response),
            patch('infra_mgmt.scanner.subdomain_scanner.dns.resolver.resolve', return_value=[mock_dns_answer]),
        ])
        
        # Certificate scanner patches
        patches.extend([
            patch('infra_mgmt.scanner.certificate_scanner.socket.create_connection', return_value=MockSocket()),
            patch('infra_mgmt.scanner.certificate_scanner.ssl.create_default_context', return_value=MockSSLContext()),
            patch('infra_mgmt.scanner.certificate_scanner.requests.get', return_value=mock_http_response),
        ])
        
        # Utils patches
        patches.extend([
            patch('infra_mgmt.scanner.utils.whois.whois', return_value=mock_whois_result),
            patch('infra_mgmt.utils.dns_records.dns.resolver.resolve', return_value=[mock_dns_answer]),
        ])
        
        return patches
    
    def start(self):
        """Start all network isolation patches"""
        if self.active:
            return
            
        self.patches = self.create_patches()
        for patch_obj in self.patches:
            try:
                patch_obj.start()
            except Exception as e:
                logger.debug(f"Could not start patch {patch_obj}: {e}")
        
        self.active = True
        logger.info(f"Network isolation activated with {len(self.patches)} patches")
    
    def stop(self):
        """Stop all network isolation patches"""
        if not self.active:
            return
            
        for patch_obj in self.patches:
            try:
                patch_obj.stop()
            except Exception as e:
                logger.debug(f"Could not stop patch {patch_obj}: {e}")
        
        self.patches.clear()
        self.active = False
        logger.info("Network isolation deactivated")
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

# Global isolation manager
_isolation_manager = NetworkIsolationManager()

def isolated_test(func):
    """Decorator to isolate a test function from external network calls"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with _isolation_manager:
            return func(*args, **kwargs)
    return wrapper

class IsolatedTestCase:
    """Base class for isolated test cases"""
    
    def setUp(self):
        """Set up network isolation"""
        _isolation_manager.start()
    
    def tearDown(self):
        """Clean up network isolation"""
        _isolation_manager.stop()

def ensure_network_isolation():
    """Ensure network isolation is active for current test"""
    if not _isolation_manager.active:
        _isolation_manager.start()

def create_mock_whois_result(domain: str = "example.com", **kwargs) -> MockWhoisResult:
    """Create a mock WHOIS result with custom data"""
    result = MockWhoisResult(domain)
    for key, value in kwargs.items():
        setattr(result, key, value)
    return result

def create_mock_dns_answer(address: str = "1.2.3.4", record_type: str = "A", **kwargs) -> MockDNSAnswer:
    """Create a mock DNS answer with custom data"""
    answer = MockDNSAnswer(address)
    for key, value in kwargs.items():
        setattr(answer, key, value)
    return answer

def create_mock_http_response(status_code: int = 200, json_data: Any = None, text: str = "", **kwargs) -> MockHTTPResponse:
    """Create a mock HTTP response with custom data"""
    response = MockHTTPResponse(status_code, json_data, text)
    for key, value in kwargs.items():
        setattr(response, key, value)
    return response

# Auto-activate isolation for pytest
def pytest_configure(config):
    """Auto-configure network isolation for pytest"""
    ensure_network_isolation()

def pytest_unconfigure(config):
    """Clean up network isolation after pytest"""
    _isolation_manager.stop()