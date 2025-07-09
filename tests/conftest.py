"""
Comprehensive test configuration with network mocking.
Ensures no real external sites are hit during testing.
"""
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

import pytest
import logging
import pandas as pd
from sqlalchemy import create_engine, NullPool

# Add the project root directory to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

@pytest.fixture(autouse=True)
def prevent_network_calls():
    """Auto-fixture that prevents ALL network calls during tests with comprehensive patching."""
    
    # Create realistic mock responses for different types of network operations
    mock_whois_result = MagicMock()
    mock_whois_result.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
    mock_whois_result.expiration_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
    mock_whois_result.registrar = "Test Registrar"
    mock_whois_result.registrant_name = "Test Owner"
    mock_whois_result.status = "active"
    mock_whois_result.name_servers = ["ns1.example.com", "ns2.example.com"]

    mock_dns_answer = MagicMock()
    mock_dns_answer.address = '1.2.3.4'
    mock_dns_answer.ttl = 300

    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = []
    mock_http_response.text = "Mock response"

    # Mock certificate scan result
    mock_cert_info = MagicMock()
    mock_cert_info.san = ['example.com', 'www.example.com']
    mock_cert_info.common_name = 'example.com'
    mock_cert_info.validation_errors = []
    
    mock_scan_result = MagicMock()
    mock_scan_result.certificate_info = mock_cert_info
    mock_scan_result.error = None
    mock_scan_result.has_certificate = True

    # Mock subprocess result for whois command
    mock_subprocess_result = MagicMock()
    mock_subprocess_result.returncode = 0
    mock_subprocess_result.stdout = "Mock WHOIS output"

    # Comprehensive patching of ALL the specific network call points
    with patch('socket.socket') as mock_socket, \
          patch('socket.create_connection') as mock_create_conn, \
          patch('socket.getaddrinfo', return_value=[('AF_INET', 'SOCK_STREAM', 6, '', ('1.2.3.4', 443))]), \
          patch('ssl.create_default_context') as mock_ssl_context, \
          patch('requests.get', return_value=mock_http_response), \
          patch('requests.post', return_value=mock_http_response), \
          patch('subprocess.run', return_value=mock_subprocess_result), \
          patch('dns.resolver.resolve', return_value=[mock_dns_answer]), \
          patch('dns.resolver.Resolver') as mock_resolver_class, \
          patch('infra_mgmt.utils.dns_records.dns.resolver.resolve', return_value=[mock_dns_answer]), \
          patch('infra_mgmt.scanner.domain_scanner.socket.getaddrinfo', return_value=[('AF_INET', 'SOCK_STREAM', 6, '', ('1.2.3.4', 443))]), \
          patch('infra_mgmt.scanner.certificate_scanner.CertificateScanner.scan_certificate', return_value=mock_scan_result), \
          patch('infra_mgmt.scanner.subdomain_scanner.requests.get', return_value=mock_http_response), \
          patch('time.sleep') as mock_sleep:
        
        # Configure socket mocks
        mock_socket_instance = MagicMock()
        mock_socket.return_value = mock_socket_instance
        mock_create_conn.return_value = mock_socket_instance
        
        # Configure SSL mocks
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.getpeercert.return_value = b'MOCK_CERTIFICATE_DATA'
        mock_ssl_context_instance = MagicMock()
        mock_ssl_context_instance.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_ssl_context_instance
        
        # Configure DNS resolver mock
        mock_resolver_instance = MagicMock()
        mock_resolver_instance.resolve.return_value = [mock_dns_answer]
        mock_resolver_instance.timeout = 5
        mock_resolver_instance.lifetime = 5
        mock_resolver_class.return_value = mock_resolver_instance
        
        # Try to patch WHOIS operations if modules are available
        try:
            with patch('whois.whois', return_value=mock_whois_result), \
                 patch('infra_mgmt.scanner.domain_scanner.whois.whois', return_value=mock_whois_result):
                yield
        except ImportError:
            # whois module not available, continue without it
            yield

# Create test data directory if it doesn't exist
@pytest.fixture(autouse=True)
def setup_test_env(tmp_path):
    """Set up test environment before each test"""
    test_data_dir = tmp_path / "data"
    test_data_dir.mkdir(exist_ok=True)
    
    # Set environment variables for testing
    os.environ['PYTHONPATH'] = project_root
    
    yield
    
    # Clean up after tests
    if 'infra_mgmt_CONFIG' in os.environ:
        del os.environ['infra_mgmt_CONFIG']

# Create a proper mock for streamlit components
components_mock = MagicMock()
components_mock.v1 = MagicMock()

# Mock Streamlit modules to prevent warnings (but don't break built-in types)
mock_module = MagicMock()
mock_module.get_script_run_ctx = lambda: None
mock_module.components = components_mock
sys.modules['streamlit'] = mock_module
sys.modules['streamlit.runtime'] = mock_module
sys.modules['streamlit.runtime.scriptrunner'] = mock_module
sys.modules['streamlit.runtime.scriptrunner_utils'] = mock_module
sys.modules['streamlit.components'] = components_mock
sys.modules['streamlit.components.v1'] = components_mock.v1

# Mock st_aggrid package
class MockGridOptionsBuilder:
    def __init__(self):
        self.options = {}
    
    def configure_default_column(self, **kwargs):
        return self
    
    def configure_column(self, field, **kwargs):
        return self
    
    def configure_selection(self, **kwargs):
        return self
    
    def configure_pagination(self, **kwargs):
        return self
    
    def configure_grid_options(self, **kwargs):
        self.options.update(kwargs)
        return self
    
    def build(self):
        return self.options

    @classmethod
    def from_dataframe(cls, dataframe, **kwargs):
        instance = cls()
        instance.options = {
            'columnDefs': [{'field': col} for col in dataframe.columns],
            'rowData': dataframe.to_dict('records')
        }
        return instance

class MockAgGrid:
    def __init__(self, *args, **kwargs):
        self.selected_rows = []
        self.data = kwargs.get('data', [])
        self.grid_options = kwargs.get('gridOptions', {})

    def __call__(self, *args, **kwargs):
        return {
            'data': args[0] if args else pd.DataFrame(),
            'selected_rows': [],
            'grid_options': kwargs.get('gridOptions', {})
        }

mock_aggrid = MagicMock()
mock_aggrid.GridOptionsBuilder = MockGridOptionsBuilder
mock_aggrid.AgGrid = MockAgGrid
mock_aggrid.GridUpdateMode = MagicMock()
mock_aggrid.DataReturnMode = MagicMock()
sys.modules['st_aggrid'] = mock_aggrid

def pytest_configure(config):
    """Configure logging based on pytest command line options"""
    log_cli_level = config.getoption('--log-cli-level', None)
    
    # Set up root logger with console handler
    root_logger = logging.getLogger()
    console_handler = logging.StreamHandler(sys.stdout)
    
    # Set log level based on pytest options
    level = logging.INFO if log_cli_level == 'INFO' else logging.WARNING
    root_logger.setLevel(level)
    console_handler.setLevel(level)
    
    # Add handler to root logger
    root_logger.addHandler(console_handler)
    
    # Suppress specific Streamlit warnings
    logging.getLogger('streamlit').setLevel(logging.ERROR)
    logging.getLogger('streamlit.runtime').setLevel(logging.ERROR)

    # Add network test markers
    config.addinivalue_line(
        "markers", "network: marks tests that require network access (deselect with '-m \"not network\"')"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )

@pytest.fixture
def mock_engine():
    """Provide a mock SQLAlchemy engine for tests."""
    engine = create_engine('sqlite:///:memory:', echo=False, poolclass=NullPool)
    # Ensure tables are created if models are available
    try:
        from infra_mgmt.models import Base
        Base.metadata.create_all(engine)
    except ImportError:
        pass
    
    yield engine
    engine.dispose()

def pytest_collection_modifyitems(config, items):
    """Automatically mark certain tests based on patterns."""
    for item in items:
        # Mark any test that looks like it might hit the network
        if any(keyword in item.nodeid.lower() for keyword in ['network', 'external', 'real']):
            item.add_marker(pytest.mark.network)
        
        # Mark integration tests as slow
        if 'integration' in item.nodeid.lower():
            item.add_marker(pytest.mark.slow)

@pytest.fixture
def fast_rate_limits():
    """Fixture to speed up rate limiting for tests by setting very high rate limits."""
    from unittest.mock import patch
    
    # Mock settings to return very high rate limits (effectively disabling rate limiting for tests)
    def mock_settings_get(key, default=None):
        rate_limit_keys = [
            'scanning.certificate.rate_limit',
            'scanning.default_rate_limit', 
            'scanning.internal.rate_limit',
            'scanning.external.rate_limit',
            'scanning.whois.rate_limit',
            'scanning.dns.rate_limit',
            'scanning.ct.rate_limit'
        ]
        
        if any(rate_key in key for rate_key in rate_limit_keys):
            return 36000  # 600 requests per second - effectively no rate limiting
        
        if key in ['scanning.internal.domains', 'scanning.external.domains']:
            return []
        
        # Mock timeout settings to be fast
        if 'timeout' in key:
            return 0.1  # Very short timeouts for tests
            
        return default
    
    with patch('infra_mgmt.settings.settings.get', side_effect=mock_settings_get):
        yield

@pytest.fixture
def normal_rate_limits():
    """Fixture to test actual rate limiting behavior."""
    from unittest.mock import patch
    
    # Mock settings to return realistic rate limits for testing rate limiting functionality
    def mock_settings_get(key, default=None):
        rate_limits = {
            'scanning.certificate.rate_limit': 10,   # 10 per minute
            'scanning.default_rate_limit': 10,
            'scanning.internal.rate_limit': 10,
            'scanning.external.rate_limit': 10,
            'scanning.whois.rate_limit': 10,
            'scanning.dns.rate_limit': 10,
            'scanning.ct.rate_limit': 10
        }
        
        if key in rate_limits:
            return rate_limits[key]
        
        if key in ['scanning.internal.domains', 'scanning.external.domains']:
            return []
        
        # Mock timeout settings
        if 'timeout' in key:
            return 5.0
            
        return default
    
    with patch('infra_mgmt.settings.settings.get', side_effect=mock_settings_get):
        yield

@pytest.fixture
def comprehensive_network_mocks():
    """Fixture that provides comprehensive network mocking for tests that need to verify specific behavior."""
    from unittest.mock import patch
    
    # Create detailed mock objects for testing
    mock_responses = {
        'dns_records': [
            {'type': 'A', 'name': 'example.com', 'value': '1.2.3.4', 'ttl': 300},
            {'type': 'AAAA', 'name': 'example.com', 'value': '2001:db8::1', 'ttl': 300}
        ],
        'whois_info': {
            'registrar': 'Test Registrar',
            'registrant': 'Test Owner',
            'creation_date': datetime(2020, 1, 1, tzinfo=timezone.utc),
            'expiration_date': datetime(2030, 1, 1, tzinfo=timezone.utc),
            'status': ['active'],
            'nameservers': ['ns1.example.com', 'ns2.example.com']
        },
        'certificate_info': {
            'san': ['example.com', 'www.example.com'],
            'common_name': 'example.com',
            'validation_errors': []
        },
        'ct_logs': []
    }
    
    # Patch all network operations with these mock responses
    with patch('infra_mgmt.utils.dns_records.DNSRecordUtil.get_dns_records', return_value=mock_responses['dns_records']), \
         patch('infra_mgmt.scanner.domain_scanner.DomainScanner._whois_query', return_value=mock_responses['whois_info']), \
         patch('infra_mgmt.scanner.subdomain_scanner.SubdomainScanner._get_ct_logs_subdomains', return_value=set()), \
         patch('infra_mgmt.scanner.certificate_scanner.CertificateScanner.scan_certificate') as mock_cert_scan:
        
        # Configure certificate scanner mock
        mock_scan_result = MagicMock()
        mock_scan_result.certificate_info = MagicMock()
        mock_scan_result.certificate_info.san = mock_responses['certificate_info']['san']
        mock_scan_result.certificate_info.common_name = mock_responses['certificate_info']['common_name']
        mock_scan_result.certificate_info.validation_errors = mock_responses['certificate_info']['validation_errors']
        mock_scan_result.error = None
        mock_scan_result.has_certificate = True
        mock_cert_scan.return_value = mock_scan_result
        
        yield mock_responses 