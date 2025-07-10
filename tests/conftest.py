"""
Test configuration with comprehensive network mocking.
Prevents all real external network calls during testing.
"""
import os
import sys
import pytest
import logging
from unittest.mock import MagicMock, patch
import pandas as pd

# Add the project root directory to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Global patches to prevent network calls during scanner tests
_network_patches = []

@pytest.fixture(autouse=True)
def prevent_network_calls_for_scanner_tests(request):
    """Auto-applied fixture that prevents network calls for scanner VIEW tests only."""
    # Only apply to scanner VIEW tests, not unit tests of scanner modules
    if 'scannerView' in request.node.nodeid or 'test_views' in request.node.nodeid:
        from datetime import datetime, timezone
        
        # Create comprehensive mock responses
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

        mock_subprocess_result = MagicMock()
        mock_subprocess_result.returncode = 0
        mock_subprocess_result.stdout = "Mock WHOIS output"
        
        # Mock certificate scan result
        mock_cert_result = MagicMock()
        mock_cert_result.has_certificate = False
        mock_cert_result.error = "Mocked - no real network access"

        # Comprehensive patching at the lowest level
        global _network_patches
        _network_patches = [
            # Socket level
            patch('socket.socket'),
            patch('socket.create_connection'),
            patch('socket.getaddrinfo', return_value=[('AF_INET', 'SOCK_STREAM', 6, '', ('1.2.3.4', 443))]),
            
            # DNS level
            patch('dns.resolver.resolve', return_value=[mock_dns_answer]),
            patch('dns.resolver.Resolver'),
            
            # HTTP level
            patch('requests.get', return_value=mock_http_response),
            patch('requests.post', return_value=mock_http_response),
            
            # Subprocess (for command-line tools)
            patch('subprocess.run', return_value=mock_subprocess_result),
            patch('subprocess.Popen'),
            
            # SSL/TLS
            patch('ssl.create_default_context'),
            
            # Time delays
            patch('time.sleep'),
        ]
        
        # Try to patch whois if available
        try:
            _network_patches.append(patch('whois.whois', return_value=mock_whois_result))
        except ImportError:
            pass
        
        # Try to patch specific application modules
        try:
            _network_patches.append(patch('infra_mgmt.utils.dns_records.dns.resolver.resolve', return_value=[mock_dns_answer]))
        except (ImportError, AttributeError):
            pass
            
        try:
            _network_patches.append(patch('infra_mgmt.scanner.domain_scanner.whois.whois', return_value=mock_whois_result))
        except (ImportError, AttributeError):
            pass
            
        try:
            _network_patches.append(patch('infra_mgmt.scanner.subdomain_scanner.requests.get', return_value=mock_http_response))
        except (ImportError, AttributeError):
            pass
            
        # Note: Not patching CertificateScanner.scan_certificate to allow unit tests to work
        # The certificate scanner unit tests should control their own mocking

        # Start all patches
        for p in _network_patches:
            p.start()
    
    yield
    
    # Stop all patches
    if _network_patches:
        for p in _network_patches:
            try:
                p.stop()
            except:
                pass
        _network_patches.clear()

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

# Mock Streamlit modules to prevent warnings
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

@pytest.fixture
def fast_rate_limits():
    """Fixture to speed up rate limiting for tests by setting very high rate limits."""
    from unittest.mock import patch
    
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
            
        return default
    
    with patch('infra_mgmt.settings.settings.get', side_effect=mock_settings_get):
        yield 