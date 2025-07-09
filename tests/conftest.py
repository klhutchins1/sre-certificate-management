"""
Comprehensive test configuration with network mocking.
Ensures no real external sites are hit during testing.
"""
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

# Mock all network-related modules before any imports
def setup_network_mocks():
    """Setup comprehensive network mocking to prevent hitting real sites."""
    
    # Mock whois module
    mock_whois_module = MagicMock()
    mock_whois_module.__file__ = 'mock_whois.py'
    mock_whois_module.__path__ = []
    
    # Mock the parser submodule
    mock_parser = MagicMock()
    mock_parser.PywhoisError = Exception
    mock_parser.__file__ = 'mock_whois_parser.py'
    mock_whois_module.parser = mock_parser
    
    # Mock whois function with realistic data
    def mock_whois_function(domain):
        result = MagicMock()
        result.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        result.expiration_date = datetime(2030, 1, 1, tzinfo=timezone.utc)
        result.registrar = "Test Registrar"
        result.registrant_name = "Test Owner"
        result.status = "active"
        result.name_servers = ["ns1.example.com", "ns2.example.com"]
        return result
    
    mock_whois_module.whois = mock_whois_function
    
    # Mock DNS module
    mock_dns = MagicMock()
    mock_dns.resolver = MagicMock()
    mock_dns.reversename = MagicMock()
    
    # Mock DNS answer
    mock_dns_answer = MagicMock()
    mock_dns_answer.address = '1.2.3.4'
    mock_dns_answer.ttl = 300
    mock_dns.resolver.resolve.return_value = [mock_dns_answer]
    
    # Mock socket module
    mock_socket = MagicMock()
    mock_socket.socket = MagicMock()
    mock_socket.create_connection = MagicMock()
    mock_socket.getaddrinfo = MagicMock(return_value=[('AF_INET', 'SOCK_STREAM', 6, '', ('1.2.3.4', 443))])
    mock_socket.gaierror = Exception
    mock_socket.timeout = Exception
    mock_socket.IPPROTO_TCP = 6
    
    # Mock SSL module
    mock_ssl = MagicMock()
    mock_ssl.create_default_context = MagicMock()
    mock_ssl.SSLError = Exception
    mock_ssl.CERT_NONE = 0
    mock_ssl.CERT_REQUIRED = 2
    
    # Mock SSL context and socket
    mock_ssl_context = MagicMock()
    mock_ssl_socket = MagicMock()
    mock_ssl_context.wrap_socket.return_value = mock_ssl_socket
    mock_ssl_socket.getpeercert.return_value = b'MOCK_CERTIFICATE_DATA'
    mock_ssl.create_default_context.return_value = mock_ssl_context
    
    # Mock requests module
    mock_requests = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = []
    mock_response.text = "Mock response"
    mock_requests.get.return_value = mock_response
    mock_requests.post.return_value = mock_response
    mock_requests.RequestException = Exception
    
    # Mock subprocess to prevent external commands
    mock_subprocess = MagicMock()
    mock_subprocess.run = MagicMock(return_value=MagicMock(returncode=0, stdout="Mock output"))
    mock_subprocess.TimeoutExpired = Exception
    mock_subprocess.SubprocessError = Exception
    
    # Mock urllib3 to prevent connection pooling issues
    mock_urllib3 = MagicMock()
    mock_urllib3.disable_warnings = MagicMock()
    mock_urllib3.exceptions = MagicMock()
    
    # Update sys.modules with all mocks
    sys.modules['whois'] = mock_whois_module
    sys.modules['whois.parser'] = mock_parser
    sys.modules['dns'] = mock_dns
    sys.modules['dns.resolver'] = mock_dns.resolver
    sys.modules['dns.reversename'] = mock_dns.reversename
    sys.modules['socket'] = mock_socket
    sys.modules['ssl'] = mock_ssl
    sys.modules['requests'] = mock_requests
    sys.modules['subprocess'] = mock_subprocess
    sys.modules['urllib3'] = mock_urllib3
    
    return {
        'whois': mock_whois_module,
        'dns': mock_dns,
        'socket': mock_socket,
        'ssl': mock_ssl,
        'requests': mock_requests,
        'subprocess': mock_subprocess,
        'urllib3': mock_urllib3
    }

# Setup mocks immediately when conftest is imported
NETWORK_MOCKS = setup_network_mocks()

import pytest
import logging
from unittest.mock import MagicMock
import pandas as pd
from sqlalchemy import create_engine, NullPool

# Add the project root directory to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

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

# Test configuration - add to existing pytest_configure if it exists
def configure_network_test_markers(config):
    """Configure pytest with network-related markers."""
    config.addinivalue_line(
        "markers", "network: marks tests that require network access (deselect with '-m \"not network\"')"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )

def pytest_collection_modifyitems(config, items):
    """Automatically mark certain tests based on patterns."""
    for item in items:
        # Mark any test that looks like it might hit the network
        if any(keyword in item.nodeid.lower() for keyword in ['network', 'external', 'real']):
            item.add_marker(pytest.mark.network)
        
        # Mark integration tests as slow
        if 'integration' in item.nodeid.lower():
            item.add_marker(pytest.mark.slow)

# Provide network mock access for individual tests
@pytest.fixture
def network_mocks():
    """Access to network mocks for custom test scenarios."""
    return NETWORK_MOCKS 