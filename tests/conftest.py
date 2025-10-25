"""
Test configuration with comprehensive network isolation for ALL tests.
Prevents all real external network calls during testing.
"""
import os
import sys
import pytest
import logging
from unittest.mock import MagicMock, patch

# Import compatibility fixes first, before any other imports
try:
    # Add project root to path first
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    from infra_mgmt.compatibility import ensure_compatibility
    ensure_compatibility()
except ImportError:
    # If compatibility module not available, continue anyway
    pass

# Make pandas import optional to avoid ImportError during test collection
try:
    import pandas as pd
except ImportError:
    # Create a mock pandas module for test environments without pandas
    pd = MagicMock()
    pd.DataFrame = MagicMock
    sys.modules['pandas'] = pd

# Add the project root directory to the Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Import our comprehensive isolation system
from tests.test_isolation import NetworkIsolationManager, ensure_network_isolation

# Global isolation manager
_isolation_manager = NetworkIsolationManager()

@pytest.fixture(autouse=True)
def prevent_all_network_calls(request):
    """
    Auto-applied fixture that prevents ALL network calls for ALL tests.
    This ensures complete test isolation from external services.
    """
    test_name = request.node.nodeid
    print(f"[isolation] Activating network isolation for: {test_name}")
    
    # Start comprehensive network isolation
    _isolation_manager.start()
    
    yield
    
    # Stop network isolation
    _isolation_manager.stop()
    print(f"[isolation] Deactivated network isolation for: {test_name}")

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
            'columnDefs': [{'field': col} for col in dataframe.columns] if hasattr(dataframe, 'columns') else [],
            'rowData': dataframe.to_dict('records') if hasattr(dataframe, 'to_dict') else []
        }
        return instance

class MockAgGrid:
    def __init__(self, *args, **kwargs):
        self.selected_rows = []
        self.data = kwargs.get('data', [])
        self.grid_options = kwargs.get('gridOptions', {})

    def __call__(self, *args, **kwargs):
        return {
            'data': args[0] if args else pd.DataFrame() if hasattr(pd, 'DataFrame') else [],
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
    """Configure logging, network isolation, and custom markers for pytest"""
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
    
    # Register custom markers
    config.addinivalue_line(
        "markers", "networkisolation: mark test as using network isolation"
    )
    config.addinivalue_line(
        "markers", "timeout: mark test with timeout"
    )
    
    # Ensure network isolation is configured
    print("[pytest] Configuration: Network isolation enabled for ALL tests")

def pytest_unconfigure(config):
    """Clean up network isolation after pytest"""
    _isolation_manager.stop()
    print("[pytest] Cleanup: Network isolation disabled")

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

@pytest.fixture
def mock_whois_result():
    """Fixture providing a mock WHOIS result for tests"""
    from tests.test_isolation import MockWhoisResult
    return MockWhoisResult()

@pytest.fixture
def mock_dns_answer():
    """Fixture providing a mock DNS answer for tests"""
    from tests.test_isolation import MockDNSAnswer
    return MockDNSAnswer()

@pytest.fixture
def mock_http_response():
    """Fixture providing a mock HTTP response for tests"""
    from tests.test_isolation import MockHTTPResponse
    return MockHTTPResponse()

@pytest.fixture
def isolated_test_environment():
    """Fixture providing an isolated test environment with all mocks"""
    from tests.test_isolation import create_mock_whois_result, create_mock_dns_answer, create_mock_http_response
    
    return {
        'whois_result': create_mock_whois_result(),
        'dns_answer': create_mock_dns_answer(),
        'http_response': create_mock_http_response(),
    }

# Session-scoped fixtures for performance
@pytest.fixture(scope="session")
def session_isolation_manager():
    """Session-scoped network isolation manager"""
    manager = NetworkIsolationManager()
    manager.start()
    yield manager
    manager.stop()

# Configuration validation
def pytest_collection_modifyitems(config, items):
    """Modify test items to ensure network isolation"""
    for item in items:
        # Mark all tests to use network isolation
        item.add_marker(pytest.mark.networkisolation)
        
        # Add timeout to prevent hanging tests
        if not hasattr(item, 'pytestmark'):
            item.pytestmark = []
        
        # Add reasonable timeout for tests
        timeout_marker = pytest.mark.timeout(30)  # 30 second timeout
        item.add_marker(timeout_marker)

# Ensure no real external calls can happen
def pytest_sessionstart(session):
    """Ensure network isolation is active for the entire session"""
    ensure_network_isolation()
    print("[session] Network isolation ACTIVE")

def pytest_sessionfinish(session, exitstatus):
    """Clean up after session"""
    _isolation_manager.stop()
    print("[session] Network isolation DEACTIVATED")