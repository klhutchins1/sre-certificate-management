import pytest
from unittest.mock import patch, MagicMock
import streamlit as st
import sys

@pytest.fixture(autouse=True)
def clean_imports():
    """Clean up imports before each test"""
    # Remove run module if it exists
    if 'run' in sys.modules:
        del sys.modules['run']
    yield

@patch('streamlit.set_page_config')
def test_wide_space_default(mock_set_page_config):
    """Test that wide_space_default sets the correct page configuration"""
    # Mock app_main to prevent it from running
    with patch('cert_scanner.app.main'):
        # Import the module (this will execute the top-level code)
        import run
        
        # Call the function
        run.wide_space_default()
        
        # Verify page config was called with correct parameters
        mock_set_page_config.assert_called_once_with(
            page_title="Certificate Manager",
            page_icon="🔐",
            layout="wide",  # Force wide mode
            initial_sidebar_state="expanded",
            menu_items=None  # Completely disable menu items
        ) 