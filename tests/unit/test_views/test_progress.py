import pytest
from unittest.mock import MagicMock, patch
from infra_mgmt.views.scannerView import StreamlitProgressContainer
from unittest.mock import ANY

@pytest.fixture
def mock_progress_bar():
    return MagicMock()

@pytest.fixture
def mock_status_text():
    return MagicMock()

@pytest.fixture
def progress_container(mock_progress_bar, mock_status_text):
    return StreamlitProgressContainer(mock_progress_bar, mock_status_text)

def test_progress_container_initialization(progress_container, mock_progress_bar, mock_status_text):
    """Test StreamlitProgressContainer initialization."""
    assert progress_container.progress_bar == mock_progress_bar
    assert progress_container.status_text == mock_status_text

def test_progress_update(progress_container, mock_progress_bar):
    """Test progress bar updates."""
    # Test valid progress values
    progress_container.progress(0.5)
    mock_progress_bar.progress.assert_called_once_with(0.5)

    # Test boundary values
    progress_container.progress(0.0)
    progress_container.progress(1.0)
    assert mock_progress_bar.progress.call_count == 3

def test_progress_invalid_values(progress_container, mock_progress_bar):
    """Test progress bar with invalid values."""
    # Test negative value
    progress_container.progress(-0.1)
    mock_progress_bar.progress.assert_called_once_with(0.0)

    # Test value > 1
    progress_container.progress(1.1)
    mock_progress_bar.progress.assert_called_with(1.0)

def test_status_text_update(progress_container, mock_status_text):
    """Test status text updates."""
    test_message = "Processing target: example.com"
    progress_container.text(test_message)
    mock_status_text.text.assert_called_once_with(test_message)

def test_status_text_empty(progress_container, mock_status_text):
    """Test status text with empty message."""
    progress_container.text("")
    mock_status_text.text.assert_called_once_with("")

def test_status_text_none(progress_container, mock_status_text):
    """Test status text with None message."""
    progress_container.text(None)
    mock_status_text.text.assert_called_once_with(None)

def test_progress_container_error_handling(progress_container, mock_progress_bar, mock_status_text):
    """Test error handling in progress container."""
    # Suppress error logging
    with patch('logging.Logger.error'), patch('logging.Logger.exception'):
        # Test progress bar error
        mock_progress_bar.progress.side_effect = Exception("Progress bar error")
        progress_container.progress(0.5)  # Should not raise exception

        # Test status text error
        mock_status_text.text.side_effect = Exception("Status text error")
        progress_container.text("test")  # Should not raise exception 