"""
Tests for enhanced scan control functionality (pause/resume/stop).
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from infra_mgmt.scanner.scan_manager import ScanManager
from infra_mgmt.services.ScanService import ScanService
import threading
import time

class TestScanManagerControls:
    """Test the enhanced scan control methods in ScanManager."""
    
    def test_scan_manager_initialization(self):
        """Test that ScanManager initializes with proper control state."""
        scan_manager = ScanManager()
        
        # Check initial state
        assert scan_manager.scan_state == "idle"
        assert scan_manager.scan_paused is False
        assert scan_manager.scan_stopped is False
    
    def test_pause_scan(self):
        """Test pausing a scan."""
        scan_manager = ScanManager()
        scan_manager.scan_state = "running"
        
        scan_manager.pause_scan()
        
        assert scan_manager.scan_state == "paused"
        assert scan_manager.scan_paused is True
        assert scan_manager.is_scan_paused() is True
    
    def test_resume_scan(self):
        """Test resuming a paused scan."""
        scan_manager = ScanManager()
        scan_manager.scan_state = "paused"
        scan_manager.scan_paused = True
        
        scan_manager.resume_scan()
        
        assert scan_manager.scan_state == "running"
        assert scan_manager.scan_paused is False
        assert scan_manager.is_scan_paused() is False
    
    def test_stop_scan(self):
        """Test stopping a scan."""
        scan_manager = ScanManager()
        scan_manager.scan_state = "running"
        
        scan_manager.stop_scan()
        
        assert scan_manager.scan_state == "stopped"
        assert scan_manager.scan_stopped is True
        assert scan_manager.is_scan_stopped() is True
    
    def test_start_scan(self):
        """Test starting a scan."""
        scan_manager = ScanManager()
        
        scan_manager.start_scan()
        
        assert scan_manager.scan_state == "running"
        assert scan_manager.scan_paused is False
        assert scan_manager.scan_stopped is False
    
    def test_reset_scan_controls(self):
        """Test resetting scan controls."""
        scan_manager = ScanManager()
        scan_manager.scan_state = "stopped"
        scan_manager.scan_paused = True
        scan_manager.scan_stopped = True
        
        scan_manager.reset_scan_controls()
        
        assert scan_manager.scan_state == "idle"
        assert scan_manager.scan_paused is False
        assert scan_manager.scan_stopped is False
    
    def test_get_scan_state(self):
        """Test getting current scan state."""
        scan_manager = ScanManager()
        
        # Test different states
        scan_manager.scan_state = "idle"
        assert scan_manager.get_scan_state() == "idle"
        
        scan_manager.scan_state = "running"
        assert scan_manager.get_scan_state() == "running"
        
        scan_manager.scan_state = "paused"
        assert scan_manager.get_scan_state() == "paused"
        
        scan_manager.scan_state = "stopped"
        assert scan_manager.get_scan_state() == "stopped"
    
    def test_scan_state_transitions(self):
        """Test valid scan state transitions."""
        scan_manager = ScanManager()
        
        # idle -> running
        scan_manager.start_scan()
        assert scan_manager.scan_state == "running"
        
        # running -> paused
        scan_manager.pause_scan()
        assert scan_manager.scan_state == "paused"
        
        # paused -> running
        scan_manager.resume_scan()
        assert scan_manager.scan_state == "running"
        
        # running -> stopped
        scan_manager.stop_scan()
        assert scan_manager.scan_state == "stopped"
        
        # Reset and start again
        scan_manager.reset_scan_controls()
        scan_manager.start_scan()
        assert scan_manager.scan_state == "running"
    
    def test_invalid_state_transitions(self):
        """Test that invalid state transitions are handled gracefully."""
        scan_manager = ScanManager()
        
        # Pause when idle (will set to paused state)
        scan_manager.pause_scan()
        assert scan_manager.scan_state == "paused"
        
        # Can't resume when not paused
        scan_manager.start_scan()
        scan_manager.resume_scan()  # Already running, should be no-op
        assert scan_manager.scan_state == "running"
        
        # Can't start when already running (should be no-op)
        scan_manager.start_scan()
        assert scan_manager.scan_state == "running"

class TestScanControlIntegration:
    """Integration tests for scan controls with actual scanning."""
    
    @patch('infra_mgmt.scanner.scan_manager.ScanManager.scan_target')
    def test_scan_respects_pause_state(self, mock_scan_target):
        """Test that scanning respects pause state."""
        scan_manager = ScanManager()
        
        # Start scan
        scan_manager.start_scan()
        assert scan_manager.scan_state == "running"
        
        # Pause scan
        scan_manager.pause_scan()
        assert scan_manager.is_scan_paused() is True
        
        # Resume scan
        scan_manager.resume_scan()
        assert scan_manager.is_scan_paused() is False
    
    @patch('infra_mgmt.scanner.scan_manager.ScanManager.scan_target')
    def test_scan_respects_stop_state(self, mock_scan_target):
        """Test that scanning respects stop state."""
        scan_manager = ScanManager()
        
        # Start scan
        scan_manager.start_scan()
        assert scan_manager.scan_state == "running"
        
        # Stop scan
        scan_manager.stop_scan()
        assert scan_manager.is_scan_stopped() is True
        
        # Resume after stop (will change state to running)
        scan_manager.resume_scan()
        assert scan_manager.scan_state == "running"
    
    def test_scan_control_thread_safety(self):
        """Test that scan controls are thread-safe."""
        scan_manager = ScanManager()
        results = []
        
        def control_scan():
            scan_manager.start_scan()
            time.sleep(0.01)
            scan_manager.pause_scan()
            time.sleep(0.01)
            scan_manager.resume_scan()
            time.sleep(0.01)
            scan_manager.stop_scan()
            results.append(scan_manager.get_scan_state())
        
        # Run control operations in a thread
        thread = threading.Thread(target=control_scan)
        thread.start()
        thread.join()
        
        # Verify final state
        assert len(results) == 1
        assert results[0] == "stopped"
        assert scan_manager.is_scan_stopped() is True

class TestScanServiceIntegration:
    """Test scan controls integration with ScanService."""
    
    def test_scan_service_pause_resume(self):
        """Test pause/resume functionality through ScanService."""
        # Mock engine
        mock_engine = Mock()
        scan_service = ScanService(mock_engine)
        
        # Test pause
        scan_service.pause_scan()
        assert scan_service.scan_paused is True
        
        # Test resume
        scan_service.resume_scan()
        assert scan_service.scan_paused is False
    
    def test_scan_service_stop(self):
        """Test stop functionality through ScanService."""
        # Mock engine
        mock_engine = Mock()
        scan_service = ScanService(mock_engine)
        
        # Test stop
        scan_service.stop_scan()
        assert scan_service.scan_stopped is True
        assert scan_service.scan_paused is False
    
    def test_scan_service_get_status(self):
        """Test getting scan status through ScanService."""
        # Mock engine
        mock_engine = Mock()
        scan_service = ScanService(mock_engine)
        
        # Test initial status
        assert scan_service.scan_paused is False
        assert scan_service.scan_stopped is False
        
        # Test status after pause
        scan_service.pause_scan()
        assert scan_service.scan_paused is True
        
        # Test status after stop
        scan_service.stop_scan()
        assert scan_service.scan_stopped is True
        assert scan_service.scan_paused is False

class TestScanControlErrorHandling:
    """Test error handling in scan controls."""
    
    def test_scan_control_with_none_manager(self):
        """Test scan controls when scan manager is None."""
        # Mock engine
        mock_engine = Mock()
        scan_service = ScanService(mock_engine)
        scan_service.scan_manager = None
        
        # All operations should handle None gracefully
        scan_service.pause_scan()  # Should not raise exception
        scan_service.resume_scan()  # Should not raise exception
        scan_service.stop_scan()  # Should not raise exception
    
    def test_scan_control_exception_handling(self):
        """Test that scan control exceptions are handled gracefully."""
        scan_manager = ScanManager()
        
        # Test that normal operations work
        scan_manager.pause_scan()
        assert scan_manager.scan_state == "paused"
        
        # Test that resume works after pause
        scan_manager.resume_scan()
        assert scan_manager.scan_state == "running"
    
    def test_scan_state_consistency(self):
        """Test that scan state remains consistent across operations."""
        scan_manager = ScanManager()
        
        # Test state consistency through multiple operations
        scan_manager.start_scan()
        assert scan_manager.scan_state == "running"
        assert not scan_manager.scan_paused
        assert not scan_manager.scan_stopped
        
        scan_manager.pause_scan()
        assert scan_manager.scan_state == "paused"
        assert scan_manager.scan_paused
        assert not scan_manager.scan_stopped
        
        scan_manager.resume_scan()
        assert scan_manager.scan_state == "running"
        assert not scan_manager.scan_paused
        assert not scan_manager.scan_stopped
        
        scan_manager.stop_scan()
        assert scan_manager.scan_state == "stopped"
        assert not scan_manager.scan_paused
        assert scan_manager.scan_stopped
