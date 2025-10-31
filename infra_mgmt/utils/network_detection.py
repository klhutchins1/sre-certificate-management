"""
Network Detection Utility

Provides functionality to detect network connectivity and offline state.
Used to automatically detect offline mode and respect offline_mode configuration.
"""

import socket
import logging
import time
from typing import Tuple, Optional, Dict, Any
import dns.resolver
from ..settings import settings

logger = logging.getLogger(__name__)

class NetworkDetector:
    """
    Utility class for detecting network connectivity and offline state.
    
    Provides methods to:
    - Check DNS resolution capability
    - Check internet connectivity
    - Detect proxy availability
    - Determine if system should be in offline mode
    """
    
    # Well-known test endpoints
    TEST_DNS_SERVERS = [
        '8.8.8.8',  # Google DNS
        '1.1.1.1',  # Cloudflare DNS
    ]
    
    TEST_CONNECTIVITY_HOSTS = [
        'google.com',
        'cloudflare.com',
        'github.com',
    ]
    
    TEST_CONNECTIVITY_IPS = [
        '8.8.8.8',  # Google DNS
        '1.1.1.1',  # Cloudflare DNS
    ]
    
    def __init__(self, timeout: float = 2.0):
        """
        Initialize network detector.
        
        Args:
            timeout: Timeout in seconds for network checks
        """
        self.timeout = timeout
        self._last_check_time: Optional[float] = None
        self._last_check_result: Optional[bool] = None
        self._check_cache_ttl = 60  # Cache results for 60 seconds
    
    def check_dns_resolution(self, hostname: str = "google.com") -> bool:
        """
        Check if DNS resolution is working.
        
        Args:
            hostname: Hostname to resolve (default: google.com)
            
        Returns:
            bool: True if DNS resolution works, False otherwise
        """
        try:
            socket.gethostbyname(hostname)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False
        except Exception as e:
            logger.debug(f"Unexpected error in DNS resolution check: {e}")
            return False
    
    def check_internet_connectivity(self) -> bool:
        """
        Check if internet connectivity is available.
        
        Tries multiple methods:
        1. DNS resolution of well-known hosts
        2. Direct IP connectivity test
        3. DNS server connectivity
        
        Returns:
            bool: True if internet connectivity appears available, False otherwise
        """
        # Check DNS resolution
        dns_works = False
        for host in self.TEST_CONNECTIVITY_HOSTS:
            if self.check_dns_resolution(host):
                dns_works = True
                break
        
        if not dns_works:
            logger.debug("DNS resolution check failed for all test hosts")
        
        # Check direct IP connectivity (bypasses DNS)
        ip_connectivity = False
        for test_ip in self.TEST_CONNECTIVITY_IPS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((test_ip, 53))  # DNS port
                sock.close()
                if result == 0:
                    ip_connectivity = True
                    break
            except Exception as e:
                logger.debug(f"IP connectivity check failed for {test_ip}: {e}")
                continue
        
        # Return True if either DNS or IP connectivity works
        return dns_works or ip_connectivity
    
    def check_offline_mode(self, force_check: bool = False) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if system should be in offline mode based on network connectivity.
        
        Uses cached results if available to avoid excessive network checks.
        
        Args:
            force_check: If True, bypass cache and force a new check
            
        Returns:
            tuple: (is_offline: bool, details: dict)
                details contains:
                - 'dns_available': bool
                - 'internet_available': bool
                - 'check_timestamp': float
                - 'cached': bool
        """
        # Check cache first
        if not force_check and self._last_check_result is not None and self._last_check_time:
            elapsed = time.time() - self._last_check_time
            if elapsed < self._check_cache_ttl:
                logger.debug(f"Using cached offline mode check (age: {elapsed:.1f}s)")
                return self._last_check_result, {
                    'dns_available': True,  # Assume from previous check
                    'internet_available': not self._last_check_result,
                    'check_timestamp': self._last_check_time,
                    'cached': True
                }
        
        # Perform new check
        logger.debug("Performing new offline mode check")
        dns_available = self.check_dns_resolution()
        internet_available = self.check_internet_connectivity()
        
        # Determine offline state
        is_offline = not internet_available
        
        # Cache results
        self._last_check_time = time.time()
        self._last_check_result = is_offline
        
        details = {
            'dns_available': dns_available,
            'internet_available': internet_available,
            'check_timestamp': self._last_check_time,
            'cached': False
        }
        
        logger.info(f"Offline mode check: offline={is_offline}, dns={dns_available}, internet={internet_available}")
        
        return is_offline, details
    
    def is_offline(self, respect_config: bool = True) -> bool:
        """
        Quick check if system should be in offline mode.
        
        Args:
            respect_config: If True, respect config.yaml offline_mode setting
            
        Returns:
            bool: True if offline mode should be active
        """
        # First check config setting
        if respect_config:
            config_offline = settings.get("scanning.offline_mode", False)
            if config_offline:
                logger.debug("Offline mode active due to config setting")
                return True
        
        # Then check network connectivity
        is_offline, _ = self.check_offline_mode()
        return is_offline


# Global instance
_network_detector: Optional[NetworkDetector] = None

def get_network_detector() -> NetworkDetector:
    """
    Get or create the global network detector instance.
    
    Returns:
        NetworkDetector: Global network detector instance
    """
    global _network_detector
    if _network_detector is None:
        timeout = settings.get("scanning.timeouts.dns", 2.0)
        _network_detector = NetworkDetector(timeout=float(timeout))
    return _network_detector

def check_offline_mode(force_check: bool = False) -> Tuple[bool, Dict[str, Any]]:
    """
    Convenience function to check offline mode.
    
    Args:
        force_check: If True, bypass cache and force a new check
        
    Returns:
        tuple: (is_offline: bool, details: dict)
    """
    detector = get_network_detector()
    return detector.check_offline_mode(force_check=force_check)

def is_offline(respect_config: bool = True) -> bool:
    """
    Convenience function to check if offline mode should be active.
    
    Args:
        respect_config: If True, respect config.yaml offline_mode setting
        
    Returns:
        bool: True if offline mode should be active
    """
    detector = get_network_detector()
    return detector.is_offline(respect_config=respect_config)


