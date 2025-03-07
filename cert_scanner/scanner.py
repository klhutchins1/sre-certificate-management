"""
Scanner module for the Certificate Management System.

This module provides the central scanning coordination and tracking functionality,
including:
- Scan queue management
- Domain tracking
- Progress monitoring
- Result aggregation
"""

import logging
from typing import Optional, List, Dict, Set, Tuple
from urllib.parse import urlparse

from .settings import settings
from .domain_scanner import DomainScanner
from .subdomain_scanner import SubdomainScanner
from .models import IgnoredDomain

# Import CertificateScanner lazily to avoid circular imports
CertificateScanner = None

#------------------------------------------------------------------------------
# Domain Configuration
#------------------------------------------------------------------------------

# Common internal TLDs and subdomains
# Used for automatic domain classification when not explicitly configured
INTERNAL_TLDS = {
    '.local', '.lan', '.internal', '.intranet', '.corp', '.private',
    '.test', '.example', '.invalid', '.localhost'
}

# Common external TLDs
# Used for automatic domain classification when not explicitly configured
EXTERNAL_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.io', '.co', '.biz', '.info', '.name', '.mobi', '.app',
    '.cloud', '.dev', '.ai'
}

#------------------------------------------------------------------------------
# Scan Tracking
#------------------------------------------------------------------------------

class ScanTracker:
    """Centralized tracking for domain scanning operations."""
    
    def __init__(self):
        """Initialize the scan tracker."""
        self.reset()
        self.logger = logging.getLogger(__name__)
    
    def reset(self):
        """Reset all tracking data."""
        self.master_domain_list = set()  # Master list of all domains discovered
        self.scanned_domains = set()  # Domains already scanned
        self.pending_domains = set()  # Domains discovered but not yet scanned
        self.scanned_endpoints = set()  # (host, port) combinations already scanned
        self.discovered_ips = {}  # Map of domain to list of IPs
        self.scan_history = []  # List of all scan operations in order
        self.total_discovered = 0  # Total number of domains discovered
        self.total_scanned = 0  # Total number of domains scanned
        self.scan_queue = set()  # Queue of (domain, port) pairs to scan
    
    def is_domain_known(self, domain: str) -> bool:
        """Check if a domain is in our master list."""
        return domain in self.master_domain_list
    
    def is_domain_scanned(self, domain: str) -> bool:
        """Check if a domain has been scanned."""
        return domain in self.scanned_domains
    
    def is_endpoint_scanned(self, host: str, port: int) -> bool:
        """Check if a host:port combination has been scanned."""
        return (host, port) in self.scanned_endpoints
    
    def add_to_master_list(self, domain: str) -> bool:
        """Add a domain to the master list if not already present."""
        if domain not in self.master_domain_list:
            self.master_domain_list.add(domain)
            self.total_discovered += 1
            self.logger.info(f"[TRACKER] Added new domain to master list: {domain}")
            return True
        return False
    
    def add_scanned_domain(self, domain: str):
        """Mark a domain as scanned."""
        if domain not in self.scanned_domains:
            self.add_to_master_list(domain)  # Ensure it's in master list
            self.logger.info(f"[TRACKER] Marking domain as scanned: {domain}")
            self.scanned_domains.add(domain)
            self.total_scanned += 1
            self.scan_history.append({"action": "scanned", "domain": domain})
        if domain in self.pending_domains:
            self.logger.info(f"[TRACKER] Removing {domain} from pending list")
            self.pending_domains.remove(domain)
    
    def add_scanned_endpoint(self, host: str, port: int):
        """Mark a host:port combination as scanned."""
        if (host, port) not in self.scanned_endpoints:
            self.logger.info(f"[TRACKER] Marking endpoint as scanned: {host}:{port}")
            self.scanned_endpoints.add((host, port))
            self.scan_history.append({"action": "scanned_endpoint", "host": host, "port": port})
    
    def add_to_queue(self, domain: str, port: int) -> bool:
        """Add a domain:port pair to the scan queue if not already processed."""
        # First add to master list
        self.add_to_master_list(domain)
        
        # Check if already scanned or queued
        if not self.is_endpoint_scanned(domain, port) and (domain, port) not in self.scan_queue:
            self.scan_queue.add((domain, port))
            self.logger.info(f"[TRACKER] Added to scan queue: {domain}:{port}")
            return True
        return False
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """Get the next target from the queue."""
        try:
            return self.scan_queue.pop()
        except KeyError:
            return None
    
    def has_pending_targets(self) -> bool:
        """Check if there are targets waiting to be scanned."""
        return len(self.scan_queue) > 0
    
    def queue_size(self) -> int:
        """Get the number of targets in the queue."""
        return len(self.scan_queue)
    
    def add_discovered_ips(self, domain: str, ips: List[str]):
        """Record IPs discovered for a domain."""
        self.add_to_master_list(domain)  # Ensure domain is in master list
        self.discovered_ips[domain] = ips
        self.logger.info(f"[TRACKER] Recorded IPs for {domain}: {ips}")
        self.scan_history.append({"action": "discovered_ips", "domain": domain, "ips": ips})
    
    def get_pending_domains(self) -> Set[str]:
        """Get list of domains waiting to be scanned."""
        pending = self.pending_domains.copy()  # Create a copy to avoid modification during iteration
        self.logger.info(f"[TRACKER] Current pending domains ({len(pending)}): {sorted(pending)}")
        return pending
    
    def get_discovered_ips(self, domain: str) -> List[str]:
        """Get list of IPs discovered for a domain."""
        return self.discovered_ips.get(domain, [])
    
    def get_scan_stats(self) -> Dict:
        """Get current scanning statistics."""
        return {
            "total_discovered": len(self.master_domain_list),
            "total_scanned": len(self.scanned_domains),
            "pending_count": len(self.pending_domains),
            "scanned_count": len(self.scanned_domains),
            "endpoints_count": len(self.scanned_endpoints),
            "queue_size": len(self.scan_queue)
        }
    
    def print_status(self):
        """Print current scanning status for debugging."""
        stats = self.get_scan_stats()
        self.logger.info("=== Scanner Status ===")
        self.logger.info(f"Total Domains in Master List: {stats['total_discovered']}")
        self.logger.info(f"Total Scanned: {stats['total_scanned']}")
        self.logger.info(f"Pending Domains: {stats['pending_count']}")
        self.logger.info(f"Scanned Domains: {stats['scanned_count']}")
        self.logger.info(f"Scanned Endpoints: {stats['endpoints_count']}")
        self.logger.info(f"Queue Size: {stats['queue_size']}")
        self.logger.info("=== Pending Domains ===")
        for domain in sorted(self.pending_domains):
            self.logger.info(f"- {domain}")
        self.logger.info("===================")

class ScanManager:
    """
    Centralized manager for scanning operations.
    
    This class coordinates between different scanners and manages:
    - Target validation and processing
    - Scan queue management
    - Progress tracking
    - Result aggregation
    """
    
    def __init__(self):
        """Initialize scan manager with required scanners."""
        # Import CertificateScanner lazily to avoid circular imports
        global CertificateScanner
        if CertificateScanner is None:
            from .certificate_scanner import CertificateScanner
        
        self.cert_scanner = CertificateScanner()
        self.domain_scanner = DomainScanner()
        self.subdomain_scanner = SubdomainScanner()
        
        # Share tracker between scanners
        self.subdomain_scanner.tracker = self.cert_scanner.tracker
        
        # Initialize scan state
        self.scan_history = set()
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": []
        }
        
        self.logger = logging.getLogger(__name__)
    
    def reset_scan_state(self):
        """Reset scan state for a new scan session."""
        self.cert_scanner.reset_scan_state()
        self.scan_history.clear()
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": []
        }
    
    def process_scan_target(self, target: str) -> tuple:
        """
        Process and validate a scan target.
        
        Args:
            target: Raw target string (domain, URL, or domain:port)
            
        Returns:
            tuple: (is_valid, hostname, port, error_message)
        """
        try:
            # Check if target is empty
            if not target.strip():
                return False, None, None, "Empty target"
            
            # Parse target
            has_scheme = target.startswith(('http://', 'https://'))
            
            if has_scheme:
                parsed = urlparse(target)
                hostname = parsed.netloc
                if ':' in hostname:
                    hostname, port_str = hostname.rsplit(':', 1)
                    try:
                        port = int(port_str)
                        if port < 1 or port > 65535:
                            return False, None, None, f"Invalid port number: {port}"
                    except ValueError:
                        return False, None, None, f"Invalid port format: {port_str}"
                elif parsed.port:
                    port = parsed.port
                else:
                    port = 443
            else:
                if ':' in target:
                    hostname, port_str = target.rsplit(':', 1)
                    try:
                        port = int(port_str)
                        if port < 1 or port > 65535:
                            return False, None, None, f"Invalid port number: {port}"
                    except ValueError:
                        return False, None, None, f"Invalid port format: {port_str}"
                else:
                    hostname = target
                    port = 443
            
            # Clean up hostname
            hostname = hostname.strip('/')
            if not hostname:
                return False, None, None, "Empty hostname"
            
            # Basic domain validation
            if not self.domain_scanner._validate_domain(hostname):
                return False, None, None, f"Invalid domain format: {hostname}"
            
            return True, hostname, port, None
            
        except Exception as e:
            return False, None, None, str(e)
    
    def add_to_queue(self, hostname: str, port: int) -> bool:
        """
        Add target to scan queue if not already processed.
        
        Args:
            hostname: Domain to scan
            port: Port to scan
            
        Returns:
            bool: True if target was added, False if already scanned
        """
        if hostname in self.scan_history:
            self.scan_results["warning"].append(f"{hostname}:{port} - Skipped (already scanned)")
            return False
        
        if self.cert_scanner.add_scan_target(hostname, port):
            self.scan_history.add(hostname)
            self.logger.info(f"[SCAN] Added target to queue: {hostname}:{port}")
            return True
        
        return False
    
    def get_scan_stats(self) -> dict:
        """Get current scanning statistics."""
        stats = self.cert_scanner.get_scan_stats()
        stats.update({
            "scan_history_size": len(self.scan_history),
            "success_count": len(self.scan_results["success"]),
            "error_count": len(self.scan_results["error"]),
            "warning_count": len(self.scan_results["warning"])
        })
        return stats
    
    def has_pending_targets(self) -> bool:
        """Check if there are targets waiting to be scanned."""
        return self.cert_scanner.has_pending_targets()
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """Get the next target from the queue."""
        return self.cert_scanner.get_next_target() 