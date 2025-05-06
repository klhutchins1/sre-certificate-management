import logging
from typing import Dict, List, Optional, Set, Tuple


class ScanTracker:
    """
    Tracks scan progress and state for the Infrastructure Management System (IMS).

    This class is responsible for:
    - Tracking which domains and endpoints have been scanned
    - Managing the scan queue
    - Recording discovered IPs and master domain list
    - Providing statistics and status for the scanning process
    - Supporting deduplication and efficient scan orchestration

    Example usage:
        >>> tracker = ScanTracker()
        >>> tracker.add_to_queue('example.com', 443)
        >>> while tracker.has_pending_targets():
        ...     target = tracker.get_next_target()
        ...     # scan target
        ...     tracker.add_scanned_endpoint(*target)
    """
    
    def __init__(self):
        """
        Initialize scan tracking state and logger.
        """
        self.scanned_domains = set()  # Domains that have been scanned
        self.scanned_endpoints = set()  # Domain:port combinations that have been scanned
        self.discovered_ips = {}  # Domain -> List[IP] mapping
        self.scan_queue = set()  # Set of (domain, port) tuples to scan
        self.processed_certificates = set()  # Set of certificate serial numbers that have been processed
        self.master_domain_list = set()  # All known domains
        self.logger = logging.getLogger(__name__)
    
    def reset(self):
        """
        Reset all tracking state to initial empty values.
        """
        self.scanned_domains.clear()
        self.scanned_endpoints.clear()
        self.discovered_ips.clear()
        self.scan_queue.clear()
        self.processed_certificates.clear()
        self.master_domain_list.clear()
        self.logger.info("[TRACKER] Reset all tracking state")
    
    def is_domain_known(self, domain: str) -> bool:
        """
        Check if a domain is in the master list of known domains.
        
        Args:
            domain (str): Domain name
        
        Returns:
            bool: True if domain is known, False otherwise
        """
        return domain in self.master_domain_list
    
    def is_domain_scanned(self, domain: str) -> bool:
        """
        Check if a domain has been scanned.
        
        Args:
            domain (str): Domain name
        
        Returns:
            bool: True if scanned, False otherwise
        """
        return domain in self.scanned_domains
    
    def is_endpoint_scanned(self, host: str, port: int) -> bool:
        """
        Check if a host:port combination has been scanned.
        
        Args:
            host (str): Hostname or IP
            port (int): Port number
        
        Returns:
            bool: True if endpoint has been scanned, False otherwise
        """
        return (host, port) in self.scanned_endpoints
    
    def add_to_master_list(self, domain: str) -> bool:
        """
        Add a domain to the master list if not already present.
        
        Args:
            domain (str): Domain name
        
        Returns:
            bool: True if added, False if already present
        """
        if domain not in self.master_domain_list:
            self.master_domain_list.add(domain)
            self.logger.info(f"[TRACKER] Added new domain to master list: {domain}")
            return True
        return False
    
    def add_scanned_domain(self, domain: str):
        """
        Mark a domain as scanned and ensure it is in the master list.
        
        Args:
            domain (str): Domain name
        """
        if domain not in self.scanned_domains:
            self.add_to_master_list(domain)  # Ensure it's in master list
            self.logger.info(f"[TRACKER] Marking domain as scanned: {domain}")
            self.scanned_domains.add(domain)
    
    def add_scanned_endpoint(self, host: str, port: int):
        """
        Mark a host:port combination as scanned.
        
        Args:
            host (str): Hostname or IP
            port (int): Port number
        """
        if (host, port) not in self.scanned_endpoints:
            self.logger.info(f"[TRACKER] Marking endpoint as scanned: {host}:{port}")
            self.scanned_endpoints.add((host, port))
    
    def add_to_queue(self, domain: str, port: int) -> bool:
        """
        Add a domain:port pair to the scan queue if not already processed.
        
        Args:
            domain (str): Domain name
            port (int): Port number
        
        Returns:
            bool: True if added to queue, False if already scanned or queued
        """
        # First add to master list
        self.add_to_master_list(domain)
        
        # Check if already scanned or queued
        if not self.is_endpoint_scanned(domain, port) and (domain, port) not in self.scan_queue:
            self.scan_queue.add((domain, port))
            self.logger.info(f"[TRACKER] Added to scan queue: {domain}:{port}")
            return True
        return False
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """
        Get the next target from the scan queue.
        
        Returns:
            Optional[Tuple[str, int]]: (domain, port) tuple or None if queue is empty
        """
        try:
            return self.scan_queue.pop()
        except KeyError:
            return None
        except Exception as e:
            self.logger.exception(f"Unexpected error getting next target from scan queue: {str(e)}")
            return None
    
    def has_pending_targets(self) -> bool:
        """
        Check if there are targets waiting to be scanned in the queue.
        
        Returns:
            bool: True if there are pending targets, False otherwise
        """
        return len(self.scan_queue) > 0
    
    def queue_size(self) -> int:
        """
        Get the number of targets in the scan queue.
        
        Returns:
            int: Number of targets in the queue
        """
        return len(self.scan_queue)
    
    def add_discovered_ips(self, domain: str, ips: List[str]):
        """
        Record IPs discovered for a domain.
        
        Args:
            domain (str): Domain name
            ips (List[str]): List of IP addresses
        """
        self.add_to_master_list(domain)  # Ensure domain is in master list
        self.discovered_ips[domain] = ips
        self.logger.info(f"[TRACKER] Recorded IPs for {domain}: {ips}")
    
    def get_pending_domains(self) -> Set[str]:
        """
        Get list of domains waiting to be scanned (in master list but not yet scanned).
        
        Returns:
            Set[str]: Set of pending domains
        """
        pending = self.master_domain_list - self.scanned_domains
        self.logger.info(f"[TRACKER] Current pending domains ({len(pending)}): {sorted(pending)}")
        return pending
    
    def get_discovered_ips(self, domain: str) -> List[str]:
        """
        Get list of IPs discovered for a domain.
        
        Args:
            domain (str): Domain name
        
        Returns:
            List[str]: List of IP addresses
        """
        return self.discovered_ips.get(domain, [])
    
    def get_scan_stats(self) -> Dict:
        """
        Get current scanning statistics.
        
        Returns:
            dict: Dictionary of scan statistics
        """
        return {
            "total_discovered": len(self.master_domain_list),
            "total_scanned": len(self.scanned_domains),
            "pending_count": len(self.master_domain_list - self.scanned_domains),
            "scanned_count": len(self.scanned_domains),
            "endpoints_count": len(self.scanned_endpoints),
            "queue_size": len(self.scan_queue)
        }
    
    def print_status(self):
        """
        Print current scanning status for debugging/logging purposes.
        """
        try:
            stats = self.get_scan_stats()
            self.logger.info("=== Scanner Status ===")
            self.logger.info(f"Total Domains in Master List: {stats['total_discovered']}")
            self.logger.info(f"Total Scanned: {stats['total_scanned']}")
            self.logger.info(f"Pending Domains: {stats['pending_count']}")
            self.logger.info(f"Scanned Domains: {stats['scanned_count']}")
            self.logger.info(f"Scanned Endpoints: {stats['endpoints_count']}")
            self.logger.info(f"Queue Size: {stats['queue_size']}")
            self.logger.info("=== Pending Domains ===")
            for domain in sorted(self.master_domain_list - self.scanned_domains):
                self.logger.info(f"- {domain}")
            self.logger.info("===================")
        except Exception as e:
            self.logger.exception(f"Unexpected error printing scan tracker status: {str(e)}")
    
    def is_certificate_processed(self, serial_number: str) -> bool:
        """
        Check if a certificate has already been processed.
        
        Args:
            serial_number (str): Certificate serial number
        
        Returns:
            bool: True if processed, False otherwise
        """
        return serial_number in self.processed_certificates
    
    def add_processed_certificate(self, serial_number: str):
        """
        Mark a certificate as processed.
        
        Args:
            serial_number (str): Certificate serial number
        """
        self.processed_certificates.add(serial_number)
        self.logger.info(f"[TRACKER] Marked certificate as processed: {serial_number}")

