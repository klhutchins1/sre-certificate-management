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
from typing import Optional, List, Dict, Set, Tuple, Any
from urllib.parse import urlparse
from datetime import datetime
import json
from sqlalchemy.orm import Session

from .settings import settings
from .domain_scanner import DomainScanner, DomainInfo
from .subdomain_scanner import SubdomainScanner
from .models import IgnoredDomain, Domain, DomainDNSRecord, Certificate, Host, HostIP, CertificateBinding, CertificateScan, HOST_TYPE_SERVER, HOST_TYPE_CDN, HOST_TYPE_LOAD_BALANCER, ENV_PRODUCTION, IgnoredCertificate
from .constants import PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION
from .certificate_scanner import CertificateInfo

# Import CertificateScanner and CertificateInfo lazily to avoid circular imports
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
    """Track scan progress and state."""
    
    def __init__(self):
        """Initialize scan tracking state."""
        self.scanned_domains = set()  # Domains that have been scanned
        self.scanned_endpoints = set()  # Domain:port combinations that have been scanned
        self.discovered_ips = {}  # Domain -> List[IP] mapping
        self.scan_queue = set()  # Set of (domain, port) tuples to scan
        self.processed_certificates = set()  # Set of certificate serial numbers that have been processed
        self.master_domain_list = set()  # All known domains
        self.logger = logging.getLogger(__name__)
    
    def reset(self):
        """Reset all tracking state."""
        self.scanned_domains.clear()
        self.scanned_endpoints.clear()
        self.discovered_ips.clear()
        self.scan_queue.clear()
        self.processed_certificates.clear()
        self.master_domain_list.clear()
        self.logger.info("[TRACKER] Reset all tracking state")
    
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
            self.logger.info(f"[TRACKER] Added new domain to master list: {domain}")
            return True
        return False
    
    def add_scanned_domain(self, domain: str):
        """Mark a domain as scanned."""
        if domain not in self.scanned_domains:
            self.add_to_master_list(domain)  # Ensure it's in master list
            self.logger.info(f"[TRACKER] Marking domain as scanned: {domain}")
            self.scanned_domains.add(domain)
    
    def add_scanned_endpoint(self, host: str, port: int):
        """Mark a host:port combination as scanned."""
        if (host, port) not in self.scanned_endpoints:
            self.logger.info(f"[TRACKER] Marking endpoint as scanned: {host}:{port}")
            self.scanned_endpoints.add((host, port))
    
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
    
    def get_pending_domains(self) -> Set[str]:
        """Get list of domains waiting to be scanned."""
        pending = self.master_domain_list - self.scanned_domains
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
            "pending_count": len(self.master_domain_list - self.scanned_domains),
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
        for domain in sorted(self.master_domain_list - self.scanned_domains):
            self.logger.info(f"- {domain}")
        self.logger.info("===================")
    
    def is_certificate_processed(self, serial_number: str) -> bool:
        """Check if a certificate has already been processed."""
        return serial_number in self.processed_certificates
    
    def add_processed_certificate(self, serial_number: str):
        """Mark a certificate as processed."""
        self.processed_certificates.add(serial_number)
        self.logger.info(f"[TRACKER] Marked certificate as processed: {serial_number}")

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
        
        self.infra_mgmt = CertificateScanner()
        self.domain_scanner = DomainScanner()
        self.subdomain_scanner = SubdomainScanner()
        
        # Share tracker between scanners
        self.subdomain_scanner.tracker = self.infra_mgmt.tracker
        
        # Initialize scan state
        self.scan_history = []  # Changed from set() to [] since we want to maintain order
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": []  # Add no_cert category
        }
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize processor as None - will be set when needed
        self.processor = None
    
    def reset_scan_state(self):
        """Reset scan state for a new scan session."""
        self.infra_mgmt.reset_scan_state()
        self.scan_history.clear()  # Clear scan history for new session
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": []  # Add no_cert category
        }
    
    def process_scan_target(self, target: str, session: Session = None) -> tuple:
        """
        Process and validate a scan target.
        
        Args:
            target: Raw target string (domain, URL, or domain:port)
            session: Optional database session for domain ignore list checks
            
        Returns:
            tuple: (is_valid, hostname, port, error_message)
        """
        try:
            # Check if target is empty
            if not target.strip():
                return False, None, None, "Empty target"
            
            # Initialize result tracking
            result = {
                "target": target,
                "status": "success",
                "details": {},
                "errors": [],
                "warnings": []
            }
            
            # Parse the target
            if '://' in target:
                # URL format
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or 443
            else:
                # domain:port or just domain format
                parts = target.split(':')
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443
            
            # Validate hostname - allow both domains and IP addresses
            if not hostname:
                result["status"] = "error"
                result["errors"].append("Invalid hostname")
                self.scan_results["error"].append(result)
                self.scan_history.append(result)
                return False, None, None, "Invalid hostname"
            
            # Check if it's an IP address
            import ipaddress
            try:
                # Try to parse as IP address
                ipaddress.ip_address(hostname)
                # If we get here, it's a valid IP address
                is_ip = True
            except ValueError:
                # Not an IP address, treat as domain
                is_ip = False
            
            # Validate port
            if not (1 <= port <= 65535):
                result["status"] = "error"
                result["errors"].append(f"Invalid port number: {port}")
                self.scan_results["error"].append(result)
                self.scan_history.append(result)
                return False, None, None, f"Invalid port number: {port}"
            
            # Add to scan history
            result["details"]["hostname"] = hostname
            result["details"]["port"] = port
            result["details"]["is_ip"] = is_ip
            
            # Check if domain is in ignore list if session is provided and it's not an IP
            if session and not is_ip:
                is_ignored, reason = self._is_domain_ignored(session, hostname)
                if is_ignored:
                    result["status"] = "warning"
                    result["warnings"].append(f"Domain is in ignore list: {reason}")
                    self.scan_results["warning"].append(result)
                    self.scan_history.append(result)
                    return False, None, None, f"Domain is in ignore list: {reason}"
            
            # Add to scan history and results
            self.scan_history.append(result)
            self.scan_results["success"].append(result)
            
            return True, hostname, port, None
            
        except Exception as e:
            error_msg = f"Error processing scan target {target}: {str(e)}"
            self.logger.error(error_msg)
            result = {
                "target": target,
                "status": "error",
                "errors": [error_msg],
                "details": {}
            }
            self.scan_results["error"].append(result)
            self.scan_history.append(result)
            return False, None, None, error_msg
    
    def _is_domain_ignored(self, session: Session, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a domain is in the ignore list.
        
        Args:
            session: Database session
            domain: Domain to check
            
        Returns:
            Tuple[bool, Optional[str]]: (is_ignored, reason)
        """
        try:
            # Get ignore patterns from database
            ignore_patterns = session.query(IgnoredDomain).all()
            
            # Check each pattern
            for pattern in ignore_patterns:
                pattern_str = pattern.pattern
                
                # Handle wildcard prefix (e.g., *.example.com)
                if pattern_str.startswith('*.'):
                    base_domain = pattern_str[2:]  # Remove '*.'
                    if domain.endswith(base_domain):
                        return True, pattern.reason
                        
                # Handle suffix match (e.g., example.com)
                elif pattern_str.startswith('.'):
                    if domain.endswith(pattern_str):
                        return True, pattern.reason
                        
                # Handle exact match
                elif pattern_str == domain:
                    return True, pattern.reason
                    
                # Handle contains pattern (e.g., *test*)
                elif '*' in pattern_str:
                    parts = pattern_str.split('*')
                    if len(parts) == 2:  # Only handle single wildcard patterns
                        if parts[0] in domain and parts[1] in domain:
                            return True, pattern.reason
            
            return False, None
            
        except Exception as e:
            self.logger.error(f"Error checking ignore list for domain {domain}: {str(e)}")
            return False, None

    def _is_certificate_ignored(self, session: Session, common_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a certificate should be ignored based on its Common Name.
        
        Args:
            session: Database session
            common_name: Certificate Common Name to check
            
        Returns:
            Tuple[bool, Optional[str]]: (is_ignored, reason)
        """
        try:
            # First check exact matches
            ignored = session.query(IgnoredCertificate).filter_by(pattern=common_name).first()
            if ignored:
                return True, ignored.reason
            
            # Then check patterns
            patterns = session.query(IgnoredCertificate).all()
            for pattern in patterns:
                if pattern.matches(common_name):
                    return True, pattern.reason
            
            return False, None
            
        except Exception as e:
            self.logger.error(f"Error checking certificate ignore list for {common_name}: {str(e)}")
            return False, None
    
    def add_to_queue(self, hostname: str, port: int) -> bool:
        """
        Add target to scan queue if not already processed.
        
        Args:
            hostname: Domain to scan
            port: Port to scan
            
        Returns:
            bool: True if target was added, False if already scanned
        """
        # Create a session to check ignore lists
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session
        from .settings import settings
        
        db_path = settings.get("paths.database", "data/certificates.db")
        engine = create_engine(f"sqlite:///{db_path}")
        session = Session(engine)
        
        try:
            # First check if already scanned to avoid unnecessary DB queries
            if self.infra_mgmt.tracker.is_endpoint_scanned(hostname, port):
                self.logger.info(f"[SCAN] Skipping {hostname}:{port} - Already scanned in this scan session")
                self.scan_results["warning"].append(f"{hostname}:{port} - Skipped (already scanned in this scan session)")
                return False

            # Check if domain is ignored using all pattern types
            is_ignored = False
            ignore_reason = None
            
            # Get all ignore patterns at once to minimize DB queries
            patterns = session.query(IgnoredDomain).all()
            
            # First check exact matches
            for pattern in patterns:
                if pattern.pattern == hostname:
                    is_ignored = True
                    ignore_reason = pattern.reason
                    break
                    
                # Handle wildcard prefix (*.example.com)
                if pattern.pattern.startswith('*.'):
                    suffix = pattern.pattern[2:]  # Remove *. from pattern
                    if hostname.endswith(suffix):
                        is_ignored = True
                        ignore_reason = pattern.reason
                        break
                        
                # Handle suffix match (example.com)
                elif hostname.endswith(pattern.pattern):
                    is_ignored = True
                    ignore_reason = pattern.reason
                    break
                    
                # Handle contains pattern (*test*)
                elif pattern.pattern.startswith('*') and pattern.pattern.endswith('*'):
                    search_term = pattern.pattern.strip('*')
                    if search_term in hostname:
                        is_ignored = True
                        ignore_reason = pattern.reason
                        break
            
            if is_ignored:
                self.logger.info(f"[SCAN] Skipping {hostname} - Domain is in ignore list" + 
                               (f" ({ignore_reason})" if ignore_reason else ""))
                self.scan_results["warning"].append(f"{hostname}:{port} - Skipped (domain in ignore list)")
                # Mark as scanned to prevent re-scanning attempts
                self.infra_mgmt.tracker.add_scanned_domain(hostname)
                self.infra_mgmt.tracker.add_scanned_endpoint(hostname, port)
                return False
            
            # If not ignored and not already scanned, add to queue
            if self.infra_mgmt.add_scan_target(hostname, port):
                self.scan_history.append(hostname)
                self.logger.info(f"[SCAN] Added target to queue: {hostname}:{port}")
                return True
            
            return False
            
        finally:
            session.close()
            engine.dispose()
    
    def scan_target(self, session, domain: str, port: int, check_whois: bool = True, 
                   check_dns: bool = True, check_subdomains: bool = True,
                   check_sans: bool = False, detect_platform: bool = True, validate_chain: bool = True,
                   status_container=None, progress_container=None, current_step=None, total_steps=None) -> bool:
        """
        Scan a single target and process results.
        
        Args:
            session: Database session
            domain: Domain to scan
            port: Port to scan
            check_whois: Whether to check WHOIS information
            check_dns: Whether to check DNS records
            check_subdomains: Whether to check for subdomains
            check_sans: Whether to scan Subject Alternative Names
            detect_platform: Whether to detect platform (F5, Akamai, etc.)
            validate_chain: Whether to validate certificate chain
            status_container: Optional container for status updates
            progress_container: Optional container for progress updates
            current_step: Current step number for progress tracking
            total_steps: Total number of steps for progress tracking
        """
        try:
            # Initialize result tracking
            result = {
                "target": f"{domain}:{port}",
                "status": "success",
                "details": {},
                "errors": [],
                "warnings": [],
                "no_cert": False
            }
            
            # Check if domain is in ignore list BEFORE any scanning
            is_ignored, reason = self._is_domain_ignored(session, domain)
            if is_ignored:
                result["status"] = "warning"
                result["warnings"].append(f"Domain is in ignore list: {reason}")
                self.scan_results["warning"].append(result)
                self.scan_history.append(result)
                return True

            def calculate_progress(sub_step: int, total_sub_steps: int) -> float:
                """Calculate overall progress including sub-steps."""
                if current_step is None or total_steps is None:
                    return 0.0
                
                # Calculate base progress for completed steps
                base_progress = (current_step - 1) / total_steps
                
                # Calculate progress for current step
                step_progress = (sub_step / total_sub_steps) / total_steps
                
                return min(base_progress + step_progress, 1.0)

            def update_progress(sub_step: int, total_sub_steps: int):
                """Update progress bar and queue status."""
                if progress_container and current_step is not None and total_steps is not None:
                    progress = calculate_progress(sub_step, total_sub_steps)
                    progress_container.progress(progress)
                    progress_container.text(f"Remaining targets in queue: {self.infra_mgmt.tracker.queue_size()}")

            # Calculate total sub-steps
            total_sub_steps = 1
            if check_whois or check_dns:
                total_sub_steps += 1  # Domain info gathering
                if check_dns:
                    total_sub_steps += 1  # DNS processing
            total_sub_steps += 2  # Certificate scanning and processing
            if check_subdomains:
                total_sub_steps += 1  # Subdomain processing
            if check_sans:
                total_sub_steps += 1  # SAN processing
            if detect_platform:
                total_sub_steps += 1  # Platform detection
            
            current_sub_step = 0
            
            # Initialize processor if needed
            if not self.processor:
                self.processor = ScanProcessor(session, status_container)
            else:
                self.processor.session = session
                self.processor.status_container = status_container
            
            # Skip if already scanned in this scan session
            if self.infra_mgmt.tracker.is_endpoint_scanned(domain, port):
                result["status"] = "warning"
                result["warnings"].append(f"Already scanned in this scan session")
                self.scan_results["warning"].append(result)
                self.scan_history.append(result)
                update_progress(total_sub_steps, total_sub_steps)  # Complete progress for skipped domain
                return True
            
            current_sub_step += 1
            update_progress(current_sub_step, total_sub_steps)
            
            # Get domain information first
            domain_info = None
            if check_whois or check_dns:
                try:
                    if status_container:
                        status_container.text(f'Gathering domain information for {domain}...')
                    
                    self.logger.info(f"[SCAN] Domain info gathering for {domain} - WHOIS: {'enabled' if check_whois else 'disabled'}, DNS: {'enabled' if check_dns else 'disabled'}")
                    domain_info = self.domain_scanner.scan_domain(
                        domain,
                        get_whois=check_whois,
                        get_dns=check_dns
                    )
                    current_sub_step += 1
                    update_progress(current_sub_step, total_sub_steps)
                    
                    # Add related domains to scan queue
                    if domain_info and domain_info.related_domains:
                        for related_domain in domain_info.related_domains:
                            if not self.infra_mgmt.tracker.is_endpoint_scanned(related_domain, port):
                                self.infra_mgmt.tracker.add_to_queue(related_domain, port)
                                self.logger.info(f"[SCAN] Added related domain to scan queue: {related_domain}:{port}")
                
                except Exception as e:
                    self.logger.error(f"[SCAN] Error gathering domain info for {domain}: {str(e)}")
                    result["errors"].append(f"Error gathering domain info: {str(e)}")
                    result["status"] = "error"
            
            # Process domain information
            try:
                if status_container:
                    status_container.text(f'Processing domain information for {domain}...')
                
                domain_obj = self.processor.process_domain_info(domain, domain_info)
                
                # Process DNS records if available
                if check_dns and domain_info and domain_info.dns_records:
                    if status_container:
                        status_container.text(f'Processing DNS records for {domain}...')
                    
                    self.processor.process_dns_records(
                        domain_obj,
                        domain_info.dns_records,
                        self.infra_mgmt.tracker.scan_queue,
                        port
                    )
                    current_sub_step += 1
                    update_progress(current_sub_step, total_sub_steps)
                
                session.commit()
                self.logger.info(f"[SCAN] Domain information updated for {domain}")
                
            except Exception as e:
                self.logger.error(f"[SCAN] Error processing domain info for {domain}: {str(e)}")
                session.rollback()
                result["errors"].append(f"Error processing domain info: {str(e)}")
                result["status"] = "error"
            
            # Now scan for certificates
            if status_container:
                status_container.text(f'Scanning certificates for {domain}:{port}...')
            scan_result = self.infra_mgmt.scan_certificate(domain, port)
            
            if scan_result and scan_result.certificate_info:
                cert_info = scan_result.certificate_info
                try:
                    # Process certificate
                    cert = session.query(Certificate).filter_by(
                        serial_number=cert_info.serial_number
                    ).first()
                    
                    if not cert:
                        if status_container:
                            status_container.text(f'Found new certificate for {domain}...')
                        cert = Certificate(
                            serial_number=cert_info.serial_number,
                            thumbprint=cert_info.thumbprint,
                            common_name=cert_info.common_name,
                            valid_from=cert_info.valid_from,
                            valid_until=cert_info.expiration_date,
                            _issuer=json.dumps(cert_info.issuer),
                            _subject=json.dumps(cert_info.subject),
                            _san=json.dumps(cert_info.san),
                            key_usage=json.dumps(cert_info.key_usage) if cert_info.key_usage else None,
                            signature_algorithm=cert_info.signature_algorithm,
                            chain_valid=validate_chain and cert_info.chain_valid,
                            sans_scanned=check_sans,
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        session.add(cert)
                    else:
                        if status_container:
                            status_container.text(f'Updating existing certificate for {domain}...')
                        cert.thumbprint = cert_info.thumbprint
                        cert.common_name = cert_info.common_name
                        cert.valid_from = cert_info.valid_from
                        cert.valid_until = cert_info.expiration_date
                        cert._issuer = json.dumps(cert_info.issuer)
                        cert._subject = json.dumps(cert_info.subject)
                        cert._san = json.dumps(cert_info.san)
                        cert.key_usage = json.dumps(cert_info.key_usage) if cert_info.key_usage else None
                        cert.signature_algorithm = cert_info.signature_algorithm
                        cert.chain_valid = validate_chain and cert_info.chain_valid
                        cert.sans_scanned = check_sans
                        cert.updated_at = datetime.now()
                    
                    # Associate certificate with domain
                    if cert not in domain_obj.certificates:
                        domain_obj.certificates.append(cert)
                    
                    # Create host record
                    host = session.query(Host).filter_by(name=domain).first()
                    if not host:
                        if status_container:
                            status_container.text(f'Creating host record for {domain}...')
                        host = Host(
                            name=domain,
                            host_type=HOST_TYPE_SERVER,  # Will be updated if platform detection is enabled
                            environment=ENV_PRODUCTION,
                            last_seen=datetime.now()
                        )
                        session.add(host)
                    else:
                        host.last_seen = datetime.now()
                    
                    # Update host type based on platform if enabled
                    if detect_platform and cert_info.platform:
                        if cert_info.platform in [PLATFORM_CLOUDFLARE, PLATFORM_AKAMAI]:
                            host.host_type = HOST_TYPE_CDN
                        elif cert_info.platform == PLATFORM_F5:
                            host.host_type = HOST_TYPE_LOAD_BALANCER
                        current_sub_step += 1
                        update_progress(current_sub_step, total_sub_steps)
                    
                    # Create or update IP addresses
                    if cert_info.ip_addresses:
                        if status_container:
                            status_container.text(f'Updating IP addresses for {domain}...')
                        self.infra_mgmt.tracker.add_discovered_ips(domain, cert_info.ip_addresses)
                        existing_ips = {ip.ip_address for ip in host.ip_addresses}
                        for ip_addr in cert_info.ip_addresses:
                            if ip_addr not in existing_ips:
                                host_ip = HostIP(
                                    host=host,
                                    ip_address=ip_addr,
                                    is_active=True,
                                    last_seen=datetime.now()
                                )
                                session.add(host_ip)
                            else:
                                # Update last_seen for existing IP
                                for ip in host.ip_addresses:
                                    if ip.ip_address == ip_addr:
                                        ip.last_seen = datetime.now()
                                        ip.is_active = True
                    
                    # Create certificate binding
                    host_ip = None
                    if cert_info.ip_addresses:
                        for ip in host.ip_addresses:
                            if ip.ip_address in cert_info.ip_addresses:
                                host_ip = ip
                                break
                    
                    binding = session.query(CertificateBinding).filter_by(
                        host=host,
                        host_ip=host_ip,
                        port=port
                    ).first()
                    
                    if not binding:
                        if status_container:
                            status_container.text(f'Creating certificate binding for {domain}:{port}...')
                        binding = CertificateBinding(
                            host=host,
                            host_ip=host_ip,
                            certificate=cert,
                            port=port,
                            binding_type='IP',
                            platform=cert_info.platform if detect_platform else None,
                            last_seen=datetime.now(),
                            manually_added=False
                        )
                        session.add(binding)
                    else:
                        binding.certificate = cert
                        binding.last_seen = datetime.now()
                        if detect_platform:
                            binding.platform = cert_info.platform
                    
                    # Create scan history record
                    scan_record = CertificateScan(
                        certificate=cert,
                        host=host,
                        scan_date=datetime.now(),
                        status="Success",
                        port=port
                    )
                    session.add(scan_record)
                    
                    session.commit()
                    self.logger.info(f"[SCAN] Successfully processed certificate for {domain}:{port}")
                    
                    # Update success state
                    self.scan_results["success"].append(result)
                    
                except Exception as cert_error:
                    self.logger.error(f"[SCAN] Error processing certificate for {domain}:{port}: {str(cert_error)}")
                    session.rollback()
                    result["errors"].append(f"Error processing certificate: {str(cert_error)}")
                    result["status"] = "error"
            else:
                self.logger.error(f"[SCAN] No certificate found or error for {domain}:{port}")
                if scan_result and scan_result.error:
                    result["errors"].append(scan_result.error)
                    result["status"] = "error"
                else:
                    result["no_cert"] = True
                    result["status"] = "warning"
                    result["warnings"].append("No certificate found")
            
            # Process subdomains if requested
            if check_subdomains:
                try:
                    if status_container:
                        status_container.text(f'Discovering subdomains for {domain}...')
                    
                    self.subdomain_scanner.set_status_container(status_container)
                    
                    subdomain_results = self.subdomain_scanner.scan_and_process_subdomains(
                        domain=domain,
                        port=port,
                        check_whois=check_whois,
                        check_dns=check_dns,
                        scanned_domains=self.infra_mgmt.tracker.scanned_domains
                    )
                    
                    if subdomain_results:
                        self.logger.info(f"[SCAN] Found {len(subdomain_results)} subdomains for {domain}")
                        
                        for result in subdomain_results:
                            subdomain = result['domain']
                            if not self.infra_mgmt.tracker.is_endpoint_scanned(subdomain, port):
                                self.infra_mgmt.tracker.add_to_queue(subdomain, port)
                                self.logger.info(f"[SCAN] Added subdomain to queue: {subdomain}:{port}")
                    
                    current_sub_step += 1
                    update_progress(current_sub_step, total_sub_steps)
                    
                    self.subdomain_scanner.set_status_container(None)
                    
                except Exception as subdomain_error:
                    self.logger.error(f"[SCAN] Error in subdomain scanning for {domain}: {str(subdomain_error)}")
                    result["errors"].append(f"Error in subdomain scanning: {str(subdomain_error)}")
                    result["status"] = "error"
                    self.subdomain_scanner.set_status_container(None)
            
            # Update final status and add to appropriate result category
            if result["status"] == "error":
                self.scan_results["error"].append(result)
            elif result["status"] == "warning":
                self.scan_results["warning"].append(result)
            elif result["no_cert"]:
                self.scan_results["no_cert"].append(result)
            else:
                self.scan_results["success"].append(result)
            
            # Add to scan history
            self.scan_history.append(result)
            
            return True
            
        except Exception as e:
            self.logger.error(f"[SCAN] Error processing {domain}:{port}: {str(e)}")
            result = {
                "target": f"{domain}:{port}",
                "status": "error",
                "errors": [str(e)],
                "details": {}
            }
            self.scan_results["error"].append(result)
            self.scan_history.append(result)
            return False
    
    def get_scan_stats(self) -> dict:
        """Get current scanning statistics."""
        stats = self.infra_mgmt.get_scan_stats()
        stats.update({
            "scan_history_size": len(self.scan_history),
            "success_count": len(self.scan_results["success"]),
            "error_count": len(self.scan_results["error"]),
            "warning_count": len(self.scan_results["warning"]),
            "no_cert_count": len(self.scan_results["no_cert"])
        })
        return stats
    
    def has_pending_targets(self) -> bool:
        """Check if there are targets waiting to be scanned."""
        return self.infra_mgmt.has_pending_targets()
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """Get the next target from the queue."""
        return self.infra_mgmt.get_next_target()

class ScanProcessor:
    """
    Handles the processing and storage of scan results.
    
    This class is responsible for:
    - Creating and updating domain records
    - Processing and storing certificates
    - Managing DNS records
    - Creating and updating host records
    - Managing certificate bindings
    """
    
    def __init__(self, session: Session, status_container: Optional[Any] = None):
        """Initialize scan processor."""
        self.session = session
        self.status_container = status_container
        self.logger = logging.getLogger(__name__)
    
    def set_status(self, message: str) -> None:
        """Update status if container is available."""
        if self.status_container:
            self.status_container.text(message)
    
    def process_domain_info(self, domain: str, domain_info: Optional[DomainInfo]) -> Domain:
        """Process domain information and update database."""
        try:
            # Get or create domain
            domain_obj = self.session.query(Domain).filter_by(domain_name=domain).first()
            if not domain_obj:
                self.set_status(f'Creating new domain record for {domain}...')
                domain_obj = Domain(
                    domain_name=domain,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                self.session.add(domain_obj)
            else:
                self.set_status(f'Updating existing domain record for {domain}...')
                domain_obj.updated_at = datetime.now()
            
            # Update domain information
            if domain_info:
                if domain_info.registrar:
                    domain_obj.registrar = domain_info.registrar
                if domain_info.registration_date:
                    domain_obj.registration_date = domain_info.registration_date
                if domain_info.expiration_date:
                    domain_obj.expiration_date = domain_info.expiration_date
                if domain_info.registrant:
                    domain_obj.owner = domain_info.registrant
            
            return domain_obj
            
        except Exception as e:
            self.logger.error(f"Error processing domain info for {domain}: {str(e)}")
            raise
    
    def process_dns_records(self, domain_obj: Domain, dns_records: List[Dict[str, Any]], scan_queue: Optional[Set[Tuple[str, int]]] = None, port: int = 443) -> None:
        """Process DNS records and update database."""
        try:
            if not dns_records:
                return
                
            self.set_status(f'Updating DNS records for {domain_obj.domain_name}...')
            self.logger.info(f"[DNS] Processing {len(dns_records)} DNS records for {domain_obj.domain_name}")
            
            with self.session.no_autoflush:
                # Get existing DNS records
                existing_records = self.session.query(DomainDNSRecord).filter_by(domain_id=domain_obj.id).all()
                existing_map = {(r.record_type, r.name, r.value): r for r in existing_records}
                
                # Track which records are updated
                updated_records = set()
                
                # Process new records
                for record in dns_records:
                    record_key = (record['type'], record['name'], record['value'])
                    updated_records.add(record_key)
                    
                    # Check for CNAME records that might point to new domains
                    if record['type'] == 'CNAME' and scan_queue is not None:
                        cname_target = record['value'].rstrip('.')
                        
                        # Check if CNAME target should be ignored
                        is_ignored = False
                        patterns = self.session.query(IgnoredDomain).all()
                        for pattern in patterns:
                            if pattern.pattern.startswith('*.'):
                                suffix = pattern.pattern[2:]  # Remove *. from pattern
                                if cname_target.endswith(suffix):
                                    self.logger.info(f"[SCAN] Skipping CNAME target {cname_target} - Matches ignore pattern {pattern.pattern}")
                                    is_ignored = True
                                    break
                            elif pattern.pattern in cname_target:
                                self.logger.info(f"[SCAN] Skipping CNAME target {cname_target} - Contains ignored pattern {pattern.pattern}")
                                is_ignored = True
                                break
                            elif cname_target.endswith(pattern.pattern):
                                self.logger.info(f"[SCAN] Skipping CNAME target {cname_target} - Matches ignore pattern {pattern.pattern}")
                                is_ignored = True
                                break
                        
                        if not is_ignored:
                            scan_queue.add((cname_target, port))
                            self.logger.info(f"[SCAN] Added CNAME target to queue: {cname_target}:{port}")
                    
                    if record_key in existing_map:
                        # Update existing record
                        existing_record = existing_map[record_key]
                        existing_record.ttl = record['ttl']
                        existing_record.priority = record.get('priority')
                        existing_record.updated_at = datetime.now()
                        self.logger.debug(f"[DNS] Updated record: {record_key}")
                    else:
                        # Add new record
                        dns_record = DomainDNSRecord(
                            domain_id=domain_obj.id,
                            record_type=record['type'],
                            name=record['name'],
                            value=record['value'],
                            ttl=record['ttl'],
                            priority=record.get('priority'),
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        self.session.add(dns_record)
                        self.logger.debug(f"[DNS] Added new record: {record_key}")
                
                # Remove old records that no longer exist
                for key, record in existing_map.items():
                    if key not in updated_records:
                        self.session.delete(record)
                        self.logger.debug(f"[DNS] Removed old record: {key}")
                
                self.session.flush()
                self.logger.info(f"[DNS] Successfully processed {len(dns_records)} records for {domain_obj.domain_name}")
                
        except Exception as e:
            self.logger.error(f"Error processing DNS records for {domain_obj.domain_name}: {str(e)}")
            raise
    
    def process_certificate(self, domain: str, port: int, cert_info: CertificateInfo, domain_obj: Domain) -> None:
        """Process certificate information and update database."""
        try:
            # Get or create certificate
            cert = self.session.query(Certificate).filter_by(
                serial_number=cert_info.serial_number
            ).first()
            
            if not cert:
                self.set_status(f'Found new certificate for {domain}...')
                cert = Certificate(
                    serial_number=cert_info.serial_number,
                    thumbprint=cert_info.thumbprint,
                    common_name=cert_info.common_name,
                    valid_from=cert_info.valid_from,
                    valid_until=cert_info.expiration_date,
                    _issuer=json.dumps(cert_info.issuer),
                    _subject=json.dumps(cert_info.subject),
                    _san=json.dumps(cert_info.san),
                    key_usage=json.dumps(cert_info.key_usage) if cert_info.key_usage else None,
                    signature_algorithm=cert_info.signature_algorithm,
                    chain_valid=validate_chain and cert_info.chain_valid,
                    sans_scanned=check_sans,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                self.session.add(cert)
            else:
                self.set_status(f'Updating existing certificate for {domain}...')
                cert.thumbprint = cert_info.thumbprint
                cert.common_name = cert_info.common_name
                cert.valid_from = cert_info.valid_from
                cert.valid_until = cert_info.expiration_date
                cert._issuer = json.dumps(cert_info.issuer)
                cert._subject = json.dumps(cert_info.subject)
                cert._san = json.dumps(cert_info.san)
                cert.key_usage = json.dumps(cert_info.key_usage) if cert_info.key_usage else None
                cert.signature_algorithm = cert_info.signature_algorithm
                cert.chain_valid = validate_chain and cert_info.chain_valid
                cert.sans_scanned = check_sans
                cert.updated_at = datetime.now()
            
            # Associate certificate with domain
            if cert not in domain_obj.certificates:
                domain_obj.certificates.append(cert)
            
            # Create or update host record
            host = self.session.query(Host).filter_by(name=domain).first()
            if not host:
                self.set_status(f'Creating host record for {domain}...')
                # Set host type based on detected platform
                host_type = HOST_TYPE_SERVER
                if cert_info.platform:
                    if cert_info.platform in [PLATFORM_CLOUDFLARE, PLATFORM_AKAMAI]:
                        host_type = HOST_TYPE_CDN
                    elif cert_info.platform == PLATFORM_F5:
                        host_type = HOST_TYPE_LOAD_BALANCER
                
                host = Host(
                    name=domain,
                    host_type=host_type,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                self.session.add(host)
            else:
                host.last_seen = datetime.now()
                # Update host type if platform detected
                if cert_info.platform:
                    if cert_info.platform in [PLATFORM_CLOUDFLARE, PLATFORM_AKAMAI] and host.host_type != HOST_TYPE_CDN:
                        host.host_type = HOST_TYPE_CDN
                    elif cert_info.platform == PLATFORM_F5 and host.host_type != HOST_TYPE_LOAD_BALANCER:
                        host.host_type = HOST_TYPE_LOAD_BALANCER
            
            # Create or update IP addresses
            if cert_info.ip_addresses:
                self.set_status(f'Updating IP addresses for {domain}...')
                existing_ips = {ip.ip_address for ip in host.ip_addresses}
                for ip_addr in cert_info.ip_addresses:
                    if ip_addr not in existing_ips:
                        host_ip = HostIP(
                            host=host,
                            ip_address=ip_addr,
                            is_active=True,
                            last_seen=datetime.now()
                        )
                        self.session.add(host_ip)
                    else:
                        # Update last_seen for existing IP
                        for ip in host.ip_addresses:
                            if ip.ip_address == ip_addr:
                                ip.last_seen = datetime.now()
                                ip.is_active = True
            
            # Create or update certificate binding
            host_ip = None
            if cert_info.ip_addresses:
                for ip in host.ip_addresses:
                    if ip.ip_address in cert_info.ip_addresses:
                        host_ip = ip
                        break
            
            binding = self.session.query(CertificateBinding).filter_by(
                host=host,
                host_ip=host_ip,
                port=port
            ).first()
            
            if not binding:
                self.set_status(f'Creating certificate binding for {domain}:{port}...')
                binding = CertificateBinding(
                    host=host,
                    host_ip=host_ip,
                    certificate=cert,
                    port=port,
                    binding_type='IP',
                    platform=cert_info.platform if detect_platform else None,
                    last_seen=datetime.now(),
                    manually_added=False
                )
                self.session.add(binding)
            else:
                binding.certificate = cert
                binding.last_seen = datetime.now()
                if detect_platform:
                    binding.platform = cert_info.platform
            
            # Create scan history record
            scan_record = CertificateScan(
                certificate=cert,
                host=host,
                scan_date=datetime.now(),
                status="Success",
                port=port
            )
            self.session.add(scan_record)
            
            self.session.flush()
            
        except Exception as e:
            self.logger.error(f"Error processing certificate for {domain}: {str(e)}")
            raise 