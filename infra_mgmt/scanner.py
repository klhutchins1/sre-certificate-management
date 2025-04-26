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
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .settings import settings
from .domain_scanner import DomainScanner, DomainInfo
from .subdomain_scanner import SubdomainScanner
from .models import (
    IgnoredDomain, Domain, DomainDNSRecord, Certificate, 
    Host, HostIP, CertificateBinding, CertificateScan, 
    HOST_TYPE_SERVER, HOST_TYPE_CDN, HOST_TYPE_LOAD_BALANCER, 
    ENV_PRODUCTION, IgnoredCertificate
)
from .constants import PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION
from .certificate_scanner import CertificateInfo
from .notifications import notify
import socket
import ipaddress
import dns.resolver
import dns.reversename

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
    
    def process_scan_target(self, entry: str, session: Session = None) -> tuple:
        """Process and validate a scan target."""
        try:
            # Check if target is empty
            if not entry.strip():
                return False, None, None, "Empty target"
            
            # Parse the target
            if '://' in entry:
                # URL format
                parsed = urlparse(entry)
                hostname = parsed.hostname
                port = parsed.port or 443
            else:
                # domain:port or just domain format
                parts = entry.split(':')
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443
            
            # Check if it's an IP address
            is_ip = is_ip_address(hostname)
            
            if is_ip:
                # Get IP information
                ip_info = get_ip_info(hostname)
                logger.info(f"[SCAN] IP information for {hostname}: {ip_info}")
                
                # Create or update host record
                host = session.query(Host).filter_by(name=hostname).first()
                if not host:
                    host = Host(
                        name=hostname,
                        host_type=HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                
                # Add any discovered hostnames from reverse DNS
                if ip_info['hostnames']:
                    logger.info(f"[SCAN] Found hostnames for {hostname}: {ip_info['hostnames']}")
                    # Add these domains to scan queue if needed
                
                # Add network information if available
                if ip_info['network']:
                    logger.info(f"[SCAN] Network for {hostname}: {ip_info['network']}")
                
                session.commit()
            
            return True, hostname, port, None
            
        except Exception as e:
            logger.error(f"Error processing scan target {entry}: {str(e)}")
            return False, None, None, str(e)
    
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
    
    def scan_target(self, session: Session, domain: str, port: int, **kwargs):
        """
        Scan a target (domain or IP).
        """
        try:
            # Check if it's an IP address
            is_ip = is_ip_address(domain)
            
            if is_ip:
                # For IPs, skip DNS checks and only do certificate and WHOIS
                kwargs['check_dns'] = False
                kwargs['check_subdomains'] = False
                
                # Get IP information
                ip_info = get_ip_info(domain)
                logger.info(f"[SCAN] IP information for {domain}: {ip_info}")
                
                # Update host record with IP information
                host = session.query(Host).filter_by(name=domain).first()
                if not host:
                    host = Host(
                        name=domain,
                        host_type=HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                
                if ip_info['whois'] and ip_info['whois'].get('organization'):
                    host.owner = ip_info['whois']['organization']
                if ip_info['whois'] and ip_info['whois'].get('country'):
                    host.environment = ip_info['whois']['country']
                
                # Add any discovered hostnames from reverse DNS
                if ip_info['hostnames']:
                    logger.info(f"[SCAN] Found hostnames for {domain}: {ip_info['hostnames']}")
                
                # Add network information if available
                if ip_info['network']:
                    logger.info(f"[SCAN] Network for {domain}: {ip_info['network']}")
                
                session.commit()
            else:
                # Handle domain scanning
                # Get domain information first
                domain_info = None
                if kwargs.get('check_whois') or kwargs.get('check_dns'):
                    try:
                        if kwargs.get('status_container'):
                            kwargs['status_container'].text(f'Gathering domain information for {domain}...')
                        
                        logger.info(f"[SCAN] Domain info gathering for {domain} - WHOIS: {kwargs.get('check_whois', False)}, DNS: {kwargs.get('check_dns', False)}")
                        domain_info = self.domain_scanner.scan_domain(
                            domain,
                            get_whois=kwargs.get('check_whois', False),
                            get_dns=kwargs.get('check_dns', False)
                        )
                        
                        # Process domain information
                        if domain_info:
                            # Get or create domain
                            domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
                            if not domain_obj:
                                domain_obj = Domain(
                                    domain_name=domain,
                                    created_at=datetime.now(),
                                    updated_at=datetime.now()
                                )
                                session.add(domain_obj)
                                session.commit()  # Commit to get domain ID
                            
                            # Update domain information
                            if kwargs.get('check_whois') and domain_info.registrar:
                                domain_obj.registrar = domain_info.registrar
                                domain_obj.registration_date = domain_info.registration_date
                                domain_obj.expiration_date = domain_info.expiration_date
                                domain_obj.owner = domain_info.registrant
                                domain_obj.updated_at = datetime.now()
                                session.commit()  # Commit WHOIS updates
                            
                            # Process DNS records
                            if kwargs.get('check_dns') and domain_info.dns_records:
                                try:
                                    # Get all existing DNS records for this domain
                                    existing_records = session.query(DomainDNSRecord).filter_by(domain_id=domain_obj.id).all()
                                    existing_map = {(r.record_type, r.name, r.value): r for r in existing_records}
                                    
                                    # Track which records we've seen
                                    seen_records = set()
                                    
                                    # Process each DNS record
                                    for record in domain_info.dns_records:
                                        record_key = (record['type'], record['name'], record['value'])
                                        seen_records.add(record_key)
                                        
                                        if record_key in existing_map:
                                            # Update existing record
                                            existing_record = existing_map[record_key]
                                            existing_record.ttl = record['ttl']
                                            existing_record.priority = record.get('priority')
                                            existing_record.updated_at = datetime.now()
                                        else:
                                            # Create new record
                                            dns_record = DomainDNSRecord(
                                                domain=domain_obj,
                                                record_type=record['type'],
                                                name=record['name'],
                                                value=record['value'],
                                                ttl=record['ttl'],
                                                priority=record.get('priority'),
                                                created_at=datetime.now(),
                                                updated_at=datetime.now()
                                            )
                                            session.add(dns_record)
                                    
                                    # Remove records that no longer exist
                                    for key, record in existing_map.items():
                                        if key not in seen_records:
                                            session.delete(record)
                                    
                                    # Commit all DNS changes at once
                                    session.commit()
                                    
                                except Exception as dns_error:
                                    logger.error(f"[DNS] Error processing DNS records for {domain}: {str(dns_error)}")
                                    session.rollback()
                                    # Continue with the scan even if DNS processing fails
                    
                    except Exception as e:
                        logger.error(f"[SCAN] Error gathering domain info for {domain}: {str(e)}")
                        session.rollback()
                        raise
                
                # Scan for certificate
                scan_result = self.infra_mgmt.scan_certificate(domain, port)
                if scan_result and scan_result.certificate_info:
                    cert_info = scan_result.certificate_info
                    
                    # Process certificate
                    cert = session.query(Certificate).filter_by(
                        serial_number=cert_info.serial_number
                    ).first()
                    
                    if not cert:
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
                            chain_valid=kwargs.get('validate_chain', True) and cert_info.chain_valid,
                            sans_scanned=kwargs.get('check_sans', False),
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        session.add(cert)
                        session.commit()  # Commit certificate creation
                    
                    # Get or create host record if not already created
                    if not is_ip:  # Only create host for domains, IPs already have one
                        host = session.query(Host).filter_by(name=domain).first()
                        if not host:
                            host = Host(
                                name=domain,
                                host_type=HOST_TYPE_SERVER,
                                environment=ENV_PRODUCTION,
                                last_seen=datetime.now()
                            )
                            session.add(host)
                            session.commit()  # Commit host creation
                        else:
                            host.last_seen = datetime.now()
                            session.commit()  # Commit host update
                    
                    # Create or update certificate binding
                    binding = session.query(CertificateBinding).filter_by(
                        host=host,
                        port=port
                    ).first()
                    
                    if not binding:
                        binding = CertificateBinding(
                            host=host,
                            certificate=cert,
                            port=port,
                            binding_type='IP',
                            platform=cert_info.platform if kwargs.get('detect_platform', True) else None,
                            last_seen=datetime.now(),
                            manually_added=False
                        )
                        session.add(binding)
                    else:
                        binding.certificate = cert
                        binding.last_seen = datetime.now()
                        if kwargs.get('detect_platform', True):
                            binding.platform = cert_info.platform
                    session.commit()  # Commit binding changes
                    
                    # Process subdomains if requested and this is a domain
                    if not is_ip and kwargs.get('check_subdomains'):
                        try:
                            if kwargs.get('status_container'):
                                kwargs['status_container'].text(f'Discovering subdomains for {domain}...')
                            
                            self.subdomain_scanner.set_status_container(kwargs.get('status_container'))
                            
                            subdomain_results = self.subdomain_scanner.scan_and_process_subdomains(
                                domain=domain,
                                port=port,
                                check_whois=kwargs.get('check_whois', False),
                                check_dns=kwargs.get('check_dns', False),
                                scanned_domains=self.infra_mgmt.tracker.scanned_domains
                            )
                            
                            if subdomain_results:
                                logger.info(f"[SCAN] Found {len(subdomain_results)} subdomains for {domain}")
                                
                                for result in subdomain_results:
                                    subdomain = result['domain']
                                    if not self.infra_mgmt.tracker.is_endpoint_scanned(subdomain, port):
                                        self.infra_mgmt.tracker.add_to_queue(subdomain, port)
                                        logger.info(f"[SCAN] Added subdomain to queue: {subdomain}:{port}")
                            
                            self.subdomain_scanner.set_status_container(None)
                            
                        except Exception as subdomain_error:
                            logger.error(f"[SCAN] Error in subdomain scanning for {domain}: {str(subdomain_error)}")
                            session.rollback()
                            raise
                    
                    logger.info(f"[SCAN] Successfully processed certificate for {'IP' if is_ip else 'domain'} {domain}:{port}")
                    
                    # Remove from no_cert list if present
                    if domain in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].remove(domain)
                    
                    # Add to success list if not already there
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"]:
                        self.scan_results["success"].append(target_key)
                    
                    return True
                else:
                    logger.warning(f"[SCAN] No certificate found for {'IP' if is_ip else 'domain'} {domain}:{port}")
                    # Only add to no_cert if not already in success list
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"] and domain not in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].append(domain)
                    return False
            
        except Exception as e:
            logger.error(f"Error in scan_target for {domain}:{port}: {str(e)}")
            session.rollback()
            raise
    
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

    def get_scanners(self):
        """Get scanner instances with shared tracking."""
        return self.domain_scanner, self.infra_mgmt, self.subdomain_scanner

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

def get_db_session():
    """Get a new database session."""
    db_path = settings.get("paths.database", "data/certificates.db")
    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)
    return Session()

def validate_port(port_str: str, entry: str) -> Tuple[bool, int]:
    """
    Validate a port number string.
    
    Args:
        port_str: The port number as a string
        entry: The full entry string for error messages
        
    Returns:
        Tuple[bool, int]: (is_valid, port_number)
    """
    try:
        port = int(port_str)
        if port < 0:
            notify(f"Invalid port number in {entry}: Port cannot be negative", "error")
            return False, 0
        if port > 65535:
            notify(f"Invalid port number in {entry}: Port must be between 1 and 65535", "error")
            return False, 0
        return True, port
    except ValueError as e:
        notify(f"Invalid port number in {entry}: '{port_str}' is not a valid number", "error")
        return False, 0

def is_ip_address(address: str) -> bool:
    """Check if a string is an IP address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def get_ip_info(ip: str) -> Dict[str, Any]:
    """
    Get information about an IP address.
    
    Args:
        ip: IP address to look up
        
    Returns:
        Dict containing IP information including:
        - WHOIS data
        - Reverse DNS
        - Network range
    """
    info = {
        'whois': None,
        'hostnames': [],
        'network': None
    }
    
    try:
        # Get reverse DNS (PTR records)
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(addr, "PTR")
            info['hostnames'] = [str(rdata).rstrip('.') for rdata in answers]
        except Exception as e:
            logger.debug(f"Reverse DNS lookup failed for {ip}: {str(e)}")
        
        # Get network information
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
            else:
                network = ipaddress.ip_network(f"{ip}/64", strict=False)
            info['network'] = str(network)
        except Exception as e:
            logger.debug(f"Network determination failed for {ip}: {str(e)}")
        
        # Get WHOIS information
        try:
            import whois
            whois_info = whois.whois(ip)
            if whois_info:
                info['whois'] = {
                    'registrar': whois_info.registrar,
                    'organization': whois_info.org,
                    'country': whois_info.country,
                    'creation_date': whois_info.creation_date,
                    'updated_date': whois_info.updated_date
                }
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {ip}: {str(e)}")
        
        return info
        
    except Exception as e:
        logger.error(f"Error getting IP information for {ip}: {str(e)}")
        return info 