from datetime import datetime
import json
import logging
from .domain_scanner import DomainScanner
from .subdomain_scanner import SubdomainScanner
from urllib.parse import urlparse
from .utils import is_ip_address, get_ip_info
from sqlalchemy.orm import Session
from ..models import Certificate, CertificateBinding, Domain, DomainDNSRecord, Host, HOST_TYPE_SERVER, ENV_PRODUCTION, IgnoredCertificate, IgnoredDomain
from typing import Tuple, Optional
from ..settings import settings

CertificateScanner = None

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
                self.logger.info(f"[SCAN] IP information for {hostname}: {ip_info}")
                
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
                    self.logger.info(f"[SCAN] Found hostnames for {hostname}: {ip_info['hostnames']}")
                    # Add these domains to scan queue if needed
                
                # Add network information if available
                if ip_info['network']:
                    self.logger.info(f"[SCAN] Network for {hostname}: {ip_info['network']}")
                
                session.commit()
            
            return True, hostname, port, None
            
        except Exception as e:
            self.logger.error(f"Error processing scan target {entry}: {str(e)}")
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
                self.logger.info(f"[SCAN] IP information for {domain}: {ip_info}")
                
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
                    self.logger.info(f"[SCAN] Found hostnames for {domain}: {ip_info['hostnames']}")
                
                # Add network information if available
                if ip_info['network']:
                    self.logger.info(f"[SCAN] Network for {domain}: {ip_info['network']}")
                
                session.commit()
            else:
                # Handle domain scanning
                # Get domain information first
                domain_info = None
                if kwargs.get('check_whois') or kwargs.get('check_dns'):
                    try:
                        if kwargs.get('status_container'):
                            kwargs['status_container'].text(f'Gathering domain information for {domain}...')
                        
                        self.logger.info(f"[SCAN] Domain info gathering for {domain} - WHOIS: {kwargs.get('check_whois', False)}, DNS: {kwargs.get('check_dns', False)}")
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
                                    self.logger.error(f"[DNS] Error processing DNS records for {domain}: {str(dns_error)}")
                                    session.rollback()
                                    # Continue with the scan even if DNS processing fails
                    
                    except Exception as e:
                        self.logger.error(f"[SCAN] Error gathering domain info for {domain}: {str(e)}")
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
                                self.logger.info(f"[SCAN] Found {len(subdomain_results)} subdomains for {domain}")
                                
                                for result in subdomain_results:
                                    subdomain = result['domain']
                                    if not self.infra_mgmt.tracker.is_endpoint_scanned(subdomain, port):
                                        self.infra_mgmt.tracker.add_to_queue(subdomain, port)
                                        self.logger.info(f"[SCAN] Added subdomain to queue: {subdomain}:{port}")
                            
                            self.subdomain_scanner.set_status_container(None)
                            
                        except Exception as subdomain_error:
                            self.logger.error(f"[SCAN] Error in subdomain scanning for {domain}: {str(subdomain_error)}")
                            session.rollback()
                            raise
                    
                    self.logger.info(f"[SCAN] Successfully processed certificate for {'IP' if is_ip else 'domain'} {domain}:{port}")
                    
                    # Remove from no_cert list if present
                    if domain in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].remove(domain)
                    
                    # Add to success list if not already there
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"]:
                        self.scan_results["success"].append(target_key)
                    
                    return True
                else:
                    self.logger.warning(f"[SCAN] No certificate found for {'IP' if is_ip else 'domain'} {domain}:{port}")
                    # Only add to no_cert if not already in success list
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"] and domain not in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].append(domain)
                    return False
            
        except Exception as e:
            self.logger.error(f"Error in scan_target for {domain}:{port}: {str(e)}")
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
