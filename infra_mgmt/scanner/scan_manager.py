from datetime import datetime
import json
import logging
import socket
from .domain_scanner import DomainScanner
from .subdomain_scanner import SubdomainScanner
from urllib.parse import urlparse
from .utils import is_ip_address, get_ip_info
from sqlalchemy.orm import Session
from ..models import Certificate, CertificateBinding, Domain, DomainDNSRecord, Host, HOST_TYPE_SERVER, ENV_PRODUCTION, IgnoredCertificate, IgnoredDomain
from typing import Tuple, Optional
from ..settings import settings
from infra_mgmt.utils.ignore_list import IgnoreListUtil
from infra_mgmt.utils.dns_records import DNSRecordUtil
from infra_mgmt.utils.certificate_db import CertificateDBUtil
from infra_mgmt.utils.cache import ScanSessionCache

CertificateScanner = None

class ScanManager:
    """
    Centralized manager for all scanning operations in the Infrastructure Management System (IMS).

    ScanManager acts as the orchestrator for domain, subdomain, and certificate scanning. It coordinates
    between the various scanner classes (CertificateScanner, DomainScanner, SubdomainScanner), manages
    the scan queue, tracks progress, and aggregates results. It is responsible for:

    - Validating and processing scan targets (domains, IPs, URLs)
    - Managing the scan queue and avoiding duplicate or ignored targets
    - Delegating scanning tasks to the appropriate scanner (domain, subdomain, certificate)
    - Handling scan results, including success, error, warning, and no-certificate cases
    - Providing statistics and status for the scanning process
    - Integrating with the database for persistent tracking and ignore lists
    - Ensuring robust error handling and logging throughout the scan lifecycle

    Relationships:
        - Uses CertificateScanner for certificate retrieval and analysis
        - Uses DomainScanner for WHOIS/DNS/domain info
        - Uses SubdomainScanner for passive subdomain discovery
        - Shares a tracker instance across scanners for unified state

    Example usage:
        >>> manager = ScanManager()
        >>> valid, host, port, err = manager.process_scan_target('example.com:443', session)
        >>> if valid:
        ...     manager.add_to_queue(host, port)
        ...     # ...
        >>> while manager.has_pending_targets():
        ...     target = manager.get_next_target()
        ...     if target:
        ...         manager.scan_target(session, *target)

    Edge Cases:
        - Handles empty/invalid input, duplicate scans, ignored domains/certificates, and network errors
        - Designed to be robust against partial failures and to log all significant events
    """
    
    def __init__(self):
        """
        Initialize scan manager with required scanners and shared state.
        
        This constructor sets up the core scanning components and ensures that the
        subdomain scanner shares the same tracker as the certificate scanner, so that
        all discovered domains and endpoints are tracked consistently. It also initializes
        the scan history and results structures, and prepares a logger for detailed tracing.
        
        Side Effects:
            - Imports CertificateScanner lazily to avoid circular imports.
            - Initializes scanner instances and shared tracker.
            - Sets up scan state and logging.
        """
        global CertificateScanner
        if CertificateScanner is None:
            from .certificate_scanner import CertificateScanner
        self.session_cache = ScanSessionCache()
        self.infra_mgmt = CertificateScanner(session_cache=self.session_cache)
        self.domain_scanner = DomainScanner(session_cache=self.session_cache)
        self.subdomain_scanner = SubdomainScanner(session_cache=self.session_cache)
        self.subdomain_scanner.tracker = self.infra_mgmt.tracker
        self.scan_history = []
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": []
        }
        self.logger = logging.getLogger(__name__)
        self.processor = None
    
    def reset_scan_state(self):
        """
        Reset scan state for a new scan session.
        
        This method clears all accumulated scan history and results, and resets the
        underlying CertificateScanner's state. It is typically called at the start of
        a new scan session to ensure no stale data is carried over.
        
        Side Effects:
            - Clears scan history and results.
            - Resets state in infra_mgmt (CertificateScanner).
        """
        self.infra_mgmt.reset_scan_state()
        self.scan_history.clear()
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": []
        }
        self.session_cache.clear()
    
    def process_scan_target(self, entry: str, session: Session = None) -> tuple:
        """
        Process and validate a scan target string, extracting the hostname and port.
        
        This method parses the input (which may be a domain, IP, or URL), determines
        if it is a valid scan target, and prepares it for queueing. For IP addresses,
        it also updates the database with host information and logs any discovered
        hostnames or network details. Returns a tuple indicating validity, the parsed
        hostname, port, and an error message if applicable.
        
        Args:
            entry (str): The scan target string (domain, IP, or URL)
            session (Session, optional): SQLAlchemy session for DB operations
        
        Returns:
            tuple: (is_valid, hostname, port, error_message)
                - is_valid (bool): True if the target is valid and ready for scanning
                - hostname (str or None): The parsed hostname or IP
                - port (int or None): The parsed port (default 443 if not specified)
                - error_message (str or None): Error message if invalid
        
        Edge Cases:
            - Handles empty input, invalid formats, and parsing errors.
            - For IPs, creates/updates host records and logs info.
            - Accepts both URL and domain:port formats.
        
        Example:
            >>> process_scan_target('example.com:443', session)
            (True, 'example.com', 443, None)
            >>> process_scan_target('https://test.com', session)
            (True, 'test.com', 443, None)
            >>> process_scan_target('', session)
            (False, None, None, 'Empty target')
        """
        try:
            if not entry.strip():
                return False, None, None, "Empty target"
            if '://' in entry:
                parsed = urlparse(entry)
                hostname = parsed.hostname
                port = parsed.port or 443
            else:
                parts = entry.split(':')
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443
            is_ip = is_ip_address(hostname)
            if is_ip:
                ip_info = get_ip_info(hostname)
                self.logger.info(f"[SCAN] IP information for {hostname}: {ip_info}")
                host = session.query(Host).filter_by(name=hostname).first()
                if not host:
                    host = Host(
                        name=hostname,
                        host_type=HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                if ip_info['hostnames']:
                    self.logger.info(f"[SCAN] Found hostnames for {hostname}: {ip_info['hostnames']}")
                if ip_info['network']:
                    self.logger.info(f"[SCAN] Network for {hostname}: {ip_info['network']}")
                session.commit()
            return True, hostname, port, None
        except ValueError as e:
            self.logger.error(f"Value error processing scan target {entry}: {str(e)}")
            return False, None, None, str(e)
        except TypeError as e:
            self.logger.error(f"Type error processing scan target {entry}: {str(e)}")
            return False, None, None, str(e)
        except Exception as e:
            self.logger.exception(f"Unexpected error processing scan target {entry}: {str(e)}")
            return False, None, None, str(e)

    def add_to_queue(self, hostname: str, port: int, session) -> bool:
        """
        Add a scan target to the queue if not already processed or ignored.

        This method checks the ignore list and the scan tracker to avoid duplicate or
        unwanted scans. If the target is valid, it is added to the scan queue and scan history.
        Returns True if the target was added, False otherwise.

        Args:
            hostname (str): Domain to scan
            port (int): Port to scan
            session: SQLAlchemy session for DB operations

        Returns:
            bool: True if target was added, False if already scanned or ignored

        Side Effects:
            - Checks ignore lists and updates scan history.
            - Adds to scan queue if not ignored or already scanned.
        
        Example:
            >>> add_to_queue('example.com', 443, session)
            True
        """
        try:
            if self.infra_mgmt.tracker.is_endpoint_scanned(hostname, port) or (hostname, port) in self.infra_mgmt.tracker.scan_queue:
                self.logger.info(f"[SCAN] Skipping {hostname}:{port} - Already scanned or queued")
                self.scan_results["warning"].append(f"{hostname}:{port} - Skipped (already scanned or queued)")
                return False
            is_ignored, ignore_reason = IgnoreListUtil.is_domain_ignored(session, hostname)
            if is_ignored:
                self.logger.info(f"[SCAN] Skipping {hostname} - Domain is in ignore list" + (f" ({ignore_reason})" if ignore_reason else ""))
                self.scan_results["warning"].append(f"{hostname}:{port} - Skipped (domain in ignore list)")
                self.infra_mgmt.tracker.add_scanned_domain(hostname)
                self.infra_mgmt.tracker.add_scanned_endpoint(hostname, port)
                return False
            if self.infra_mgmt.add_scan_target(hostname, port):
                self.scan_history.append(hostname)
                self.logger.info(f"[SCAN] Added target to queue: {hostname}:{port}")
                return True
            return False
        except Exception as e:
            self.logger.exception(f"Error adding target to queue: {str(e)}")
            return False

    def scan_target(self, session: Session, domain: str, port: int, **kwargs):
        """
        Scan a target (domain or IP), performing all necessary sub-steps.

        This method is the main entry point for scanning a single target. It handles
        DNS resolution, certificate retrieval, WHOIS/DNS info, subdomain discovery,
        and updates all relevant database records and scan state. It is robust to
        network errors and partial failures, and logs all significant events.

        Args:
            session (Session): SQLAlchemy session for DB operations
            domain (str): Domain or IP to scan
            port (int): Port to scan
            **kwargs: Additional scan options (e.g., check_whois, check_dns, check_subdomains, check_sans, detect_platform, validate_chain, status_container, progress_container, current_step, total_steps)

        Returns:
            bool: True if scan was successful, False otherwise

        Raises:
            Exception: If an unexpected error occurs during scanning

        Side Effects:
            - Updates database records for hosts, domains, certificates, and bindings.
            - Modifies scan_results and tracker state.

        Edge Cases:
            - Handles DNS resolution failures, connection errors, and missing certificates.
            - Skips targets that cannot be resolved or are ignored.
        
        Example:
            >>> scan_target(session, 'example.com', 443, check_whois=True, check_dns=True)
            True
        """
        try:
            # Guard against None or non-string domain
            if not domain or not isinstance(domain, str):
                self.logger.warning(f"[SCAN] Skipping invalid domain: {domain}")
                self.scan_results["error"].append(f"{domain}:{port} - Invalid domain (None or not a string)")
                return False
            # Normalize domain
            domain = domain.strip().lower().rstrip('.')
            is_ip = is_ip_address(domain)
            
            # --- New: Check if domain resolves before scanning certificate ---
            if not is_ip:
                try:
                    # Try to resolve the domain to an IP address
                    addrinfo = socket.getaddrinfo(domain, port, proto=socket.IPPROTO_TCP)
                    if not addrinfo:
                        self.logger.warning(f"[SCAN] Skipping {domain}:{port} - No A or AAAA record (cannot resolve)")
                        self.scan_results["error"].append(f"{domain}:{port} - No A or AAAA record (cannot resolve)")
                        return False
                except socket.gaierror:
                    self.logger.warning(f"[SCAN] Skipping {domain}:{port} - No A or AAAA record (cannot resolve)")
                    self.scan_results["error"].append(f"{domain}:{port} - No A or AAAA record (cannot resolve)")
                    return False
                except Exception as e:
                    self.logger.warning(f"[SCAN] Skipping {domain}:{port} - DNS resolution error: {str(e)}")
                    self.scan_results["error"].append(f"{domain}:{port} - DNS resolution error: {str(e)}")
                    return False
            
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

                # --- Certificate scan for IPs (same as for domains) ---
                # Always check DNS resolution before scanning
                try:
                    addrinfo = socket.getaddrinfo(domain, port, proto=socket.IPPROTO_TCP)
                    if not addrinfo:
                        self.logger.warning(f"[SCAN] Skipping {domain}:{port} - No A or AAAA record (cannot resolve)")
                        self.scan_results["error"].append(f"{domain}:{port} - No A or AAAA record (cannot resolve)")
                        return False
                except socket.gaierror:
                    self.logger.warning(f"[SCAN] Skipping {domain}:{port} - No A or AAAA record (cannot resolve)")
                    self.scan_results["error"].append(f"{domain}:{port} - No A or AAAA record (cannot resolve)")
                    return False
                except Exception as e:
                    self.logger.warning(f"[SCAN] Skipping {domain}:{port} - DNS resolution error: {str(e)}")
                    self.scan_results["error"].append(f"{domain}:{port} - DNS resolution error: {str(e)}")
                    return False
                scan_result = self.infra_mgmt.scan_certificate(domain, port)
                if scan_result and scan_result.certificate_info:
                    cert_info = scan_result.certificate_info
                    # Process certificate
                    CertificateDBUtil.upsert_certificate_and_binding(session, domain, port, cert_info, host, detect_platform=kwargs.get('detect_platform', True), check_sans=kwargs.get('check_sans', False), validate_chain=kwargs.get('validate_chain', True))
                    # Remove from no_cert list if present
                    if domain in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].remove(domain)
                    # Add to success list if not already there
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"]:
                        self.scan_results["success"].append(target_key)
                    # --- SAN scanning for IPs ---
                    if kwargs.get('check_sans', False) and cert_info.san:
                        for san in cert_info.san:
                            san_clean = san.strip('*. ').lower().rstrip('.')
                            if san_clean and not self.infra_mgmt.tracker.is_endpoint_scanned(san_clean, port) and (san_clean, port) not in self.infra_mgmt.tracker.scan_queue:
                                if '.' in san_clean and san_clean != domain:
                                    self.infra_mgmt.tracker.add_to_queue(san_clean, port)
                                    self.logger.info(f"[SCAN] Added SAN to queue: {san_clean}:{port}")
                    # After scanning (success or fail), mark as scanned
                    self.infra_mgmt.tracker.add_scanned_endpoint(domain, port)
                    return True
                else:
                    self.logger.warning(f"[SCAN] No certificate found for IP {domain}:{port}")
                    # Only add to no_cert if not already in success list
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"] and domain not in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].append(domain)
                    # After scanning (success or fail), mark as scanned
                    self.infra_mgmt.tracker.add_scanned_endpoint(domain, port)
                    return False
            else:
                # Handle domain scanning
                # Get domain information first
                domain_info = None
                domain_obj = None
                if kwargs.get('check_whois') or kwargs.get('check_dns'):
                    try:
                        if kwargs.get('status_container'):
                            kwargs['status_container'].text(f'Gathering domain information for {domain}...')
                        
                        self.logger.info(f"[SCAN] Domain info gathering for {domain} - WHOIS: {kwargs.get('check_whois', False)}, DNS: {kwargs.get('check_dns', False)}")
                        domain_info = self.domain_scanner.scan_domain(domain, session, get_whois=kwargs.get('check_whois', False), get_dns=kwargs.get('check_dns', False))
                        
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
                        self.logger.exception(f"[SCAN] Error gathering domain info for {domain}: {str(e)}")
                        session.rollback()
                        raise
                
                # Scan for certificate
                # Always check DNS resolution before scanning
                try:
                    addrinfo = socket.getaddrinfo(domain, port, proto=socket.IPPROTO_TCP)
                    if not addrinfo:
                        self.logger.warning(f"[SCAN] Skipping {domain}:{port} - No A or AAAA record (cannot resolve)")
                        self.scan_results["error"].append(f"{domain}:{port} - No A or AAAA record (cannot resolve)")
                        return False
                except socket.gaierror:
                    self.logger.warning(f"[SCAN] Skipping {domain}:{port} - No A or AAAA record (cannot resolve)")
                    self.scan_results["error"].append(f"{domain}:{port} - No A or AAAA record (cannot resolve)")
                    return False
                except Exception as e:
                    self.logger.warning(f"[SCAN] Skipping {domain}:{port} - DNS resolution error: {str(e)}")
                    self.scan_results["error"].append(f"{domain}:{port} - DNS resolution error: {str(e)}")
                    return False
                scan_result = self.infra_mgmt.scan_certificate(domain, port)
                if scan_result and scan_result.certificate_info:
                    cert_info = scan_result.certificate_info
                    
                    # Process certificate
                    CertificateDBUtil.upsert_certificate_and_binding(session, domain, port, cert_info, domain_obj if domain_obj else None, detect_platform=kwargs.get('detect_platform', True), check_sans=kwargs.get('check_sans', False), validate_chain=kwargs.get('validate_chain', True))
                    
                    # Process subdomains if requested and this is a domain
                    if not is_ip and kwargs.get('check_subdomains'):
                        try:
                            if kwargs.get('status_container'):
                                kwargs['status_container'].text(f'Discovering subdomains for {domain}...')
                            self.subdomain_scanner.set_status_container(kwargs.get('status_container'))
                            subdomain_results = self.subdomain_scanner.scan_and_process_subdomains(domain=domain, session=session, port=port, check_whois=kwargs.get('check_whois', False), check_dns=kwargs.get('check_dns', False), scanned_domains=self.infra_mgmt.tracker.scanned_domains)
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
                    # --- SAN scanning for domains ---
                    if kwargs.get('check_sans', False) and cert_info.san:
                        for san in cert_info.san:
                            san_clean = san.strip('*. ').lower().rstrip('.')
                            if san_clean and not self.infra_mgmt.tracker.is_endpoint_scanned(san_clean, port) and (san_clean, port) not in self.infra_mgmt.tracker.scan_queue:
                                if '.' in san_clean and san_clean != domain:
                                    self.infra_mgmt.tracker.add_to_queue(san_clean, port)
                                    self.logger.info(f"[SCAN] Added SAN to queue: {san_clean}:{port}")
                    self.logger.info(f"[SCAN] Successfully processed certificate for {'IP' if is_ip else 'domain'} {domain}:{port}")
                    
                    # Remove from no_cert list if present
                    if domain in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].remove(domain)
                    
                    # Add to success list if not already there
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"]:
                        self.scan_results["success"].append(target_key)
                    
                    # After scanning (success or fail), mark as scanned
                    self.infra_mgmt.tracker.add_scanned_endpoint(domain, port)
                    return True
                else:
                    self.logger.warning(f"[SCAN] No certificate found for {'IP' if is_ip else 'domain'} {domain}:{port}")
                    # Only add to no_cert if not already in success list
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"] and domain not in self.scan_results["no_cert"]:
                        self.scan_results["no_cert"].append(domain)
                    # After scanning (success or fail), mark as scanned
                    self.infra_mgmt.tracker.add_scanned_endpoint(domain, port)
                    return False
            
        except Exception as e:
            self.logger.exception(f"Unexpected error in scan_target for {domain}:{port}: {str(e)}")
            if session is not None:
                session.rollback()
            raise
        finally:
            # At the end of the scan loop, if there are no more pending targets, log completion
            if not self.has_pending_targets():
                stats = self.get_scan_stats()
                self.logger.info(
                    f"[SCAN COMPLETE] All scanning finished. "
                    f"Success: {stats.get('success_count', 0)}, "
                    f"Errors: {stats.get('error_count', 0)}, "
                    f"Warnings: {stats.get('warning_count', 0)}, "
                    f"No Cert: {stats.get('no_cert_count', 0)}."
                )
    
    def get_scan_stats(self) -> dict:
        """
        Get current scanning statistics, including scan history and result counts.

        Returns:
            dict: Dictionary of scan statistics (history size, success, error, warning, no_cert counts)
        
        Example:
            >>> get_scan_stats()
            {'scan_history_size': 10, 'success_count': 8, 'error_count': 1, 'warning_count': 1, 'no_cert_count': 0}
        """
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
        """
        Check if there are targets waiting to be scanned in the queue.

        Returns:
            bool: True if there are pending targets, False otherwise
        
        Example:
            >>> has_pending_targets()
            True
        """
        return self.infra_mgmt.has_pending_targets()
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """
        Get the next target from the scan queue.

        Returns:
            Optional[Tuple[str, int]]: (domain, port) tuple or None if queue is empty
        
        Example:
            >>> get_next_target()
            ('example.com', 443)
        """
        return self.infra_mgmt.get_next_target()

    def get_scanners(self):
        """
        Get scanner instances (domain, certificate, subdomain) with shared tracking.

        Returns:
            tuple: (domain_scanner, infra_mgmt, subdomain_scanner)
        
        Example:
            >>> domain_scanner, cert_scanner, subdomain_scanner = get_scanners()
        """
        return self.domain_scanner, self.infra_mgmt, self.subdomain_scanner
