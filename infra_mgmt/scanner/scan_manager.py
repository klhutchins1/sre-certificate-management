from datetime import datetime
import json
import logging
import socket
from .domain_scanner import DomainScanner
from .subdomain_scanner import SubdomainScanner
from urllib.parse import urlparse
from .utils import is_ip_address, get_ip_info
from sqlalchemy.orm import Session
from ..models import Certificate, CertificateBinding, Domain, DomainDNSRecord, Host, IgnoredCertificate, IgnoredDomain
from ..constants import HOST_TYPE_SERVER, ENV_PRODUCTION
from typing import Tuple, Optional
from ..settings import settings
from infra_mgmt.utils.ignore_list import IgnoreListUtil
from infra_mgmt.utils.dns_records import DNSRecordUtil
from infra_mgmt.utils.certificate_db import CertificateDBUtil
from infra_mgmt.utils.cache import ScanSessionCache
import re
from infra_mgmt.utils.proxy_detection import detect_proxy_certificate

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
            "no_cert": [],
            "info": []
        }
        self.logger = logging.getLogger(__name__)
        self.processor = None
        self.logger.info(f"[DEBUG] ScanManager initialized: {id(self)}")
    
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
        self.logger.info(f"[DEBUG] reset_scan_state called on ScanManager: {id(self)}")
        self.infra_mgmt.reset_scan_state()
        self.scan_history.clear()
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": [],
            "info": []
        }
        self.session_cache.clear()
        # Debug logging to confirm tracker is empty
        scanned = self.infra_mgmt.tracker.scanned_endpoints if hasattr(self.infra_mgmt.tracker, 'scanned_endpoints') else None
        queue = self.infra_mgmt.tracker.scan_queue if hasattr(self.infra_mgmt.tracker, 'scan_queue') else None
        self.logger.debug(f"[RESET] Tracker scanned_endpoints after reset: {scanned}")
        self.logger.debug(f"[RESET] Tracker scan_queue after reset: {queue}")
    
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
                # Split only on the last colon to support IPv4 addresses
                if entry.count(':') > 1 and not entry.startswith('['):
                    # Likely an IPv4 address with port (e.g., 74.120.158.36:443)
                    hostname, port = entry.rsplit(':', 1)
                    port = int(port)
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
                    # Patch: Add discovered hostnames to scan queue if not already scanned or queued
                    for discovered_hostname in ip_info['hostnames']:
                        if not self.infra_mgmt.tracker.is_domain_scanned(discovered_hostname):
                            added = self.add_to_queue(discovered_hostname, 443, session)
                            if added:
                                self.logger.info(f"[SCAN] Added discovered hostname to queue: {discovered_hostname}:443")
                if ip_info['network']:
                    self.logger.info(f"[SCAN] Network for {hostname}: {ip_info['network']}")
                try:
                    session.commit()
                except Exception as e:
                    self.logger.error(f"Error committing host info for {hostname}: {str(e)}")
                    session.rollback()
                    return False, None, None, f"DB error: {str(e)}"
            return True, hostname, port, None
        except ValueError as e:
            self.logger.error(f"Value error processing scan target {entry}: {str(e)}")
            if session is not None:
                session.rollback()
            return False, None, None, str(e)
        except TypeError as e:
            self.logger.error(f"Type error processing scan target {entry}: {str(e)}")
            if session is not None:
                session.rollback()
            return False, None, None, str(e)
        except Exception as e:
            self.logger.exception(f"Unexpected error processing scan target {entry}: {str(e)}")
            if session is not None:
                session.rollback()
            return False, None, None, str(e)

    def add_to_queue(self, hostname: str, port: int, session) -> bool:
        """
        Add a scan target to the queue if not already processed or ignored.
        Only mark as 'skipped' if the endpoint was already scanned in this session.
        """
        try:
            # Only skip if already scanned in this session
            if self.infra_mgmt.tracker.is_endpoint_scanned(hostname, port):
                self.logger.info(f"[SCAN] Skipping {hostname}:{port} - Already scanned in this session")
                self.scan_results["warning"].append(f"{hostname}:{port} - Skipped (already scanned in this session)")
                return False
            is_ignored, ignore_reason = IgnoreListUtil.is_domain_ignored(session, hostname)
            if is_ignored:
                self.logger.info(f"[SCAN] Skipping {hostname} - Domain is in ignore list" + (f" ({ignore_reason})" if ignore_reason else ""))
                self.scan_results["warning"].append(f"{hostname}:{port} - Skipped (domain in ignore list)")
                return False
            if self.infra_mgmt.add_scan_target(hostname, port):
                self.scan_history.append(hostname)
                self.logger.info(f"[SCAN] Added target to queue: {hostname}:{port}")
                self.logger.info(f"[SCAN][DEBUG] Current scan queue: {self.infra_mgmt.tracker.scan_queue}")
                return True
            return False
        except Exception as e:
            self.logger.exception(f"Error adding target to queue: {str(e)}")
            return False

    def scan_target(self, session: Session, domain: str, port: int, **kwargs):
        """
        Scan a target (domain or IP), performing all necessary sub-steps in the user-specified order.
        For domains: hasCertificate, getDNSRecords, getWhoIsRecords, getIPaddresses, getSubdomains, detect platform.
        For IPs: hasCertificate, getWhoIsRecords, detect platform.
        Always display and save any info found, and add subdomains/SANs/CT to scan queue if checked.
        Notifies for missing data, never skips a domain. 'Skipped' warnings only apply within the current session.
        """
        try:
            # Guard against None or non-string domain
            if not domain or not isinstance(domain, str):
                self.logger.warning(f"[SCAN] Skipping invalid domain: {domain}")
                self.scan_results["error"].append(f"{domain}:{port} - Invalid domain (None or not a string)")
                return False
            domain = domain.strip().lower().rstrip('.')
            is_ip = is_ip_address(domain)
            def is_valid_domain_name(name):
                pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
                if re.match(pattern, name) and not is_ip_address(name):
                    return True
                return False
            
            is_offline = settings.get("scanning.offline_mode", False)
            if is_offline:
                self.logger.info(f"[SCAN] Offline mode enabled for target: {domain}:{port}")

            # --- IP SCAN FLOW ---
            if is_ip:
                kwargs['check_dns'] = False
                kwargs['check_subdomains'] = False
                ip_info = get_ip_info(domain)
                self.logger.info(f"[SCAN] IP information for {domain}: {ip_info}")
                host = session.query(Host).filter_by(name=domain).first()
                if not host:
                    host = Host(
                        name=domain,
                        host_type=HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                # 1. hasCertificate
                cert_result = self.infra_mgmt.scan_certificate(domain, port, offline_mode=is_offline)
                if cert_result and cert_result.certificate_info:
                    cert_info_from_scan = cert_result.certificate_info
                    
                    is_proxy, proxy_reason = detect_proxy_certificate(cert_info_from_scan, settings)
                    print(f"DEBUG [ScanManager.scan_target IP FLOW]: detect_proxy_certificate returned: is_proxy={is_proxy}, reason='{proxy_reason}'")

                    if is_proxy:
                        cert_info_from_scan.proxied = True
                        cert_info_from_scan.proxy_info = proxy_reason
                        print(f"DEBUG [ScanManager.scan_target IP FLOW INSIDE if is_proxy]: cert_info_from_scan.proxied={getattr(cert_info_from_scan, 'proxied', 'NotSet')}, cert_info_from_scan.proxy_info='{getattr(cert_info_from_scan, 'proxy_info', 'NotSet')}'")
                    else:
                        cert_info_from_scan.proxied = False
                        cert_info_from_scan.proxy_info = None
                    
                    print(f"DEBUG [ScanManager.scan_target IP FLOW]: About to upsert. cert_info_from_scan.proxied={getattr(cert_info_from_scan, 'proxied', 'NotSet')}, cert_info_from_scan.proxy_info='{getattr(cert_info_from_scan, 'proxy_info', 'NotSet')}'")

                    CertificateDBUtil.upsert_certificate_and_binding(session, domain, port, cert_info_from_scan, host, detect_platform=kwargs.get('detect_platform', True), check_sans=kwargs.get('check_sans', False), validate_chain=kwargs.get('validate_chain', True))
                    # --- PATCH: Associate cert with SAN domains if present ---
                    if hasattr(cert_info_from_scan, 'san') and cert_info_from_scan.san:
                        from infra_mgmt.utils.certificate_db import is_valid_domain
                        for san_item in cert_info_from_scan.san:
                            if is_valid_domain(san_item):
                                san_domain_obj = session.query(Domain).filter_by(domain_name=san_item).first()
                                if not san_domain_obj:
                                    san_domain_obj = Domain(domain_name=san_item, created_at=datetime.now(), updated_at=datetime.now())
                                    session.add(san_domain_obj)
                                if cert_info_from_scan.serial_number:
                                    cert = session.query(Certificate).filter_by(serial_number=cert_info_from_scan.serial_number).first()
                                    if cert and cert not in san_domain_obj.certificates:
                                        san_domain_obj.certificates.append(cert)
                                        self.logger.info(f"[SCAN] Associated certificate {cert.serial_number} with SAN domain {san_item}")
                    session.commit()
                    target_key = f"{domain}:{port}"
                    if target_key not in self.scan_results["success"]:
                        self.scan_results["success"].append(target_key)
                else:
                    self.scan_results["warning"].append(f"{domain}:{port} - No certificate found")
                    self.scan_results["error"].append(f"{domain}:{port} - Certificate scan failed or no certificate info")
                # 2. getWhoIsRecords
                if ip_info['whois']:
                    if is_offline:
                        self.logger.info(f"[SCAN] Offline mode: Skipping WHOIS for IP {domain}")
                    elif ip_info['whois'].get('organization'):
                        host.owner = ip_info['whois']['organization']
                    if ip_info['whois'].get('country') and not is_offline:
                        host.environment = ip_info['whois']['country']
                else:
                    self.scan_results["warning"].append(f"{domain}:{port} - No WHOIS info found")
                # 3. detect platform (if implemented)
                # ...
                try:
                    session.commit()
                except Exception as e:
                    self.logger.error(f"Error committing IP scan for {domain}: {str(e)}")
                    session.rollback()
                self.infra_mgmt.tracker.add_scanned_endpoint(domain, port)
                return True
            # --- DOMAIN SCAN FLOW ---
            if not is_valid_domain_name(domain):
                self.logger.warning(f"[SCAN] Skipping invalid domain name for Domain creation: {domain}")
                self.scan_results["error"].append(f"{domain}:{port} - Invalid domain name format")
                return False
            domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
            if not domain_obj:
                domain_obj = Domain(
                    domain_name=domain,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                session.add(domain_obj)
                try:
                    session.commit()
                except Exception as e:
                    self.logger.error(f"Error committing new domain {domain}: {str(e)}")
                    session.rollback()
                    return False
            # Always create or get Host for the domain
            host = session.query(Host).filter_by(name=domain).first()
            if not host:
                host = Host(
                    name=domain,
                    host_type=HOST_TYPE_SERVER,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                session.add(host)
                try:
                    session.commit()
                except Exception as e:
                    self.logger.error(f"Error committing new host for domain {domain}: {str(e)}")
                    session.rollback()
                    return False
            # 1. hasCertificate
            cert_result = self.infra_mgmt.scan_certificate(domain, port, offline_mode=is_offline)
            if cert_result and cert_result.certificate_info:
                cert_info_from_scan = cert_result.certificate_info
                
                is_proxy, proxy_reason = detect_proxy_certificate(cert_info_from_scan, settings)
                print(f"DEBUG [ScanManager.scan_target DOMAIN FLOW]: detect_proxy_certificate returned: is_proxy={is_proxy}, reason='{proxy_reason}'")
                
                if is_proxy:
                    cert_info_from_scan.proxied = True
                    cert_info_from_scan.proxy_info = proxy_reason
                    print(f"DEBUG [ScanManager.scan_target DOMAIN FLOW INSIDE if is_proxy]: cert_info_from_scan.proxied={getattr(cert_info_from_scan, 'proxied', 'NotSet')}, cert_info_from_scan.proxy_info='{getattr(cert_info_from_scan, 'proxy_info', 'NotSet')}'")
                else:
                    cert_info_from_scan.proxied = False
                    cert_info_from_scan.proxy_info = None

                print(f"DEBUG [ScanManager.scan_target DOMAIN FLOW]: About to upsert. cert_info_from_scan.proxied={getattr(cert_info_from_scan, 'proxied', 'NotSet')}, cert_info_from_scan.proxy_info='{getattr(cert_info_from_scan, 'proxy_info', 'NotSet')}'")

                CertificateDBUtil.upsert_certificate_and_binding(session, domain, port, cert_info_from_scan, host, detect_platform=kwargs.get('detect_platform', True), check_sans=kwargs.get('check_sans', False), validate_chain=kwargs.get('validate_chain', True))
                # --- PATCH: Associate cert with SAN domains if present ---
                if hasattr(cert_info_from_scan, 'san') and cert_info_from_scan.san:
                    from infra_mgmt.utils.certificate_db import is_valid_domain
                    for san_item in cert_info_from_scan.san:
                        if is_valid_domain(san_item):
                            san_domain_obj = session.query(Domain).filter_by(domain_name=san_item).first()
                            if not san_domain_obj:
                                san_domain_obj = Domain(domain_name=san_item, created_at=datetime.now(), updated_at=datetime.now())
                                session.add(san_domain_obj)
                            if cert_info_from_scan.serial_number:
                                cert = session.query(Certificate).filter_by(serial_number=cert_info_from_scan.serial_number).first()
                                if cert and cert not in san_domain_obj.certificates:
                                    san_domain_obj.certificates.append(cert)
                                    self.logger.info(f"[SCAN] Associated certificate {cert.serial_number} with SAN domain {san_item}")
                session.commit()
                target_key = f"{domain}:{port}"
                if target_key not in self.scan_results["success"]:
                    self.scan_results["success"].append(target_key)
            else:
                # Patch: If scan_certificate fails, record as error (not just warning)
                self.scan_results["warning"].append(f"{domain}:{port} - No certificate found")
                self.scan_results["error"].append(f"{domain}:{port} - Certificate scan failed or no certificate info")
            # 2. getDNSRecords
            dns_records = []
            try:
                dns_info = self.domain_scanner.scan_domain(domain, session, get_whois=False, get_dns=True, offline_mode=is_offline)
                if dns_info and dns_info.dns_records:
                    dns_records = dns_info.dns_records
                    # Update DNS records in DB
                    existing_records = session.query(DomainDNSRecord).filter_by(domain_id=domain_obj.id).all()
                    existing_map = {(r.record_type, r.name, r.value): r for r in existing_records}
                    seen_records = set()
                    for record in dns_records:
                        record_key = (record['type'], record['name'], record['value'])
                        seen_records.add(record_key)
                        if record_key in existing_map:
                            existing_record = existing_map[record_key]
                            existing_record.ttl = record['ttl']
                            existing_record.priority = record.get('priority')
                            existing_record.updated_at = datetime.now()
                        else:
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
                    for key, record in existing_map.items():
                        if key not in seen_records:
                            session.delete(record)
                    try:
                        session.commit()
                    except Exception as e:
                        self.logger.error(f"Error committing DNS records for {domain}: {str(e)}")
                        session.rollback()
                        self.scan_results["warning"].append(f"{domain}:{port} - DNS DB error: {str(e)}")
                else:
                    self.scan_results["warning"].append(f"{domain}:{port} - No DNS records found")
            except Exception as e:
                self.scan_results["warning"].append(f"{domain}:{port} - DNS error: {str(e)}")
                session.rollback()
            # 3. getWhoIsRecords
            whois_info = None
            try:
                if is_offline:
                    self.logger.info(f"[SCAN] Offline mode: Skipping WHOIS query for domain {domain}")
                    self.scan_results["info"].append(f"{domain}:{port} - WHOIS skipped (offline mode)")
                else:
                    whois_info = self.domain_scanner.scan_domain(domain, session, get_whois=True, get_dns=False, offline_mode=is_offline)
                    if whois_info and whois_info.registrar:
                        domain_obj.registrar = whois_info.registrar
                        domain_obj.registration_date = whois_info.registration_date
                        domain_obj.expiration_date = whois_info.expiration_date
                        domain_obj.owner = whois_info.registrant
                        domain_obj.updated_at = datetime.now()
                        try:
                            session.commit()
                        except Exception as e:
                            self.logger.error(f"Error committing WHOIS info for {domain}: {str(e)}")
                            session.rollback()
                            self.scan_results["error"].append(f"{domain}:{port} - WHOIS DB error: {str(e)}")
                    else:
                        self.scan_results["error"].append(f"{domain}:{port} - No WHOIS info found")
            except Exception as e:
                self.scan_results["error"].append(f"{domain}:{port} - WHOIS error: {str(e)}")
                session.rollback()
            # 4. getIPaddresses
            try:
                ip_list = []
                import socket
                try:
                    hostname_ip = socket.getaddrinfo(domain, port, proto=socket.IPPROTO_TCP)
                    for item in hostname_ip:
                        ip_address = item[4][0]
                        if ip_address not in ip_list:
                            ip_list.append(ip_address)
                    if not ip_list:
                        self.scan_results["warning"].append(f"{domain}:{port} - No IP addresses found")
                except Exception as e:
                    self.scan_results["warning"].append(f"{domain}:{port} - IP address lookup error: {str(e)}")
            except Exception as e:
                self.scan_results["warning"].append(f"{domain}:{port} - IP address error: {str(e)}")
            # 5. getSubdomains
            try:
                subdomains = self.subdomain_scanner.scan_and_process_subdomains(
                    domain=domain,
                    session=session,
                    port=port,
                    check_whois=False,
                    check_dns=False,
                    scanned_domains=self.infra_mgmt.tracker.scanned_domains,
                    enable_ct=kwargs.get('enable_ct', True),
                    offline_mode=is_offline
                )
                # Add discovered subdomains to scan queue if not already scanned in this session
                for sub in subdomains:
                    subdomain_name = sub['domain'] if isinstance(sub, dict) and 'domain' in sub else sub
                    if not self.infra_mgmt.tracker.is_domain_scanned(subdomain_name):
                        self.add_to_queue(subdomain_name, port, session)
                if not subdomains:
                    self.scan_results["info"].append(f"{domain}:{port} - No subdomains found")
            except Exception as e:
                self.scan_results["info"].append(f"{domain}:{port} - Subdomain scan error: {str(e)}")
            # 6. detect platform (if implemented)
            # ...
            self.infra_mgmt.tracker.add_scanned_endpoint(domain, port)
            return True
        except Exception as e:
            self.logger.exception(f"Unexpected error in scan_target for {domain}:{port}: {str(e)}")
            if session is not None:
                session.rollback()
            raise
        finally:
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
            "no_cert_count": len(self.scan_results["no_cert"]),
            "info_count": len(self.scan_results["info"])
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
