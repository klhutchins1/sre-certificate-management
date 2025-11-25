from sqlalchemy.orm import sessionmaker, joinedload
from datetime import datetime

from infra_mgmt.constants import ENV_PRODUCTION, HOST_TYPE_SERVER
from infra_mgmt.models import Certificate, CertificateBinding, Domain, Host, HostIP
from ..scanner.scan_manager import ScanManager
from ..scanner.utils import is_ip_address
from typing import List, Tuple, Dict, Any

class ScanService:
    """
    Service layer for orchestrating domain/certificate scans.
    Handles input validation, scan session management, progress, and result aggregation.
    Delegates scanning to ScanManager and exposes a clean interface for the view/UI.
    """
    def __init__(self, engine):
        """
        Initialize ScanService with a SQLAlchemy engine and ScanManager.
        Args:
            engine: SQLAlchemy engine instance
        """
        self.engine = engine
        self.scan_manager = ScanManager()
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": [],
            "db_only": [],
            "info_only": []  # New category for domains with partial info
        }
        self.session_factory = sessionmaker(bind=engine)
        # Scan control state
        self.scan_paused = False
        self.scan_stopped = False
        print(f"[DEBUG] ScanService initialized: {id(self)}")
    
    def pause_scan(self):
        """Pause the current scan."""
        self.scan_paused = True
        # Also pause the scan manager
        if hasattr(self.scan_manager, 'pause_scan'):
            self.scan_manager.pause_scan()
    
    def resume_scan(self):
        """Resume a paused scan."""
        self.scan_paused = False
        # Also resume the scan manager
        if hasattr(self.scan_manager, 'resume_scan'):
            self.scan_manager.resume_scan()
    
    def stop_scan(self):
        """Stop the current scan."""
        self.scan_stopped = True
        self.scan_paused = False
        # Also stop the scan manager
        if hasattr(self.scan_manager, 'stop_scan'):
            self.scan_manager.stop_scan()
    
    def reset_scan_control(self):
        """Reset scan control state."""
        self.scan_paused = False
        self.scan_stopped = False

    def validate_and_prepare_targets(self, scan_input: str) -> Tuple[List[Tuple[str, int]], List[str]]:
        """
        Parse and validate scan input, returning a list of (hostname, port) tuples and a list of validation errors.
        Args:
            scan_input (str): Raw user input (one target per line)
        Returns:
            Tuple[List[Tuple[str, int]], List[str]]: (valid_targets, errors)
        """
        valid_targets = []
        errors = []
        entries = [h.strip() for h in scan_input.split('\n') if h.strip()]
        with self.session_factory() as session:
            def is_ip_address_str(addr):
                try:
                    import ipaddress
                    ipaddress.ip_address(addr)
                    return True
                except Exception:
                    return False
            for entry in entries:
                is_valid, hostname, port, error = self.scan_manager.process_scan_target(entry, session)
                if is_valid:
                    valid_targets.append((hostname, port))
                else:
                    errors.append(f"Invalid entry '{entry}': {error}")
        return valid_targets, errors

    def run_scan(self, targets: List[Tuple[str, int]], options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestrate the scan process for the given targets and options.
        Args:
            targets: List of (hostname, port) tuples
            options: Dict of scan options (e.g., check_whois, check_dns, etc.)
        Returns:
            Dict[str, Any]: Aggregated scan results
        """
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": [],
            "db_only": [],
            "info_only": []  # New category for domains with partial info
        }
        with self.session_factory() as session:
            def get_root_domain(domain_name: str) -> str:
                if not domain_name or not isinstance(domain_name, str):
                    return ""
                # Only return root domain for valid domain names, not IPs
                try:
                    import ipaddress
                    ipaddress.ip_address(domain_name)
                    return domain_name
                except Exception:
                    parts = domain_name.split('.')
                    if len(parts) >= 2:
                        return '.'.join(parts[-2:])
                    return domain_name
            root_targets = set()
            for hostname, port in targets:
                # Only add root domains for valid domain names, not IPs
                try:
                    import ipaddress
                    ipaddress.ip_address(hostname)
                    continue  # Skip adding root for IPs
                except Exception:
                    root = get_root_domain(hostname)
                    root_targets.add((root, port))
            for hostname, port in targets:
                self.scan_manager.add_to_queue(hostname, port, session)
            for root, port in root_targets:
                self.scan_manager.add_to_queue(root, port, session)
            # Main scan loop: process the queue until empty
            # This ensures that any new targets (e.g., discovered hostnames) are also scanned
            # Check both ScanService and ScanManager stop flags
            while self.scan_manager.has_pending_targets() and not self.scan_stopped and not getattr(self.scan_manager, 'scan_stopped', False):
                # Check for stop condition first (before pause check)
                if self.scan_stopped or getattr(self.scan_manager, 'scan_stopped', False):
                    if options.get("status_container"):
                        options["status_container"].text("Scan stopped by user")
                    if options.get("progress_container"):
                        options["progress_container"].text("Scan stopped by user")
                    break
                
                # Check for pause condition - check both ScanService and ScanManager
                is_paused = self.scan_paused or getattr(self.scan_manager, 'scan_paused', False)
                if is_paused:
                    if options.get("status_container"):
                        options["status_container"].text("Scan paused. Click Resume to continue.")
                    if options.get("progress_container"):
                        options["progress_container"].text("Scan paused. Click Resume to continue.")
                    # Wait in a loop while paused, checking for stop frequently
                    import time
                    while (self.scan_paused or getattr(self.scan_manager, 'scan_paused', False)) and not self.scan_stopped and not getattr(self.scan_manager, 'scan_stopped', False):
                        time.sleep(0.1)  # Small delay to prevent busy waiting
                        # Update UI periodically while paused
                        if options.get("status_container"):
                            options["status_container"].text("Scan paused. Click Resume to continue.")
                    if self.scan_stopped or getattr(self.scan_manager, 'scan_stopped', False):
                        if options.get("status_container"):
                            options["status_container"].text("Scan stopped by user")
                        if options.get("progress_container"):
                            options["progress_container"].text("Scan stopped by user")
                        break
                
                # Check for stop again before processing next target
                if self.scan_stopped or getattr(self.scan_manager, 'scan_stopped', False):
                    break
                
                target = self.scan_manager.get_next_target()
                if not target:
                    break
                try:
                    scan_result = self.scan_manager.scan_target(
                        session=session,
                        domain=target[0],
                        port=target[1],
                        **options
                    )
                    # Always check for registrar info after scan, regardless of scan_result
                    db_domain = session.query(Domain).filter_by(domain_name=target[0]).first()
                    db_key = f"{target[0]}:{target[1]}"
                    has_registrar = db_domain and (db_domain.registrar or db_domain.registration_date or db_domain.expiration_date or db_domain.owner)
                    already_in_results = any([
                        db_key in self.scan_results[cat] for cat in ["success", "db_only", "info_only"]
                    ])
                    if has_registrar and not already_in_results:
                        self.scan_results["info_only"].append(db_key)
                except Exception as e:
                    self.scan_results["error"].append(f"{target[0]}:{target[1]} - {str(e)}")
                    session.rollback()
                # Check for stop after each target (before updating progress)
                if self.scan_stopped or getattr(self.scan_manager, 'scan_stopped', False):
                    if options.get("status_container"):
                        options["status_container"].text("Scan stopped by user")
                    if options.get("progress_container"):
                        options["progress_container"].text("Scan stopped by user")
                    break
                
                completed = len(self.scan_manager.infra_mgmt.tracker.scanned_endpoints)
                remaining = len(self.scan_manager.infra_mgmt.tracker.scan_queue)
                total = completed + remaining
                progress = completed / total if total > 0 else 1.0
                if options.get("progress_container"):
                    options["progress_container"].progress(progress)
                    if self.scan_stopped or getattr(self.scan_manager, 'scan_stopped', False):
                        options["progress_container"].text("Scan stopped by user")
                    elif self.scan_paused or getattr(self.scan_manager, 'scan_paused', False):
                        options["progress_container"].text("Scan paused. Click Resume to continue.")
                    else:
                        options["progress_container"].text(
                            f"Scanning target {completed} of {total} (Remaining in queue: {remaining})"
                        )
                if options.get("status_container"):
                    if self.scan_stopped or getattr(self.scan_manager, 'scan_stopped', False):
                        options["status_container"].text("Scan stopped by user")
                    elif self.scan_paused or getattr(self.scan_manager, 'scan_paused', False):
                        options["status_container"].text("Scan paused. Click Resume to continue.")
                    else:
                        options["status_container"].text(
                            f"Scanning {target[0]}:{target[1]}"
                        )
            session.commit()
            if options.get("progress_container"):
                options["progress_container"].progress(1.0)
                options["progress_container"].text("Scan completed!")
            if options.get("status_container"):
                options["status_container"].text("Scan completed!")

        # After the scan loop, before returning results:
        # Initialize final results with what ScanService itself might have populated during the scan loop
        final_scan_results = {
            "success": [],
            "error": list(set(self.scan_results.get("error", []))),  # Errors caught by ScanService directly
            "warning": [],
            "no_cert": [],
            "db_only": list(set(self.scan_results.get("db_only", []))), # Populated by ScanService
            "info_only": list(set(self.scan_results.get("info_only", []))) # Populated by ScanService
        }

        # Merge results from ScanManager
        manager_results = self.scan_manager.scan_results
        final_scan_results["success"] = list(set(final_scan_results.get("success", [])) | set(manager_results.get("success", [])))
        final_scan_results["error"]   = list(set(final_scan_results.get("error", []))   | set(manager_results.get("error", [])))
        final_scan_results["warning"] = list(set(final_scan_results.get("warning", [])) | set(manager_results.get("warning", [])))
        final_scan_results["no_cert"] = list(set(final_scan_results.get("no_cert", [])) | set(manager_results.get("no_cert", [])))
        
        # Merge ScanManager's general "info" category into ScanService's "info_only"
        manager_info = manager_results.get("info", [])
        final_scan_results["info_only"] = list(set(final_scan_results.get("info_only", [])) | set(manager_info))

        self.scan_results = final_scan_results
        return self.scan_results

    def get_scan_results(self) -> Dict[str, Any]:
        """
        Get the latest scan results.
        Returns:
            Dict[str, Any]: Scan results (success, error, warning, no_cert)
        """
        return self.scan_results

    def get_scan_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the current/last scan session.
        Returns:
            Dict[str, Any]: Stats (history size, success count, error count, etc.)
        """
        return self.scan_manager.get_scan_stats()

    def get_certificates_for_domain(self, engine, domain_name: str):
        """
        Aggregate all certificates for a given domain or host, including direct and binding-based certificates.
        Args:
            engine: SQLAlchemy engine
            domain_name: Domain or host name
        Returns:
            List of Certificate objects (deduplicated)
        """
        Session = sessionmaker(bind=engine)
        with Session() as session:
            certificates = []
            # Try domain first
            domain_obj = session.query(Domain).filter_by(domain_name=domain_name).first()
            if domain_obj:
                # Eagerly load certificate_bindings for each certificate
                cert_ids = [c.id for c in domain_obj.certificates]
                certs = session.query(Certificate).options(joinedload(Certificate.certificate_bindings)).filter(Certificate.id.in_(cert_ids)).all() if cert_ids else []
                certificates.extend(certs)
                # Also get certificates from bindings via host
                host = session.query(Host).filter_by(name=domain_name).first()
                if host:
                    bindings = session.query(CertificateBinding).options(joinedload(CertificateBinding.certificate).joinedload(Certificate.certificate_bindings)).filter_by(host=host).all()
                    cert_from_bindings = [b.certificate for b in bindings if b.certificate]
                    certificates.extend(cert_from_bindings)
            else:
                # Try as host
                host = session.query(Host).filter_by(name=domain_name).first()
                if host:
                    bindings = session.query(CertificateBinding).options(joinedload(CertificateBinding.certificate).joinedload(Certificate.certificate_bindings)).filter_by(host=host).all()
                    certificates = [b.certificate for b in bindings if b.certificate]
            # Deduplicate while preserving order
            seen = set()
            deduped = []
            for cert in certificates:
                if cert and cert.id not in seen:
                    deduped.append(cert)
                    seen.add(cert.id)
            print(f"DEBUG: get_certificates_for_domain({domain_name}) found {len(deduped)} certificates: {[c.serial_number for c in deduped]}")
            return deduped

    def get_dns_records_for_domain(self, engine, domain_name: str):
        """
        Aggregate all DNS records for a given domain.
        Args:
            engine: SQLAlchemy engine
            domain_name: Domain name
        Returns:
            List of DomainDNSRecord objects
        """
        from sqlalchemy.orm import sessionmaker
        Session = sessionmaker(bind=engine)
        with Session() as session:
            domain_obj = session.query(Domain).filter_by(domain_name=domain_name).first()
            if domain_obj:
                return list(domain_obj.dns_records)
            return []

    def load_domain_data(self, engine, domain_name):
        try:
            Session = sessionmaker(bind=engine)
            with Session() as session:
                # Check if this is an IP address
                if is_ip_address(domain_name):
                    host = session.query(Host).options(
                        joinedload(Host.ip_addresses),
                        joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate).joinedload(Certificate.certificate_bindings)
                    ).filter_by(name=domain_name).first()
                    if not host:
                        host = Host(
                            name=domain_name,
                            host_type=HOST_TYPE_SERVER,
                            environment=ENV_PRODUCTION,
                            last_seen=datetime.now()
                        )
                        host_ip = HostIP(
                            host=host,
                            ip_address=domain_name,
                            is_active=True,
                            last_seen=datetime.now()
                        )
                        session.add(host)
                        session.add(host_ip)
                        session.flush()
                    return {'success': True, 'data': host}
                # Not an IP address, proceed with domain lookup
                domain = session.query(Domain).options(
                    joinedload(Domain.certificates).joinedload(Certificate.certificate_bindings),
                    joinedload(Domain.dns_records)
                ).filter_by(domain_name=domain_name).first()
                if not domain:
                    return {'success': False, 'error': 'Domain not found'}
                return {'success': True, 'data': domain}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_domain_display_data(self, engine, domain_name: str) -> dict:
        """
        Return all display data for a domain or host as a dict of primitives for the UI.
        Args:
            engine: SQLAlchemy engine
            domain_name: Domain or IP to load
        Returns:
            dict: {success: bool, data: dict, error: str}
        """
        Session = sessionmaker(bind=engine)
        try:
            with Session() as session:
                if is_ip_address(domain_name):
                    host = session.query(Host).filter_by(name=domain_name).first()
                    if not host:
                        return {"success": False, "error": "Host not found"}
                    # Get hostnames (reverse DNS)
                    hostnames = []
                    try:
                        import dns.resolver
                        import dns.reversename
                        addr = dns.reversename.from_address(host.name)
                        answers = dns.resolver.resolve(addr, "PTR")
                        hostnames = [str(rdata).rstrip('.') for rdata in answers]
                    except Exception:
                        pass
                    # Get network
                    network = None
                    try:
                        import ipaddress
                        ip_obj = ipaddress.ip_address(host.name)
                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            network = str(ipaddress.ip_network(f"{host.name}/24", strict=False))
                        else:
                            network = str(ipaddress.ip_network(f"{host.name}/64", strict=False))
                    except Exception:
                        pass
                    # Get certificate bindings and ports
                    bindings = session.query(CertificateBinding).filter_by(host_id=host.id).all()
                    ports = [b.port for b in bindings if b.port]
                    return {
                        "success": True,
                        "data": {
                            "type": "host",
                            "name": host.name,
                            "host_type": host.host_type,
                            "environment": host.environment,
                            "last_seen": host.last_seen.strftime("%Y-%m-%d %H:%M:%S") if host.last_seen else None,
                            "hostnames": hostnames,
                            "network": network,
                            "cert_count": len(bindings),
                            "ports": ports
                        }
                    }
                # Not an IP address, treat as domain
                domain = session.query(Domain).filter_by(domain_name=domain_name).first()
                if not domain:
                    return {"success": False, "error": "Domain not found"}
                # Get DNS records
                dns_records = [
                    {
                        "type": r.record_type,
                        "name": r.name,
                        "value": r.value,
                        "ttl": r.ttl,
                        "priority": r.priority
                    }
                    for r in domain.dns_records
                ] if domain.dns_records else []
                return {
                    "success": True,
                    "data": {
                        "type": "domain",
                        "domain_name": domain.domain_name,
                        "registrar": domain.registrar,
                        "registration_date": domain.registration_date.strftime("%Y-%m-%d") if domain.registration_date else None,
                        "expiration_date": domain.expiration_date.strftime("%Y-%m-%d") if domain.expiration_date else None,
                        "owner": domain.owner,
                        "cert_count": len(domain.certificates),
                        "dns_count": len(domain.dns_records),
                        "dns_records": dns_records,
                    }
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
