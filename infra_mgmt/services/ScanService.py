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
            "no_cert": []
        }
        self.session_factory = sessionmaker(bind=engine)

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
        self.scan_manager.reset_scan_state()
        self.scan_results = {
            "success": [],
            "error": [],
            "warning": [],
            "no_cert": []
        }
        with self.session_factory() as session:
            # --- Ensure root domains are also scanned ---
            def get_root_domain(domain_name: str) -> str:
                if not domain_name or not isinstance(domain_name, str):
                    return ""
                parts = domain_name.split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:])
                return domain_name

            # Collect all root domains from targets
            root_targets = set()
            for hostname, port in targets:
                root = get_root_domain(hostname)
                root_targets.add((root, port))
            # Add initial targets to the scan queue
            for hostname, port in targets:
                self.scan_manager.add_to_queue(hostname, port, session)
            # Add root domains to the scan queue (if not already present)
            for root, port in root_targets:
                self.scan_manager.add_to_queue(root, port, session)
            while self.scan_manager.has_pending_targets():
                target = self.scan_manager.get_next_target()
                if not target:
                    break
                # Scan the target first
                try:
                    self.scan_manager.scan_target(
                        session=session,
                        domain=target[0],
                        port=target[1],
                        **options
                    )
                except Exception as e:
                    self.scan_results["error"].append(f"{target[0]}:{target[1]} - {str(e)}")
                    session.rollback()
                # Now update progress and status (but do NOT set to complete here)
                completed = len(self.scan_manager.infra_mgmt.tracker.scanned_endpoints)
                remaining = len(self.scan_manager.infra_mgmt.tracker.scan_queue)
                total = completed + remaining
                progress = completed / total if total > 0 else 1.0
                if options.get("progress_container"):
                    options["progress_container"].progress(progress)
                    options["progress_container"].text(
                        f"Scanning target {completed} of {total} (Remaining in queue: {remaining}) [{target[0]}:{target[1]}]"
                    )
                if options.get("status_container"):
                    options["status_container"].text(
                        f"Scanning {target[0]}:{target[1]} (Completed: {completed}, Remaining: {remaining})"
                    )
            # After all scans, set progress to complete
            session.commit()
            if options.get("progress_container"):
                options["progress_container"].progress(1.0)
                options["progress_container"].text("Scan completed!")
            if options.get("status_container"):
                options["status_container"].text("Scan completed!")
        # Copy results from scan_manager
        self.scan_results = dict(self.scan_manager.scan_results)
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
                        "dns_count": len(domain.dns_records)
                    }
                }
        except Exception as e:
            return {"success": False, "error": str(e)}
