import json
import logging
from datetime import datetime
from typing import Optional
from infra_mgmt.models import Certificate, Host, HostIP, CertificateBinding, CertificateScan, Domain
from infra_mgmt.constants import HOST_TYPE_SERVER, HOST_TYPE_CDN, HOST_TYPE_LOAD_BALANCER, ENV_PRODUCTION
import re

class CertificateDBUtil:
    """
    Utility class for upserting certificate, host, host IP, binding, and scan records in the database.
    Centralizes logic for creating/updating Certificate, Host, HostIP, CertificateBinding, and CertificateScan records.
    """
    @staticmethod
    def upsert_certificate_and_binding(
        session,
        domain: str,
        port: int,
        cert_info,
        domain_obj=None,
        detect_platform: bool = False,
        check_sans: bool = False,
        validate_chain: bool = True,
        status_callback: Optional[callable] = None
    ) -> Certificate:
        """
        Create or update certificate, host, host IP, binding, and scan records for a given domain and cert_info.
        Args:
            session: SQLAlchemy session
            domain (str): Domain name
            port (int): Port number
            cert_info: CertificateInfo object
            domain_obj: Optional Domain SQLAlchemy object
            detect_platform (bool): Whether to update platform info
            check_sans (bool): Whether SANs were checked
            validate_chain (bool): Whether to validate chain
            status_callback (callable): Optional status update function
        Returns:
            Certificate: The upserted Certificate object
        """
        logger = logging.getLogger(__name__)
        def set_status(msg):
            if status_callback:
                status_callback(msg)
        # Upsert Certificate
        cert = session.query(Certificate).filter_by(serial_number=cert_info.serial_number).first()
        if not cert:
            set_status(f'Found new certificate for {domain}...')
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
                updated_at=datetime.now(),
                proxied=getattr(cert_info, 'proxied', False),
                proxy_info=getattr(cert_info, 'proxy_info', None)
            )
            session.add(cert)
        else:
            set_status(f'Updating existing certificate for {domain}...')
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
            cert.proxied = getattr(cert_info, 'proxied', False)
            cert.proxy_info = getattr(cert_info, 'proxy_info', None)
        # Associate certificate with domain (if domain_obj is a Domain)
        if domain_obj and hasattr(domain_obj, 'certificates') and cert not in domain_obj.certificates:
            domain_obj.certificates.append(cert)
        # If domain_obj is a Host, try to find a Domain with the same name and associate
        elif domain_obj and isinstance(domain_obj, Host):
            domain_name = domain_obj.name
            domain_rec = session.query(Domain).filter_by(domain_name=domain_name).first()
            if domain_rec and cert not in domain_rec.certificates:
                domain_rec.certificates.append(cert)
        # For each SAN in the certificate, associate with Domain if valid
        if hasattr(cert_info, 'san') and cert_info.san:
            for san in cert_info.san:
                if is_valid_domain(san):
                    san_domain = session.query(Domain).filter_by(domain_name=san).first()
                    if not san_domain:
                        san_domain = Domain(domain_name=san, created_at=datetime.now(), updated_at=datetime.now())
                        session.add(san_domain)
                    if cert not in san_domain.certificates:
                        san_domain.certificates.append(cert)
        # Upsert Host
        host = session.query(Host).filter_by(name=domain).first()
        if not host:
            set_status(f'Creating host record for {domain}...')
            host_type = HOST_TYPE_SERVER
            if cert_info.platform:
                if cert_info.platform in ["Cloudflare", "Akamai"]:
                    host_type = HOST_TYPE_CDN
                elif cert_info.platform == "F5":
                    host_type = HOST_TYPE_LOAD_BALANCER
            host = Host(
                name=domain,
                host_type=host_type,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
        else:
            host.last_seen = datetime.now()
            if cert_info.platform:
                if cert_info.platform in ["Cloudflare", "Akamai"] and host.host_type != HOST_TYPE_CDN:
                    host.host_type = HOST_TYPE_CDN
                elif cert_info.platform == "F5" and host.host_type != HOST_TYPE_LOAD_BALANCER:
                    host.host_type = HOST_TYPE_LOAD_BALANCER
        # Upsert HostIP
        if cert_info.ip_addresses:
            set_status(f'Updating IP addresses for {domain}...')
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
                    for ip in host.ip_addresses:
                        if ip.ip_address == ip_addr:
                            ip.last_seen = datetime.now()
                            ip.is_active = True
        # Upsert CertificateBinding
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
            set_status(f'Creating certificate binding for {domain}:{port}...')
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
        try:
            session.flush()
            logger.info(f"[CERT DB] Flushed certificate and binding for {domain}:{port}")
        except Exception as e:
            logger.exception(f"Error during session.flush() for {domain}:{port}: {e}")
            raise
        return cert 

def is_valid_domain(name):
    pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
    return re.match(pattern, name) is not None 

def detect_proxy_certificate(cert_info, settings):
    """
    Checks if the given certificate matches known proxy CA fingerprints, subjects, or serial numbers.
    Args:
        cert_info: CertificateInfo object (must have issuer, fingerprint, serial_number)
        settings: Settings instance (for proxy_detection config)
    Returns:
        (is_proxy: bool, reason: str)
    """
    if not cert_info:
        return False, None
    if not settings.get("proxy_detection.enabled", True):
        return False, None
    # Get config
    proxy_fingerprints = settings.get("proxy_detection.ca_fingerprints") or []
    proxy_subjects = settings.get("proxy_detection.ca_subjects") or []
    proxy_serials = settings.get("proxy_detection.ca_serials") or []
    # Defensive: ensure all are lists of strings
    if not isinstance(proxy_fingerprints, list):
        proxy_fingerprints = []
    else:
        proxy_fingerprints = [str(fp) for fp in proxy_fingerprints if fp]
    if not isinstance(proxy_subjects, list):
        proxy_subjects = []
    else:
        proxy_subjects = [str(s) for s in proxy_subjects if s]
    if not isinstance(proxy_serials, list):
        proxy_serials = []
    else:
        proxy_serials = [str(sn) for sn in proxy_serials if sn]
    # Check fingerprint
    if hasattr(cert_info, 'fingerprint') and cert_info.fingerprint:
        if cert_info.fingerprint in proxy_fingerprints:
            return True, f"Matched proxy CA fingerprint: {cert_info.fingerprint}"
    # Check subject (issuer)
    issuer_str = None
    if hasattr(cert_info, 'issuer') and cert_info.issuer:
        if isinstance(cert_info.issuer, dict):
            # Try to get a string representation
            issuer_str = cert_info.issuer.get('rfc4514_string') or cert_info.issuer.get('common_name')
            if not issuer_str:
                issuer_str = str(cert_info.issuer)
        elif isinstance(cert_info.issuer, str):
            issuer_str = cert_info.issuer
        if issuer_str:
            for proxy_subj in proxy_subjects:
                if proxy_subj in issuer_str:
                    return True, f"Matched proxy CA subject: {proxy_subj} in {issuer_str}"
    # Check serial number
    if hasattr(cert_info, 'serial_number') and cert_info.serial_number:
        if str(cert_info.serial_number) in proxy_serials:
            return True, f"Matched proxy CA serial number: {cert_info.serial_number}"
    return False, None 