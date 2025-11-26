import json
import logging
from datetime import datetime
from typing import Optional
from unittest.mock import MagicMock
from infra_mgmt.models import Certificate, Host, HostIP, CertificateBinding, CertificateScan, Domain
from infra_mgmt.constants import HOST_TYPE_SERVER, HOST_TYPE_CDN, HOST_TYPE_LOAD_BALANCER, ENV_PRODUCTION
import re

# Import enhanced deduplication functionality
from .proxy_certificate_deduplication import enhanced_deduplicate_certificate

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
        status_callback: Optional[callable] = None,
        change_id: Optional[int] = None,
        scan_type: Optional[str] = None
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

        # ENHANCED: Check for enhanced certificate deduplication first
        should_save_new, existing_cert_to_update, dedup_reason = enhanced_deduplicate_certificate(
            session, cert_info, domain, port
        )
        
        if not should_save_new and existing_cert_to_update:
            # Certificate was deduplicated - return existing certificate
            set_status(f'Certificate deduplicated: {dedup_reason}')
            logger.info(f"Certificate deduplicated for {domain}:{port}: {dedup_reason}")
            
            # Ensure the certificate is in the current session (merge if needed)
            # This prevents session identity issues when adding to collections
            if existing_cert_to_update.id:
                cert = session.merge(existing_cert_to_update)
            else:
                cert = existing_cert_to_update
            
            # Update the existing certificate's updated_at timestamp to track last scan
            cert.updated_at = datetime.now()
            
        else:
            # Check if we need to delete/replace an existing certificate
            if existing_cert_to_update:
                set_status(f'Replacing existing certificate: {dedup_reason}')
                logger.info(f"Replacing existing certificate for {domain}:{port}: {dedup_reason}")
                
                # Delete the old certificate to avoid duplicates
                session.delete(existing_cert_to_update)
                session.flush()
            
            # Proceed with normal certificate creation/update logic
            # Upsert Certificate: Primary lookup by thumbprint
            cert = session.query(Certificate).filter_by(thumbprint=cert_info.thumbprint).first()

            if cert:
                # Certificate with this thumbprint exists, update it
                set_status(f'Updating existing certificate (thumbprint: {cert_info.thumbprint[:12]}...).')
            else:
                # No certificate with this thumbprint, create a new one
                # We should also check by serial if thumbprint not found, in case of re-key with same serial (less common)
                cert_by_serial = session.query(Certificate).filter_by(serial_number=cert_info.serial_number).first()
                if cert_by_serial:
                    set_status(f'Updating existing certificate (serial: {cert_info.serial_number}), new thumbprint {cert_info.thumbprint[:12]}...')
                    cert = cert_by_serial # Use the existing cert object found by serial
                    cert.thumbprint = cert_info.thumbprint # Update its thumbprint
                else:
                    set_status(f'Creating new certificate (thumbprint: {cert_info.thumbprint[:12]}...).')
                    cert = Certificate(thumbprint=cert_info.thumbprint) # Create with the unique key
                    session.add(cert) # Add to session if new, this will be flushed later with other changes

            # Update all fields for the (now existing or newly added) certificate object
            cert.serial_number = cert_info.serial_number
            cert.common_name = cert_info.common_name
            # Convert timezone-aware datetimes to naive for SQLite compatibility
            from datetime import timezone as tz
            def to_naive_datetime(dt):
                """Convert timezone-aware datetime to naive, or return as-is if already naive or not a datetime."""
                if isinstance(dt, datetime) and dt.tzinfo is not None:
                    return dt.replace(tzinfo=None)
                return dt
            cert.valid_from = to_naive_datetime(cert_info.valid_from)
            cert.valid_until = to_naive_datetime(cert_info.expiration_date)
            cert._issuer = json.dumps(cert_info.issuer)
            cert._subject = json.dumps(cert_info.subject)
            cert._san = json.dumps(cert_info.san)
            cert.key_usage = json.dumps(cert_info.key_usage) if cert_info.key_usage else None
            cert.signature_algorithm = cert_info.signature_algorithm
            # Ensure chain_valid uses the result from the actual validation attempt if available in cert_info,
            # otherwise, it uses the validate_chain flag if cert_info doesn't have it explicitly.
            cert.chain_valid = getattr(cert_info, 'chain_valid', validate_chain) 
            cert.sans_scanned = check_sans # Update this flag
            cert.proxied = getattr(cert_info, 'proxied', False)
            cert.proxy_info = getattr(cert_info, 'proxy_info', None)
            
            # Update revocation status if available
            # Only set revocation fields if they are real values (not MagicMock objects)
            def is_not_mock(value):
                """Check if value is not a MagicMock instance."""
                return value is not None and not isinstance(value, MagicMock)
            
            revocation_status = getattr(cert_info, 'revocation_status', None)
            if is_not_mock(revocation_status):
                cert.revocation_status = revocation_status
                revocation_date = getattr(cert_info, 'revocation_date', None)
                # Only set revocation_date if it's a real datetime object (not a MagicMock)
                if revocation_date is not None and isinstance(revocation_date, datetime):
                    if revocation_date.tzinfo is not None:
                        revocation_date = revocation_date.replace(tzinfo=None)
                    cert.revocation_date = revocation_date
                else:
                    cert.revocation_date = None
                
                revocation_reason = getattr(cert_info, 'revocation_reason', None)
                cert.revocation_reason = revocation_reason if is_not_mock(revocation_reason) else None
                
                revocation_check_method = getattr(cert_info, 'revocation_check_method', None)
                if is_not_mock(revocation_check_method):
                    cert.revocation_check_method = revocation_check_method
                    cert.revocation_last_checked = datetime.now()
                    # Set OCSP cache expiration if OCSP was used
                    if revocation_check_method in ('OCSP', 'both'):
                        # Get cache expiration from OCSP result if available
                        # This would need to be passed through cert_info or checked separately
                        # For now, we'll set a default cache time
                        from datetime import timedelta
                        ocsp_cached_until = getattr(cert_info, 'ocsp_response_cached_until', None)
                        if ocsp_cached_until is not None and isinstance(ocsp_cached_until, datetime):
                            if ocsp_cached_until.tzinfo is not None:
                                ocsp_cached_until = ocsp_cached_until.replace(tzinfo=None)
                            cert.ocsp_response_cached_until = ocsp_cached_until
                        else:
                            cert.ocsp_response_cached_until = datetime.now() + timedelta(hours=24)
                else:
                    cert.revocation_check_method = None
                    cert.revocation_last_checked = None
            
            cert.updated_at = datetime.now()
            if not cert.id: # If cert.id is None, it means it's a new instance not yet flushed (or created_at not set)
                cert.created_at = datetime.now()

        # Flush certificate if it's new (doesn't have an ID yet) to ensure it has an ID for many-to-many relationships
        if cert.id is None:
            session.flush()
            # Refresh to ensure the certificate is properly in the session
            session.refresh(cert)
        
        # Ensure cert is properly in the session before associating with domains
        # Re-query to ensure it's in the current session context
        if cert.id:
            cert_in_session = session.query(Certificate).filter_by(id=cert.id).first()
            if not cert_in_session:
                # If not found, merge it into the session
                cert_in_session = session.merge(cert)
            else:
                cert_in_session = cert
        else:
            cert_in_session = cert
        
        # Associate certificate with domain (if domain_obj is a Domain)
        if domain_obj and hasattr(domain_obj, 'certificates'):
            try:
                if cert_in_session.id and cert_in_session not in domain_obj.certificates:
                    domain_obj.certificates.append(cert_in_session)
            except Exception as e:
                logger.warning(f"Error associating certificate with domain_obj: {e}")
                # Refresh the domain object and try again
                session.expire(domain_obj, ['certificates'])
                # Re-query cert to ensure it's in session
                cert_in_session = session.query(Certificate).filter_by(id=cert.id).first() if cert.id else cert
                if cert_in_session and cert_in_session.id and cert_in_session not in domain_obj.certificates:
                    domain_obj.certificates.append(cert_in_session)
        # If domain_obj is a Host, try to find a Domain with the same name and associate
        elif domain_obj and isinstance(domain_obj, Host):
            domain_name = domain_obj.name
            domain_rec = session.query(Domain).filter_by(domain_name=domain_name).first()
            if domain_rec and cert_in_session.id:
                try:
                    if cert_in_session not in domain_rec.certificates:
                        domain_rec.certificates.append(cert_in_session)
                except Exception as e:
                    logger.warning(f"Error associating certificate with domain {domain_name}: {e}")
                    session.expire(domain_rec, ['certificates'])
                    # Re-query cert to ensure it's in session
                    cert_in_session = session.query(Certificate).filter_by(id=cert.id).first() if cert.id else cert
                    if cert_in_session and cert_in_session.id and cert_in_session not in domain_rec.certificates:
                        domain_rec.certificates.append(cert_in_session)
        # For each SAN in the certificate, associate with Domain if valid
        if hasattr(cert_info, 'san') and cert_info.san and cert.id:
            # Ensure cert is properly in the session before associating with domains
            # Re-query to ensure it's in the current session context
            cert_in_session = session.query(Certificate).filter_by(id=cert.id).first()
            if not cert_in_session:
                # If not found, merge it into the session
                cert_in_session = session.merge(cert)
            else:
                cert_in_session = cert
            
            for san in cert_info.san:
                if is_valid_domain(san):
                    # Query for domain first (outside no_autoflush to allow proper session tracking)
                    san_domain = session.query(Domain).filter_by(domain_name=san).first()
                    if not san_domain:
                        san_domain = Domain(domain_name=san, created_at=datetime.now(), updated_at=datetime.now())
                        session.add(san_domain)
                        # Flush the new domain to get its ID before appending certificate
                        session.flush()
                    # Check if certificate is already associated before appending
                    # Use cert_in_session which is guaranteed to be in the current session
                    try:
                        if cert_in_session not in san_domain.certificates:
                            san_domain.certificates.append(cert_in_session)
                    except Exception as e:
                        # If there's an issue with the relationship, refresh and try again
                        logger.warning(f"Error checking certificate association for {san}, refreshing domain: {e}")
                        session.expire(san_domain, ['certificates'])
                        # Re-query cert to ensure it's in session
                        cert_in_session = session.query(Certificate).filter_by(id=cert.id).first()
                        if cert_in_session and cert_in_session not in san_domain.certificates:
                            san_domain.certificates.append(cert_in_session)
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
            port=port,
            change_id=change_id,  # Associate with change if provided
            scan_type=scan_type  # 'before' or 'after' if provided
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