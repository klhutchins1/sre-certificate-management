from sqlalchemy import func, desc
from ..models import Certificate, Domain, Host, HostIP, CertificateBinding, HOST_TYPE_VIRTUAL, HOST_TYPE_SERVER, ENV_INTERNAL
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from sqlalchemy.orm import joinedload

class CertificateService:
    def __init__(self, repository=None):
        self.repository = repository

    def get_certificate_list(self, session):
        """Fetch all certificates with their domains for display."""
        certificates = session.query(
            Certificate.id,
            Certificate.common_name,
            Certificate.valid_from,
            Certificate.valid_until,
            Certificate.chain_valid,
            func.group_concat(Domain.domain_name).label('domains')
        ).join(
            Certificate.domains
        ).group_by(
            Certificate.id
        ).order_by(
            desc(Certificate.valid_until)
        ).all()

        certs_data = [
            {
                'Common Name': cert.common_name,
                'Valid From': cert.valid_from.strftime('%Y-%m-%d'),
                'Valid Until': cert.valid_until.strftime('%Y-%m-%d'),
                'Status': '✅' if cert.chain_valid else '❌',
                'Domains': cert.domains.split(',') if cert.domains else []
            }
            for cert in certificates
        ]
        return certs_data

    def get_certificate_details(self, session, cert_id):
        """Fetch detailed information for a specific certificate by ID."""
        cert = session.query(Certificate).get(cert_id)
        if not cert:
            return None
        return {
            'Common Name': cert.common_name,
            'Valid From': cert.valid_from.strftime('%Y-%m-%d'),
            'Valid Until': cert.valid_until.strftime('%Y-%m-%d'),
            'Chain Valid': cert.chain_valid,
            'Serial Number': cert.serial_number,
            'Signature Algorithm': cert.signature_algorithm,
            'Issuer': cert.issuer,
            'Subject': cert.subject,
            'Key Usage': cert.key_usage,
            'SAN': cert.san if cert.san else [],
        }

    def get_certificate_bindings(self, cert_id, session):
        """Fetch all bindings for a given certificate ID."""
        cert = session.query(Certificate).options(
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.application),
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host),
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host_ip)
        ).get(cert_id)
        if not cert:
            return []
        bindings = []
        for binding in cert.certificate_bindings:
            bindings.append({
                'id': binding.id,
                'binding_type': binding.binding_type,
                'platform': binding.platform,
                'host_name': binding.host.name if binding.host else None,
                'host_ip': binding.host_ip.ip_address if binding.host_ip else None,
                'port': binding.port,
                'application_id': binding.application_id,
                'last_seen': binding.last_seen,
            })
        return bindings

    def add_host_to_certificate(self, cert_id, hostname, ip, port, platform, binding_type, session):
        """Add a new host binding to a certificate."""
        try:
            # Create or get host
            host = session.query(Host).filter_by(name=hostname).first()
            if not host:
                host = Host(
                    name=hostname,
                    host_type=HOST_TYPE_VIRTUAL if binding_type != 'IP' else HOST_TYPE_SERVER,
                    environment=ENV_INTERNAL,
                    last_seen=datetime.now()
                )
                session.add(host)
                session.flush()
            # Create HostIP if provided
            host_ip = None
            if ip:
                host_ip = session.query(HostIP).filter_by(
                    host_id=host.id,
                    ip_address=ip
                ).first()
                if not host_ip:
                    host_ip = HostIP(
                        host_id=host.id,
                        ip_address=ip,
                        last_seen=datetime.now()
                    )
                    session.add(host_ip)
                    session.flush()
            # Create binding
            binding = CertificateBinding(
                host_id=host.id,
                host_ip_id=host_ip.id if host_ip else None,
                certificate_id=cert_id,
                port=port if binding_type == 'IP' else None,
                binding_type=binding_type,
                platform=platform,
                last_seen=datetime.now()
            )
            session.add(binding)
            session.commit()
            return {'success': True, 'binding_id': binding.id}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    def add_usage_record_to_certificate(self, cert_id, platform, binding_type_label, hostname, ip, port, session):
        """
        Add a usage record (binding) to a certificate, with input validation and binding type mapping.
        Args:
            cert_id (int): Certificate ID
            platform (str): Platform name
            binding_type_label (str): User-facing binding type label (e.g., 'IP-Based Usage')
            hostname (str): Hostname or application/service name
            ip (str): IP address (optional)
            port (int): Port (optional)
            session: SQLAlchemy session
        Returns:
            dict: { 'success': bool, 'error': str (if any), 'binding_id': int (if success) }
        """
        # Validate input
        if not hostname or not hostname.strip():
            return {'success': False, 'error': 'Hostname or service/application name is required.'}
        if binding_type_label == 'IP-Based Usage':
            if not ip or not ip.strip():
                return {'success': False, 'error': 'IP address is required for IP-Based Usage.'}
            if not port or not (1 <= port <= 65535):
                return {'success': False, 'error': 'Valid port is required for IP-Based Usage.'}
        # Map binding type
        binding_type_map = {
            'IP-Based Usage': 'IP',
            'Application Usage': 'JWT',
            'Client Certificate Usage': 'CLIENT'
        }
        if binding_type_label not in binding_type_map:
            return {'success': False, 'error': f'Unknown binding type: {binding_type_label}'}
        binding_type = binding_type_map[binding_type_label]
        # Call lower-level method
        result = self.add_host_to_certificate(
            cert_id, hostname, ip, port, platform, binding_type, session
        )
        return result

    def add_manual_certificate(self, cert_type, common_name, serial_number, thumbprint, valid_from, valid_until, platform, session):
        """
        Create and save a manually entered certificate to the database, with validation and error handling.
        Args:
            cert_type (str): Type of certificate (e.g., 'SSL/TLS', 'JWT', 'Client')
            common_name (str): Common Name
            serial_number (str): Serial Number
            thumbprint (str): Thumbprint/Fingerprint
            valid_from (date): Valid From date
            valid_until (date): Valid Until date
            platform (str): Platform (optional)
            session: SQLAlchemy session
        Returns:
            dict: { 'success': bool, 'error': str (if any), 'certificate_id': int (if success) }
        """
        import json
        from datetime import datetime
        # Basic validation
        if not common_name or not common_name.strip():
            return {'success': False, 'error': 'Common Name is required.'}
        if not serial_number or not serial_number.strip():
            return {'success': False, 'error': 'Serial Number is required.'}
        if not thumbprint or not thumbprint.strip():
            return {'success': False, 'error': 'Thumbprint is required.'}
        if not valid_from or not valid_until:
            return {'success': False, 'error': 'Valid From and Valid Until dates are required.'}
        if valid_from > valid_until:
            return {'success': False, 'error': 'Valid From date cannot be after Valid Until date.'}
        try:
            cert = Certificate(
                serial_number=serial_number,
                thumbprint=thumbprint,
                common_name=common_name,
                valid_from=datetime.combine(valid_from, datetime.min.time()),
                valid_until=datetime.combine(valid_until, datetime.max.time()),
                sans_scanned=False,
                _san=json.dumps([])
            )
            session.add(cert)
            session.commit()
            return {'success': True, 'certificate_id': cert.id}
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error saving certificate: {str(e)}")
            return {'success': False, 'error': str(e)}

    def delete_certificate(self, cert, session):
        """
        Delete a certificate from the database, handling dependencies and errors.
        Args:
            cert (Certificate): The certificate object to delete
            session: SQLAlchemy session
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            # Optionally, check for dependencies (bindings, scans, etc.)
            # If you want to prevent deletion with dependencies, add logic here
            session.delete(cert)
            session.commit()
            return {'success': True}
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error deleting certificate: {str(e)}")
            return {'success': False, 'error': str(e)}
