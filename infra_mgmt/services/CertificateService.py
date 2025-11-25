from sqlalchemy import func, desc
from infra_mgmt.models import Certificate, Domain, Host, HostIP, CertificateBinding
from infra_mgmt.constants import HOST_TYPE_SERVER, HOST_TYPE_VIRTUAL, ENV_INTERNAL
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import Session
from infra_mgmt.utils.SessionManager import SessionManager

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

    def get_certificate_details(self, engine, cert_id):
        try:
            with SessionManager(engine) as session:
                cert = session.get(Certificate, cert_id)
                if not cert:
                    return {'success': False, 'error': 'Certificate not found'}
                return {'success': True, 'data': cert}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_certificate_bindings(self, cert_id, session):
        """Fetch all bindings for a given certificate ID."""
        cert = session.query(Certificate).options(
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.application),
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host),
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host_ip)
        ).filter(Certificate.id == cert_id).first()
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
    
    def get_certificate_bindings_for_scan(self, cert_id, session, binding_ids=None):
        """
        Get scan targets from certificate bindings.
        
        Args:
            cert_id: Certificate ID
            session: SQLAlchemy session
            binding_ids: Optional list of binding IDs to scan (if None, scans all IP bindings)
            
        Returns:
            dict: {
                'success': bool,
                'targets': list of tuples (hostname/ip: str, port: int),
                'bindings': list of binding info dicts,
                'count': int
            }
        """
        try:
            cert = session.query(Certificate).options(
                joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host),
                joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host_ip)
            ).filter(Certificate.id == cert_id).first()
            
            if not cert:
                return {'success': False, 'error': 'Certificate not found', 'targets': [], 'bindings': [], 'count': 0}
            
            targets = []
            binding_infos = []
            
            for binding in cert.certificate_bindings:
                # Only scan IP-based bindings (not JWT or CLIENT bindings)
                if binding.binding_type != 'IP':
                    continue
                
                # Filter by binding_ids if specified
                if binding_ids is not None and binding.id not in binding_ids:
                    continue
                
                # Determine target hostname/IP and port
                target_host = None
                target_port = binding.port or 443  # Default to 443 if port not specified
                
                # Prefer hostname over IP if both available
                if binding.host and binding.host.name:
                    target_host = binding.host.name
                elif binding.host_ip and binding.host_ip.ip_address:
                    target_host = binding.host_ip.ip_address
                else:
                    # Skip bindings without hostname or IP
                    continue
                
                targets.append((target_host, target_port))
                binding_infos.append({
                    'id': binding.id,
                    'host_name': binding.host.name if binding.host else None,
                    'host_ip': binding.host_ip.ip_address if binding.host_ip else None,
                    'port': target_port,
                    'platform': binding.platform,
                    'last_seen': binding.last_seen,
                })
            
            return {
                'success': True,
                'targets': targets,
                'bindings': binding_infos,
                'count': len(targets)
            }
            
        except Exception as e:
            import logging
            logging.getLogger(__name__).exception(f"Error getting certificate bindings for scan: {str(e)}")
            return {'success': False, 'error': str(e), 'targets': [], 'bindings': [], 'count': 0}

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

    def get_manual_entry_form_data(self, engine):
        try:
            # If you need to fetch dropdown options or other data for the form, do it here
            # For now, just return an empty dict or any required data structure
            form_data = {}
            return {'success': True, 'data': form_data}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def delete_certificate_binding(self, binding_id, session):
        """
        Delete a certificate binding (usage record) by its ID.
        Args:
            binding_id (int): The ID of the CertificateBinding to delete
            session: SQLAlchemy session
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            binding = session.get(CertificateBinding, binding_id)
            if not binding:
                return {'success': False, 'error': 'Binding not found'}
            session.delete(binding)
            session.commit()
            return {'success': True}
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error deleting certificate binding: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def update_proxy_override(self, cert_id, real_serial_number, real_thumbprint, 
                            real_issuer, real_subject, real_valid_from, real_valid_until, 
                            override_notes, session):
        """
        Update proxy override information for a certificate.
        
        Args:
            cert_id (int): Certificate ID
            real_serial_number (str): Real serial number
            real_thumbprint (str): Real thumbprint
            real_issuer (dict): Real issuer information
            real_subject (dict): Real subject information
            real_valid_from (datetime): Real valid from date
            real_valid_until (datetime): Real valid until date
            override_notes (str): Notes about the override
            session: SQLAlchemy session
            
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            cert = session.get(Certificate, cert_id)
            if not cert:
                return {'success': False, 'error': 'Certificate not found'}
            
            # Update override fields
            cert.real_serial_number = real_serial_number
            cert.real_thumbprint = real_thumbprint
            cert.real_issuer_dict = real_issuer
            cert.real_subject_dict = real_subject
            cert.real_valid_from = real_valid_from
            cert.real_valid_until = real_valid_until
            cert.override_notes = override_notes
            cert.override_created_at = datetime.now()
            
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error updating proxy override: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def clear_proxy_override(self, cert_id, session):
        """
        Clear proxy override information for a certificate.
        
        Args:
            cert_id (int): Certificate ID
            session: SQLAlchemy session
            
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            cert = session.get(Certificate, cert_id)
            if not cert:
                return {'success': False, 'error': 'Certificate not found'}
            
            # Clear override fields
            cert.real_serial_number = None
            cert.real_thumbprint = None
            cert.real_issuer = None
            cert.real_subject = None
            cert.real_valid_from = None
            cert.real_valid_until = None
            cert.override_notes = None
            cert.override_created_at = None
            
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error clearing proxy override: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def promote_real_values_to_primary(self, cert_id, session):
        """
        Promote real certificate values to be the primary values, replacing proxy values.
        This moves real_serial_number -> serial_number, real_thumbprint -> thumbprint, etc.
        The proxy values are preserved in the real_* fields for reference.
        
        Args:
            cert_id (int): Certificate ID
            session: SQLAlchemy session
            
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            cert = session.get(Certificate, cert_id)
            if not cert:
                return {'success': False, 'error': 'Certificate not found'}
            
            if not cert.real_serial_number or not cert.real_thumbprint:
                return {'success': False, 'error': 'Real certificate values not set. Please provide real serial number and thumbprint first.'}
            
            # Validate that real date fields are set (required for non-nullable columns)
            if cert.real_valid_from is None or cert.real_valid_until is None:
                return {'success': False, 'error': 'Real certificate date values not set. Please provide real valid_from and valid_until dates first.'}
            
            # Validate that real issuer and subject are set (to prevent None assignment to primary fields)
            if cert.real_issuer is None or cert.real_subject is None:
                return {'success': False, 'error': 'Real certificate issuer and subject values not set. Please provide real issuer and subject information first.'}
            
            # Check for uniqueness of real serial number and thumbprint before promoting
            existing_by_serial = session.query(Certificate).filter(
                Certificate.serial_number == cert.real_serial_number,
                Certificate.id != cert_id
            ).first()
            if existing_by_serial:
                return {'success': False, 'error': f'Serial number {cert.real_serial_number} already exists for another certificate'}
            
            existing_by_thumbprint = session.query(Certificate).filter(
                Certificate.thumbprint == cert.real_thumbprint,
                Certificate.id != cert_id
            ).first()
            if existing_by_thumbprint:
                return {'success': False, 'error': f'Thumbprint {cert.real_thumbprint} already exists for another certificate'}
            
            # Store current proxy values in real_* fields (swap them)
            # This preserves the proxy values for reference
            proxy_serial = cert.serial_number
            proxy_thumbprint = cert.thumbprint
            proxy_issuer = cert._issuer
            proxy_subject = cert._subject
            proxy_valid_from = cert.valid_from
            proxy_valid_until = cert.valid_until
            
            # Promote real values to primary
            cert.serial_number = cert.real_serial_number
            cert.thumbprint = cert.real_thumbprint
            cert._issuer = cert.real_issuer
            cert._subject = cert.real_subject
            cert.valid_from = cert.real_valid_from
            cert.valid_until = cert.real_valid_until
            
            # Store old proxy values in real_* fields (for reference/history)
            cert.real_serial_number = proxy_serial
            cert.real_thumbprint = proxy_thumbprint
            cert.real_issuer = proxy_issuer
            cert.real_subject = proxy_subject
            cert.real_valid_from = proxy_valid_from
            cert.real_valid_until = proxy_valid_until
            
            # Update notes to indicate the promotion
            if cert.override_notes:
                cert.override_notes += f"\n[Promoted to primary on {datetime.now().strftime('%Y-%m-%d %H:%M')}]"
            else:
                cert.override_notes = f"Real values promoted to primary on {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            
            # Keep proxied flag as True since it was detected as proxy
            # But now the primary values are the real ones
            
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error promoting real values: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def update_certificate_serial_thumbprint(self, cert_id, serial_number, thumbprint, session):
        """
        Update the primary serial number and thumbprint for a certificate.
        Useful for directly correcting proxy certificate values.
        
        Args:
            cert_id (int): Certificate ID
            serial_number (str): New serial number
            thumbprint (str): New thumbprint
            session: SQLAlchemy session
            
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            cert = session.get(Certificate, cert_id)
            if not cert:
                return {'success': False, 'error': 'Certificate not found'}
            
            if not serial_number or not serial_number.strip():
                return {'success': False, 'error': 'Serial number is required'}
            if not thumbprint or not thumbprint.strip():
                return {'success': False, 'error': 'Thumbprint is required'}
            
            # Check for uniqueness
            existing_by_serial = session.query(Certificate).filter(
                Certificate.serial_number == serial_number,
                Certificate.id != cert_id
            ).first()
            if existing_by_serial:
                return {'success': False, 'error': f'Serial number {serial_number} already exists for another certificate'}
            
            existing_by_thumbprint = session.query(Certificate).filter(
                Certificate.thumbprint == thumbprint,
                Certificate.id != cert_id
            ).first()
            if existing_by_thumbprint:
                return {'success': False, 'error': f'Thumbprint {thumbprint} already exists for another certificate'}
            
            # Update values
            cert.serial_number = serial_number.strip()
            cert.thumbprint = thumbprint.strip()
            
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error updating certificate serial/thumbprint: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def update_tracking_entry(self, tracking_id, change_number, planned_date, status, notes, session):
        """
        Update a certificate tracking entry.
        
        Args:
            tracking_id (int): Tracking entry ID
            change_number (str): Change/ticket number
            planned_date (datetime): Planned change date
            status (str): Change status
            notes (str): Change notes
            session: SQLAlchemy session
            
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            from infra_mgmt.models import CertificateTracking
            tracking = session.get(CertificateTracking, tracking_id)
            if not tracking:
                return {'success': False, 'error': 'Tracking entry not found'}
            
            # Update fields
            tracking.change_number = change_number
            tracking.planned_change_date = planned_date
            tracking.status = status
            tracking.notes = notes
            tracking.updated_at = datetime.now()
            
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error updating tracking entry: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def delete_tracking_entry(self, tracking_id, session):
        """
        Delete a certificate tracking entry.
        
        Args:
            tracking_id (int): Tracking entry ID
            session: SQLAlchemy session
            
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            from infra_mgmt.models import CertificateTracking
            tracking = session.get(CertificateTracking, tracking_id)
            if not tracking:
                return {'success': False, 'error': 'Tracking entry not found'}
            
            session.delete(tracking)
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error deleting tracking entry: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def clear_proxy_flag(self, cert_id, session):
        """
        Clear the proxy flag from a certificate if it was incorrectly marked as a proxy.
        
        Args:
            cert_id (int): Certificate ID
            session: SQLAlchemy session
            
        Returns:
            dict: { 'success': bool, 'error': str (if any) }
        """
        try:
            cert = session.get(Certificate, cert_id)
            if not cert:
                return {'success': False, 'error': 'Certificate not found'}
            
            # Clear proxy flag and info
            cert.proxied = False
            cert.proxy_info = None
            
            session.commit()
            return {'success': True}
            
        except Exception as e:
            session.rollback()
            import logging
            logging.getLogger(__name__).exception(f"Error clearing proxy flag: {str(e)}")
            return {'success': False, 'error': str(e)}