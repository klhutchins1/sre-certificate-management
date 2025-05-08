from datetime import datetime
from ..models import Host, HostIP, CertificateBinding
from sqlalchemy.exc import SQLAlchemyError

class HostService:
    @staticmethod
    def add_host_with_ips(session, hostname, host_type, environment, description, ip_addresses):
        """
        Create a new host and associated IP addresses.
        Args:
            session: SQLAlchemy session
            hostname: str
            host_type: str
            environment: str
            description: str
            ip_addresses: list of str
        Returns:
            dict: { 'success': bool, 'host_id': int (if success), 'error': str (if error) }
        """
        try:
            new_host = Host(
                name=hostname,
                host_type=host_type,
                environment=environment,
                description=description,
                last_seen=datetime.now()
            )
            session.add(new_host)
            session.flush()  # Get the new host ID
            for ip in ip_addresses:
                ip = ip.strip()
                if ip:
                    new_ip = HostIP(
                        host_id=new_host.id,
                        ip_address=ip,
                        is_active=True,
                        last_seen=datetime.now()
                    )
                    session.add(new_ip)
            session.commit()
            return {'success': True, 'host_id': new_host.id}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    @staticmethod
    def update_binding_platform(session, binding_id, platform):
        """
        Update the platform for a certificate binding.
        Args:
            session: SQLAlchemy session
            binding_id: int
            platform: str
        Returns:
            dict: { 'success': bool, 'error': str (if error) }
        """
        try:
            binding = session.query(CertificateBinding).get(binding_id)
            if not binding:
                return {'success': False, 'error': 'Binding not found'}
            binding.platform = platform
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    @staticmethod
    def delete_binding(session, binding_id):
        """
        Delete a certificate binding by ID.
        Args:
            session: SQLAlchemy session
            binding_id: int
        Returns:
            dict: { 'success': bool, 'error': str (if error) }
        """
        try:
            binding = session.query(CertificateBinding).get(binding_id)
            if not binding:
                return {'success': False, 'error': 'Binding not found'}
            session.delete(binding)
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
