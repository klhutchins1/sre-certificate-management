from datetime import datetime
from ..models import Application, CertificateBinding, Certificate, Host, HostIP
from ..constants import HOST_TYPE_SERVER, HOST_TYPE_VIRTUAL, ENV_INTERNAL, ENV_PRODUCTION
from sqlalchemy.exc import SQLAlchemyError
from infra_mgmt.utils.SessionManager import SessionManager

class ApplicationService:
    @staticmethod
    def add_application(session, name, app_type, description, owner):
        try:
            # Check if application name already exists
            existing_app = session.query(Application).filter(Application.name == name).first()
            if existing_app:
                return {'success': False, 'error': f"An application with the name '{name}' already exists"}
            new_app = Application(
                name=name,
                app_type=app_type,
                description=description,
                owner=owner,
                created_at=datetime.now()
            )
            session.add(new_app)
            session.commit()
            return {'success': True, 'app_id': new_app.id}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    @staticmethod
    def update_application(engine, app_id, new_name, new_type, new_description, new_owner):
        try:
            with SessionManager(engine) as session:
                app = session.get(Application, app_id)
                if not app:
                    return {'success': False, 'error': 'Application not found'}
                app.name = new_name
                app.app_type = new_type
                app.description = new_description
                app.owner = new_owner
                session.commit()
                return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def delete_application(engine, app_id):
        try:
            with SessionManager(engine) as session:
                app = session.get(Application, app_id)
                if not app:
                    return {'success': False, 'error': 'Application not found'}
                session.delete(app)
                session.commit()
                return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def remove_binding(engine, binding_id):
        try:
            with SessionManager(engine) as session:
                binding = session.get(CertificateBinding, binding_id)
                if not binding:
                    return {'success': False, 'error': 'Binding not found'}
                session.delete(binding)
                session.commit()
                return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def bind_certificates(engine, app_id, cert_ids, binding_type):
        try:
            with SessionManager(engine) as session:
                app = session.get(Application, app_id)
                if not app:
                    return {'success': False, 'error': 'Application not found'}
                count = 0
                for cert_id in cert_ids:
                    cert = session.get(Certificate, cert_id)
                    if not cert:
                        continue
                    binding = CertificateBinding(
                        application_id=app_id,
                        certificate_id=cert_id,
                        binding_type=binding_type,
                        last_seen=datetime.now()
                    )
                    session.add(binding)
                    count += 1
                session.commit()
                return {'success': True, 'count': count}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def get_available_certificates(engine, app_id):
        try:
            with SessionManager(engine) as session:
                from ..models import Certificate, CertificateBinding
                available_certs = (
                    session.query(Certificate)
                    .join(CertificateBinding, isouter=True)
                    .filter(
                        (CertificateBinding.application_id.is_(None)) |
                        (CertificateBinding.application_id != app_id)
                    )
                    .all()
                )
                return {'success': True, 'data': available_certs}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def get_available_hosts(engine):
        """Get all hosts from the database for selection."""
        try:
            from sqlalchemy.orm import joinedload
            with SessionManager(engine) as session:
                hosts = session.query(Host).options(
                    joinedload(Host.ip_addresses)
                ).order_by(Host.name).all()
                return {'success': True, 'data': hosts}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def bind_certificate_with_host(engine, app_id, cert_id, host_id, host_ip_id, port, platform, binding_type):
        """Bind a certificate to an application with a specific host and IP."""
        try:
            with SessionManager(engine) as session:
                app = session.get(Application, app_id)
                if not app:
                    return {'success': False, 'error': 'Application not found'}
                
                cert = session.get(Certificate, cert_id)
                if not cert:
                    return {'success': False, 'error': 'Certificate not found'}
                
                host = session.get(Host, host_id)
                if not host:
                    return {'success': False, 'error': 'Host not found'}
                
                host_ip = None
                if host_ip_id:
                    host_ip = session.get(HostIP, host_ip_id)
                    if not host_ip:
                        return {'success': False, 'error': 'Host IP not found'}
                
                # Check for existing binding
                existing = session.query(CertificateBinding).filter_by(
                    application_id=app_id,
                    certificate_id=cert_id,
                    host_id=host_id,
                    host_ip_id=host_ip_id,
                    port=port if binding_type == 'IP' else None
                ).first()
                
                if existing:
                    return {'success': False, 'error': 'Binding already exists'}
                
                binding = CertificateBinding(
                    application_id=app_id,
                    certificate_id=cert_id,
                    host_id=host_id,
                    host_ip_id=host_ip_id,
                    port=port if binding_type == 'IP' else None,
                    binding_type=binding_type,
                    platform=platform,
                    last_seen=datetime.now()
                )
                session.add(binding)
                session.commit()
                return {'success': True, 'binding_id': binding.id}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def bind_certificate_with_domain(engine, app_id, cert_id, hostname, ip_address, port, platform, binding_type):
        """Bind a certificate to an application with a domain/hostname (creates host if needed)."""
        try:
            with SessionManager(engine) as session:
                app = session.get(Application, app_id)
                if not app:
                    return {'success': False, 'error': 'Application not found'}
                
                cert = session.get(Certificate, cert_id)
                if not cert:
                    return {'success': False, 'error': 'Certificate not found'}
                
                # Create or get host
                host = session.query(Host).filter_by(name=hostname).first()
                if not host:
                    host = Host(
                        name=hostname,
                        host_type=HOST_TYPE_VIRTUAL if binding_type != 'IP' else HOST_TYPE_SERVER,
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                    session.flush()
                
                # Create or get host IP if provided
                host_ip = None
                if ip_address:
                    host_ip = session.query(HostIP).filter_by(
                        host_id=host.id,
                        ip_address=ip_address
                    ).first()
                    if not host_ip:
                        host_ip = HostIP(
                            host_id=host.id,
                            ip_address=ip_address,
                            last_seen=datetime.now()
                        )
                        session.add(host_ip)
                        session.flush()
                
                # Check for existing binding
                existing = session.query(CertificateBinding).filter_by(
                    application_id=app_id,
                    certificate_id=cert_id,
                    host_id=host.id,
                    host_ip_id=host_ip.id if host_ip else None,
                    port=port if binding_type == 'IP' else None
                ).first()
                
                if existing:
                    return {'success': False, 'error': 'Binding already exists'}
                
                binding = CertificateBinding(
                    application_id=app_id,
                    certificate_id=cert_id,
                    host_id=host.id,
                    host_ip_id=host_ip.id if host_ip else None,
                    port=port if binding_type == 'IP' else None,
                    binding_type=binding_type,
                    platform=platform,
                    last_seen=datetime.now()
                )
                session.add(binding)
                session.commit()
                return {'success': True, 'binding_id': binding.id}
        except SQLAlchemyError as e:
            return {'success': False, 'error': str(e)} 