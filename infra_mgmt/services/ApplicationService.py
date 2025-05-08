from datetime import datetime
from ..models import Application, CertificateBinding, Certificate
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
                app = session.query(Application).get(app_id)
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
                app = session.query(Application).get(app_id)
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
                binding = session.query(CertificateBinding).get(binding_id)
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
                app = session.query(Application).get(app_id)
                if not app:
                    return {'success': False, 'error': 'Application not found'}
                count = 0
                for cert_id in cert_ids:
                    cert = session.query(Certificate).get(cert_id)
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