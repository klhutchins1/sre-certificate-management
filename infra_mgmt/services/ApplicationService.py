from datetime import datetime
from ..models import Application, CertificateBinding, Certificate
from sqlalchemy.exc import SQLAlchemyError

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
    def update_application(session, application, name, app_type, description, owner):
        try:
            application = session.merge(application)
            application.name = name
            application.app_type = app_type
            application.description = description
            application.owner = owner
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    @staticmethod
    def delete_application(session, application):
        try:
            session.delete(application)
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    @staticmethod
    def remove_binding(session, binding):
        try:
            binding.application_id = None
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)}

    @staticmethod
    def bind_certificates(session, application_id, cert_ids, binding_type):
        try:
            success_count = 0
            for cert_id in cert_ids:
                new_binding = CertificateBinding(
                    certificate_id=cert_id,
                    application_id=application_id,
                    binding_type=binding_type,
                    last_seen=datetime.now()
                )
                session.add(new_binding)
                success_count += 1
            if success_count > 0:
                session.commit()
            return {'success': True, 'count': success_count}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)} 