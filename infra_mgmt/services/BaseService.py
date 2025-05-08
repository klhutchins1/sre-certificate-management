from contextlib import contextmanager
from infra_mgmt.utils.SessionManager import SessionManager

class BaseService:
    @contextmanager
    def session_scope(self, engine):
        """
        Provide a transactional scope around a series of operations.
        Usage:
            with self.session_scope(engine) as session:
                ...
        """
        session = None
        try:
            with SessionManager(engine) as session:
                yield session
                session.commit()
        except Exception as e:
            if session:
                session.rollback()
            raise
        finally:
            if session:
                session.close()

    def result(self, success, data=None, error=None):
        """
        Standard result object for service methods.
        """
        return {
            'success': success,
            'data': data,
            'error': error
        } 