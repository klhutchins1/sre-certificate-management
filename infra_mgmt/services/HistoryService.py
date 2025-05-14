from datetime import datetime, timedelta
from ..models import Certificate, CertificateScan, Host, HostIP, CertificateBinding, CertificateTracking
from sqlalchemy.orm import joinedload
from sqlalchemy import desc
from sqlalchemy.exc import SQLAlchemyError
import pandas as pd
from infra_mgmt.utils.SessionManager import SessionManager

class HistoryService:
    @staticmethod
    def get_host_certificate_history(engine):
        try:
            with SessionManager(engine) as session:
                hosts = session.query(Host).options(
                    joinedload(Host.ip_addresses),
                    joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate)
                ).all()
                host_options = {}
                for host in hosts:
                    for ip in host.ip_addresses:
                        key = f"{host.name} ({ip.ip_address})"
                        host_options[key] = (host.id, ip.id)
                return {'success': True, 'data': {'hosts': hosts, 'host_options': host_options}}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def get_bindings_for_host(engine, host_id, ip_id):
        try:
            with SessionManager(engine) as session:
                bindings = session.query(CertificateBinding).options(
                    joinedload(CertificateBinding.certificate)
                ).filter(
                    CertificateBinding.host_id == host_id,
                    CertificateBinding.host_ip_id == ip_id
                ).order_by(CertificateBinding.last_seen.desc()).all()
                return bindings
        except Exception as e:
            return []

    @staticmethod
    def get_scan_history(session):
        scans = session.query(CertificateScan)\
            .outerjoin(Certificate)\
            .outerjoin(Host)\
            .options(
                joinedload(CertificateScan.certificate),
                joinedload(CertificateScan.host).joinedload(Host.ip_addresses)
            )\
            .order_by(desc(CertificateScan.scan_date))\
            .all()
        return scans

    @staticmethod
    def get_cn_history(session):
        common_names = session.query(Certificate.common_name)\
            .distinct()\
            .order_by(Certificate.common_name)\
            .all()
        return [cn[0] for cn in common_names if cn[0]]

    @staticmethod
    def get_certificates_by_cn(session, selected_cn):
        certificates = session.query(Certificate)\
            .filter(Certificate.common_name == selected_cn)\
            .order_by(Certificate.valid_from.desc())\
            .all()
        return certificates

    @staticmethod
    def add_certificate_tracking_entry(session, cert_id, change_number, planned_date, status, notes):
        try:
            new_entry = CertificateTracking(
                certificate_id=cert_id,
                change_number=change_number,
                planned_change_date=datetime.combine(planned_date, datetime.min.time()),
                notes=notes,
                status=status,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            session.add(new_entry)
            session.commit()
            return {'success': True}
        except SQLAlchemyError as e:
            session.rollback()
            return {'success': False, 'error': str(e)} 