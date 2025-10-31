from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy import func, case, select
from sqlalchemy.orm import selectinload
from ..models import Certificate, Host, Domain, Application

class DashboardService:
    def __init__(self):
        pass

    @staticmethod
    def get_root_domain(domain_name: str) -> str:
        parts = domain_name.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain_name

    @staticmethod
    def get_domain_hierarchy(domains):
        domain_tree = defaultdict(list)
        all_domain_names = {domain.domain_name for domain in domains}
        root_domains = set()
        for domain in domains:
            root_name = DashboardService.get_root_domain(domain.domain_name)
            root_domains.add(root_name)
        for root_name in root_domains:
            root_domain = next((d for d in domains if d.domain_name == root_name), None)
            if root_domain:
                domain_tree[root_name] = []
            else:
                subdomains = [d for d in domains if DashboardService.get_root_domain(d.domain_name) == root_name]
                if subdomains:
                    domain_tree[root_name] = []
        for domain in domains:
            root_name = DashboardService.get_root_domain(domain.domain_name)
            if root_name in domain_tree and domain.domain_name != root_name:
                domain_tree[root_name].append(domain)
        for root_name in domain_tree:
            domain_tree[root_name].sort(key=lambda d: d.domain_name)
        return domain_tree

    @staticmethod
    def get_root_domains(session, domains=None):
        if domains is None:
            domains = session.query(Domain).all()
        root_domain_names = {DashboardService.get_root_domain(d.domain_name) for d in domains}
        root_domains = [d for d in domains if d.domain_name in root_domain_names]
        domains_to_update = []
        for domain in root_domains:
            if not domain.registration_date or not domain.expiration_date:
                domain.registration_date = datetime(2007, 5, 31, 21, 27, 42)
                domain.expiration_date = datetime(2025, 5, 31, 21, 27, 42)
                domain.updated_at = datetime.now()
                domains_to_update.append(domain)
        if domains_to_update:
            session.bulk_save_objects(domains_to_update, update_changed_only=True)
            session.commit()
        return root_domains

    @staticmethod
    def get_dashboard_metrics(session):
        thirty_days = datetime.now() + timedelta(days=30)
        now = datetime.now()
        cert_metrics_query = select(
            func.count(func.distinct(Certificate.id)).label('total_certs'),
            func.sum(
                case(
                    (Certificate.valid_until <= thirty_days, 1),
                    else_=0
                )
            ).label('expiring_certs')
        ).select_from(Certificate)
        cert_result = session.execute(cert_metrics_query).first()
        domain_count = session.query(func.count(func.distinct(Domain.id))).scalar()
        app_count = session.query(func.count(func.distinct(Application.id))).scalar()
        host_count = session.query(func.count(func.distinct(Host.id))).scalar()
        domains = session.query(Domain).options(
            selectinload(Domain.certificates)
        ).all()
        root_domain_names = {DashboardService.get_root_domain(d.domain_name) for d in domains}
        root_domains = [d for d in domains if d.domain_name in root_domain_names]
        metrics = {
            'total_certs': cert_result.total_certs or 0,
            'expiring_certs': cert_result.expiring_certs or 0,
            'total_domains': domain_count or 0,
            'total_root_domains': len(root_domains),
            'expiring_domains': sum(
                1 for d in root_domains
                if d.expiration_date and now < d.expiration_date <= thirty_days
            ),
            'total_apps': app_count or 0,
            'total_hosts': host_count or 0,
            'total_subdomains': (domain_count or 0) - len(root_domains),
            'root_domains': root_domains
        }
        return metrics

    @staticmethod
    def get_certificate_timeline_data(session, limit=100):
        """
        Get certificate timeline data, ensuring each certificate has a unique name
        to prevent gaps in the timeline visualization caused by duplicate common names.
        
        Args:
            session: SQLAlchemy session
            limit: Maximum number of certificates to return
            
        Returns:
            List of dictionaries with 'Name', 'Start', and 'End' keys
        """
        certs = session.query(
            Certificate.id,
            Certificate.common_name,
            Certificate.serial_number,
            Certificate.valid_from,
            Certificate.valid_until
        ).order_by(Certificate.valid_until).limit(limit).all()
        
        # Convert to list of dictionaries, ensuring unique names
        timeline_data = []
        common_name_counts = {}
        
        for cert in certs:
            cn = cert.common_name or f"Unknown (ID: {cert.id})"
            
            # Track how many times we've seen this common name
            if cn not in common_name_counts:
                common_name_counts[cn] = 0
            common_name_counts[cn] += 1
            
            # Make name unique by appending serial number if we have duplicates
            if common_name_counts[cn] > 1:
                # Use serial number (first 8 chars) to make it unique
                serial_suffix = f" ({cert.serial_number[:8]}...)" if cert.serial_number else f" (ID: {cert.id})"
                unique_name = f"{cn}{serial_suffix}"
            else:
                unique_name = cn
            
            timeline_data.append({
                'Name': unique_name,
                'Start': cert.valid_from,
                'End': cert.valid_until
            })
        
        return timeline_data

    @staticmethod
    def get_domain_timeline_data(root_domains):
        domain_data = [
            {
                'Name': d.domain_name,
                'Start': d.registration_date,
                'End': d.expiration_date
            }
            for d in root_domains
            if d.registration_date and d.expiration_date
        ]
        return domain_data 