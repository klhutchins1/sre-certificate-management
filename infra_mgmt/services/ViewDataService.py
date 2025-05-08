from .BaseService import BaseService
from .CertificateService import CertificateService
from .DashboardService import DashboardService
from .DomainService import DomainService
from .SearchService import SearchService
from ..models import Certificate, CertificateBinding, Domain, IgnoredDomain, Host, HostIP, Application
from datetime import datetime, timedelta
from sqlalchemy.orm import joinedload

class ViewDataService(BaseService):
    def get_certificate_list_view_data(self, engine):
        """
        Aggregate all data needed for the certificate list view.
        Returns a dict with metrics and table_data.
        """
        cert_service = CertificateService()
        with self.session_scope(engine) as session:
            # Metrics
            try:
                total_certs = session.query(Certificate).count()
                valid_certs = session.query(Certificate).filter(Certificate.valid_until > datetime.now()).count()
                total_bindings = session.query(CertificateBinding).count()
            except Exception as e:
                return self.result(False, error=f"Error fetching metrics: {str(e)}")
            # Table data
            try:
                table_data = []
                certificates = session.query(Certificate).all()
                for cert in certificates:
                    table_data.append({
                        "Common Name": str(cert.common_name),
                        "Serial Number": str(cert.serial_number),
                        "Valid From": cert.valid_from.strftime("%Y-%m-%d"),
                        "Valid Until": cert.valid_until.strftime("%Y-%m-%d"),
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                        "Bindings": int(len(cert.certificate_bindings)),
                        "_id": int(cert.id)
                    })
            except Exception as e:
                return self.result(False, error=f"Error fetching table data: {str(e)}")
            metrics = {
                "total_certs": total_certs,
                "valid_certs": valid_certs,
                "total_bindings": total_bindings
            }
            return self.result(True, data={"metrics": metrics, "table_data": table_data})

    def get_dashboard_view_data(self, engine):
        """
        Aggregate all data needed for the dashboard view.
        Returns a dict with metrics, certificate timeline, and domain timeline data.
        """
        with self.session_scope(engine) as session:
            try:
                metrics = DashboardService.get_dashboard_metrics(session)
                cert_timeline = DashboardService.get_certificate_timeline_data(session)
                domain_timeline = DashboardService.get_domain_timeline_data(metrics['root_domains'])
                return self.result(True, data={
                    "metrics": metrics,
                    "cert_timeline": cert_timeline,
                    "domain_timeline": domain_timeline
                })
            except Exception as e:
                return self.result(False, error=f"Error fetching dashboard data: {str(e)}")

    def get_domain_list_view_data(self, engine):
        """
        Aggregate all data needed for the domain list view.
        Returns a dict with visible_domains, metrics, and ignored_patterns.
        """
        with self.session_scope(engine) as session:
            try:
                domains = session.query(Domain)\
                    .options(
                        joinedload(Domain.certificates),
                        joinedload(Domain.dns_records),
                        joinedload(Domain.subdomains)
                    )\
                    .order_by(Domain.domain_name).all()
                ignored_domains = session.query(IgnoredDomain).all()
                ignored_patterns = [d.pattern for d in ignored_domains]
                # Filter out ignored domains
                visible_domains = []
                for domain in domains:
                    should_show = True
                    for pattern in ignored_patterns:
                        if pattern.startswith('*') and pattern.endswith('*'):
                            search_term = pattern.strip('*')
                            if search_term.lower() in domain.domain_name.lower():
                                should_show = False
                                break
                        elif pattern.startswith('*.'):
                            suffix = pattern[2:]
                            if domain.domain_name.endswith(suffix):
                                should_show = False
                                break
                        elif pattern == domain.domain_name:
                            should_show = False
                            break
                    if should_show:
                        visible_domains.append(domain)
                # Metrics
                total_domains = len(visible_domains)
                active_domains = sum(1 for d in visible_domains if d.is_active)
                expiring_soon = sum(1 for d in visible_domains 
                                  if d.expiration_date and d.expiration_date <= datetime.now() + timedelta(days=30)
                                  and d.expiration_date > datetime.now())
                expired = sum(1 for d in visible_domains 
                             if d.expiration_date and d.expiration_date <= datetime.now())
                metrics = {
                    "total_domains": total_domains,
                    "active_domains": active_domains,
                    "expiring_soon": expiring_soon,
                    "expired": expired
                }
                return self.result(True, data={
                    "visible_domains": visible_domains,
                    "metrics": metrics,
                    "ignored_patterns": ignored_patterns
                })
            except Exception as e:
                return self.result(False, error=f"Error fetching domain list data: {str(e)}")

    def get_hosts_list_view_data(self, engine):
        """
        Aggregate all data needed for the hosts list view.
        Returns a dict with hosts, binding_data, and metrics.
        """
        with self.session_scope(engine) as session:
            try:
                hosts = session.query(Host)\
                    .options(
                        joinedload(Host.ip_addresses),
                        joinedload(Host.certificate_bindings)
                            .joinedload(CertificateBinding.certificate)
                            .joinedload(Certificate.scans),
                        joinedload(Host.scans)  # Eagerly load Host.scans
                    )\
                    .all()
                total_hosts = session.query(Host).count()
                total_ips = session.query(HostIP).count()
                total_certs = session.query(Certificate).count()
                # Build binding_data for both views
                binding_data = []
                now = datetime.now()
                for host in hosts:
                    # Hostname view
                    if host.certificate_bindings:
                        for binding in host.certificate_bindings:
                            binding_data.append({
                                'Hostname': host.name,
                                'IP Address': binding.host_ip.ip_address if binding.host_ip else 'No IP',
                                'Port': binding.port,
                                'Certificate': binding.certificate.common_name if binding.certificate else 'No Certificate',
                                'Platform': binding.platform or 'Unknown',
                                'Status': 'Valid' if binding.certificate and binding.certificate.valid_until > now else 'Expired',
                                'Expires': binding.certificate.valid_until if binding.certificate else None,
                                'Last Seen': binding.last_seen,
                                '_id': binding.id,
                                'Source': '🔒 Manual' if getattr(binding, 'manually_added', False) else '🔍 Scanned'
                            })
                    else:
                        binding_data.append({
                            'Hostname': host.name,
                            'IP Address': host.ip_addresses[0].ip_address if host.ip_addresses else 'No IP',
                            'Port': None,
                            'Certificate': 'No Certificate',
                            'Platform': 'Unknown',
                            'Status': 'No Certificate',
                            'Expires': None,
                            'Last Seen': None,
                            '_id': None,
                            'Source': ''
                        })
                metrics = {
                    'total_hosts': total_hosts,
                    'total_ips': total_ips,
                    'total_certs': total_certs
                }
                return self.result(True, data={
                    'hosts': hosts,
                    'binding_data': binding_data,
                    'metrics': metrics
                })
            except Exception as e:
                return self.result(False, error=f"Error fetching hosts list data: {str(e)}")

    def get_applications_list_view_data(self, engine):
        """
        Aggregate all data needed for the applications list view.
        Returns a dict with applications, app_data, and metrics.
        """
        with self.session_scope(engine) as session:
            try:
                applications = session.query(Application)\
                    .options(
                        joinedload(Application.certificate_bindings)
                            .joinedload(CertificateBinding.certificate),
                        joinedload(Application.certificate_bindings)
                            .joinedload(CertificateBinding.host),
                        joinedload(Application.certificate_bindings)
                            .joinedload(CertificateBinding.host_ip)
                    )\
                    .all()
                total_apps = session.query(Application).count()
                total_bindings = session.query(CertificateBinding).filter(CertificateBinding.application_id.isnot(None)).count()
                now = datetime.now()
                valid_certs = session.query(CertificateBinding).join(CertificateBinding.certificate).filter(
                    CertificateBinding.application_id.isnot(None),
                    Certificate.valid_until > now
                ).count()
                app_data = []
                for app in applications:
                    cert_count = len(app.certificate_bindings)
                    valid_certs_count = sum(1 for binding in app.certificate_bindings if binding.certificate and binding.certificate.valid_until > now)
                    app_data.append({
                        'Application': app.name,
                        'Type': app.app_type,
                        'Description': app.description or '',
                        'Owner': app.owner,
                        'Certificates': cert_count,
                        'Valid Certificates': valid_certs_count,
                        'Expired Certificates': cert_count - valid_certs_count,
                        'Created': app.created_at,
                        '_id': app.id
                    })
                metrics = {
                    'total_apps': total_apps,
                    'total_bindings': total_bindings,
                    'valid_certs': valid_certs
                }
                return self.result(True, data={
                    'applications': applications,
                    'app_data': app_data,
                    'metrics': metrics
                })
            except Exception as e:
                return self.result(False, error=f"Error fetching applications list data: {str(e)}")

    def get_search_view_data(self, engine, query, search_type, status_filter, platform_filter):
        """
        Aggregate all data needed for the search view.
        Returns a dict with search results (certificates, hosts, etc.).
        """
        with self.session_scope(engine) as session:
            try:
                results = SearchService.perform_search(session, query, search_type, status_filter, platform_filter)
                return self.result(True, data=results)
            except Exception as e:
                return self.result(False, error=f"Error fetching search results: {str(e)}") 