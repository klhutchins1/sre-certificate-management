from .BaseService import BaseService
from .CertificateService import CertificateService
from .DashboardService import DashboardService
from .DomainService import DomainService
from ..models import Certificate, CertificateBinding, Domain, IgnoredDomain, Host, HostIP, Application
from datetime import datetime, timedelta
from sqlalchemy.orm import joinedload
import pandas as pd
from st_aggrid import JsCode
from infra_mgmt.services.SearchService import SearchService
import logging

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
                df = pd.DataFrame(table_data)
                column_config = {
                    "Common Name": {"minWidth": 200, "flex": 2},
                    "Serial Number": {"minWidth": 150, "flex": 1},
                    "Valid From": {"type": ["dateColumnFilter"], "minWidth": 120, "valueFormatter": "value ? new Date(value).toLocaleDateString() : ''"},
                    "Valid Until": {"type": ["dateColumnFilter"], "minWidth": 120, "valueFormatter": "value ? new Date(value).toLocaleDateString() : ''", "cellClass": JsCode("""
                        function(params) {
                            if (!params.data) return ['ag-date-cell'];
                            if (params.data.Status === 'Expired') return ['ag-date-cell', 'ag-date-cell-expired'];
                            return ['ag-date-cell'];
                        }
                    """)},
                    "Status": {"minWidth": 100, "cellClass": JsCode("""
                        function(params) {
                            if (!params.data) return [];
                            if (params.value === 'Expired') return ['ag-status-expired'];
                            if (params.value === 'Valid') return ['ag-status-valid'];
                            return [];
                        }
                    """)},
                    "Bindings": {"type": ["numericColumn"], "minWidth": 100, "cellClass": 'ag-numeric-cell'},
                    "_id": {"hide": True}
                }
                metrics = {
                    "total_certs": total_certs,
                    "valid_certs": valid_certs,
                    "total_bindings": total_bindings
                }
                return self.result(True, data={"df": df, "column_config": column_config, "metrics": metrics})
            except Exception as e:
                return self.result(False, error=f"Error fetching table data: {str(e)}")

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

    def get_host_list_view_data(self, engine):
        with self.session_scope(engine) as session:
            try:
                hosts = session.query(Host).all()
                table_data = []
                for host in hosts:
                    table_data.append({
                        "Hostname": host.name,
                        "IP Addresses": ', '.join(ip.ip_address for ip in getattr(host, 'ip_addresses', [])),
                        "Type": host.host_type,
                        "Environment": host.environment,
                        "Description": host.description or "",
                        "Last Seen": host.last_seen.strftime("%Y-%m-%d %H:%M") if host.last_seen else "",
                        "_id": int(host.id)
                    })
                df = pd.DataFrame(table_data)
                column_config = {
                    "Hostname": {"minWidth": 200, "flex": 2},
                    "IP Addresses": {"minWidth": 200, "flex": 2},
                    "Type": {"minWidth": 120},
                    "Environment": {"minWidth": 120},
                    "Description": {"minWidth": 200},
                    "Last Seen": {"minWidth": 150, "valueFormatter": "value ? new Date(value).toLocaleString() : ''"},
                    "_id": {"hide": True}
                }
                # Add metrics
                total_hosts = len(hosts)
                total_ips = sum(len(getattr(host, 'ip_addresses', [])) for host in hosts)
                total_certs = sum(len(getattr(host, 'certificate_bindings', [])) for host in hosts)
                metrics = {
                    "total_hosts": total_hosts,
                    "total_ips": total_ips,
                    "total_certs": total_certs
                }
                return self.result(True, data={"df": df, "column_config": column_config, "metrics": metrics})
            except Exception as e:
                return self.result(False, error=f"Error fetching host table data: {str(e)}")

    def get_applications_list_view_data(self, engine):
        with self.session_scope(engine) as session:
            try:
                applications = session.query(Application).all()
                table_data = []
                for app in applications:
                    table_data.append({
                        "Name": app.name,
                        "Type": getattr(app, 'app_type', ''),
                        "Description": app.description or "",
                        "Owner": app.owner or "",
                        "_id": int(app.id)
                    })
                df = pd.DataFrame(table_data)
                column_config = {
                    "Name": {"minWidth": 200, "flex": 2},
                    "Type": {"minWidth": 120},
                    "Description": {"minWidth": 200},
                    "Owner": {"minWidth": 120},
                    "_id": {"hide": True}
                }
                return self.result(True, data={"df": df, "column_config": column_config, "view_type": "All Applications"})
            except Exception as e:
                return self.result(False, error=f"Error fetching application table data: {str(e)}")

    def get_search_view_data(self, engine, query, search_type, status_filter, platform_filter):
        logger = logging.getLogger(__name__)
        with self.session_scope(engine) as session:
            try:
                # Use SearchService for all search types
                results = SearchService.perform_search(session, query, search_type, status_filter, platform_filter)
                table_data = []
                # Certificates
                for cert in results.get('certificates', []):
                    table_data.append({
                        "type": "certificate",
                        "Common Name": cert.common_name,
                        "Serial Number": cert.serial_number,
                        "Valid From": cert.valid_from.strftime("%Y-%m-%d"),
                        "Valid Until": cert.valid_until.strftime("%Y-%m-%d"),
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                        "Bindings": len(cert.certificate_bindings),
                        "_id": cert.id
                    })
                # Hosts
                for host in results.get('hosts', []):
                    table_data.append({
                        "type": "host",
                        "Hostname": host.name,
                        "Type": getattr(host, 'host_type', ''),
                        "Environment": getattr(host, 'environment', ''),
                        "Description": getattr(host, 'description', ''),
                        "Last Seen": host.last_seen.strftime("%Y-%m-%d %H:%M") if host.last_seen else "",
                        "_id": host.id
                    })
                df = pd.DataFrame(table_data)
                # Build column config
                column_config = {
                    "Common Name": {"minWidth": 200, "flex": 2},
                    "Serial Number": {"minWidth": 150, "flex": 1},
                    "Valid From": {"type": ["dateColumnFilter"], "minWidth": 120, "valueFormatter": "value ? new Date(value).toLocaleDateString() : ''"},
                    "Valid Until": {"type": ["dateColumnFilter"], "minWidth": 120, "valueFormatter": "value ? new Date(value).toLocaleDateString() : ''"},
                    "Status": {"minWidth": 100},
                    "Bindings": {"type": ["numericColumn"], "minWidth": 100},
                    "Hostname": {"minWidth": 200, "flex": 2},
                    "Type": {"minWidth": 120},
                    "Environment": {"minWidth": 120},
                    "Description": {"minWidth": 200},
                    "Last Seen": {"minWidth": 150, "valueFormatter": "value ? new Date(value).toLocaleString() : ''"},
                    "_id": {"hide": True},
                    "type": {"hide": True}
                }
                return self.result(True, data={"df": df, "column_config": column_config})
            except Exception as e:
                logger.exception(f"Error fetching search results: {str(e)}")
                return self.result(False, error=f"Error fetching search results: {str(e)}") 