from datetime import datetime
from sqlalchemy.orm import joinedload
from sqlalchemy import or_
from ..models import Certificate, Host, HostIP, CertificateBinding
import logging

logger = logging.getLogger(__name__)

class SearchService:
    @staticmethod
    def perform_search(session, query, search_type, status_filter, platform_filter):
        """
        Perform a comprehensive search across the database based on user criteria.
        Args:
            session: SQLAlchemy session for database operations
            query: Search string to match against various fields
            search_type: Type of entities to search (All/Certificates/Hosts/IP Addresses)
            status_filter: Certificate validity filter (All/Valid/Expired)
            platform_filter: Platform filter for certificate bindings
        Returns:
            dict: Dictionary containing search results with keys:
                - 'certificates': List of matching Certificate objects
                - 'hosts': List of matching Host objects
        """
        logger.debug(f"perform_search called with query='{query}', search_type='{search_type}', status_filter='{status_filter}', platform_filter='{platform_filter}'")
        results = {}
        now = datetime.now()
        # Build base certificate query with relationships
        cert_query = session.query(Certificate).options(
            joinedload(Certificate.certificate_bindings)
                .joinedload(CertificateBinding.host)
                .joinedload(Host.ip_addresses),
            joinedload(Certificate.certificate_bindings)
                .joinedload(CertificateBinding.certificate),
            joinedload(Certificate.certificate_bindings)
                .joinedload(CertificateBinding.host_ip),
            joinedload(Certificate.certificate_bindings)
                .joinedload(CertificateBinding.certificate)
                .joinedload(Certificate.certificate_bindings)
        )
        # Apply certificate status filter
        if status_filter != "All":
            is_valid = status_filter == "Valid"
            cert_query = cert_query.filter(
                Certificate.valid_until > now if is_valid else Certificate.valid_until <= now
            )
        # Apply platform filter to certificate bindings
        if platform_filter != "All":
            cert_query = cert_query.join(CertificateBinding).filter(
                CertificateBinding.platform == platform_filter
            )
        # Search certificates if requested
        if search_type in ['All', 'Certificates']:
            results['certificates'] = cert_query.filter(
                or_(
                    Certificate.common_name.ilike(f"%{query}%"),
                    Certificate.serial_number.ilike(f"%{query}%"),
                    Certificate._subject.ilike(f"%{query}%"),
                    Certificate._san.ilike(f"%{query}%")
                )
            ).all()
            logger.debug(f"Certificates found: {len(results['certificates'])}")
        # Search hosts and IPs if requested
        if search_type in ['All', 'Hosts', 'IP Addresses']:
            # Build base host query with relationships
            host_query = session.query(Host).options(
                joinedload(Host.ip_addresses),
                joinedload(Host.certificate_bindings)
                    .joinedload(CertificateBinding.certificate)
                    .joinedload(Certificate.certificate_bindings),
                joinedload(Host.certificate_bindings)
                    .joinedload(CertificateBinding.host_ip)
            )
            # Apply platform filter if specified
            if platform_filter != "All":
                host_query = host_query.join(
                    CertificateBinding,
                    Host.certificate_bindings
                ).filter(
                    CertificateBinding.platform == platform_filter
                )
            # Apply certificate status filter
            if status_filter != "All":
                is_valid = status_filter == "Valid"
                host_query = host_query.join(
                    CertificateBinding,
                    Host.certificate_bindings
                ).join(
                    Certificate,
                    CertificateBinding.certificate
                ).filter(
                    Certificate.valid_until > now if is_valid else Certificate.valid_until <= now
                )
            # Execute host search query
            results['hosts'] = host_query.filter(
                or_(
                    Host.name.ilike(f"%{query}%"),
                    Host.ip_addresses.any(HostIP.ip_address.ilike(f"%{query}%"))
                )
            ).all()
            logger.debug(f"Hosts found: {len(results['hosts'])}")
        return results 