"""
Dashboard Service Module

This module provides service methods for dashboard-related operations including:
- Domain hierarchy calculations
- Dashboard metrics aggregation
- Timeline data generation for certificates and domains

All methods are static and can be used without instantiating the class.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Optional
from sqlalchemy import func, case, select
from sqlalchemy.orm import Session, selectinload
from ..models import Certificate, Host, Domain, Application


class DashboardService:
    """
    Service class for dashboard-related operations.
    
    Provides static methods for calculating domain hierarchies, aggregating metrics,
    and generating timeline data for dashboard visualizations.
    """
    
    def __init__(self):
        """Initialize DashboardService. No instance state is required."""
        pass

    @staticmethod
    def get_root_domain(domain_name: str) -> str:
        """
        Extract the root domain from a domain name.
        
        For a domain name, extracts the root domain (last two parts).
        Examples:
            - "www.example.com" -> "example.com"
            - "api.v1.example.com" -> "example.com"
            - "example.com" -> "example.com"
            - "ex.co" -> "ex.co"
        
        Args:
            domain_name: The domain name to extract root from
            
        Returns:
            The root domain name (last two parts separated by dot)
        """
        parts = domain_name.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain_name

    @staticmethod
    def get_domain_hierarchy(domains: List[Domain]) -> Dict[str, List[Domain]]:
        """
        Organize domains into a hierarchy of root domains and their subdomains.
        
        Creates a dictionary where keys are root domain names and values are lists
        of subdomain objects. Only true root domains (e.g., example.com) are used
        as keys, not intermediate subdomains.
        
        Args:
            domains: List of Domain objects to organize
            
        Returns:
            Dictionary mapping root domain names to lists of their subdomains.
            Root domains with no subdomains will have empty lists.
            
        Example:
            Input: [Domain("example.com"), Domain("www.example.com"), Domain("api.example.com")]
            Output: {"example.com": [Domain("www.example.com"), Domain("api.example.com")]}
        """
        domain_tree = defaultdict(list)
        all_domain_names = {domain.domain_name for domain in domains}
        root_domains = set()
        
        # Identify all root domains
        for domain in domains:
            root_name = DashboardService.get_root_domain(domain.domain_name)
            root_domains.add(root_name)
        
        # Initialize tree with root domains
        for root_name in root_domains:
            root_domain = next((d for d in domains if d.domain_name == root_name), None)
            if root_domain:
                # Root domain exists in database
                domain_tree[root_name] = []
            else:
                # Root domain only exists as part of subdomains
                subdomains = [d for d in domains if DashboardService.get_root_domain(d.domain_name) == root_name]
                if subdomains:
                    domain_tree[root_name] = []
        
        # Organize subdomains under their root domains
        for domain in domains:
            root_name = DashboardService.get_root_domain(domain.domain_name)
            if root_name in domain_tree and domain.domain_name != root_name:
                domain_tree[root_name].append(domain)
        
        # Sort subdomains within each root domain alphabetically
        for root_name in domain_tree:
            domain_tree[root_name].sort(key=lambda d: d.domain_name)
        
        return domain_tree

    @staticmethod
    def get_root_domains(session: Session, domains: Optional[List[Domain]] = None) -> List[Domain]:
        """
        Get all root domains from the database, ensuring they have registration data.
        
        Retrieves all root domains (e.g., "example.com" not "www.example.com").
        If a root domain is missing registration_date or expiration_date, sets default
        values and updates the database.
        
        Args:
            session: SQLAlchemy database session
            domains: Optional pre-fetched list of domains. If None, queries all domains.
            
        Returns:
            List of Domain objects representing root domains
            
        Side Effects:
            Updates domains missing registration/expiration dates in the database
        """
        if domains is None:
            domains = session.query(Domain).all()
        
        root_domain_names = {DashboardService.get_root_domain(d.domain_name) for d in domains}
        root_domains = [d for d in domains if d.domain_name in root_domain_names]
        
        # Update domains missing registration/expiration dates
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
    def get_dashboard_metrics(session: Session) -> Dict[str, Any]:
        """
        Calculate and return all dashboard metrics in a single optimized query.
        
        Aggregates metrics including:
        - Total certificates and expiring certificates (within 30 days)
        - Total domains, root domains, and subdomains
        - Expiring domains (within 30 days)
        - Total applications and hosts
        
        Args:
            session: SQLAlchemy database session
            
        Returns:
            Dictionary containing all dashboard metrics:
            - total_certs: Total number of certificates
            - expiring_certs: Number of certificates expiring within 30 days
            - total_domains: Total number of domains
            - total_root_domains: Number of root domains
            - expiring_domains: Number of root domains expiring within 30 days
            - total_apps: Total number of applications
            - total_hosts: Total number of hosts
            - total_subdomains: Number of subdomains (total - root)
            - root_domains: List of root domain objects
        """
        thirty_days = datetime.now() + timedelta(days=30)
        now = datetime.now()
        
        # Query certificate metrics using optimized select statement
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
        
        # Count distinct entities
        domain_count = session.query(func.count(func.distinct(Domain.id))).scalar()
        app_count = session.query(func.count(func.distinct(Application.id))).scalar()
        host_count = session.query(func.count(func.distinct(Host.id))).scalar()
        
        # Load domains with certificates for expiration checking
        domains = session.query(Domain).options(
            selectinload(Domain.certificates)
        ).all()
        
        # Calculate root domains
        root_domain_names = {DashboardService.get_root_domain(d.domain_name) for d in domains}
        root_domains = [d for d in domains if d.domain_name in root_domain_names]
        
        # Build metrics dictionary
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
    def get_certificate_timeline_data(session: Session, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get certificate timeline data, ensuring each certificate has a unique name
        to prevent gaps in the timeline visualization caused by duplicate common names.
        
        For certificates with duplicate common names, appends serial number suffixes
        to make them unique in the visualization.
        
        Args:
            session: SQLAlchemy database session
            limit: Maximum number of certificates to return (default: 100)
            
        Returns:
            List of dictionaries with keys:
            - 'Name': Certificate common name (with serial suffix if duplicate)
            - 'Start': Certificate valid_from date
            - 'End': Certificate valid_until date
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
    def get_domain_timeline_data(root_domains: List[Domain]) -> List[Dict[str, Any]]:
        """
        Generate timeline data for domain registration and expiration dates.
        
        Creates a list of dictionaries suitable for timeline visualization,
        containing domain names and their registration/expiration dates.
        Only includes domains that have both registration and expiration dates.
        
        Args:
            root_domains: List of root Domain objects
            
        Returns:
            List of dictionaries with keys:
            - 'Name': Domain name
            - 'Start': Registration date
            - 'End': Expiration date
        """
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