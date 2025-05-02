"""
Subdomain Scanner Module

This module provides subdomain enumeration functionality using safe, passive methods:
1. Certificate-based discovery (from SSL certificates' Subject Alternative Names)
2. Public sources (Certificate Transparency logs)
"""

import dns.resolver
import requests
import logging
import socket
import time
from typing import Set, List, Optional, Dict
from .domain_scanner import DomainScanner
from .certificate_scanner import CertificateScanner
from ..models import IgnoredDomain, Domain
from ..db import get_session
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Only add console handler if no handlers exist
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    console_handler.stream.reconfigure(encoding='utf-8')
    logger.addHandler(console_handler)

class SubdomainScanner:
    """
    Passive subdomain discovery using certificate data and public sources.
    """
    
    def __init__(self, methods=None):
        """Initialize the subdomain scanner."""
        self.domain_scanner = DomainScanner()
        self.infra_mgmt = CertificateScanner()
        self.last_ct_query_time = 0
        self.tracker = None  # Will be set by scanner view
        self.status_container = None  # Will be set by scanner view
        
        # Set default methods if none provided
        self.methods = methods or ['cert', 'ct']
        
        # Load rate limits from settings
        from ..settings import settings
        self.ct_rate_limit = settings.get('scanning.ct.rate_limit', 10)  # Default 10/min
        
        logger.info(f"Initialized SubdomainScanner with methods: {self.methods}, CT rate limit: {self.ct_rate_limit}/min")
    
    def set_status_container(self, container):
        """Set the status container for UI updates."""
        self.status_container = container
    
    def update_status(self, message: str):
        """Update the UI status if container is available."""
        if self.status_container:
            self.status_container.text(message)
        logger.info(message)

    def _get_certificate_sans(self, domain: str, port: int = 443) -> Set[str]:
        """
        Get subdomains from SSL certificate's Subject Alternative Names.
        
        Args:
            domain: Domain to check
            port: Port to connect to (default: 443)
            
        Returns:
            Set[str]: Set of discovered subdomains
        """
        subdomains = set()
        try:
            self.update_status(f'Checking SSL certificate for {domain}:{port} for subdomains...')
            
            # Remove any leading wildcards for matching
            base_domain = domain.lstrip('*.')
            
            # Use CertificateScanner to get certificate
            scan_result = self.infra_mgmt.scan_certificate(domain, port)
            if scan_result:
                if scan_result.error:
                    logger.warning(f"[CERT] Error scanning certificate for {domain}: {scan_result.error}")
                    return subdomains
                
                if scan_result.certificate_info:
                    cert_info = scan_result.certificate_info
                    # Process SANs from certificate info
                    for san in cert_info.san:
                        # Clean up the SAN
                        san = san.strip('*. ')
                        # Only add if it's a subdomain of our target domain
                        if san and (san == base_domain or san.endswith('.' + base_domain)):
                            if san != base_domain:  # Don't add the base domain itself
                                subdomains.add(san)
                                self.update_status(f'Found subdomain in certificate: {san}')
            
        except Exception as e:
            logger.warning(f"[CERT] Error getting certificate SANs for {domain}: {str(e)}")
        
        return subdomains
    
    def _get_ct_logs_subdomains(self, domain: str) -> Set[str]:
        """
        Get subdomains from Certificate Transparency logs.
        
        Args:
            domain: Domain to search for
            
        Returns:
            Set[str]: Set of discovered subdomains
        """
        subdomains = set()
        try:
            self.update_status(f'Searching Certificate Transparency logs for {domain} subdomains...')
            
            # Remove any leading wildcards for the search
            search_domain = domain.lstrip('*.')
            
            # Apply rate limiting for CT log queries
            current_time = time.time()
            time_since_last = current_time - self.last_ct_query_time
            min_time_between_queries = 60.0 / self.ct_rate_limit  # Time in seconds between queries
            
            if time_since_last < min_time_between_queries:
                sleep_time = min_time_between_queries - time_since_last
                logger.debug(f"[CT] Rate limiting: sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
            
            # Get request timeout from settings
            from ..settings import settings
            request_timeout = settings.get('scanning.timeouts.request', 10)
            
            # Query crt.sh with both direct and wildcard searches
            urls = [
                f"https://crt.sh/?q={search_domain}&output=json",  # Exact domain
                f"https://crt.sh/?q=%.{search_domain}&output=json"  # Subdomains
            ]
            
            for url in urls:
                try:
                    # Update last query time
                    self.last_ct_query_time = time.time()
                    
                    response = requests.get(url, timeout=request_timeout)
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            # Split by newlines and handle multiple SANs
                            for name in name_value.split('\\n'):
                                # Clean up the name
                                name = name.strip('*. ')
                                # Only process if it's related to our target domain
                                if name and (name == search_domain or name.endswith('.' + search_domain)):
                                    # Skip if it's just the base domain
                                    if name != search_domain:
                                        # Validate the subdomain format
                                        if self._validate_domain_format(name):
                                            subdomains.add(name)
                                            self.update_status(f'Found subdomain in CT logs: {name}')
                                        else:
                                            logger.debug(f"[CT] Skipping invalid subdomain format: {name}")
                    
                    # Add delay between queries to the same service
                    time.sleep(min_time_between_queries)
                    
                except Exception as e:
                    logger.warning(f"[CT] Error querying {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.warning(f"[CT] Error searching CT logs for {domain}: {str(e)}")
        
        return subdomains

    def _validate_domain_format(self, domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            bool: True if domain name format is valid
        """
        # Handle wildcard domains
        if domain.startswith('*.'):
            domain = domain[2:]  # Remove wildcard prefix for validation
        
        # Remove trailing dot if present
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Basic length check
        if not domain or len(domain) > 253:
            logger.debug(f"Domain {domain} failed length validation")
            return False
        
        # Split into parts and validate each
        parts = domain.split('.')
        
        # Must have at least two parts
        if len(parts) < 2:
            logger.debug(f"Domain {domain} has insufficient parts")
            return False
        
        # Validate each part
        for part in parts:
            # Check length
            if not part or len(part) > 63:
                logger.debug(f"Domain part {part} failed length validation")
                return False
            
            # Must start and end with alphanumeric
            if not part[0].isalnum() or not part[-1].isalnum():
                logger.debug(f"Domain part {part} must start and end with alphanumeric")
                return False
            
            # Can only contain alphanumeric and hyphen
            if not all(c.isalnum() or c == '-' for c in part):
                logger.debug(f"Domain part {part} contains invalid characters")
                return False
        
        return True
    
    def scan_subdomains(self, domain: str, methods: List[str] = None) -> Set[str]:
        """
        Discover subdomains using passive methods.
        
        Args:
            domain: Domain to scan
            methods: List of methods to use (cert, ct)
                    If None, uses instance default methods
        
        Returns:
            Set[str]: Set of all discovered subdomains
        """
        # Use provided methods or instance defaults
        methods = methods or self.methods
        
        # Check if domain is in ignore list
        from sqlalchemy import create_engine
        from ..settings import settings
        
        # Get database path from settings
        db_path = settings.get("paths.database", "data/certificates.db")
        engine = create_engine(f"sqlite:///{db_path}")
        session = Session(engine)
        
        try:
            # First check exact matches
            ignored = session.query(IgnoredDomain).filter_by(pattern=domain).first()
            if ignored:
                logger.info(f"[IGNORE] Skipping {domain} - Domain is in ignore list" + (f" ({ignored.reason})" if ignored.reason else ""))
                return set()
            
            # Then check wildcard patterns
            wildcard_patterns = session.query(IgnoredDomain).filter(
                IgnoredDomain.pattern.like('*.*')
            ).all()
            
            for pattern in wildcard_patterns:
                if pattern.pattern.startswith('*.'):
                    suffix = pattern.pattern[2:]  # Remove *. from pattern
                    if domain.endswith(suffix):
                        logger.info(f"[IGNORE] Skipping {domain} - Matches wildcard pattern {pattern.pattern}" + 
                                  (f" ({pattern.reason})" if pattern.reason else ""))
                        return set()
        finally:
            if session:
                session.close()
            if engine:
                engine.dispose()
        
        all_subdomains = set()
        logger.info(f"[SCAN] Starting passive subdomain discovery for {domain} using methods: {methods}")
        
        # Certificate-based discovery
        if 'cert' in methods:
            try:
                cert_subdomains = self._get_certificate_sans(domain)
                all_subdomains.update(cert_subdomains)
                logger.info(f"[SCAN] Found {len(cert_subdomains)} subdomains via certificates")
            except Exception as e:
                logger.error(f"[SCAN] Error scanning certificates for {domain}: {str(e)}")
        
        # Certificate Transparency logs
        if 'ct' in methods:
            try:
                ct_subdomains = self._get_ct_logs_subdomains(domain)
                all_subdomains.update(ct_subdomains)
                logger.info(f"[SCAN] Found {len(ct_subdomains)} subdomains via CT logs")
            except Exception as e:
                logger.error(f"[SCAN] Error scanning CT logs for {domain}: {str(e)}")
        
        logger.info(f"[SCAN] Total unique subdomains found for {domain}: {len(all_subdomains)}")
        return all_subdomains

    def _save_subdomain_to_db(self, session: Session, parent_domain: str, subdomain: str) -> Optional[Domain]:
        """
        Save a discovered subdomain to the database.
        
        Args:
            session: Database session
            parent_domain: Parent domain name
            subdomain: Subdomain name to save
            
        Returns:
            Optional[Domain]: Created or updated domain object
        """
        try:
            # Get or create parent domain
            parent = session.query(Domain).filter_by(domain_name=parent_domain).first()
            if not parent:
                parent = Domain(
                    domain_name=parent_domain,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                session.add(parent)
                session.flush()  # Get parent ID
            
            # Get or create subdomain
            sub = session.query(Domain).filter_by(domain_name=subdomain).first()
            if not sub:
                sub = Domain(
                    domain_name=subdomain,
                    parent_domain_id=parent.id,  # Set parent relationship
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                session.add(sub)
            else:
                sub.parent_domain_id = parent.id  # Update parent relationship
                sub.updated_at = datetime.now()
            
            session.commit()
            logger.info(f"[DB] Saved subdomain relationship: {subdomain} -> {parent_domain}")
            return sub
            
        except Exception as e:
            logger.error(f"[DB] Error saving subdomain {subdomain}: {str(e)}")
            session.rollback()
            return None

    def scan_and_process_subdomains(self, domain: str, port: int = 443, check_whois: bool = True, check_dns: bool = True, scanned_domains: Set[str] = None) -> List[Dict]:
        """
        Discover and process subdomains for a given domain.
        
        Args:
            domain: The domain to scan subdomains for
            port: Port to use for scanning (default: 443)
            check_whois: Whether to check WHOIS for discovered subdomains
            check_dns: Whether to check DNS for discovered subdomains
            scanned_domains: Set of already scanned domains to avoid duplicates
            
        Returns:
            List[Dict]: List of processed subdomain results
        """
        results = []
        
        # Start passive subdomain discovery
        self.update_status(f'Starting subdomain discovery for {domain}...')
        
        # Get subdomains using all configured methods
        discovered_subdomains = set()
        
        # Check certificate for subdomains
        if 'cert' in self.methods:
            cert_subdomains = self._get_certificate_sans(domain, port)
            discovered_subdomains.update(cert_subdomains)
            if cert_subdomains:
                self.update_status(f'Found {len(cert_subdomains)} subdomains via certificates for {domain}')
        
        # Check Certificate Transparency logs
        if 'ct' in self.methods:
            ct_subdomains = self._get_ct_logs_subdomains(domain)
            discovered_subdomains.update(ct_subdomains)
            if ct_subdomains:
                self.update_status(f'Found {len(ct_subdomains)} subdomains via CT logs for {domain}')
        
        # Log total unique subdomains found
        if discovered_subdomains:
            self.update_status(f'Processing {len(discovered_subdomains)} discovered subdomains for {domain}...')
            
            # Create database session
            from ..db import get_session
            from sqlalchemy import create_engine
            from ..settings import settings
            
            # Get database path from settings
            db_path = settings.get("paths.database", "data/certificates.db")
            engine = create_engine(f"sqlite:///{db_path}")
            session = Session(engine)
            
            try:
                # Process each subdomain
                for subdomain in discovered_subdomains:
                    # Skip if already in master list
                    if self.tracker and self.tracker.is_domain_known(subdomain):
                        self.update_status(f'Skipping {subdomain} - Already processed')
                        continue
                    
                    try:
                        self.update_status(f'Processing subdomain: {subdomain}...')
                        
                        # Get domain information
                        domain_info = None
                        if check_whois or check_dns:
                            if check_whois:
                                self.update_status(f'Getting WHOIS information for {subdomain}...')
                            if check_dns:
                                self.update_status(f'Getting DNS records for {subdomain}...')
                            domain_info = self.domain_scanner.scan_domain(
                                subdomain,
                                get_whois=check_whois,
                                get_dns=check_dns
                            )
                        
                        # Save subdomain to database
                        self.update_status(f'Saving subdomain relationship: {subdomain} -> {domain}')
                        subdomain_obj = self._save_subdomain_to_db(session, domain, subdomain)
                        
                        # Add to results
                        result = {
                            'domain': subdomain,
                            'info': domain_info.to_dict() if domain_info else None
                        }
                        results.append(result)
                        
                        # Add to tracker's master list
                        if self.tracker:
                            self.tracker.add_to_master_list(subdomain)
                        
                        self.update_status(f'Successfully processed subdomain: {subdomain}')
                        
                    except Exception as e:
                        logger.error(f"[SCAN] Error processing subdomain {subdomain}: {str(e)}")
                        continue
                    
            finally:
                session.close()
                engine.dispose()
        else:
            self.update_status(f'No subdomains found for {domain}')
        
        return results 