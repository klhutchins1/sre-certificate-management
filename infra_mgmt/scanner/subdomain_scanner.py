"""
Subdomain Scanner Module

This module provides subdomain enumeration functionality using safe, passive methods:
1. Certificate-based discovery (from SSL certificates' Subject Alternative Names)
2. Public sources (Certificate Transparency logs)

It is designed to support robust, error-tolerant, and auditable subdomain discovery for the Infrastructure Management System (IMS).
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
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from datetime import datetime
from infra_mgmt.utils.ignore_list import IgnoreListUtil
from infra_mgmt.utils.domain_validation import DomainValidationUtil
from infra_mgmt.utils.cache import ScanSessionCache

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
    Passive subdomain discovery using certificate data and public sources for IMS.

    This class provides methods to:
    - Discover subdomains from SSL certificate SANs
    - Discover subdomains from Certificate Transparency logs
    - Save discovered subdomains to the database
    - Integrate with the scan queue and tracker
    - Support rate limiting and robust error handling

    Example usage:
        >>> scanner = SubdomainScanner()
        >>> subdomains = scanner.scan_subdomains('example.com')
        >>> print(subdomains)
    """
    
    def __init__(self, methods=None, session_cache: ScanSessionCache = None):
        """
        Initialize the subdomain scanner, loading configuration and rate limits.
        
        Args:
            methods (Optional[List[str]]): List of methods to use ('cert', 'ct'). Defaults to both.
            session_cache (ScanSessionCache, optional): Session cache for domain lookups. Defaults to None.
        """
        self.session_cache = session_cache or ScanSessionCache()
        self.domain_scanner = DomainScanner(session_cache=self.session_cache)
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
        """
        Set the status container for UI updates.
        
        Args:
            container: Streamlit or UI status container
        """
        self.status_container = container
    
    def update_status(self, message: str):
        """
        Update the UI status if container is available and log the message.
        
        Args:
            message (str): Status message
        """
        if self.status_container:
            self.status_container.text(message)
        logger.info(message)

    def _get_certificate_sans(self, domain: str, port: int = 443) -> Set[str]:
        """
        Get subdomains from SSL certificate's Subject Alternative Names (SANs).
        
        Args:
            domain (str): Domain to check
            port (int): Port to connect to (default: 443)
        
        Returns:
            Set[str]: Set of discovered subdomains
        
        Edge Cases:
            - Handles missing/invalid certificates, wildcards, and non-matching SANs.
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
            
        except ValueError as e:
            logger.error(f"Value error getting certificate SANs for {domain}: {str(e)}")
        except TypeError as e:
            logger.error(f"Type error getting certificate SANs for {domain}: {str(e)}")
        except Exception as e:
            logger.warning(f"[CERT] Error getting certificate SANs for {domain}: {str(e)}")
        
        return subdomains
    
    def _get_ct_logs_subdomains(self, domain: str) -> Set[str]:
        """
        Get subdomains from Certificate Transparency logs (crt.sh).
        
        Args:
            domain (str): Domain to search for
        
        Returns:
            Set[str]: Set of discovered subdomains
        
        Edge Cases:
            - Handles rate limiting, request errors, and invalid formats.
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
                                        if DomainValidationUtil.is_valid_domain(name):
                                            subdomains.add(name)
                                            self.update_status(f'Found subdomain in CT logs: {name}')
                                        else:
                                            logger.debug(f"[CT] Skipping invalid subdomain format: {name}")
                    
                    # Add delay between queries to the same service
                    time.sleep(min_time_between_queries)
                    
                except requests.RequestException as e:
                    logger.warning(f"[CT] Request error querying {url}: {str(e)}")
                    continue
                except ValueError as e:
                    logger.error(f"Value error parsing CT logs from {url}: {str(e)}")
                    continue
                except TypeError as e:
                    logger.error(f"Type error parsing CT logs from {url}: {str(e)}")
                    continue
                except Exception as e:
                    logger.warning(f"[CT] Error querying {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.warning(f"[CT] Error searching CT logs for {domain}: {str(e)}")
        
        return subdomains

    def _discover_subdomains_ct(self, domain: str, offline_mode: bool = False, enable_ct: bool = True) -> Set[str]:
        """
        Discover subdomains using Certificate Transparency logs, respecting offline mode.

        Args:
            domain (str): The domain to search for.
            offline_mode (bool): If True, CT log lookup will be skipped.
            enable_ct (bool): If False, CT log lookup will be skipped.

        Returns:
            Set[str]: A set of discovered subdomains.
        """
        if offline_mode:
            logger.info(f"[CT] Offline mode enabled, skipping CT log lookup for {domain}")
            return set()
        if not enable_ct:
            logger.info(f"[CT] CT log lookup disabled by configuration, skipping for {domain}")
            return set()
        return self._get_ct_logs_subdomains(domain) # Actual call to existing CT logic

    def scan_subdomains(self, domain: str, session, methods: List[str] = None, offline_mode: bool = False, enable_ct: bool = True) -> Set[str]:
        """
        Discover subdomains for a domain using the provided session.
        Args:
            domain (str): Domain to scan
            session: SQLAlchemy session to use
            methods (List[str], optional): Methods to use ('cert', 'ct'). Defaults to instance methods.
            offline_mode (bool): If True, CT log lookup will be skipped if 'ct' is in methods.
            enable_ct (bool): If False, CT log lookup will be skipped if 'ct' is in methods.
        Returns:
            Set[str]: Set of all discovered subdomains
        """
        methods_to_use = methods or self.methods
        discovered = set()
        if 'cert' in methods_to_use:
            discovered |= self._get_certificate_sans(domain)
        if 'ct' in methods_to_use:
            discovered |= self._discover_subdomains_ct(domain, offline_mode=offline_mode, enable_ct=enable_ct)
        # Save discovered subdomains to DB
        for subdomain in discovered:
            self._save_subdomain_to_db(session, domain, subdomain)
        return discovered

    def scan_and_process_subdomains(self, domain: str, session, port: int = 443, check_whois: bool = True, check_dns: bool = True, scanned_domains: Set[str] = None, enable_ct: bool = True, offline_mode: bool = False) -> List[Dict]:
        """
        Discover and process subdomains for a given domain, saving results to the database.
        Args:
            domain (str): The domain to scan subdomains for
            session: SQLAlchemy session to use
            port (int): Port to use for scanning (default: 443)
            check_whois (bool): Whether to check WHOIS for discovered subdomains
            check_dns (bool): Whether to check DNS for discovered subdomains
            scanned_domains (Set[str], optional): Already scanned domains to avoid duplicates
            enable_ct (bool): Whether to use Certificate Transparency logs for subdomain discovery
            offline_mode (bool): If True, CT log lookup will be skipped if 'ct' is in methods.
        Returns:
            List[Dict]: List of processed subdomain results
        """
        scanned_domains = scanned_domains or set()
        # Use only 'cert' if CT is disabled, otherwise both
        methods = ['cert', 'ct'] if enable_ct else ['cert']
        subdomains = self.scan_subdomains(domain, session, methods=methods, offline_mode=offline_mode, enable_ct=enable_ct)
        results = []
        for subdomain in subdomains:
            if subdomain in scanned_domains:
                continue
            # Optionally scan WHOIS/DNS for each subdomain
            info = None
            if check_whois or check_dns:
                info = self.domain_scanner.scan_domain(subdomain, session, get_whois=check_whois, get_dns=check_dns)
            results.append({'domain': subdomain, 'info': info.to_dict() if info else None})
        return results

    def _save_subdomain_to_db(self, session: Session, parent_domain: str, subdomain: str) -> Optional[Domain]:
        """
        Save a discovered subdomain to the database and link to parent domain.
        
        Args:
            session (Session): Database session
            parent_domain (str): Parent domain name
            subdomain (str): Subdomain name to save
        
        Returns:
            Optional[Domain]: Created or updated domain object
        
        Edge Cases:
            - Handles DB errors, duplicate domains, and parent relationships.
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
            
        except ValueError as e:
            logger.error(f"Value error saving subdomain {subdomain}: {str(e)}")
            session.rollback()
            return None
        except TypeError as e:
            logger.error(f"Type error saving subdomain {subdomain}: {str(e)}")
            session.rollback()
            return None
        except Exception as e:
            logger.error(f"[DB] Error saving subdomain {subdomain}: {str(e)}")
            session.rollback()
            return None 