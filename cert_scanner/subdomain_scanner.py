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
from typing import Set, List, Optional
from .domain_scanner import DomainScanner
from .scanner import CertificateScanner

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler if it doesn't exist
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
    
    def __init__(self):
        """Initialize the subdomain scanner."""
        self.domain_scanner = DomainScanner()
        self.cert_scanner = CertificateScanner()
        self.last_ct_query_time = 0
        
        # Load rate limits from settings
        from .settings import settings
        self.ct_rate_limit = settings.get('scanning.ct.rate_limit', 10)  # Default 10/min
        
        logger.info(f"Initialized SubdomainScanner with CT rate limit: {self.ct_rate_limit}/min")
    
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
            logger.info(f"[CERT] Checking SSL certificate for {domain}:{port}")
            
            # Remove any leading wildcards for matching
            base_domain = domain.lstrip('*.')
            
            # Use CertificateScanner to get certificate
            scan_result = self.cert_scanner.scan_certificate(domain, port)
            if scan_result and scan_result.certificate_info:
                cert_info = scan_result.certificate_info
                # Process SANs from certificate info
                for san in cert_info.san:
                    # Clean up the SAN
                    san = san.strip('*. ')
                    # Only add if it's a subdomain of our target domain
                    if san and (san == base_domain or san.endswith('.' + base_domain)):
                        if san != base_domain:  # Don't add the base domain itself
                            subdomains.add(san)
                            logger.info(f"[CERT] Found subdomain: {san}")
            
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
            # Use crt.sh for CT log search
            logger.info(f"[CT] Searching Certificate Transparency logs for {domain}")
            
            # Remove any leading wildcards for the search
            search_domain = domain.lstrip('*.')
            
            # Apply rate limiting for CT log queries
            current_time = time.time()
            time_since_last = current_time - self.last_ct_query_time
            min_time_between_queries = 60.0 / self.ct_rate_limit  # Time in seconds between queries
            
            if time_since_last < min_time_between_queries:
                sleep_time = min_time_between_queries - time_since_last
                logger.info(f"[CT] Rate limiting: sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
            
            # Get request timeout from settings
            from .settings import settings
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
                                            logger.info(f"[CT] Found subdomain: {name}")
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
                    If None, all methods will be used
        
        Returns:
            Set[str]: Set of all discovered subdomains
        """
        if not methods:
            methods = ['cert', 'ct']
        
        all_subdomains = set()
        logger.info(f"[SCAN] Starting passive subdomain discovery for {domain} using methods: {methods}")
        
        # Certificate-based discovery
        if 'cert' in methods:
            cert_subdomains = self._get_certificate_sans(domain)
            all_subdomains.update(cert_subdomains)
            logger.info(f"[SCAN] Found {len(cert_subdomains)} subdomains via certificates")
        
        # Certificate Transparency logs
        if 'ct' in methods:
            ct_subdomains = self._get_ct_logs_subdomains(domain)
            all_subdomains.update(ct_subdomains)
            logger.info(f"[SCAN] Found {len(ct_subdomains)} subdomains via CT logs")
        
        logger.info(f"[SCAN] Total unique subdomains found for {domain}: {len(all_subdomains)}")
        return all_subdomains 