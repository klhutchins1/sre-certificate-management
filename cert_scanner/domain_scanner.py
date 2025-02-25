"""
Domain Scanner Module

This module provides functionality for scanning and analyzing domain information, including:
- WHOIS information retrieval and parsing
- DNS record scanning
- Domain validation
- Registration information processing
"""

import whois
import dns.resolver
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import re
import socket
import time

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler if it doesn't exist
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    # Set UTF-8 encoding for the handler
    console_handler.stream.reconfigure(encoding='utf-8')
    logger.addHandler(console_handler)

class DomainInfo:
    """Data class representing domain information."""
    def __init__(
        self,
        domain_name: str,
        registrar: Optional[str] = None,
        registration_date: Optional[datetime] = None,
        expiration_date: Optional[datetime] = None,
        registrant: Optional[str] = None,
        status: Optional[List[str]] = None,
        nameservers: Optional[List[str]] = None,
        dns_records: Optional[List[Dict[str, Any]]] = None,
        is_valid: bool = True,
        error: Optional[str] = None
    ):
        self.domain_name = domain_name
        self.registrar = registrar
        self.registration_date = registration_date
        self.expiration_date = expiration_date
        self.registrant = registrant
        self.status = status or []
        self.nameservers = nameservers or []
        self.dns_records = dns_records or []
        self.is_valid = is_valid
        self.error = error

class DomainScanner:
    """
    Domain scanner class for retrieving and analyzing domain information.
    
    This class provides methods for:
    - Validating domain names
    - Retrieving WHOIS information
    - Scanning DNS records
    - Processing registration information
    """
    
    def __init__(self):
        """Initialize the domain scanner."""
        self.dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        self.last_whois_query_time = 0
        self.last_dns_query_time = 0
        
        # Load rate limits from settings
        from .settings import settings
        self.whois_rate_limit = settings.get('scanning.whois.rate_limit', 10)  # Default 10/min
        self.dns_rate_limit = settings.get('scanning.dns.rate_limit', 30)      # Default 30/min
        
        # Load timeout settings
        self.dns_timeout = settings.get('scanning.timeouts.dns', 3.0)         # Default 3.0 seconds
        
        logger.info(f"Initialized DomainScanner with WHOIS rate limit: {self.whois_rate_limit}/min, DNS rate limit: {self.dns_rate_limit}/min, DNS timeout: {self.dns_timeout}s")
    
    def _apply_rate_limit(self, last_time: float, rate_limit: int, query_type: str) -> float:
        """
        Apply rate limiting for queries.
        
        Args:
            last_time: Time of last query
            rate_limit: Maximum queries per minute
            query_type: Type of query for logging
            
        Returns:
            float: Current time after rate limiting
        """
        current_time = time.time()
        time_since_last = current_time - last_time
        min_time_between_queries = 60.0 / rate_limit
        
        if time_since_last < min_time_between_queries:
            sleep_time = min_time_between_queries - time_since_last
            logger.info(f"[{query_type}] Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
            current_time = time.time()
        
        return current_time
    
    def _validate_domain(self, domain: str) -> bool:
        """
        Validate domain name format.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            bool: True if domain name is valid
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
    
    def _parse_whois_date(self, date_value: Any) -> Optional[datetime]:
        """Parse WHOIS date values which can be in various formats."""
        if not date_value:
            return None
            
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        if isinstance(date_value, datetime):
            return date_value
            
        return None
    
    def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """
        Get WHOIS information for a domain.
        
        Args:
            domain: Domain name to query
            
        Returns:
            dict: WHOIS information
        """
        try:
            logger.info(f"[WHOIS] Starting query for {domain}")
            
            # Apply rate limiting
            self.last_whois_query_time = self._apply_rate_limit(
                self.last_whois_query_time,
                self.whois_rate_limit,
                "WHOIS"
            )
            
            w = whois.whois(domain)
            
            if not w:
                logger.warning(f"[WHOIS] No information found for {domain}")
                return {}
            
            # Process dates
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                logger.debug(f"[WHOIS] Multiple creation dates found for {domain}, using {creation_date}")
            
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
                logger.debug(f"[WHOIS] Multiple expiration dates found for {domain}, using {expiration_date}")
            
            # Get registrar info with fallbacks
            registrar = None
            for field in ['registrar', 'whois_server', 'registrar_name']:
                value = getattr(w, field, None)
                if value:
                    if isinstance(value, list):
                        value = value[0]
                    registrar = value
                    logger.info(f"[WHOIS] Found registrar for {domain}: {value}")
                    break
            
            # If no registrar found, try socket-based lookup
            if not registrar:
                logger.info(f"[WHOIS] No registrar found, attempting direct lookup for {domain}")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect(("whois.internic.net", 43))
                    s.send((domain + "\r\n").encode())
                    response = b""
                    while True:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data
                    s.close()
                    text = response.decode('utf-8', errors='ignore')
                    registrar_match = re.search(r"Registrar:\s*(.+)", text)
                    if registrar_match:
                        registrar = registrar_match.group(1).strip()
                        logger.info(f"[WHOIS] Found registrar via direct lookup: {registrar}")
                except Exception as e:
                    logger.warning(f"[WHOIS] Direct lookup failed for {domain}: {str(e)}")
            
            # Get registrant info with fallbacks
            registrant = None
            for field in ['registrant_name', 'org', 'owner', 'name', 'organization']:
                value = getattr(w, field, None)
                if value:
                    if isinstance(value, list):
                        value = value[0]
                    registrant = value
                    logger.info(f"[WHOIS] Found registrant for {domain}: {value}")
                    break
            
            # Get status and nameservers
            status = w.status
            if isinstance(status, str):
                status = [status]
            elif not status:
                status = []
            
            nameservers = w.name_servers
            if isinstance(nameservers, str):
                nameservers = [nameservers]
            elif not nameservers:
                nameservers = []
            
            result = {
                'registrar': registrar,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'registrant': registrant,
                'status': status,
                'nameservers': nameservers
            }
            
            logger.info(f"[WHOIS] Successfully retrieved information for {domain}")
            return result
            
        except Exception as e:
            logger.error(f"[WHOIS] Error retrieving information for {domain}: {str(e)}")
            return {}
    
    def _get_dns_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get DNS records for a domain.
        
        Args:
            domain: Domain name to query
            
        Returns:
            list: List of DNS records
        """
        records = []
        logger.info(f"[DNS] Starting record lookup for {domain}")
        
        # Configure DNS resolver with timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        
        for record_type in self.dns_record_types:
            try:
                # Apply rate limiting for each DNS query
                self.last_dns_query_time = self._apply_rate_limit(
                    self.last_dns_query_time,
                    self.dns_rate_limit,
                    "DNS"
                )
                
                logger.debug(f"[DNS] Querying {record_type} records for {domain}")
                answers = resolver.resolve(domain, record_type)
                for rdata in answers:
                    record = {
                        'type': record_type,
                        'name': domain,
                        'value': str(rdata),
                        'ttl': answers.ttl
                    }
                    
                    # Add priority for MX records
                    if record_type == 'MX':
                        record['priority'] = rdata.preference
                    
                    # Add special handling for SOA records
                    if record_type == 'SOA':
                        record['serial'] = rdata.serial
                        record['refresh'] = rdata.refresh
                        record['retry'] = rdata.retry
                        record['expire'] = rdata.expire
                        record['minimum'] = rdata.minimum
                    
                    records.append(record)
                    logger.info(f"[DNS] Found {record_type} record for {domain}: {str(rdata)}")
            except dns.resolver.NoAnswer:
                logger.debug(f"[DNS] No {record_type} records found for {domain}")
                continue
            except dns.resolver.NXDOMAIN:
                error_msg = f"The domain '{domain}' does not exist in DNS records"
                logger.warning(f"[DNS] {error_msg}")
                raise Exception(error_msg)
            except dns.resolver.NoNameservers:
                error_msg = f"No DNS servers could be reached to resolve '{domain}'"
                logger.warning(f"[DNS] {error_msg}")
                continue
            except Exception as e:
                error_msg = f"Error looking up DNS records for '{domain}' - The domain may not exist or DNS servers are not responding"
                logger.warning(f"[DNS] {error_msg}: {str(e)}")
                continue
        
        logger.info(f"[DNS] Found {len(records)} total records for {domain}")
        return records
    
    def scan_domain(self, domain: str, get_whois: bool = True, get_dns: bool = True) -> DomainInfo:
        """
        Scan a domain for all available information.
        
        Args:
            domain: Domain name to scan
            get_whois: Whether to retrieve WHOIS information
            get_dns: Whether to retrieve DNS records
            
        Returns:
            DomainInfo: Domain information object
        """
        # Validate domain name
        if not self._validate_domain(domain):
            return DomainInfo(
                domain_name=domain,
                is_valid=False,
                error="Invalid domain name format"
            )
        
        try:
            whois_info = {}
            dns_records = []
            
            # Get WHOIS information if requested
            if get_whois:
                whois_info = self._get_whois_info(domain)
            
            # Get DNS records if requested
            if get_dns:
                try:
                    dns_records = self._get_dns_records(domain)
                except Exception as e:
                    logger.warning(f"Error getting DNS records for {domain}: {str(e)}")
            
            # Create domain info object
            return DomainInfo(
                domain_name=domain,
                registrar=whois_info.get('registrar'),
                registration_date=whois_info.get('creation_date'),
                expiration_date=whois_info.get('expiration_date'),
                registrant=whois_info.get('registrant'),
                status=whois_info.get('status'),
                nameservers=whois_info.get('nameservers'),
                dns_records=dns_records,
                is_valid=True
            )
            
        except Exception as e:
            logger.error(f"Error scanning domain {domain}: {str(e)}")
            return DomainInfo(
                domain_name=domain,
                is_valid=False,
                error=str(e)
            ) 