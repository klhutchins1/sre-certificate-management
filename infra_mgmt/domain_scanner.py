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
from typing import Dict, List, Optional, Any, Tuple, Set
import logging
import re
import socket
import time
from sqlalchemy.orm import Session
from .models import IgnoredDomain
from .db import get_session
import ipaddress
from .constants import INTERNAL_TLDS, EXTERNAL_TLDS

# Configure logging
logger = logging.getLogger(__name__)

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
        error: Optional[str] = None,
        domain_type: Optional[str] = None,
        related_domains: Optional[Set[str]] = None
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
        self.domain_type = domain_type
        self.related_domains = related_domains or set()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert domain information to dictionary format."""
        return {
            'domain_name': self.domain_name,
            'registrar': self.registrar,
            'registration_date': self.registration_date.isoformat() if self.registration_date else None,
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None,
            'registrant': self.registrant,
            'status': self.status,
            'nameservers': self.nameservers,
            'dns_records': self.dns_records,
            'is_valid': self.is_valid,
            'error': self.error,
            'domain_type': self.domain_type,
            'related_domains': list(self.related_domains)
        }

class DomainScanner:
    """
    Domain scanning and analysis class.
    
    This class provides functionality to:
    - Validate domain names and formats
    - Retrieve WHOIS information
    - Gather DNS records
    - Handle domain classification (internal/external)
    - Process wildcard domains
    - Resolve IP addresses
    
    The scanner implements intelligent rate limiting for different query types
    and provides robust error handling for network operations.
    """
    
    def __init__(self):
        """Initialize the domain scanner."""
        # Configure DNS record types to scan
        self.dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        # Initialize rate limiting state
        self.last_whois_query_time = 0
        self.last_dns_query_time = 0
        
        # Load rate limits from settings
        from .settings import settings
        self.whois_rate_limit = settings.get('scanning.whois.rate_limit', 10)  # Default 10/min
        self.dns_rate_limit = settings.get('scanning.dns.rate_limit', 30)      # Default 30/min
        
        # Load timeout settings
        self.dns_timeout = settings.get('scanning.timeouts.dns', 5.0)         # Default 5.0 seconds
        
        # Load domain classification settings
        self.internal_domains = set(settings.get('scanning.internal.domains', []))
        self.external_domains = set(settings.get('scanning.external.domains', []))
        
        # Cache for successful nameserver sets
        self.successful_nameservers = {}
        
        self.logger = logging.getLogger(__name__)
        
        logger.info(f"Initialized DomainScanner with WHOIS rate limit: {self.whois_rate_limit}/min, "
                   f"DNS rate limit: {self.dns_rate_limit}/min, DNS timeout: {self.dns_timeout}s")
    
    def _apply_rate_limit(self, last_time: float, rate_limit: int, query_type: str) -> float:
        """Apply rate limiting for queries."""
        current_time = time.time()
        time_since_last = current_time - last_time
        min_time_between_queries = 60.0 / rate_limit
        
        if time_since_last < min_time_between_queries:
            sleep_time = min_time_between_queries - time_since_last
            logger.debug(f"[{query_type}] Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
            current_time = time.time()
        
        return current_time
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name format."""
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
    
    def _get_domain_type(self, domain: str) -> str:
        """Determine if a domain is internal or external."""
        # First check configured domains
        if self._is_internal_domain(domain):
            return 'internal'
        if self._is_external_domain(domain):
            return 'external'
        
        # Then check TLDs
        domain_lower = domain.lower()
        for tld in INTERNAL_TLDS:
            if domain_lower.endswith(tld):
                return 'internal'
        
        for tld in EXTERNAL_TLDS:
            if domain_lower.endswith(tld):
                return 'external'
        
        # Default to external if no match
        return 'external'
    
    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain matches internal patterns."""
        return any(
            domain.endswith(internal_domain) if internal_domain.startswith('.')
            else domain == internal_domain
            for internal_domain in self.internal_domains
        )
    
    def _is_external_domain(self, domain: str) -> bool:
        """Check if domain matches external patterns."""
        if self._is_internal_domain(domain):
            return False
        if not self.external_domains:
            return False
        return any(
            domain.endswith(external_domain) if external_domain.startswith('.')
            else domain == external_domain
            for external_domain in self.external_domains
        )
    
    def _get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information for a domain."""
        try:
            # Check if domain should be ignored before doing WHOIS query
            is_ignored, reason = self._is_domain_ignored(domain)
            if is_ignored:
                self.logger.info(f"[WHOIS] Skipping WHOIS query for {domain} - Domain is in ignore list" + 
                               (f" ({reason})" if reason else ""))
                return {}

            self.logger.info(f"[WHOIS] Starting query for {domain}")
            
            # Apply rate limiting
            self.last_whois_query_time = self._apply_rate_limit(
                self.last_whois_query_time,
                self.whois_rate_limit,
                "WHOIS"
            )
            
            w = whois.whois(domain)
            
            if not w:
                self.logger.warning(f"[WHOIS] No information found for {domain}")
                return {}
            
            # Process dates
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                self.logger.debug(f"[WHOIS] Multiple creation dates found for {domain}, using {creation_date}")
            
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
                self.logger.debug(f"[WHOIS] Multiple expiration dates found for {domain}, using {expiration_date}")
            
            # Get registrar info with fallbacks
            registrar = None
            for field in ['registrar', 'whois_server', 'registrar_name']:
                value = getattr(w, field, None)
                if value:
                    if isinstance(value, list):
                        value = value[0]
                    registrar = value
                    self.logger.info(f"[WHOIS] Found registrar for {domain}: {value}")
                    break
            
            # Get registrant info with fallbacks
            registrant = None
            for field in ['registrant_name', 'org', 'owner', 'name', 'organization']:
                value = getattr(w, field, None)
                if value:
                    if isinstance(value, list):
                        value = value[0]
                    registrant = value
                    self.logger.info(f"[WHOIS] Found registrant for {domain}: {value}")
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
                'registrant': registrant,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'status': status,
                'nameservers': nameservers
            }
            
            self.logger.info(f"[WHOIS] Successfully retrieved information for {domain}")
            return result
            
        except Exception as e:
            self.logger.error(f"[WHOIS] Error retrieving information for {domain}: {str(e)}")
            return {}
    
    def _get_dns_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get DNS records for a domain.
        
        Args:
            domain: Domain name to query
            
        Returns:
            list: List of DNS records
        """
        # Check if domain should be ignored before doing DNS lookup
        is_ignored, reason = self._is_domain_ignored(domain)
        if is_ignored:
            self.logger.info(f"[DNS] Skipping DNS lookup for {domain} - Domain is in ignore list" + 
                           (f" ({reason})" if reason else ""))
            return []

        records = []
        self.logger.info(f"[DNS] Starting record lookup for {domain}")
        
        # Configure DNS resolver with timeout and nameservers
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        
        # Check if we have a successful nameserver set for this domain's TLD
        tld = domain.split('.')[-1]
        if tld in self.successful_nameservers:
            nameserver_sets = [self.successful_nameservers[tld]]
            self.logger.debug(f"[DNS] Using cached nameservers for .{tld}: {self.successful_nameservers[tld]}")
        else:
            # Define nameserver sets to try in order
            nameserver_sets = [
                resolver.nameservers,  # System nameservers
                ['8.8.8.8', '8.8.4.4'],  # Google DNS
                ['1.1.1.1', '1.0.0.1']   # Cloudflare
            ]
        
        # Try each nameserver set until we get a successful resolution
        resolved = False
        successful_nameservers = None
        
        for nameservers in nameserver_sets:
            if resolved:
                break
                
            resolver.nameservers = nameservers
            self.logger.debug(f"[DNS] Trying nameservers: {nameservers}")
            
            try:
                # Try to resolve the domain first to check existence
                resolver.resolve(domain, 'A')
                resolved = True
                successful_nameservers = nameservers
                self.logger.info(f"[DNS] Successfully resolved {domain} using nameservers: {nameservers}")
                
                # Cache successful nameservers for this TLD
                if tld not in self.successful_nameservers:
                    self.successful_nameservers[tld] = nameservers
                    self.logger.debug(f"[DNS] Cached nameservers for .{tld}: {nameservers}")
                
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"[DNS] Domain {domain} does not exist using nameservers: {nameservers}")
                continue
            except dns.resolver.NoNameservers:
                self.logger.warning(f"[DNS] No response from nameservers: {nameservers}")
                continue
            except Exception as e:
                self.logger.warning(f"[DNS] Error resolving {domain} with nameservers {nameservers}: {str(e)}")
                continue
        
        if not resolved:
            self.logger.error(f"[DNS] Could not resolve {domain} with any nameservers")
            return []
        
        # Use the successful nameserver set for all subsequent queries
        resolver.nameservers = successful_nameservers
        
        # Query each record type
        for record_type in self.dns_record_types:
            try:
                # Apply rate limiting for each DNS query
                self.last_dns_query_time = self._apply_rate_limit(
                    self.last_dns_query_time,
                    self.dns_rate_limit,
                    "DNS"
                )
                
                self.logger.debug(f"[DNS] Querying {record_type} records for {domain}")
                try:
                    answers = resolver.resolve(domain, record_type)
                    for rdata in answers:
                        record = {
                            'type': record_type,
                            'name': domain,
                            'value': str(rdata).rstrip('.'),  # Remove trailing dot
                            'ttl': answers.ttl
                        }
                        
                        # Add additional fields based on record type
                        if record_type == 'MX':
                            record['priority'] = rdata.preference
                        elif record_type == 'SOA':
                            record['primary_ns'] = str(rdata.mname).rstrip('.')
                            record['email'] = str(rdata.rname).rstrip('.')
                            record['serial'] = rdata.serial
                            record['refresh'] = rdata.refresh
                            record['retry'] = rdata.retry
                            record['expire'] = rdata.expire
                            record['minimum'] = rdata.minimum
                        
                        records.append(record)
                        self.logger.info(f"[DNS] Found {record_type} record for {domain}: {str(rdata)}")
                except dns.resolver.NoAnswer:
                    self.logger.debug(f"[DNS] No {record_type} records found for {domain}")
                    continue
                except dns.resolver.NXDOMAIN:
                    self.logger.debug(f"[DNS] Domain {domain} does not exist (trying next record type)")
                    continue
                except dns.resolver.NoNameservers:
                    self.logger.warning(f"[DNS] No nameservers could provide an answer for {record_type} records")
                    continue
                except Exception as e:
                    self.logger.warning(f"[DNS] Error querying {record_type} records for {domain}: {str(e)}")
                    continue
                
            except Exception as e:
                self.logger.warning(f"[DNS] Unexpected error querying {record_type} records for {domain}: {str(e)}")
                continue
        
        if not records:
            self.logger.warning(f"[DNS] No DNS records found for {domain}")
        else:
            self.logger.info(f"[DNS] Found {len(records)} total records for {domain}")
        
        return records
    
    def _get_ip_addresses(self, domain: str, port: int = 443) -> List[str]:
        """Get IP addresses for a domain."""
        try:
            # Check if domain is already an IP
            ipaddress.ip_address(domain)
            return [domain]
        except ValueError:
            try:
                ip_list = []
                hostname_ip = socket.getaddrinfo(domain, port, proto=socket.IPPROTO_TCP)
                for item in hostname_ip:
                    ip_address = item[4][0]
                    if ip_address not in ip_list:
                        ip_list.append(ip_address)
                return ip_list
            except socket.gaierror as e:
                if "[Errno 11001]" in str(e):
                    error_msg = f"Could not find '{domain}' in DNS records."
                else:
                    error_msg = f"DNS lookup failed for '{domain}' - {str(e)}"
                logger.error(f'DNS resolution failed for {domain}:{port}: {error_msg}')
                return []
    
    def _get_base_domain(self, wildcard_domain: str) -> Optional[str]:
        """Extract base domain from wildcard domain."""
        if wildcard_domain.startswith('*.'):
            return wildcard_domain[2:]
        return None
    
    def _expand_domains(self, domains: List[str]) -> List[str]:
        """Expand list of domains to include base domains for wildcards."""
        expanded = set()
        for domain in domains:
            if domain.startswith('*.'):
                base_domain = self._get_base_domain(domain)
                if base_domain:
                    logger.info(f'Converting wildcard {domain} to base domain {base_domain}')
                    expanded.add(base_domain)
            else:
                expanded.add(domain)
        return list(expanded)
    
    def _is_domain_ignored(self, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a domain is in the ignore list.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple[bool, Optional[str]]: (is_ignored, reason)
        """
        try:
            # Create database session
            from sqlalchemy import create_engine
            from sqlalchemy.orm import Session
            from .settings import settings
            from .models import IgnoredDomain
            
            # Get database path from settings
            db_path = settings.get("paths.database", "data/certificates.db")
            engine = create_engine(f"sqlite:///{db_path}")
            session = Session(engine)
            
            try:
                # First check exact matches
                ignored = session.query(IgnoredDomain).filter_by(pattern=domain).first()
                if ignored:
                    return True, ignored.reason
                
                # Then check all patterns
                patterns = session.query(IgnoredDomain).all()
                for pattern in patterns:
                    # Handle wildcard prefix (*.example.com)
                    if pattern.pattern.startswith('*.'):
                        suffix = pattern.pattern[2:]  # Remove *. from pattern
                        if domain.endswith(suffix):
                            return True, pattern.reason
                    # Handle suffix match (example.com)
                    elif domain.endswith(pattern.pattern):
                        return True, pattern.reason
                    # Handle contains pattern (*test*)
                    elif pattern.pattern.startswith('*') and pattern.pattern.endswith('*'):
                        search_term = pattern.pattern.strip('*')
                        if search_term in domain:
                            return True, pattern.reason
                
                return False, None
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            self.logger.error(f"Error checking ignore list for {domain}: {str(e)}")
            return False, None

    def _find_related_domains(self, whois_info: Dict) -> Set[str]:
        """
        Find related domains based on WHOIS information.
        
        Args:
            whois_info: WHOIS information dictionary
            
        Returns:
            Set[str]: Set of related domain names
        """
        related_domains = set()
        
        try:
            # Get registrant information
            registrant = whois_info.get('registrant', '')
            if not registrant:
                return related_domains
            
            # Apply rate limiting for WHOIS queries
            self.last_whois_query_time = self._apply_rate_limit(
                self.last_whois_query_time,
                self.whois_rate_limit,
                "WHOIS"
            )
            
            # Query WHOIS for domains with same registrant
            # Note: This is a simplified approach - in practice you'd want to use
            # a more sophisticated WHOIS query service that supports registrant-based searching
            w = whois.whois(registrant)
            if w and hasattr(w, 'domains') and w.domains:
                for domain in w.domains:
                    if self._validate_domain(domain):
                        related_domains.add(domain)
            
            return related_domains
            
        except Exception as e:
            # Log at debug level since this is non-critical functionality
            self.logger.debug(f"Could not find related domains: {str(e)}")
            return related_domains

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
        # Validate domain name format
        if not self._validate_domain(domain):
            return DomainInfo(
                domain_name=domain,
                is_valid=False,
                error="Invalid domain name format"
            )
        
        try:
            # Create database session for ignore list check
            from sqlalchemy import create_engine
            from sqlalchemy.orm import Session
            from .settings import settings
            from .models import IgnoredDomain
            
            db_path = settings.get("paths.database", "data/certificates.db")
            engine = create_engine(f"sqlite:///{db_path}")
            session = Session(engine)
            
            try:
                # Check if domain is in ignore list FIRST, before any scanning
                is_ignored = False
                ignore_reason = None
                
                # First check exact matches
                ignored = session.query(IgnoredDomain).filter_by(pattern=domain).first()
                if ignored:
                    is_ignored = True
                    ignore_reason = ignored.reason
                else:
                    # Then check all patterns
                    patterns = session.query(IgnoredDomain).all()
                    for pattern in patterns:
                        # Handle wildcard prefix (*.example.com)
                        if pattern.pattern.startswith('*.'):
                            suffix = pattern.pattern[2:]  # Remove *. from pattern
                            if domain.endswith(suffix):
                                is_ignored = True
                                ignore_reason = pattern.reason
                                break
                        # Handle suffix match (example.com)
                        elif domain.endswith(pattern.pattern):
                            is_ignored = True
                            ignore_reason = pattern.reason
                            break
                        # Handle contains pattern (*test*)
                        elif pattern.pattern.startswith('*') and pattern.pattern.endswith('*'):
                            search_term = pattern.pattern.strip('*')
                            if search_term in domain:
                                is_ignored = True
                                ignore_reason = pattern.reason
                                break
                
                if is_ignored:
                    self.logger.info(f"[SCAN] Skipping {domain} - Domain is in ignore list" + 
                                   (f" ({ignore_reason})" if ignore_reason else ""))
                    return DomainInfo(
                        domain_name=domain,
                        is_valid=True,
                        error=f"Domain is in ignore list" + (f" ({ignore_reason})" if ignore_reason else "")
                    )
            
            finally:
                session.close()
                engine.dispose()

            whois_info = {}
            dns_records = []
            related_domains = set()
            
            # Get WHOIS information if requested
            if get_whois:
                whois_info = self._get_whois_info(domain)
                # Find related domains based on WHOIS info
                if whois_info:  # Only try to find related domains if we got WHOIS info
                    related_domains = self._find_related_domains(whois_info)
            
            # Get DNS records if requested
            if get_dns:
                try:
                    dns_records = self._get_dns_records(domain)
                except Exception as e:
                    self.logger.warning(f"Error getting DNS records for {domain}: {str(e)}")
            
            # Create and return domain info object
            return DomainInfo(
                domain_name=domain,
                is_valid=True,
                registrar=whois_info.get('registrar'),
                registrant=whois_info.get('registrant'),
                registration_date=whois_info.get('creation_date'),
                expiration_date=whois_info.get('expiration_date'),
                status=whois_info.get('status', []),
                nameservers=whois_info.get('nameservers', []),
                dns_records=dns_records,
                domain_type=self._get_domain_type(domain),
                related_domains=related_domains
            )
            
        except Exception as e:
            self.logger.error(f"Error scanning domain {domain}: {str(e)}")
            return DomainInfo(
                domain_name=domain,
                is_valid=True,
                error=str(e)
            ) 