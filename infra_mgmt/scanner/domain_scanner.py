"""
Domain Scanner Module

This module provides functionality for scanning and analyzing domain information, including:
- WHOIS information retrieval and parsing
- DNS record scanning
- Domain validation
- Registration information processing

It is designed to support robust, rate-limited, and error-tolerant domain analysis for the Infrastructure Management System (IMS).
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
from ..models import IgnoredDomain, Domain, DomainDNSRecord
from ..constants import INTERNAL_TLDS, EXTERNAL_TLDS
from infra_mgmt.utils.ignore_list import IgnoreListUtil
from infra_mgmt.utils.domain_validation import DomainValidationUtil
from infra_mgmt.utils.dns_records import DNSRecordUtil
from infra_mgmt.utils.cache import ScanSessionCache

# Configure logging
logger = logging.getLogger(__name__)

class DomainInfo:
    """
    Data class representing domain information.

    Encapsulates all relevant data about a domain, including registrar, registration/expiration dates,
    DNS records, WHOIS status, and related domains. Used as the return type for domain scans.

    Attributes:
        domain_name (str): The domain name being described.
        registrar (Optional[str]): Registrar name, if available.
        registration_date (Optional[datetime]): Registration date.
        expiration_date (Optional[datetime]): Expiration date.
        registrant (Optional[str]): Registrant/owner name.
        status (Optional[List[str]]): WHOIS status codes.
        nameservers (Optional[List[str]]): List of nameservers.
        dns_records (Optional[List[Dict[str, Any]]]): DNS records for the domain.
        is_valid (bool): Whether the domain is valid.
        error (Optional[str]): Error message, if any.
        domain_type (Optional[str]): 'internal' or 'external'.
        related_domains (Optional[Set[str]]): Related domains found via WHOIS.
    """
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
        """
        Convert domain information to dictionary format.

        Returns:
            dict: Dictionary representation of the domain info, with ISO-formatted dates.
        """
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
    Domain scanning and analysis class for IMS.
    
    Provides robust, rate-limited, and error-tolerant methods to:
    - Validate domain names and formats
    - Retrieve WHOIS information
    - Gather DNS records
    - Classify domains as internal/external
    - Process wildcard domains and resolve IPs
    - Find related domains via WHOIS
    
    Implements intelligent rate limiting for different query types and provides
    robust error handling for network operations. Used by ScanManager and other
    components to enrich domain data and support compliance/audit workflows.
    
    Example usage:
        >>> scanner = DomainScanner()
        >>> info = scanner.scan_domain('example.com', get_whois=True, get_dns=True)
        >>> print(info.to_dict())
    """
    
    def __init__(self, session_cache: ScanSessionCache = None):
        """
        Initialize the domain scanner, loading configuration and rate limits.
        
        Sets up DNS/WHOIS rate limits, timeout settings, and domain classification lists.
        """
        # Configure DNS record types to scan
        self.dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        # Initialize rate limiting state
        self.last_whois_query_time = 0
        self.last_dns_query_time = 0
        
        # Load rate limits from settings
        from ..settings import settings
        self.whois_rate_limit = settings.get('scanning.whois.rate_limit', 10)  # Default 10/min
        self.dns_rate_limit = settings.get('scanning.dns.rate_limit', 30)      # Default 30/min
        
        # Load domain classification settings
        self.internal_domains = set(settings.get('scanning.internal.domains', []))
        self.external_domains = set(settings.get('scanning.external.domains', []))
        
        # Cache for successful nameserver sets
        self.successful_nameservers = {}
        
        self.logger = logging.getLogger(__name__)
        
        self.session_cache = session_cache or ScanSessionCache()
        
        logger.info(f"Initialized DomainScanner with WHOIS rate limit: {self.whois_rate_limit}/min, "
                   f"DNS rate limit: {self.dns_rate_limit}/min")
    
    def _apply_rate_limit(self, last_time: float, rate_limit: int, query_type: str) -> float:
        """
        Apply rate limiting for queries of a given type.
        
        Ensures that queries (WHOIS, DNS, etc.) do not exceed configured rate limits.
        Sleeps if necessary to avoid overloading external services.
        
        Args:
            last_time (float): Timestamp of last query
            rate_limit (int): Allowed queries per minute
            query_type (str): Type of query (for logging)
        
        Returns:
            float: Updated timestamp after rate limiting
        """
        current_time = time.time()
        time_since_last = current_time - last_time
        min_time_between_queries = 60.0 / rate_limit
        
        if time_since_last < min_time_between_queries:
            sleep_time = min_time_between_queries - time_since_last
            logger.debug(f"[{query_type}] Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
            current_time = time.time()
        
        return current_time
    
    def _get_domain_type(self, domain: str) -> str:
        """
        Determine if a domain is internal or external.
        
        Uses configured lists and TLDs to classify domains.
        
        Args:
            domain (str): Domain name
        
        Returns:
            str: 'internal' or 'external'
        """
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
        """
        Check if domain matches internal patterns from settings.
        
        Args:
            domain (str): Domain name
        
        Returns:
            bool: True if internal, False otherwise
        """
        return any(
            domain.endswith(internal_domain) if internal_domain.startswith('.')
            else domain == internal_domain
            for internal_domain in self.internal_domains
        )
    
    def _is_external_domain(self, domain: str) -> bool:
        """
        Check if domain matches external patterns from settings.
        
        Args:
            domain (str): Domain name
        
        Returns:
            bool: True if external, False otherwise
        """
        if self._is_internal_domain(domain):
            return False
        if not self.external_domains:
            return False
        return any(
            domain.endswith(external_domain) if external_domain.startswith('.')
            else domain == external_domain
            for external_domain in self.external_domains
        )
    
    def _get_whois_info(self, domain: str, session: Session) -> Dict:
        """
        Get WHOIS information for a domain, with rate limiting and ignore list checks.
        
        Args:
            domain (str): Domain name
            session (Session): SQLAlchemy session
        
        Returns:
            dict: WHOIS information fields (registrar, registrant, creation/expiration, status, nameservers)
        
        Edge Cases:
            - Handles missing/invalid WHOIS data, multiple date formats, and ignore list skips.
        """
        try:
            # Use cache if available
            cached = self.session_cache.get_whois(domain)
            if cached is not None:
                return cached

            # Check if domain should be ignored before doing WHOIS query
            is_ignored, reason = IgnoreListUtil.is_domain_ignored(session, domain)
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
            
            # Log all WHOIS information for debugging
            self.logger.info(f"[WHOIS] Retrieved information for {domain}:")
            self.logger.info(f"[WHOIS] - Registrar: {registrar}")
            self.logger.info(f"[WHOIS] - Registrant: {registrant}")
            self.logger.info(f"[WHOIS] - Creation Date: {creation_date}")
            self.logger.info(f"[WHOIS] - Expiration Date: {expiration_date}")
            self.logger.info(f"[WHOIS] - Status: {status}")
            self.logger.info(f"[WHOIS] - Nameservers: {nameservers}")
            
            # Use cache if available
            self.session_cache.set_whois(domain, result)
            return result
            
        except whois.parser.PywhoisError as e:
            self.logger.warning(f"[WHOIS] WHOIS lookup failed for {domain}: {str(e)}")
            return {}
        except Exception as e:
            self.logger.exception(f"[WHOIS] Unexpected error retrieving information for {domain}: {str(e)}")
            return {}
    
    def _get_ip_addresses(self, domain: str, port: int = 443) -> List[str]:
        """
        Get IP addresses for a domain using DNS resolution.
        
        Args:
            domain (str): Domain name or IP
            port (int): Port for socket resolution (default 443)
        
        Returns:
            list: List of resolved IP addresses (as strings)
        """
        try:
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
            except Exception as e:
                logger.exception(f"Unexpected error in DNS resolution for {domain}:{port}: {str(e)}")
                return []
    
    def _get_base_domain(self, wildcard_domain: str) -> Optional[str]:
        """
        Extract base domain from a wildcard domain (e.g., '*.example.com' -> 'example.com').
        
        Args:
            wildcard_domain (str): Wildcard domain
        
        Returns:
            str or None: Base domain if applicable
        """
        if wildcard_domain.startswith('*.'):
            return wildcard_domain[2:]
        return None
    
    def _expand_domains(self, domains: List[str]) -> List[str]:
        """
        Expand list of domains to include base domains for wildcards.
        
        Args:
            domains (List[str]): List of domains (may include wildcards)
        
        Returns:
            List[str]: Expanded list with base domains
        """
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
    
    def _find_related_domains(self, whois_info: Dict, session: Session) -> Set[str]:
        """
        Find related domains based on WHOIS information (registrant-based search).
        
        Args:
            whois_info (dict): WHOIS information dictionary
            session (Session): SQLAlchemy session
        
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
                    if DomainValidationUtil.is_valid_domain(domain):
                        related_domains.add(domain)
            
            return related_domains
            
        except whois.parser.PywhoisError as e:
            self.logger.debug(f"Could not find related domains (WHOIS error): {str(e)}")
            return related_domains
        except Exception as e:
            self.logger.debug(f"Unexpected error finding related domains: {str(e)}")
            return related_domains

    def _get_dns_records(self, domain: str) -> List[Dict]:
        cached = self.session_cache.get_dns(domain)
        if cached is not None:
            return cached
        records = DNSRecordUtil.get_dns_records(domain, self.dns_record_types)
        self.session_cache.set_dns(domain, records)
        return records

    def scan_domain(self, domain: str, session, get_whois: bool = True, get_dns: bool = True) -> DomainInfo:
        """
        Scan a domain for all available information (WHOIS, DNS, ignore list, etc.).
        Args:
            domain (str): Domain to scan
            session: SQLAlchemy session to use
            get_whois (bool): Whether to retrieve WHOIS info
            get_dns (bool): Whether to retrieve DNS records
        Returns:
            DomainInfo: Populated domain information object
        """
        # Validate domain name format
        if not DomainValidationUtil.is_valid_domain(domain):
            return DomainInfo(
                domain_name=domain,
                is_valid=False,
                error="Invalid domain name format"
            )
        # Remove any leftover try block and code that creates a session or engine
        # Only use the passed-in session for all DB operations
        # Remove any now-unused imports related to session/engine creation
        # ... rest of the method ...
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

            whois_info = {}
            dns_records = []
            related_domains = set()
            
            # Get WHOIS information if requested
            if get_whois:
                whois_info = self._get_whois_info(domain, session)
                # Find related domains based on WHOIS info
                if whois_info:  # Only try to find related domains if we got WHOIS info
                    related_domains = self._find_related_domains(whois_info, session)
            
            # Get or create domain object
            domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
            if not domain_obj:
                domain_obj = Domain(
                    domain_name=domain,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                session.add(domain_obj)
                session.commit()  # Commit to get domain ID
            
            # Update domain information from WHOIS
            if whois_info:
                domain_obj.registrar = whois_info.get('registrar')
                domain_obj.registration_date = whois_info.get('creation_date')
                domain_obj.expiration_date = whois_info.get('expiration_date')
                domain_obj.owner = whois_info.get('registrant')
                domain_obj.updated_at = datetime.now()
                session.commit()  # Commit WHOIS updates
            
            # Get DNS records if requested
            if get_dns:
                try:
                    dns_records = self._get_dns_records(domain)
                    if dns_records:
                        # Get existing DNS records
                        existing_records = session.query(DomainDNSRecord).filter_by(domain_id=domain_obj.id).all()
                        existing_map = {(r.record_type, r.name, r.value): r for r in existing_records}
                        
                        # Process each DNS record
                        for record in dns_records:
                            record_key = (record['type'], record['name'], record['value'])
                            
                            if record_key in existing_map:
                                # Update existing record
                                existing_record = existing_map[record_key]
                                existing_record.ttl = record['ttl']
                                existing_record.priority = record.get('priority')
                                existing_record.updated_at = datetime.now()
                            else:
                                # Create new record
                                dns_record = DomainDNSRecord(
                                    domain=domain_obj,
                                    record_type=record['type'],
                                    name=record['name'],
                                    value=record['value'],
                                    ttl=record['ttl'],
                                    priority=record.get('priority'),
                                    created_at=datetime.now(),
                                    updated_at=datetime.now()
                                )
                                session.add(dns_record)
                        
                        # Commit DNS changes
                        session.commit()
                        
                except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
                    self.logger.warning(f"DNS error getting records for {domain}: {str(e)}")
                    session.rollback()
                except Exception as e:
                    self.logger.exception(f"Unexpected error getting DNS records for {domain}: {str(e)}")
                    session.rollback()
            
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
            
        except ImportError as e:
            self.logger.error(f"Import error scanning domain {domain}: {str(e)}")
            return DomainInfo(
                domain_name=domain,
                is_valid=True,
                error=f"Import error: {str(e)}"
            )
        except Exception as e:
            self.logger.exception(f"Unexpected error scanning domain {domain}: {str(e)}")
            return DomainInfo(
                domain_name=domain,
                is_valid=True,
                error=str(e)
            ) 