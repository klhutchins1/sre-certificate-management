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
        
        # Basic domain name pattern
        pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
        
        # Check basic format
        if not re.match(pattern, domain):
            return False
        
        # Check length
        if len(domain) > 253:
            return False
        
        # Check segment lengths
        for segment in domain.split('.'):
            if len(segment) > 63:
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
            w = whois.whois(domain)  # Use whois() instead of query()
            if not w:
                logger.warning(f"No WHOIS information found for {domain}")
                return {}
            
            # Process dates
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            # Get registrar info
            registrar = w.registrar
            if isinstance(registrar, list):
                registrar = registrar[0]
            
            # Get registrant info
            registrant = None
            for field in ['registrant_name', 'org', 'owner', 'name']:
                value = getattr(w, field, None)
                if value:
                    if isinstance(value, list):
                        value = value[0]
                    registrant = value
                    break
            
            # Get status
            status = w.status
            if isinstance(status, str):
                status = [status]
            elif not status:
                status = []
            
            # Get nameservers
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
            
            # Log the retrieved information
            logger.info(f"Retrieved WHOIS info for {domain}: {result}")
            
            return result
            
        except Exception as e:
            logger.warning(f"Error getting WHOIS info for {domain}: {str(e)}")
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
        
        for record_type in self.dns_record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
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
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                logger.warning(f"Error getting {record_type} records for {domain}: {str(e)}")
                continue
        
        return records
    
    def scan_domain(self, domain: str) -> DomainInfo:
        """
        Scan a domain for all available information.
        
        Args:
            domain: Domain name to scan
            
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
            # Get WHOIS information
            whois_info = self._get_whois_info(domain)
            if not whois_info:
                return DomainInfo(
                    domain_name=domain,
                    is_valid=True,
                    error="Could not retrieve WHOIS information"
                )
            
            # Get DNS records
            try:
                dns_records = self._get_dns_records(domain)
            except Exception as e:
                logger.warning(f"Error getting DNS records for {domain}: {str(e)}")
                dns_records = []
            
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