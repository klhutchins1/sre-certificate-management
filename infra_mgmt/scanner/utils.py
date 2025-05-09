import ipaddress
import dns.resolver
import dns.reversename
import logging
from typing import Any, Dict, Tuple, Optional

def is_ip_address(address: str) -> bool:
    """
    Check if a string is an IP address (IPv4 or IPv6).

    Attempts to parse the input string as an IP address using the ipaddress module.
    Returns True if valid, False otherwise. Handles both IPv4 and IPv6.

    Args:
        address (str): The string to check

    Returns:
        bool: True if the string is a valid IP address, False otherwise

    Edge Cases:
        - Returns False for empty strings, malformed addresses, or exceptions
        - Logs unexpected errors for debugging

    Example:
        >>> is_ip_address('192.168.1.1')
        True
        >>> is_ip_address('not.an.ip')
        False
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
    except Exception as e:
        logging.getLogger(__name__).exception(f"Unexpected error in is_ip_address for {address}: {str(e)}")
        return False

def get_ip_info(ip: str) -> Dict[str, Any]:
    """
    Get information about an IP address, including WHOIS, reverse DNS, and network range.

    This function attempts to gather:
    - Reverse DNS (PTR records)
    - Network range (CIDR block)
    - WHOIS information (registrar, organization, country, creation/updated date)

    Args:
        ip (str): IP address to look up

    Returns:
        Dict[str, Any]: Dictionary containing:
            - 'whois': WHOIS info dict or None
            - 'hostnames': List of PTR hostnames (may be empty)
            - 'network': Network range as string (CIDR) or None

    Edge Cases:
        - Handles NXDOMAIN, NoNameservers, and other DNS errors gracefully
        - Handles ValueError for invalid IP/network
        - Handles ImportError if whois module is missing
        - Logs all errors for debugging

    Example:
        >>> get_ip_info('8.8.8.8')
        {'whois': {...}, 'hostnames': [...], 'network': '8.8.8.0/24'}
    """
    logger = logging.getLogger(__name__)
    info = {
        'whois': None,
        'hostnames': [],
        'network': None
    }
    try:
        # Get reverse DNS (PTR records)
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(addr, "PTR")
            info['hostnames'] = [str(rdata).rstrip('.') for rdata in answers]
        except dns.resolver.NXDOMAIN as e:
            logger.debug(f"Reverse DNS lookup failed for {ip} (NXDOMAIN): {str(e)}")
        except dns.resolver.NoNameservers as e:
            logger.debug(f"Reverse DNS lookup failed for {ip} (NoNameservers): {str(e)}")
        except Exception as e:
            logger.debug(f"Reverse DNS lookup failed for {ip}: {str(e)}")
        # Get network information
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
            else:
                network = ipaddress.ip_network(f"{ip}/64", strict=False)
            info['network'] = str(network)
        except ValueError as e:
            logger.debug(f"Network determination failed for {ip} (ValueError): {str(e)}")
        except Exception as e:
            logger.debug(f"Network determination failed for {ip}: {str(e)}")
        # Get WHOIS information
        try:
            import whois
            whois_info = whois.whois(ip)
            if whois_info:
                info['whois'] = {
                    'registrar': whois_info.registrar,
                    'organization': whois_info.org,
                    'country': whois_info.country,
                    'creation_date': whois_info.creation_date,
                    'updated_date': whois_info.updated_date
                }
        except ImportError as e:
            logger.error(f"WHOIS module not found for {ip}: {str(e)}")
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {ip}: {str(e)}")
        return info
    except Exception as e:
        logger.exception(f"Unexpected error getting IP information for {ip}: {str(e)}")
        return info

# --- Ignore List Utility ---
from ..models import IgnoredDomain, IgnoredCertificate

class IgnoreListUtil:
    """
    Utility class for ignore list checks (domains and certificates).
    Provides static methods to check if a domain or certificate CN should be ignored.
    """
    @staticmethod
    def is_domain_ignored(session, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a domain is in the ignore list (supports wildcards, suffix, contains, and exact).
        Args:
            session: SQLAlchemy session
            domain: Domain to check
        Returns:
            (is_ignored, reason)
        """
        try:
            # First check exact and pattern matches using model's matches()
            patterns = session.query(IgnoredDomain).all()
            for pattern in patterns:
                if pattern.matches(domain):
                    return True, pattern.reason
                # Additional contains pattern (*test*)
                if pattern.pattern.startswith('*') and pattern.pattern.endswith('*') and pattern.pattern.count('*') == 2:
                    search_term = pattern.pattern.strip('*')
                    if search_term in domain:
                        return True, pattern.reason
            return False, None
        except Exception as e:
            logging.getLogger(__name__).exception(f"Error checking ignore list for domain {domain}: {str(e)}")
            return False, None

    @staticmethod
    def is_certificate_ignored(session, common_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a certificate's Common Name is in the ignore list (supports wildcards, contains, and exact).
        Args:
            session: SQLAlchemy session
            common_name: Certificate Common Name to check
        Returns:
            (is_ignored, reason)
        """
        try:
            patterns = session.query(IgnoredCertificate).all()
            for pattern in patterns:
                if pattern.matches(common_name):
                    return True, pattern.reason
            return False, None
        except Exception as e:
            logging.getLogger(__name__).exception(f"Error checking ignore list for certificate CN {common_name}: {str(e)}")
            return False, None 