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
        # Fast guard for None and non-string inputs
        if address is None:
            return False
        if not isinstance(address, (str, bytes, bytearray)):
            return False
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False
    except Exception as e:
        logging.getLogger(__name__).error(f"Unexpected error in is_ip_address for {address}: {str(e)}")
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
            # Check offline mode before doing WHOIS query
            from ..utils.network_detection import is_offline
            if is_offline(respect_config=True):
                logger.debug(f"WHOIS lookup skipped for {ip} - System is in offline mode")
            else:
                # Import whois with compatibility handling
                try:
                    import whois
                    # Check if this is python-whois package by testing for whois.whois function
                    if hasattr(whois, 'whois') and callable(getattr(whois, 'whois', None)):
                        # Use python-whois package
                        whois_info = whois.whois(ip)  # type: ignore
                        if whois_info:
                            info['whois'] = {
                                'registrar': getattr(whois_info, 'registrar', None),
                                'organization': getattr(whois_info, 'org', None),
                                'country': getattr(whois_info, 'country', None),
                                'creation_date': getattr(whois_info, 'creation_date', None),
                                'updated_date': getattr(whois_info, 'updated_date', None)
                            }
                    else:
                        # whois package doesn't support IP lookups in the same way
                        logger.debug(f"WHOIS package doesn't support IP lookups for {ip}")
                except (ImportError, AttributeError, ModuleNotFoundError):
                    logger.debug(f"WHOIS module not available for {ip}")
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {ip}: {str(e)}")
        return info
    except Exception as e:
        logger.exception(f"Unexpected error getting IP information for {ip}: {str(e)}")
        return info 