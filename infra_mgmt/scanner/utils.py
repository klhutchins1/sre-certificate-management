import ipaddress
import dns.resolver
import dns.reversename
import logging
from typing import Any, Dict

def is_ip_address(address: str) -> bool:
    """Check if a string is an IP address."""
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
    Get information about an IP address.
    Args:
        ip: IP address to look up
    Returns:
        Dict containing IP information including:
        - WHOIS data
        - Reverse DNS
        - Network range
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