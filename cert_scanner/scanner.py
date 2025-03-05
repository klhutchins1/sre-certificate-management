"""
Certificate scanning and processing module for the Certificate Management System.

This module provides functionality for scanning and analyzing SSL/TLS certificates,
including:
- Certificate discovery and retrieval
- Certificate parsing and information extraction
- Domain information gathering
- Rate-limited scanning for different domain types
- Domain classification (internal/external)
- Wildcard certificate handling
- IP address resolution

The module implements intelligent rate limiting based on domain types and
provides robust error handling for network and certificate processing operations.
All operations are configurable through the application settings.
"""

#------------------------------------------------------------------------------
# Imports and Configuration
#------------------------------------------------------------------------------

# Standard library imports
import dataclasses
from datetime import datetime
import ssl
import socket
import logging
import ipaddress
import time
from collections import deque
from typing import Optional, List, Dict, Set

# Third-party imports
import OpenSSL.crypto

# Local application imports
from .settings import settings
from .domain_scanner import DomainScanner, DomainInfo
from .models import IgnoredDomain
from .db import get_session

#------------------------------------------------------------------------------
# Domain Configuration
#------------------------------------------------------------------------------

# Common internal TLDs and subdomains
# Used for automatic domain classification when not explicitly configured
INTERNAL_TLDS = {
    '.local', '.lan', '.internal', '.intranet', '.corp', '.private',
    '.test', '.example', '.invalid', '.localhost'
}

# Common external TLDs
# Used for automatic domain classification when not explicitly configured
EXTERNAL_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.io', '.co', '.biz', '.info', '.name', '.mobi', '.app',
    '.cloud', '.dev', '.ai'
}

#------------------------------------------------------------------------------
# Certificate Data Model
#------------------------------------------------------------------------------

@dataclasses.dataclass
class CertificateInfo:
    """
    Data class representing certificate information.
    
    Attributes:
        hostname (str): The hostname the certificate was retrieved from
        ip_addresses (List[str]): List of IP addresses the hostname resolves to
        port (int): Port number the certificate was retrieved from
        common_name (str): Certificate's Common Name (CN)
        expiration_date (datetime): Certificate expiration date
        serial_number (str): Certificate serial number
        thumbprint (str): SHA1 thumbprint of the certificate
        san (List[str]): Subject Alternative Names
        issuer (Dict[str, str]): Certificate issuer information
        subject (Dict[str, str]): Certificate subject information
        valid_from (datetime): Certificate validity start date
        key_usage (Optional[str]): Certificate key usage flags
        extended_key_usage (Optional[str]): Extended key usage flags
        signature_algorithm (Optional[str]): Signature algorithm used
        version (Optional[int]): X.509 version number
        chain_valid (bool): Indicates if the certificate chain is valid
    """
    hostname: str
    ip_addresses: List[str]
    port: int
    common_name: str
    expiration_date: datetime
    serial_number: str
    thumbprint: str
    san: List[str]
    issuer: Dict[str, str]
    subject: Dict[str, str]
    valid_from: datetime
    key_usage: Optional[str] = None
    extended_key_usage: Optional[str] = None
    signature_algorithm: Optional[str] = None
    version: Optional[int] = None
    chain_valid: bool = False

@dataclasses.dataclass
class ScanResult:
    """Data class representing complete scan results."""
    certificate_info: Optional[CertificateInfo] = None
    domain_info: Optional[DomainInfo] = None
    error: Optional[str] = None

#------------------------------------------------------------------------------
# Certificate Scanner Implementation
#------------------------------------------------------------------------------

class CertificateScanner:
    """
    Certificate scanning and analysis class.
    
    This class provides functionality to:
    - Scan certificates from network endpoints
    - Process and extract certificate information
    - Handle rate limiting for different domain types
    - Manage domain classification
    - Process wildcard certificates
    
    The scanner implements intelligent rate limiting based on domain type
    (internal/external) and provides robust error handling for network
    and certificate processing operations.
    """
    
    def __init__(self, logger=None):
        """
        Initialize the certificate scanner.
        
        Args:
            logger: Optional logger instance. If not provided, creates a new logger.
            
        The scanner initializes with configuration from settings including:
        - Rate limiting parameters for different domain types
        - Domain classification rules
        - Scanning timeouts and retry logic
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize rate limiting configuration - More conservative defaults
        self.default_rate_limit = settings.get('scanning.default_rate_limit', 30)  # Default 30 requests/minute (1/2sec)
        
        # Initialize domain-specific rate limiting configuration
        self.internal_domains = set(settings.get('scanning.internal.domains', []))
        self.external_domains = set(settings.get('scanning.external.domains', []))
        self.internal_rate_limit = settings.get('scanning.internal.rate_limit', 60)  # Default 1/sec for internal
        self.external_rate_limit = settings.get('scanning.external.rate_limit', 20)  # Default 1/3sec for external
        
        # Initialize rate limiting state with request timestamps
        self.request_timestamps = deque(maxlen=max(self.default_rate_limit, 
                                                 self.internal_rate_limit, 
                                                 self.external_rate_limit))
        self.last_scan_time = 0
        
        # Initialize domain scanner
        self.domain_scanner = DomainScanner()
    
    def _get_domain_type(self, domain: str) -> str:
        """
        Determine if a domain is internal or external based on TLD and configuration.
        
        Args:
            domain (str): Domain name to classify
            
        Returns:
            str: Domain classification ('internal', 'external', or 'custom')
            
        The classification is determined by:
        1. Checking against configured internal domains
        2. Checking against configured external domains
        3. Checking against known internal TLDs
        4. Checking against known external TLDs
        5. Defaulting to 'external' if no match
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
        Determine if a domain matches configured internal patterns.
        
        Args:
            domain (str): Domain name to check
            
        Returns:
            bool: True if domain matches internal patterns
        """
        return any(
            domain.endswith(internal_domain) if internal_domain.startswith('.')
            else domain == internal_domain
            for internal_domain in self.internal_domains
        )
    
    def _is_external_domain(self, domain: str) -> bool:
        """
        Determine if a domain matches configured external patterns.
        
        Args:
            domain (str): Domain name to check
            
        Returns:
            bool: True if domain matches external patterns
            
        Note:
            Returns False if domain matches internal patterns, regardless of
            external pattern matches.
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
    
    def _apply_rate_limit(self, domain: str):
        """
        Apply rate limiting based on domain type.
        
        Args:
            domain: Domain being scanned
            
        This method implements intelligent rate limiting by:
        1. Determining appropriate rate limit based on domain type
        2. Maintaining a rolling window of request timestamps
        3. Enforcing minimum time between requests
        4. Sleeping when rate limit is reached
        """
        current_time = time.time()
        domain_type = self._get_domain_type(domain)
        
        # Determine rate limit based on domain type
        if domain_type == 'internal':
            rate_limit = self.internal_rate_limit
            self.logger.debug(f"Using internal rate limit ({rate_limit} req/min) for {domain}")
        elif domain_type == 'external':
            rate_limit = self.external_rate_limit
            self.logger.debug(f"Using external rate limit ({rate_limit} req/min) for {domain}")
        else:
            rate_limit = self.default_rate_limit
            self.logger.debug(f"Using default rate limit ({rate_limit} req/min) for {domain}")
            
        # Calculate time per request in seconds
        time_per_request = 60.0 / rate_limit
        
        # Remove timestamps older than our window
        while self.request_timestamps and current_time - self.request_timestamps[0] > 60:
            self.request_timestamps.popleft()
            
        # If we've hit our rate limit, sleep until we can make another request
        if len(self.request_timestamps) >= rate_limit:
            sleep_time = self.request_timestamps[0] + 60 - current_time
            if sleep_time > 0:
                self.logger.info(f"Rate limiting ({domain_type}): sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                current_time = time.time()
                
                # Clean up old timestamps after sleeping
                while self.request_timestamps and current_time - self.request_timestamps[0] > 60:
                    self.request_timestamps.popleft()
        
        # Ensure minimum time between requests
        time_since_last = current_time - self.last_scan_time
        if time_since_last < time_per_request:
            sleep_time = time_per_request - time_since_last
            time.sleep(sleep_time)
            current_time = time.time()
        
        # Update rate limiting state
        self.request_timestamps.append(current_time)
        self.last_scan_time = current_time
    
    def _get_base_domain(self, wildcard_domain: str) -> Optional[str]:
        """
        Extract base domain from wildcard domain.
        
        Args:
            wildcard_domain (str): Domain name potentially containing wildcard
            
        Returns:
            Optional[str]: Base domain without wildcard, or None if not a wildcard
            
        Examples:
            *.google.com -> google.com
            *.google.co.in -> google.co.in
        """
        if wildcard_domain.startswith('*.'):
            return wildcard_domain[2:]
        return None
    
    def _expand_domains(self, domains: List[str]) -> List[str]:
        """
        Expand list of domains to include base domains for wildcards.
        
        Args:
            domains (List[str]): List of domain names
            
        Returns:
            List[str]: Expanded list with wildcard domains converted to base domains
            
        Note:
            Skips the wildcard domains themselves as they can't be scanned directly.
        """
        expanded = set()
        for domain in domains:
            if domain.startswith('*.'):
                base_domain = self._get_base_domain(domain)
                if base_domain:
                    self.logger.info(f'Converting wildcard {domain} to base domain {base_domain}')
                    expanded.add(base_domain)
            else:
                expanded.add(domain)
        return list(expanded)
    
    def scan_certificate(self, address: str, port: int = 443) -> ScanResult:
        """
        Scan a certificate and domain information.
        
        Args:
            address: Hostname or IP address to scan
            port: Port number to scan (default: 443)
            
        Returns:
            ScanResult: Combined certificate and domain scan results
        """
        result = ScanResult()
        
        # Handle wildcard domains by scanning the base domain
        if address.startswith('*.'):
            base_domain = self._get_base_domain(address)
            if base_domain:
                self.logger.info(f'Converting wildcard {address} to base domain {base_domain}')
                return self.scan_certificate(base_domain, port)
            else:
                result.error = f"Invalid wildcard domain format: {address}"
                return result
        
        try:
            # Check if domain is in ignore list
            session = get_session()
            try:
                # Convert address to lowercase for case-insensitive comparison
                address_lower = address.lower()
                
                # First check exact matches (case-insensitive)
                ignored = session.query(IgnoredDomain).filter(
                    IgnoredDomain.pattern.ilike(address_lower)
                ).first()
                if ignored:
                    self.logger.info(f"[IGNORE] Skipping {address} - Domain is in ignore list" + (f" ({ignored.reason})" if ignored.reason else ""))
                    result.error = f"Domain is in ignore list" + (f" ({ignored.reason})" if ignored.reason else "")
                    return result
                
                # Then check wildcard patterns
                wildcard_patterns = session.query(IgnoredDomain).filter(
                    IgnoredDomain.pattern.like('*.*')
                ).all()
                
                for pattern in wildcard_patterns:
                    if pattern.pattern.startswith('*.'):
                        suffix = pattern.pattern[2:].lower()  # Remove *. from pattern and convert to lowercase
                        if address_lower.endswith(suffix):
                            self.logger.info(f"[IGNORE] Skipping {address} - Matches wildcard pattern {pattern.pattern}" + 
                                          (f" ({pattern.reason})" if pattern.reason else ""))
                            result.error = f"Domain matches ignored pattern {pattern.pattern}" + (f" ({pattern.reason})" if pattern.reason else "")
                            return result
            finally:
                session.close()
            
            # Apply rate limiting before scanning certificate
            self._apply_rate_limit(address)
            
            # Get certificate information
            cert_binary = self._get_certificate(address, port)
            if cert_binary:
                cert_info = self._process_certificate(cert_binary, address, port)
                if cert_info:
                    result.certificate_info = cert_info
                    result.error = None  # Explicitly set error to None for successful scan
                else:
                    result.error = "Failed to process certificate data"
            else:
                result.error = "No certificate found"
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error scanning {address}:{port} - {str(e)}")
            result.error = str(e)
            return result
    
    def scan_domains(self, domains: List[str], port: int = 443) -> List[ScanResult]:
        """
        Scan a list of domains for certificates and domain information.
        
        Args:
            domains: List of domains to scan
            port: Port number to scan (default: 443)
            
        Returns:
            List[ScanResult]: List of scan results
        """
        expanded_domains = self._expand_domains(domains)
        results = []
        for domain in expanded_domains:
            try:
                result = self.scan_certificate(domain, port)
                if isinstance(result, CertificateInfo):
                    # Convert old-style result to ScanResult
                    scan_result = ScanResult()
                    scan_result.certificate_info = result
                    results.append(scan_result)
                else:
                    results.append(result)
            except Exception as e:
                # Convert common errors to friendly messages
                error_msg = str(e)
                if "[Errno 11001]" in error_msg:
                    error_msg = f"Could not find '{domain}' in DNS records. This usually means either:\n1. The domain name is misspelled\n2. The domain doesn't exist\n3. DNS servers are not responding"
                elif "getaddrinfo failed" in error_msg:
                    error_msg = f"DNS lookup failed for '{domain}' - Could not resolve hostname"
                results.append(ScanResult(error=error_msg))
        return results
    
    def _get_certificate(self, address: str, port: int) -> Optional[bytes]:
        """Get certificate from host with timeout."""
        sock = None
        ssock = None
        
        try:
            # Log the attempt
            self.logger.info(f"Attempting to retrieve certificate from {address}:{port}")
            
            # Get timeout from settings
            socket_timeout = settings.get('scanning.timeouts.socket', 5)
            
            # Create SSL context with chain validation
            context = ssl.create_default_context()
            context.check_hostname = False  # We'll validate hostname separately
            context.verify_mode = ssl.CERT_OPTIONAL  # Try to validate chain but don't require it
            context.set_ciphers('ALL')
            
            # Debug log the CA paths being used
            self.logger.debug(f"Default verify paths: {ssl.get_default_verify_paths()}")
            
            try:
                # Create socket with timeout
                sock = socket.create_connection((address, port), timeout=socket_timeout)
                try:
                    ssock = context.wrap_socket(sock, server_hostname=address)
                    
                    # Get the certificate chain
                    cert_chain = ssock.get_peer_cert_chain() if hasattr(ssock, 'get_peer_cert_chain') else None
                    if cert_chain:
                        self.logger.debug(f"Certificate chain length: {len(cert_chain)}")
                        for i, cert in enumerate(cert_chain):
                            self.logger.debug(f"Chain cert {i}: Subject: {cert.get_subject()}, Issuer: {cert.get_issuer()}")
                    
                    # Verify the certificate chain
                    try:
                        context.verify_mode = ssl.CERT_REQUIRED
                        ssock.do_handshake()  # Force a new handshake with stricter verification
                        self._last_cert_chain = True
                        self.logger.info(f"Certificate chain validation successful for {address}:{port}")
                    except ssl.SSLError as chain_error:
                        self._last_cert_chain = False
                        self.logger.warning(f"Certificate chain validation failed for {address}:{port}: {str(chain_error)}")
                    
                    # Get certificate in binary form
                    cert_binary = ssock.getpeercert(binary_form=True)
                    if cert_binary:
                        self.logger.info(f"Certificate retrieved from {address}:{port}")
                        return cert_binary
                    
                    msg = f"The server at {address}:{port} accepted the connection but did not present a certificate. This might mean HTTPS is not configured or SSL is handled by a proxy."
                    self.logger.warning(msg)
                    return None
                    
                except ssl.SSLError as e:
                    self._last_cert_chain = False  # Chain validation failed
                    if "alert internal error" in str(e):
                        msg = f"The server at {address}:{port} actively rejected the SSL/TLS connection."
                    else:
                        msg = f"SSL/TLS connection failed: {str(e)}"
                    self.logger.error(f"SSL error for {address}:{port}: {msg}")
                    raise Exception(msg)
                    
            except socket.timeout:
                msg = f"The server at {address}:{port} did not respond within {socket_timeout} seconds"
                self.logger.error(msg)
                raise Exception(msg)
            except ConnectionRefusedError:
                msg = f"Nothing is listening for HTTPS connections at {address}:{port}"
                self.logger.warning(f"{address}:{port} is not reachable")
                self.logger.error(msg)
                raise Exception(msg)
                
        except Exception as e:
            if isinstance(e, (socket.timeout, ConnectionRefusedError, ssl.SSLError)):
                raise
            self.logger.error(f"Error retrieving certificate from {address}:{port}: {str(e)}")
            raise
        finally:
            # Clean up sockets
            if ssock:
                try:
                    ssock.close()
                except:
                    pass
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        return None
    
    def _process_certificate(self, cert_binary: bytes, address: str, port: int) -> Optional[CertificateInfo]:
        """Process raw certificate data into structured information."""
        try:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)
        except OpenSSL.crypto.Error as e:
            error_msg = str(e)
            if e.args and isinstance(e.args[0], list) and e.args[0]:
                error_details = e.args[0][0]
                if len(error_details) >= 3:
                    error_msg = error_details[2]
            self.logger.error(f"Error loading certificate: {error_msg}")
            return None
            
        # Get IP addresses
        ip_addresses = self._get_ip_addresses(address, port)
        
        # Extract certificate information
        serial_number = f'{x509.get_serial_number():x}'
        thumbprint = x509.digest("sha1").decode('utf-8').replace(':', '')
        san = self._extract_san(x509)
        common_name = self._extract_common_name(x509)
        issuer = self._extract_name_dict(x509.get_issuer())
        subject = self._extract_name_dict(x509.get_subject())
        
        # Extract key usage
        key_usage = None
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if ext.get_short_name() == b'keyUsage':
                key_usage = str(ext)
                break
        
        # Get signature algorithm - try multiple methods
        signature_algorithm = None
        try:
            # Common signature algorithm OIDs and their names
            sig_alg_oids = {
                "1.2.840.113549.1.1.5": "SHA1withRSA",
                "1.2.840.113549.1.1.11": "SHA256withRSA",
                "1.2.840.113549.1.1.12": "SHA384withRSA",
                "1.2.840.113549.1.1.13": "SHA512withRSA",
                "1.2.840.10045.4.3.2": "ECDSA-SHA256",
                "1.2.840.10045.4.3.3": "ECDSA-SHA384",
                "1.2.840.10045.4.3.4": "ECDSA-SHA512",
                "1.3.14.3.2.29": "SHA1withRSA",
                "1.2.840.113549.1.1.4": "MD5withRSA",
                "1.2.840.113549.1.1.1": "RSA",
                "1.2.840.113549.1.1.2": "MD2withRSA",
                "1.2.840.113549.1.1.3": "MD4withRSA",
                "1.2.840.113549.1.1.6": "SHA1withRSA",
                "1.2.840.113549.1.1.7": "RSAES-OAEP",
                "1.2.840.113549.1.1.8": "MGF1",
                "1.2.840.113549.1.1.9": "RSASSA-PSS",
                "1.2.840.113549.1.1.10": "RSASSA-PSS",
                "1.2.840.10045.4.1": "ECDSA-SHA1",
                "1.2.840.10045.4.3.1": "ECDSA-SHA224",
                "1.2.840.10040.4.3": "DSA-SHA1",
                "2.16.840.1.101.3.4.3.1": "DSA-SHA224",
                "2.16.840.1.101.3.4.3.2": "DSA-SHA256"
            }

            # Method 1: Try getting algorithm directly
            try:
                sig_alg_direct = x509.get_signature_algorithm()
                if sig_alg_direct:
                    self.logger.info(f"Method 1 - Direct signature algorithm for {address}: {sig_alg_direct}")
                    signature_algorithm = sig_alg_direct.decode('utf-8')
            except Exception as e1:
                self.logger.warning(f"Method 1 failed for {address}: {str(e1)}")

            # Method 2: Try OID mapping
            if not signature_algorithm:
                try:
                    sig_alg_oid = x509.get_signature_algorithm_oid().decode('utf-8')
                    self.logger.info(f"Method 2 - Signature algorithm OID for {address}: {sig_alg_oid}")
                    if sig_alg_oid in sig_alg_oids:
                        signature_algorithm = sig_alg_oids[sig_alg_oid]
                        self.logger.info(f"Method 2 - Mapped signature algorithm for {address}: {signature_algorithm}")
                    else:
                        signature_algorithm = sig_alg_oid
                        self.logger.info(f"Method 2 - Using OID as signature algorithm for {address}: {signature_algorithm}")
                except Exception as e2:
                    self.logger.warning(f"Method 2 failed for {address}: {str(e2)}")

            # Method 3: Try getting algorithm name directly
            if not signature_algorithm:
                try:
                    sig_alg_name = x509.get_signature_algorithm_name()
                    if sig_alg_name:
                        self.logger.info(f"Method 3 - Algorithm name for {address}: {sig_alg_name}")
                        signature_algorithm = sig_alg_name.decode('utf-8') if isinstance(sig_alg_name, bytes) else str(sig_alg_name)
                except Exception as e3:
                    self.logger.warning(f"Method 3 failed for {address}: {str(e3)}")

            if not signature_algorithm:
                self.logger.warning(f"All signature algorithm extraction methods failed for {address}")
            else:
                self.logger.info(f"Final signature algorithm for {address}: {signature_algorithm}")

        except Exception as e:
            self.logger.error(f"Error getting signature algorithm for {address}: {str(e)}")
            signature_algorithm = None
        
        # Get dates
        valid_from = datetime.strptime(
            x509.get_notBefore().decode('utf-8'),
            '%Y%m%d%H%M%SZ'
        )
        expiration_date = datetime.strptime(
            x509.get_notAfter().decode('utf-8'),
            '%Y%m%d%H%M%SZ'
        )
        
        # Add chain validation status
        chain_valid = hasattr(self, '_last_cert_chain') and self._last_cert_chain
        
        cert_info = CertificateInfo(
            hostname=address,
            ip_addresses=ip_addresses,
            port=port,
            common_name=common_name,
            expiration_date=expiration_date,
            serial_number=serial_number,
            thumbprint=thumbprint,
            san=san,
            issuer=issuer,
            subject=subject,
            valid_from=valid_from,
            version=x509.get_version(),
            key_usage=key_usage,
            signature_algorithm=signature_algorithm,
            chain_valid=chain_valid  # Add chain validation status
        )
        
        # Clear the chain reference
        if hasattr(self, '_last_cert_chain'):
            delattr(self, '_last_cert_chain')
        
        return cert_info
        
    def _extract_san(self, x509cert) -> List[str]:
        """
        Extract Subject Alternative Names from certificate.
        
        Args:
            x509cert: OpenSSL certificate object
            
        Returns:
            List[str]: List of Subject Alternative Names
            
        Note:
            Only extracts DNS names from the SAN extension.
        """
        san = []
        for i in range(x509cert.get_extension_count()):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san_string = ext.__str__()
                # Parse the SAN string into a list
                for entry in san_string.split(','):
                    entry = entry.strip()
                    if entry.startswith('DNS:'):
                        san.append(entry.split('DNS:')[1].strip())
        return san
        
    def _extract_common_name(self, x509cert) -> Optional[str]:
        """
        Extract Common Name from certificate subject.
        
        Args:
            x509cert: OpenSSL certificate object
            
        Returns:
            Optional[str]: Common Name if found, None otherwise
        """
        subject = x509cert.get_subject()
        for name, value in subject.get_components():
            if name == b'CN':
                return value.decode('utf-8')
        return None
        
    def _get_ip_addresses(self, address: str, port: int = 443) -> List[str]:
        """
        Get IP addresses for hostname.
        
        Args:
            address (str): Hostname or IP address
            port (int, optional): Port number. Defaults to 443.
            
        Returns:
            List[str]: List of resolved IP addresses
            
        Note:
            - Handles both hostnames and IP addresses
            - Returns empty list if resolution fails
            - Removes duplicate IP addresses
        """
        try:
            # Check if address is already an IP
            ipaddress.ip_address(address)
            return [address]
        except ValueError:
            try:
                ip_list = []
                hostname_ip = socket.getaddrinfo(address, port, proto=socket.IPPROTO_TCP)
                for item in hostname_ip:
                    ip_address = item[4][0]
                    if ip_address not in ip_list:
                        ip_list.append(ip_address)
                return ip_list
            except socket.gaierror as e:
                if "[Errno 11001]" in str(e):
                    error_msg = f"Could not find '{address}' in DNS records."
                else:
                    error_msg = f"DNS lookup failed for '{address}' - {str(e)}"
                self.logger.error(f'DNS resolution failed for {address}:{port}: {error_msg}')
                return []
        
    def _extract_name_dict(self, x509_name) -> Dict[str, str]:
        """
        Convert X509Name to dictionary.
        
        Args:
            x509_name: OpenSSL X509Name object
            
        Returns:
            Dict[str, str]: Dictionary of name components
        """
        return {
            name.decode(): value.decode() 
            for name, value in x509_name.get_components()
        } 