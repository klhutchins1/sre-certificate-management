import dataclasses
from datetime import datetime
import OpenSSL.crypto
import ssl
import socket
import logging
import ipaddress
import time
from collections import deque
from typing import Optional, List, Dict, Set
from .settings import settings

# Common internal TLDs and subdomains
INTERNAL_TLDS = {
    '.local', '.lan', '.internal', '.intranet', '.corp', '.private',
    '.test', '.example', '.invalid', '.localhost'
}

# Common external TLDs
EXTERNAL_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.io', '.co', '.biz', '.info', '.name', '.mobi', '.app',
    '.cloud', '.dev', '.ai'
}

@dataclasses.dataclass
class CertificateInfo:
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
    
class CertificateScanner:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize rate limiting configuration
        self.default_rate_limit = settings.get('scanning.default_rate_limit', 60)  # Default 60 requests/minute (1/sec)
        
        # Initialize domain-specific rate limiting configuration
        self.internal_domains = set(settings.get('scanning.internal.domains', []))
        self.external_domains = set(settings.get('scanning.external.domains', []))
        self.internal_rate_limit = settings.get('scanning.internal.rate_limit', 60)  # Default 1/sec
        self.external_rate_limit = settings.get('scanning.external.rate_limit', 30)  # Default 1/2sec
        
        # Initialize rate limiting state with request timestamps
        self.request_timestamps = deque(maxlen=max(self.default_rate_limit, 
                                                 self.internal_rate_limit, 
                                                 self.external_rate_limit))
        self.last_scan_time = 0
    
    def _get_domain_type(self, domain: str) -> str:
        """
        Determine if a domain is internal or external based on TLD and configuration.
        Returns: 'internal', 'external', or 'custom'
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
        """Determine if a domain matches configured internal patterns"""
        return any(
            domain.endswith(internal_domain) if internal_domain.startswith('.')
            else domain == internal_domain
            for internal_domain in self.internal_domains
        )
    
    def _is_external_domain(self, domain: str) -> bool:
        """Determine if a domain matches configured external patterns"""
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
        """Apply rate limiting based on domain type"""
        current_time = time.time()
        domain_type = self._get_domain_type(domain)
        
        # Determine rate limit based on domain type
        if domain_type == 'internal':
            rate_limit = self.internal_rate_limit
        elif domain_type == 'external':
            rate_limit = self.external_rate_limit
        else:
            rate_limit = self.default_rate_limit
            
        # Calculate time per request in seconds
        time_per_request = 60.0 / rate_limit
        
        # Remove timestamps older than our window
        while self.request_timestamps and current_time - self.request_timestamps[0] > 60:
            self.request_timestamps.popleft()
            
        # If we've hit our rate limit, sleep until we can make another request
        if len(self.request_timestamps) >= rate_limit:
            sleep_time = self.request_timestamps[0] + 60 - current_time
            if sleep_time > 0:
                self.logger.debug(f"Rate limiting ({domain_type}): sleeping for {sleep_time:.2f} seconds")
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
        """Extract base domain from wildcard domain.
        Example: *.google.com -> google.com
                *.google.co.in -> google.co.in
        """
        if wildcard_domain.startswith('*.'):
            return wildcard_domain[2:]
        return None
    
    def _expand_domains(self, domains: List[str]) -> List[str]:
        """Expand list of domains to include base domains for wildcards.
        Skips the wildcard domains themselves as they can't be scanned directly."""
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
    
    def scan_certificate(self, address: str, port: int = 443) -> Optional[CertificateInfo]:
        """Scan a certificate from given address and port"""
        # Skip attempting to scan wildcard domains directly
        if address.startswith('*.'):
            self.logger.info(f'Skipping wildcard domain {address}')
            return None
        
        # Apply rate limiting before scanning
        self._apply_rate_limit(address)
            
        try:
            cert_binary = self._get_certificate(address, port)
            if not cert_binary:
                return None
                
            cert_info = self._process_certificate(cert_binary, address, port)
            return cert_info
            
        except Exception as e:
            self.logger.error(f"Error scanning {address}:{port} - {str(e)}")
            return None
    
    def scan_domains(self, domains: List[str], port: int = 443) -> List[CertificateInfo]:
        """Scan a list of domains, including base domains for wildcards."""
        expanded_domains = self._expand_domains(domains)
        results = []
        for domain in expanded_domains:
            cert_info = self.scan_certificate(domain, port)
            if cert_info:
                results.append(cert_info)
        return results
    
    def _get_certificate(self, address: str, port: int) -> Optional[bytes]:
        """Retrieve raw certificate data"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=address) as ssock:
                ssock.settimeout(5)
                ssock.connect((address, port))
                cert = ssock.getpeercert(binary_form=True)
                
                if cert:
                    self.logger.info(f'Certificate exists for {address}:{port}')
                    return cert
                else:
                    self.logger.info(f'No certificate found for {address}:{port}')
                    return None
                    
        except (ConnectionResetError, ConnectionRefusedError, socket.gaierror) as e:
            self.logger.warning(f'{address}:{port} is not reachable')
            self.logger.error(f'Error while checking certificate: {e}')
            return None
        except socket.timeout:
            self.logger.error(f'Socket timed out while checking certificate for {address}:{port}')
            return None
        
    def _process_certificate(self, cert_binary: bytes, address: str, port: int) -> CertificateInfo:
        """Process raw certificate data into CertificateInfo"""
        try:
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)
        except OpenSSL.crypto.Error as e:
            # Handle OpenSSL errors more robustly
            error_msg = str(e)
            if e.args and isinstance(e.args[0], list) and e.args[0]:
                # Try to get a more specific error message if available
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
        
        # Get dates
        valid_from = datetime.strptime(
            x509.get_notBefore().decode('utf-8'),
            '%Y%m%d%H%M%SZ'
        )
        expiration_date = datetime.strptime(
            x509.get_notAfter().decode('utf-8'),
            '%Y%m%d%H%M%SZ'
        )
        
        return CertificateInfo(
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
            key_usage=key_usage
        )
        
    def _extract_san(self, x509cert) -> List[str]:
        """Extract Subject Alternative Names as list"""
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
        """Extract Common Name from certificate subject"""
        subject = x509cert.get_subject()
        for name, value in subject.get_components():
            if name == b'CN':
                return value.decode('utf-8')
        return None
        
    def _get_ip_addresses(self, address: str, port: int = 443) -> List[str]:
        """Get IP addresses for hostname"""
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
                self.logger.error(f'DNS resolution failed for {address}:{port}: {e}')
                return []
        
    def _extract_name_dict(self, x509_name) -> Dict[str, str]:
        """Convert X509Name to dictionary"""
        return {
            name.decode(): value.decode() 
            for name, value in x509_name.get_components()
        } 