import dataclasses
from datetime import datetime
import OpenSSL.crypto
import ssl
import socket
import logging
import ipaddress
from typing import Optional, List, Dict

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
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)
        
        # Get IP addresses
        ip_addresses = self._get_ip_addresses(address, port)
        
        # Extract certificate information
        serial_number = f'{x509.get_serial_number():x}'
        thumbprint = x509.digest("sha1").decode('utf-8').replace(':', '')
        san = self._extract_san(x509)
        common_name = self._extract_common_name(x509)
        issuer = self._extract_name_dict(x509.get_issuer())
        subject = self._extract_name_dict(x509.get_subject())
        
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
            version=x509.get_version()
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