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
from datetime import datetime, timezone
import ssl
import socket
import logging
import ipaddress
import time
from collections import deque
from typing import Optional, List, Dict, Set, Tuple
import binascii

# Third-party imports
import OpenSSL.crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

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
# Scan Tracking
#------------------------------------------------------------------------------

class ScanTracker:
    """Centralized tracking for domain scanning operations."""
    
    def __init__(self):
        """Initialize the scan tracker."""
        self.reset()
        self.logger = logging.getLogger(__name__)
    
    def reset(self):
        """Reset all tracking data."""
        self.master_domain_list = set()  # Master list of all domains discovered
        self.scanned_domains = set()  # Domains already scanned
        self.pending_domains = set()  # Domains discovered but not yet scanned
        self.scanned_endpoints = set()  # (host, port) combinations already scanned
        self.discovered_ips = {}  # Map of domain to list of IPs
        self.scan_history = []  # List of all scan operations in order
        self.total_discovered = 0  # Total number of domains discovered
        self.total_scanned = 0  # Total number of domains scanned
        self.scan_queue = set()  # Queue of (domain, port) pairs to scan
    
    def is_domain_known(self, domain: str) -> bool:
        """Check if a domain is in our master list."""
        return domain in self.master_domain_list
    
    def is_domain_scanned(self, domain: str) -> bool:
        """Check if a domain has been scanned."""
        return domain in self.scanned_domains
    
    def is_endpoint_scanned(self, host: str, port: int) -> bool:
        """Check if a host:port combination has been scanned."""
        return (host, port) in self.scanned_endpoints
    
    def add_to_master_list(self, domain: str) -> bool:
        """Add a domain to the master list if not already present."""
        if domain not in self.master_domain_list:
            self.master_domain_list.add(domain)
            self.total_discovered += 1
            self.logger.info(f"[TRACKER] Added new domain to master list: {domain}")
            return True
        return False
    
    def add_scanned_domain(self, domain: str):
        """Mark a domain as scanned."""
        if domain not in self.scanned_domains:
            self.add_to_master_list(domain)  # Ensure it's in master list
            self.logger.info(f"[TRACKER] Marking domain as scanned: {domain}")
            self.scanned_domains.add(domain)
            self.total_scanned += 1
            self.scan_history.append({"action": "scanned", "domain": domain, "timestamp": datetime.now()})
        if domain in self.pending_domains:
            self.logger.info(f"[TRACKER] Removing {domain} from pending list")
            self.pending_domains.remove(domain)
    
    def add_scanned_endpoint(self, host: str, port: int):
        """Mark a host:port combination as scanned."""
        if (host, port) not in self.scanned_endpoints:
            self.logger.info(f"[TRACKER] Marking endpoint as scanned: {host}:{port}")
            self.scanned_endpoints.add((host, port))
            self.scan_history.append({"action": "scanned_endpoint", "host": host, "port": port, "timestamp": datetime.now()})
    
    def add_to_queue(self, domain: str, port: int) -> bool:
        """Add a domain:port pair to the scan queue if not already processed."""
        # First add to master list
        self.add_to_master_list(domain)
        
        # Check if already scanned or queued
        if not self.is_endpoint_scanned(domain, port) and (domain, port) not in self.scan_queue:
            self.scan_queue.add((domain, port))
            self.logger.info(f"[TRACKER] Added to scan queue: {domain}:{port}")
            return True
        return False
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """Get the next target from the queue."""
        try:
            return self.scan_queue.pop()
        except KeyError:
            return None
    
    def has_pending_targets(self) -> bool:
        """Check if there are targets waiting to be scanned."""
        return len(self.scan_queue) > 0
    
    def queue_size(self) -> int:
        """Get the number of targets in the queue."""
        return len(self.scan_queue)
    
    def add_discovered_ips(self, domain: str, ips: List[str]):
        """Record IPs discovered for a domain."""
        self.add_to_master_list(domain)  # Ensure domain is in master list
        self.discovered_ips[domain] = ips
        self.logger.info(f"[TRACKER] Recorded IPs for {domain}: {ips}")
        self.scan_history.append({"action": "discovered_ips", "domain": domain, "ips": ips, "timestamp": datetime.now()})
    
    def get_pending_domains(self) -> Set[str]:
        """Get list of domains waiting to be scanned."""
        pending = self.pending_domains.copy()  # Create a copy to avoid modification during iteration
        self.logger.info(f"[TRACKER] Current pending domains ({len(pending)}): {sorted(pending)}")
        return pending
    
    def get_discovered_ips(self, domain: str) -> List[str]:
        """Get list of IPs discovered for a domain."""
        return self.discovered_ips.get(domain, [])
    
    def get_scan_stats(self) -> Dict:
        """Get current scanning statistics."""
        return {
            "total_discovered": len(self.master_domain_list),
            "total_scanned": len(self.scanned_domains),
            "pending_count": len(self.pending_domains),
            "scanned_count": len(self.scanned_domains),
            "endpoints_count": len(self.scanned_endpoints),
            "queue_size": len(self.scan_queue)
        }
    
    def print_status(self):
        """Print current scanning status for debugging."""
        stats = self.get_scan_stats()
        self.logger.info("=== Scanner Status ===")
        self.logger.info(f"Total Domains in Master List: {stats['total_discovered']}")
        self.logger.info(f"Total Scanned: {stats['total_scanned']}")
        self.logger.info(f"Pending Domains: {stats['pending_count']}")
        self.logger.info(f"Scanned Domains: {stats['scanned_count']}")
        self.logger.info(f"Scanned Endpoints: {stats['endpoints_count']}")
        self.logger.info(f"Queue Size: {stats['queue_size']}")
        self.logger.info("=== Pending Domains ===")
        for domain in sorted(self.pending_domains):
            self.logger.info(f"- {domain}")
        self.logger.info("===================")

#------------------------------------------------------------------------------
# Certificate Data Model
#------------------------------------------------------------------------------

class CertificateInfo:
    """Container for certificate information."""
    
    def __init__(self,
                 serial_number: str = None,
                 thumbprint: str = None,
                 subject: Dict = None,
                 issuer: Dict = None,
                 valid_from: datetime = None,
                 expiration_date: datetime = None,
                 san: List[str] = None,
                 key_usage: List[str] = None,
                 signature_algorithm: str = None,
                 common_name: str = None,
                 chain_valid: bool = False,
                 ip_addresses: List[str] = None,
                 validation_errors: List[str] = None):
        """Initialize certificate information."""
        self.serial_number = serial_number
        self.thumbprint = thumbprint
        self.subject = subject or {}
        self.issuer = issuer or {}
        self.valid_from = valid_from
        self.expiration_date = expiration_date
        self.san = san or []
        self.key_usage = key_usage
        self.signature_algorithm = signature_algorithm
        self.common_name = common_name
        self.chain_valid = chain_valid
        self.ip_addresses = ip_addresses or []
        self.validation_errors = validation_errors or []
        
        # Validate the certificate
        self._validate()
    
    def _validate(self):
        """Perform basic validation of the certificate."""
        now = datetime.now(timezone.utc)  # Use UTC-aware datetime
        
        # Check expiration
        if self.expiration_date and self.expiration_date < now:
            self.validation_errors.append("Certificate has expired")
        
        # Check if not yet valid
        if self.valid_from and self.valid_from > now:
            self.validation_errors.append("Certificate is not yet valid")
        
        # Check for required fields
        if not self.serial_number:
            self.validation_errors.append("Missing serial number")
        
        if not self.thumbprint:
            self.validation_errors.append("Missing thumbprint")
        
        if not self.common_name and not self.san:
            self.validation_errors.append("Certificate has no identifiers (CN or SAN)")
        
        # Check signature algorithm for known weak algorithms
        weak_algorithms = {'md5', 'sha1'}
        if self.signature_algorithm and any(weak in self.signature_algorithm.lower() for weak in weak_algorithms):
            self.validation_errors.append(f"Weak signature algorithm: {self.signature_algorithm}")
    
    @property
    def is_valid(self) -> bool:
        """Check if the certificate is valid."""
        return not self.validation_errors and self.chain_valid
    
    @property
    def validation_status(self) -> str:
        """Get a human-readable validation status."""
        if self.is_valid:
            return "Valid"
        
        if not self.chain_valid:
            return "Invalid chain"
        
        if self.validation_errors:
            return f"Invalid: {', '.join(self.validation_errors)}"
        
        return "Unknown"
    
    def to_dict(self) -> Dict:
        """Convert certificate info to dictionary."""
        return {
            'serial_number': self.serial_number,
            'thumbprint': self.thumbprint,
            'subject': self.subject,
            'issuer': self.issuer,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None,
            'san': self.san,
            'key_usage': self.key_usage,
            'signature_algorithm': self.signature_algorithm,
            'common_name': self.common_name,
            'chain_valid': self.chain_valid,
            'ip_addresses': self.ip_addresses,
            'validation_errors': self.validation_errors,
            'is_valid': self.is_valid,
            'validation_status': self.validation_status
        }

@dataclasses.dataclass
class ScanResult:
    """Container for scan results."""
    certificate_info: Optional[CertificateInfo] = None
    error: Optional[str] = None
    ip_addresses: List[str] = dataclasses.field(default_factory=list)
    warnings: List[str] = dataclasses.field(default_factory=list)
    
    @property
    def has_certificate(self) -> bool:
        """Check if scan result contains a certificate, regardless of its validity."""
        return self.certificate_info is not None
    
    @property
    def is_valid(self) -> bool:
        """Check if scan result is valid (has certificate and no errors)."""
        return self.has_certificate and not self.error
    
    @property
    def status(self) -> str:
        """Get a human-readable status of the scan result."""
        if self.error:
            return f"Error: {self.error}"
        
        if not self.has_certificate:
            return "No certificate found"
        
        if self.certificate_info.validation_errors:
            return f"Certificate found but invalid: {', '.join(self.certificate_info.validation_errors)}"
        
        if not self.certificate_info.chain_valid:
            return "Certificate found but chain validation failed"
        
        if self.warnings:
            return f"Valid certificate with warnings: {', '.join(self.warnings)}"
        
        return "Valid certificate"
    
    def to_dict(self) -> Dict:
        """Convert scan result to dictionary."""
        return {
            'has_certificate': self.has_certificate,
            'is_valid': self.is_valid,
            'status': self.status,
            'error': self.error,
            'warnings': self.warnings,
            'ip_addresses': self.ip_addresses,
            'certificate_info': self.certificate_info.to_dict() if self.certificate_info else None
        }
    
    def add_warning(self, warning: str) -> None:
        """Add a warning message to the scan result."""
        if warning not in self.warnings:
            self.warnings.append(warning)

#------------------------------------------------------------------------------
# Certificate Scanner Implementation
#------------------------------------------------------------------------------

class CertificateScanner:
    """
    Certificate scanning and analysis class.
    
    This class provides functionality to:
    - Scan certificates from network endpoints
    - Process and extract certificate information
    - Handle rate limiting for certificate operations
    - Validate certificate chains
    - Extract certificate details
    
    The scanner implements intelligent rate limiting and provides robust error handling
    for network and certificate processing operations.
    """
    
    def __init__(self, logger=None):
        """Initialize the certificate scanner."""
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize rate limiting configuration
        self.rate_limit = settings.get('scanning.certificate.rate_limit', 30)  # Default 30 requests/minute
        self.request_timestamps = deque(maxlen=self.rate_limit)
        self.last_scan_time = 0
        
        # Load timeout settings
        self.socket_timeout = settings.get('scanning.timeouts.socket', 10)
        
        # Initialize validation flags
        self._last_cert_chain = False
        
        # Initialize scan tracker
        self.tracker = ScanTracker()
    
    def reset_scan_state(self):
        """Reset the scanner's state for a new scan session."""
        self.tracker.reset()
        self._last_cert_chain = False
        self.last_scan_time = 0
        self.request_timestamps.clear()
    
    def is_domain_scanned(self, domain: str) -> bool:
        """Check if a domain has been scanned in this session."""
        return self.tracker.is_domain_scanned(domain)
    
    def add_scanned_domain(self, domain: str):
        """Mark a domain as scanned."""
        self.tracker.add_scanned_domain(domain)
    
    def add_pending_domain(self, domain: str):
        """Add a domain to be scanned if not already processed."""
        self.tracker.add_pending_domain(domain)
    
    def get_pending_domains(self) -> Set[str]:
        """Get domains waiting to be scanned."""
        return self.tracker.get_pending_domains()
    
    def _apply_rate_limit(self):
        """Apply rate limiting for certificate operations."""
        current_time = time.time()
            
        # Calculate time per request in seconds
        time_per_request = 60.0 / self.rate_limit
        
        # Remove timestamps older than our window
        while self.request_timestamps and current_time - self.request_timestamps[0] > 60:
            self.request_timestamps.popleft()
            
        # If we've hit our rate limit, sleep until we can make another request
        if len(self.request_timestamps) >= self.rate_limit:
            sleep_time = self.request_timestamps[0] + 60 - current_time
            if sleep_time > 0:
                self.logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
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
    
    def scan_certificate(self, address: str, port: int = 443) -> ScanResult:
        """
        Scan a host for SSL/TLS certificates.
        
        Args:
            address: The hostname or IP to scan
            port: The port to scan (default 443)
            
        Returns:
            ScanResult object containing certificate info or error
        """
        result = ScanResult()
        self.logger.info(f"Starting certificate scan for {address}:{port}")
        
        try:
            # Apply rate limiting
            self._apply_rate_limit()
            
            # Reset chain validation status
            self._last_cert_chain = False
            
            # Get the certificate
            cert_binary = self._get_certificate(address, port)
            
            if cert_binary:
                try:
                    cert_info = self._process_certificate(cert_binary, address, port)
                    if cert_info:
                        result.certificate_info = cert_info
                        self.logger.info(f"Successfully processed certificate for {address}:{port}")
                        cert_info.chain_valid = self._last_cert_chain
                        if not self._last_cert_chain:
                            self.logger.warning(f"Certificate chain validation failed for {address}:{port}")
                    else:
                        result.error = "Failed to process certificate data"
                        self.logger.error(f"Failed to process certificate data for {address}:{port}")
                except Exception as process_error:
                    result.error = f"Error processing certificate: {str(process_error)}"
                    self.logger.error(f"Error processing certificate for {address}:{port}: {str(process_error)}")
            else:
                result.error = "No certificate data received"
                self.logger.error(f"No certificate data received from {address}:{port}")
            
            return result
        
        except Exception as e:
            error_msg = str(e)
            result.error = error_msg
            self.logger.error(f"Error scanning {address}:{port}: {error_msg}")
        
            return result
    
    def scan_certificates(self, targets: List[tuple]) -> List[ScanResult]:
        """
        Scan multiple targets for certificates.
        
        Args:
            targets: List of (address, port) tuples to scan
            
        Returns:
            List[ScanResult]: List of scan results
        """
        results = []
        for address, port in targets:
            try:
                result = self.scan_certificate(address, port)
                results.append(result)
            except Exception as e:
                # Convert common errors to friendly messages
                error_msg = str(e)
                if "[Errno 11001]" in error_msg:
                    error_msg = f"Could not find '{address}' in DNS records. This usually means either:\n1. The domain name is misspelled\n2. The domain doesn't exist\n3. DNS servers are not responding"
                elif "getaddrinfo failed" in error_msg:
                    error_msg = f"DNS lookup failed for '{address}' - Could not resolve hostname"
                results.append(ScanResult(error=error_msg))
        return results
    
    def _get_certificate(self, address: str, port: int) -> Optional[bytes]:
        """Get certificate from host with timeout."""
        sock = None
        ssock = None
        cert_binary = None
        
        try:
            # Log the attempt
            self.logger.info(f"Attempting to retrieve certificate from {address}:{port}")
            
            # Create SSL context - Accept all certificates initially
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Accept all certs initially
            context.set_ciphers('ALL')
            
            self.logger.debug(f"Created SSL context for {address}:{port}")
            
            # Try to resolve the hostname first
            self.logger.debug(f"Resolving hostname {address}")
            addrinfo = socket.getaddrinfo(address, port, proto=socket.IPPROTO_TCP)
            if not addrinfo:
                raise Exception(f"Could not resolve hostname '{address}'")
            self.logger.debug(f"Successfully resolved {address} to {addrinfo[0][4]}")
            
            # Get the first address info entry
            family, socktype, proto, canonname, sockaddr = addrinfo[0]
            
            # Create socket
            self.logger.debug(f"Creating socket for {address}:{port}")
            sock = socket.socket(family, socktype, proto)
            if not sock:
                raise Exception(f"Failed to create socket for {address}:{port}")
            
            # Set timeout and connect
            sock.settimeout(self.socket_timeout)
            self.logger.debug(f"Attempting connection to {sockaddr}")
            sock.connect(sockaddr)
            self.logger.debug(f"Successfully connected to {address}:{port}")
            
            # Wrap the socket with SSL
            self.logger.debug(f"Wrapping socket with SSL for {address}:{port}")
            ssock = context.wrap_socket(sock, server_hostname=address)
            if not ssock:
                raise Exception(f"Failed to wrap socket with SSL for {address}:{port}")
            
            ssock.settimeout(self.socket_timeout)
            self.logger.debug(f"Successfully established SSL connection to {address}:{port}")
                    
                    # Get certificate in binary form
            self.logger.debug(f"Retrieving certificate from {address}:{port}")
            cert_binary = ssock.getpeercert(binary_form=True)
            if cert_binary:
                self.logger.info(f"Certificate retrieved from {address}:{port}")
            
                # Validate certificate chain
                self._validate_cert_chain(address, port, self.socket_timeout)
                return cert_binary
            else:
                msg = f"The server at {address}:{port} accepted the connection but did not present a certificate"
                self.logger.warning(msg)
                return None
                    
        except ssl.SSLError as e:
            self._last_cert_chain = False
            if "alert internal error" in str(e):
                msg = f"The server at {address}:{port} actively rejected the SSL/TLS connection"
            else:
                msg = f"SSL/TLS connection failed: {str(e)}"
                self.logger.error(f"SSL error for {address}:{port}: {msg}")
                raise Exception(msg)
                    
        except socket.timeout:
            msg = f"The server at {address}:{port} did not respond within {self.socket_timeout} seconds"
            self.logger.error(msg)
            raise Exception(msg)
            
        except ConnectionRefusedError:
                msg = f"Nothing is listening for HTTPS connections at {address}:{port}"
                self.logger.warning(f"{address}:{port} is not reachable")
                self.logger.error(msg)
                raise Exception(msg)
                
        except Exception as e:
            self.logger.error(f"Error during certificate retrieval for {address}:{port}: {str(e)}")
            raise
            
        finally:
            # Clean up sockets in reverse order of creation
            if ssock:
                try:
                    ssock.close()
                except Exception as e:
                    self.logger.debug(f"Error closing SSL socket for {address}:{port}: {str(e)}")
                ssock = None
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"Error closing socket for {address}:{port}: {str(e)}")
                sock = None
        
        return cert_binary
        
    def _validate_cert_chain(self, address: str, port: int, timeout: float) -> None:
        """Validate certificate chain separately."""
        try:
            verify_context = ssl.create_default_context()
            verify_context.check_hostname = False
            verify_context.verify_mode = ssl.CERT_REQUIRED
            
            # Create new socket for validation
            verify_sock = socket.create_connection((address, port), timeout=timeout)
            try:
                with verify_context.wrap_socket(verify_sock, server_hostname=address) as verify_ssock:
                    self._last_cert_chain = True
                    self.logger.info(f"Certificate chain validation successful for {address}:{port}")
            except ssl.SSLError as chain_error:
                self._last_cert_chain = False
                self.logger.warning(f"Certificate chain validation failed for {address}:{port}: {str(chain_error)}")
            finally:
                try:
                    verify_sock.close()
                except:
                    pass
        except Exception as verify_error:
            self._last_cert_chain = False
            self.logger.warning(f"Certificate chain validation attempt failed for {address}:{port}: {str(verify_error)}")
    
    def _process_certificate(self, cert_binary: bytes, address: str, port: int) -> Optional[CertificateInfo]:
        """Process a certificate and extract its information."""
        try:
            self.logger.debug(f"Processing certificate for {address}:{port}")
            
            # Load the certificate
            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            if not cert:
                self.logger.error(f"Failed to load certificate for {address}:{port}")
                return None
        
            # Extract certificate information
            try:
                # Get subject information
                subject = {attr.oid._name: attr.value for attr in cert.subject}
                
                # Get issuer information
                issuer = {attr.oid._name: attr.value for attr in cert.issuer}
                
                # Get validity dates using UTC-aware methods
                valid_from = cert.not_valid_before_utc
                valid_until = cert.not_valid_after_utc
                
                # Get serial number and thumbprint
                serial = format(cert.serial_number, 'x')
                thumbprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode('ascii')
                
                # Get Subject Alternative Names
                san = []
                for extension in cert.extensions:
                    if extension.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        san = [name.value for name in extension.value]
                
                # Get signature algorithm
                sig_algorithm = cert.signature_algorithm_oid._name
                
                # Create certificate info object
                cert_info = CertificateInfo(
                    serial_number=serial,
                    thumbprint=thumbprint,
                    subject=subject,
                    issuer=issuer,
                    valid_from=valid_from,
                    expiration_date=valid_until,
                    san=san,
                    key_usage=None,  # Will be set later
                    signature_algorithm=sig_algorithm,
                    common_name=subject.get('commonName', address),
                    chain_valid=self._last_cert_chain,
                    ip_addresses=[]  # Will be set later
                )
                
                # Get key usage if present
                try:
                    for extension in cert.extensions:
                        if extension.oid == x509.oid.ExtensionOID.KEY_USAGE:
                            usage_flags = extension.value
                            key_usage = []
                            if usage_flags.digital_signature:
                                key_usage.append('digitalSignature')
                            if usage_flags.content_commitment:
                                key_usage.append('contentCommitment')
                            if usage_flags.key_encipherment:
                                key_usage.append('keyEncipherment')
                            if usage_flags.data_encipherment:
                                key_usage.append('dataEncipherment')
                            if usage_flags.key_agreement:
                                key_usage.append('keyAgreement')
                            if usage_flags.key_cert_sign:
                                key_usage.append('keyCertSign')
                            if usage_flags.crl_sign:
                                key_usage.append('cRLSign')
                            cert_info.key_usage = key_usage
                            break
                except Exception as e:
                    self.logger.warning(f"Could not get key usage for {address}:{port}: {str(e)}")
                
                # Try to get IP addresses
                try:
                    addrinfo = socket.getaddrinfo(address, port, proto=socket.IPPROTO_TCP)
                    if addrinfo:
                        cert_info.ip_addresses = list(set(addr[4][0] for addr in addrinfo))
                except Exception as e:
                    self.logger.warning(f"Could not get IP addresses for {address}:{port}: {str(e)}")
                
                self.logger.info(f"Successfully processed certificate for {address}:{port}")
                return cert_info
                
            except Exception as e:
                self.logger.error(f"Error extracting certificate information for {address}:{port}: {str(e)}")
                return None

        except Exception as e:
            self.logger.error(f"Error processing certificate for {address}:{port}: {str(e)}")
            return None
        
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

    def add_scan_target(self, domain: str, port: int = 443) -> bool:
        """
        Add a target to the scan queue.
        
        Args:
            domain: Domain to scan
            port: Port to scan (default: 443)
            
        Returns:
            bool: True if target was added, False if already scanned
        """
        return self.tracker.add_to_queue(domain, port)
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """Get the next target from the queue."""
        return self.tracker.get_next_target()
    
    def has_pending_targets(self) -> bool:
        """Check if there are targets waiting to be scanned."""
        return self.tracker.has_pending_targets()
    
    def get_queue_size(self) -> int:
        """Get the number of targets in the queue."""
        return self.tracker.queue_size()
    
    def get_scan_stats(self) -> Dict:
        """Get current scanning statistics."""
        return self.tracker.get_scan_stats()
    
    def process_discovered_domain(self, domain: str, port: int = 443) -> None:
        """
        Process a newly discovered domain.
        
        Args:
            domain: Domain that was discovered
            port: Port to scan (default: 443)
        """
        if not self.tracker.is_endpoint_scanned(domain, port):
            self.tracker.add_to_queue(domain, port)
            self.logger.info(f"[SCAN] Added discovered domain to queue: {domain}:{port}")
    
    def process_discovered_cname(self, cname: str, port: int = 443) -> None:
        """
        Process a newly discovered CNAME record.
        
        Args:
            cname: CNAME target that was discovered
            port: Port to scan (default: 443)
        """
        cname = cname.rstrip('.')  # Remove trailing dot if present
        if not self.tracker.is_endpoint_scanned(cname, port):
            self.tracker.add_to_queue(cname, port)
            self.logger.info(f"[SCAN] Added CNAME target to queue: {cname}:{port}") 