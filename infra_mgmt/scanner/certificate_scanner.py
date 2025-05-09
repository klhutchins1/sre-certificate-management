"""
Certificate scanning module for the Certificate Management System.

This module provides functionality for scanning and analyzing SSL/TLS certificates,
including:
- Certificate discovery and retrieval
- Certificate parsing and information extraction
- Certificate chain validation
- Rate-limited scanning operations

It is designed to support robust, error-tolerant, and auditable certificate analysis for the Infrastructure Management System (IMS).
"""

import ssl
import socket
import logging
import time
from collections import deque
from typing import Optional, List, Dict, Set, Tuple
import binascii
from datetime import datetime, timezone
import requests
import urllib3
import warnings
import dns.resolver
import json
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ..settings import settings
from ..models import Certificate, Domain
from ..notifications import notify
from infra_mgmt.exceptions import ScannerError, CertificateError

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from ..constants import PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION

def get_db_session():
    """
    Get a new database session using the configured database path.
    
    Returns:
        Session: SQLAlchemy session object
    """
    db_path = settings.get("paths.database", "data/certificates.db")
    engine = create_engine(f"sqlite:///{db_path}")
    Session = sessionmaker(bind=engine)
    return Session()

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class CertificateInfo:
    """
    Container for certificate information.
    
    Encapsulates all relevant data about an SSL/TLS certificate, including subject, issuer,
    validity, SANs, key usage, signature algorithm, and platform detection. Used as the
    return type for certificate scans and for database persistence.
    
    Attributes:
        serial_number (str): Certificate serial number
        thumbprint (str): Certificate thumbprint (SHA1)
        subject (Dict): Subject fields
        issuer (Dict): Issuer fields
        valid_from (datetime): Not valid before
        expiration_date (datetime): Not valid after
        san (List[str]): Subject Alternative Names
        key_usage (List[str]): Key usage flags
        signature_algorithm (str): Signature algorithm name
        common_name (str): Common Name (CN)
        chain_valid (bool): Whether the certificate chain is valid
        ip_addresses (List[str]): Associated IP addresses
        validation_errors (List[str]): Validation error messages
        platform (str): Detected platform (F5, Akamai, etc.)
        headers (Dict[str, str]): HTTP headers from endpoint
    """
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
                 validation_errors: List[str] = None,
                 platform: str = None,
                 headers: Dict[str, str] = None):
        """
        Initialize certificate information.
        
        All fields are optional and will be validated after initialization.
        """
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
        self.platform = platform
        self.headers = headers or {}
        
        # Validate the certificate
        self._validate()
    
    def _validate(self):
        """
        Perform basic validation of the certificate.
        
        Checks expiration, not-yet-valid, required fields, and weak signature algorithms.
        Populates validation_errors list.
        """
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
        """
        Check if the certificate is valid (no validation errors and chain is valid).
        
        Returns:
            bool: True if valid, False otherwise
        """
        return not self.validation_errors and self.chain_valid
    
    @property
    def validation_status(self) -> str:
        """
        Get a human-readable validation status string.
        
        Returns:
            str: Status message
        """
        if self.is_valid:
            return "Valid"
        
        if not self.chain_valid:
            return "Invalid chain"
        
        if self.validation_errors:
            return f"Invalid: {', '.join(self.validation_errors)}"
        
        return "Unknown"
    
    def to_dict(self) -> Dict:
        """
        Convert certificate info to dictionary.
        
        Returns:
            dict: Dictionary representation of the certificate info
        """
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
            'validation_status': self.validation_status,
            'platform': self.platform,
            'headers': self.headers
        }

class ScanResult:
    """
    Container for scan results.
    
    Encapsulates the result of a certificate scan, including the certificate info,
    error messages, IP addresses, and warnings. Used for reporting and UI display.
    
    Attributes:
        certificate_info (Optional[CertificateInfo]): Parsed certificate info
        error (Optional[str]): Error message, if any
        ip_addresses (List[str]): IP addresses scanned
        warnings (List[str]): Warning messages
    """
    def __init__(self,
                 certificate_info: Optional[CertificateInfo] = None,
                 error: Optional[str] = None,
                 ip_addresses: List[str] = None,
                 warnings: List[str] = None):
        """
        Initialize scan result.
        
        Args:
            certificate_info (Optional[CertificateInfo]): Parsed certificate info
            error (Optional[str]): Error message, if any
            ip_addresses (List[str]): IP addresses scanned
            warnings (List[str]): Warning messages
        """
        self.certificate_info = certificate_info
        self.error = error
        self.ip_addresses = ip_addresses or []
        self.warnings = warnings or []
    
    @property
    def has_certificate(self) -> bool:
        """
        Check if scan result contains a certificate.
        
        Returns:
            bool: True if certificate_info is present
        """
        return self.certificate_info is not None
    
    @property
    def is_valid(self) -> bool:
        """
        Check if scan result is valid (certificate present and no error).
        
        Returns:
            bool: True if valid, False otherwise
        """
        return self.has_certificate and not self.error
    
    @property
    def status(self) -> str:
        """
        Get human-readable status string for the scan result.
        
        Returns:
            str: Status message
        """
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
        """
        Convert scan result to dictionary.
        
        Returns:
            dict: Dictionary representation of the scan result
        """
        return {
            'has_certificate': self.has_certificate,
            'is_valid': self.is_valid,
            'status': self.status,
            'error': self.error,
            'warnings': self.warnings,
            'ip_addresses': self.ip_addresses,
            'certificate_info': self.certificate_info.to_dict() if self.certificate_info else None
        }

class CertificateScanTimeoutError(Exception):
    """
    Custom exception for certificate scan socket timeouts.
    """
    pass

class CertificateScanner:
    """
    Certificate scanning and analysis class for IMS.
    
    Provides robust, rate-limited, and error-tolerant methods to:
    - Scan certificates from network endpoints
    - Process and extract certificate information
    - Handle rate limiting for certificate operations
    - Validate certificate chains
    - Extract certificate details and platform information
    
    Used by ScanManager and other components to enrich certificate data and support compliance/audit workflows.
    
    Example usage:
        >>> scanner = CertificateScanner()
        >>> result = scanner.scan_certificate('example.com', 443)
        >>> if result.has_certificate:
        ...     print(result.certificate_info.to_dict())
    """
    def __init__(self, logger=None):
        """
        Initialize the certificate scanner, loading configuration and rate limits.
        
        Sets up rate limiting, timeout settings, and initializes the scan tracker.
        """
        self.logger = logger or logging.getLogger(__name__)
        
        # Initialize rate limiting configuration
        self.rate_limit = settings.get('scanning.certificate.rate_limit')  # Must be set in config
        if self.rate_limit is None:
            raise ValueError("Missing required config: scanning.certificate.rate_limit")
        self.request_timestamps = deque(maxlen=self.rate_limit)
        self.last_scan_time = 0
        
        # Load timeout settings
        self.socket_timeout = settings.get('scanning.timeouts.socket', 10)
        
        # Initialize validation flags
        self._last_cert_chain = False
        
        # Initialize scan tracker
        from . import ScanTracker
        self.tracker = ScanTracker()
    
    def reset_scan_state(self):
        """
        Reset the scanner's state for a new scan session.
        
        Clears the tracker, resets validation flags, and clears rate limiting state.
        """
        self.tracker.reset()
        self._last_cert_chain = False
        self.last_scan_time = 0
        self.request_timestamps.clear()
    
    def is_domain_scanned(self, domain: str) -> bool:
        """
        Check if a domain has been scanned in this session.
        
        Args:
            domain (str): Domain name
        
        Returns:
            bool: True if scanned, False otherwise
        """
        return self.tracker.is_domain_scanned(domain)
    
    def add_scanned_domain(self, domain: str):
        """
        Mark a domain as scanned in the tracker.
        
        Args:
            domain (str): Domain name
        """
        self.tracker.add_scanned_domain(domain)
    
    def add_pending_domain(self, domain: str):
        """
        Add a domain to be scanned if not already processed.
        
        Args:
            domain (str): Domain name
        """
        self.tracker.add_pending_domain(domain)
    
    def get_pending_domains(self) -> Set[str]:
        """
        Get domains waiting to be scanned.
        
        Returns:
            Set[str]: Pending domains
        """
        return self.tracker.get_pending_domains()
    
    def _apply_rate_limit(self):
        """
        Apply rate limiting for certificate operations.
        
        Ensures that certificate scans do not exceed configured rate limits.
        Sleeps if necessary to avoid overloading endpoints.
        """
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
                self.logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
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
        
        Connects to the given address and port, retrieves the certificate, parses it,
        validates the chain, and returns a ScanResult. Handles network errors, timeouts,
        and protocol issues robustly.
        
        Args:
            address (str): The hostname or IP to scan
            port (int): The port to scan (default 443)
        
        Returns:
            ScanResult: Scan result containing certificate info or error
        
        Example:
            >>> scanner = CertificateScanner()
            >>> result = scanner.scan_certificate('example.com', 443)
            >>> if result.has_certificate:
            ...     print(result.certificate_info.to_dict())
        """
        self._apply_rate_limit()
        self._last_cert_chain = False
        from ..settings import settings
        socket_timeout = settings.get('scanning.timeouts.socket', 10)
        cert_binary = self._get_certificate(address, port, socket_timeout=socket_timeout)
        if cert_binary:
            cert_info = self._process_certificate(cert_binary, address, port)
            if cert_info:
                return ScanResult(certificate_info=cert_info)
            else:
                return ScanResult(error="Failed to process certificate.")
        else:
            # If _last_error is set, use it for user-friendly error reporting
            error_msg = getattr(self, '_last_error', None)
            if error_msg:
                return ScanResult(error=error_msg)
            else:
                return ScanResult(error=f"No certificate found for {address}:{port}.")
    
    def _get_certificate(self, address: str, port: int = 443, socket_timeout: int = 10):
        """
        Retrieve the certificate from the server at the given address and port.
        Returns the certificate in binary form, or None if retrieval fails.
        """
        import socket
        context = ssl.create_default_context()
        context.check_hostname = False  # Allow retrieval of all certs, even with hostname mismatch
        context.verify_mode = ssl.CERT_NONE  # Allow self-signed/untrusted certs
        sock = None
        try:
            sock = socket.create_connection((address, port), timeout=socket_timeout)
            ssock = context.wrap_socket(sock, server_hostname=address)
            cert_binary = ssock.getpeercert(binary_form=True)
            ssock.close()
            return cert_binary
        except ssl.SSLError as e:
            # Log and handle SSL errors gracefully
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"SSL error during certificate retrieval for {address}:{port}: {str(e)}")
            # Provide a user-friendly message for TLSV1_ALERT_INTERNAL_ERROR
            if 'tlsv1 alert internal error' in str(e).lower():
                self._last_error = (
                    f"SSL handshake failed for {address}:{port}: TLS internal error. "
                    f"This is likely a server-side misconfiguration or incompatibility. "
                    f"(Original error: {str(e)})"
                )
            else:
                self._last_error = f"SSL handshake failed for {address}:{port}: {str(e)}"
            return None
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error during certificate retrieval for {address}:{port}: {str(e)}")
            self._last_error = f"Error during certificate retrieval for {address}:{port}: {str(e)}"
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _validate_cert_chain(self, address: str, port: int, timeout: float) -> None:
        """
        Validate certificate chain separately using system trust store.
        
        Sets self._last_cert_chain to True if valid, False otherwise.
        
        Args:
            address (str): Hostname or IP
            port (int): Port
            timeout (float): Timeout in seconds
        """
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
        except ssl.SSLError as verify_error:
            self._last_cert_chain = False
            self.logger.warning(f"SSL error during certificate chain validation for {address}:{port}: {str(verify_error)}")
        except Exception as verify_error:
            self._last_cert_chain = False
            self.logger.exception(f"Certificate chain validation attempt failed for {address}:{port}: {str(verify_error)}")
    
    def _check_dns_for_platform(self, domain: str) -> Optional[str]:
        """
        Check DNS records for platform indicators (Akamai, Cloudflare, etc.).
        
        Args:
            domain (str): Domain name
        
        Returns:
            Optional[str]: Detected platform or None
        """
        try:
            resolver = dns.resolver.Resolver()
            
            # Try to get CNAME record
            try:
                answers = resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).lower()
                    self.logger.info(f"[PLATFORM] Found CNAME record: {cname}")
                    if 'edgekey' in cname or 'akamai' in cname:
                        self.logger.info(f"[PLATFORM] Detected Akamai via CNAME record: {cname}")
                        return PLATFORM_AKAMAI
                    elif 'cloudflare' in cname:
                        self.logger.info(f"[PLATFORM] Detected Cloudflare via CNAME record: {cname}")
                        return PLATFORM_CLOUDFLARE
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                self.logger.debug(f"Error checking CNAME records: {str(e)}")
            
            # Try to get A record
            try:
                answers = resolver.resolve(domain, 'A')
                for rdata in answers:
                    ip = str(rdata.address)
                    self.logger.info(f"[PLATFORM] Found A record: {ip}")
                    
                    # Check for Cloudflare IP ranges
                    if ip.startswith(('1.1.1.', '1.0.0.', '103.21.244.', '103.22.200.', '103.31.4.')):
                        self.logger.info(f"[PLATFORM] Detected Cloudflare via IP address: {ip}")
                        return PLATFORM_CLOUDFLARE
                    
                    # Check for Akamai IP ranges
                    if ip.startswith(('23.32.', '23.33.', '23.34.', '23.35.', '23.36.', '23.37.', '23.38.', '23.39.')):
                        self.logger.info(f"[PLATFORM] Detected Akamai via IP address: {ip}")
                        return PLATFORM_AKAMAI
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                self.logger.debug(f"Error checking A records: {str(e)}")
            
            return None
            
        except dns.resolver.Resolver as e:
            self.logger.warning(f"DNS resolver error in platform check for {domain}: {str(e)}")
            return None
        except Exception as e:
            self.logger.debug(f"Error in DNS platform check: {str(e)}")
            return None

    def _process_certificate(self, cert_binary: bytes, address: str, port: int) -> Optional[CertificateInfo]:
        """
        Process a certificate and extract its information.
        
        Parses the DER-encoded certificate, extracts subject, issuer, SANs, key usage,
        signature algorithm, and attempts to detect platform. Handles parsing errors robustly.
        
        Args:
            cert_binary (bytes): DER-encoded certificate
            address (str): Hostname or IP
            port (int): Port
        
        Returns:
            Optional[CertificateInfo]: Parsed certificate info or None
        """
        try:
            self.logger.debug(f"Processing certificate for {address}:{port}")
            
            # Load the certificate
            cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            if not cert:
                self.logger.error(f"Failed to load certificate for {address}:{port}")
                return None
        
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
                        self.logger.debug(f"Found {len(san)} SANs in certificate for {address}:{port}")
                
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
                    ip_addresses=[],  # Will be set later
                    headers=getattr(self, '_last_headers', {})  # Include headers from scan
                )
                
                # Detect platform
                platform = None
                headers = cert_info.headers
                
                # Check headers first (most reliable)
                if headers:
                    self.logger.info(f"[PLATFORM] Checking response headers for {address}:{port}")
                    self.logger.info(f"[PLATFORM] Found headers: {list(headers.keys())}")
                    
                    # Cloudflare indicators
                    cf_headers = ['cf-ray', 'cf-cache-status', 'cloudflare-nginx']
                    matching_cf = [h for h in cf_headers if h.lower() in map(str.lower, headers.keys())]
                    if matching_cf:
                        platform = PLATFORM_CLOUDFLARE
                        self.logger.info(f"[PLATFORM] Detected Cloudflare via headers: {matching_cf}")
                    
                    # Akamai indicators
                    akamai_headers = ['x-akamai-transformed', 'akamai-origin-hop', 'x-akamai-request-id', 'akamai-cache-status']
                    matching_ak = [h for h in akamai_headers if h.lower() in map(str.lower, headers.keys())]
                    if matching_ak:
                        platform = PLATFORM_AKAMAI
                        self.logger.info(f"[PLATFORM] Detected Akamai via headers: {matching_ak}")
                    
                    # F5 indicators
                    f5_headers = ['x-f5-origin-server', 'x-bigip', 'x-f5-request-id', 'f5-unique-id']
                    matching_f5 = [h for h in f5_headers if h.lower() in map(str.lower, headers.keys())]
                    if matching_f5:
                        platform = PLATFORM_F5
                        self.logger.info(f"[PLATFORM] Detected F5 via headers: {matching_f5}")
                
                # If no platform detected from headers, check certificate and domain patterns
                if not platform:
                    self.logger.info(f"[PLATFORM] Checking certificate attributes for {address}:{port}")
                    issuer_cn = cert_info.issuer.get('CN', '').lower()
                    issuer_o = cert_info.issuer.get('O', '').lower()
                    
                    self.logger.info(f"[PLATFORM] Certificate issuer CN: {issuer_cn}")
                    self.logger.info(f"[PLATFORM] Certificate issuer O: {issuer_o}")
                    
                    # Check for Akamai edgekey pattern in domains
                    if 'edgekey' in address.lower() or any('edgekey' in san.lower() for san in cert_info.san):
                        platform = PLATFORM_AKAMAI
                        self.logger.info(f"[PLATFORM] Detected Akamai via edgekey domain pattern")
                    # Check certificate issuer
                    elif 'cloudflare' in issuer_cn or 'cloudflare' in issuer_o:
                        platform = PLATFORM_CLOUDFLARE
                        self.logger.info(f"[PLATFORM] Detected Cloudflare via certificate issuer")
                    elif 'akamai' in issuer_cn or 'akamai' in issuer_o:
                        platform = PLATFORM_AKAMAI
                        self.logger.info(f"[PLATFORM] Detected Akamai via certificate issuer")
                    else:
                        # Check SANs for F5
                        self.logger.info(f"[PLATFORM] Checking SANs: {cert_info.san}")
                        f5_sans = [san for san in cert_info.san if 'f5' in san.lower()]
                        if f5_sans:
                            platform = PLATFORM_F5
                            self.logger.info(f"[PLATFORM] Detected F5 via certificate SAN: {f5_sans}")
                
                # If still no platform detected, check DNS records
                if not platform:
                    self.logger.info(f"[PLATFORM] Checking DNS records for {address}")
                    platform = self._check_dns_for_platform(address)
                
                if not platform:
                    self.logger.info(f"[PLATFORM] No platform detected for {address}:{port}")
                
                cert_info.platform = platform
                
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
                    self.logger.debug(f"Could not get key usage for {address}:{port}: {str(e)}")
                
                # Try to get IP addresses
                try:
                    addrinfo = socket.getaddrinfo(address, port, proto=socket.IPPROTO_TCP)
                    if addrinfo:
                        cert_info.ip_addresses = list(set(addr[4][0] for addr in addrinfo))
                except Exception as e:
                    self.logger.debug(f"Could not get IP addresses for {address}:{port}: {str(e)}")
                
                self.logger.info(f"Successfully processed certificate for {address}:{port}")
                if platform:
                    self.logger.info(f"Detected platform for {address}:{port}: {platform}")
                
                return cert_info
                
            except Exception as e:
                self.logger.error(f"Error extracting certificate information for {address}:{port}: {str(e)}")
                return None

        except x509.UnsupportedAlgorithm as e:
            self.logger.error(f"Unsupported algorithm in certificate for {address}:{port}: {str(e)}")
            return None
        except Exception as e:
            self.logger.exception(f"Error processing certificate for {address}:{port}: {str(e)}")
            return None
    
    def add_scan_target(self, domain: str, port: int = 443) -> bool:
        """
        Add a target to the scan queue if not already scanned.
        
        Args:
            domain (str): Domain to scan
            port (int): Port to scan (default: 443)
        
        Returns:
            bool: True if target was added, False if already scanned
        """
        return self.tracker.add_to_queue(domain, port)
    
    def get_next_target(self) -> Optional[Tuple[str, int]]:
        """
        Get the next target from the queue.
        
        Returns:
            Optional[Tuple[str, int]]: (domain, port) tuple or None if queue is empty
        """
        return self.tracker.get_next_target()
    
    def has_pending_targets(self) -> bool:
        """
        Check if there are targets waiting to be scanned.
        
        Returns:
            bool: True if there are pending targets, False otherwise
        """
        return self.tracker.has_pending_targets()
    
    def get_queue_size(self) -> int:
        """
        Get the number of targets in the queue.
        
        Returns:
            int: Number of targets in the queue
        """
        return self.tracker.queue_size()
    
    def get_scan_stats(self) -> Dict:
        """
        Get current scanning statistics from the tracker.
        
        Returns:
            dict: Scanning statistics
        """
        return self.tracker.get_scan_stats()
    
    def process_discovered_domain(self, domain: str, port: int = 443) -> None:
        """
        Process a newly discovered domain and add it to the scan queue if not already scanned.
        
        Args:
            domain (str): Domain that was discovered
            port (int): Port to scan (default: 443)
        """
        if not self.tracker.is_endpoint_scanned(domain, port):
            self.tracker.add_to_queue(domain, port)
            self.logger.info(f"[SCAN] Added discovered domain to queue: {domain}:{port}")
    
    def process_discovered_cname(self, cname: str, port: int = 443) -> None:
        """
        Process a newly discovered CNAME record and add it to the scan queue if not already scanned.
        
        Args:
            cname (str): CNAME target that was discovered
            port (int): Port to scan (default: 443)
        """
        cname = cname.rstrip('.')  # Remove trailing dot if present
        if not self.tracker.is_endpoint_scanned(cname, port):
            self.tracker.add_to_queue(cname, port)
            self.logger.info(f"[SCAN] Added CNAME target to queue: {cname}:{port}")

    def _detect_platform(self, cert_info: CertificateInfo) -> Optional[str]:
        """
        Detect if certificate is being served through a WAF/CDN/Load Balancer.
        
        Checks HTTP headers, certificate issuer, and SANs for platform indicators.
        
        Args:
            cert_info (CertificateInfo): Certificate information object
        
        Returns:
            Optional[str]: Detected platform or None
        """
        try:
            # Check headers first (most reliable)
            if cert_info.headers:
                # Log all headers for debugging
                self.logger.debug("Checking response headers for platform detection:")
                for header, value in cert_info.headers.items():
                    self.logger.debug(f"  {header}: {value}")
                
                # Cloudflare indicators
                cloudflare_headers = ['cf-ray', 'cf-cache-status', 'cloudflare-nginx']
                matching_cf = [h for h in cloudflare_headers if h.lower() in map(str.lower, cert_info.headers.keys())]
                if matching_cf:
                    self.logger.info(f"Detected Cloudflare platform via headers: {', '.join(matching_cf)}")
                    return PLATFORM_CLOUDFLARE
                
                # Akamai indicators
                akamai_headers = ['x-akamai-transformed', 'akamai-origin-hop', 'x-akamai-request-id', 'akamai-cache-status']
                matching_ak = [h for h in akamai_headers if h.lower() in map(str.lower, cert_info.headers.keys())]
                if matching_ak:
                    self.logger.info(f"Detected Akamai platform via headers: {', '.join(matching_ak)}")
                    return PLATFORM_AKAMAI
                
                # F5 indicators
                f5_headers = ['x-f5-origin-server', 'x-bigip', 'x-f5-request-id', 'f5-unique-id']
                matching_f5 = [h for h in f5_headers if h.lower() in map(str.lower, cert_info.headers.keys())]
                if matching_f5:
                    self.logger.info(f"Detected F5 platform via headers: {', '.join(matching_f5)}")
                    return PLATFORM_F5
                
                self.logger.info("No platform-specific headers detected")
            else:
                self.logger.info("No HTTP headers available for platform detection")
            
            # Check certificate issuer
            issuer_cn = cert_info.issuer.get('CN', '').lower()
            issuer_o = cert_info.issuer.get('O', '').lower()
            
            self.logger.debug(f"Checking certificate issuer for platform detection:")
            self.logger.debug(f"  Issuer CN: {issuer_cn}")
            self.logger.debug(f"  Issuer O: {issuer_o}")
            
            if 'cloudflare' in issuer_cn or 'cloudflare' in issuer_o:
                self.logger.info(f"Detected Cloudflare platform via certificate issuer")
                return PLATFORM_CLOUDFLARE
            
            if 'akamai' in issuer_cn or 'akamai' in issuer_o:
                self.logger.info(f"Detected Akamai platform via certificate issuer")
                return PLATFORM_AKAMAI
            
            # Check for F5 specific patterns in subject or SAN
            if any('f5' in san.lower() for san in cert_info.san):
                matching_sans = [san for san in cert_info.san if 'f5' in san.lower()]
                self.logger.info(f"Detected F5 platform via SAN entries: {', '.join(matching_sans)}")
                return PLATFORM_F5
            
            self.logger.info("No platform detected via certificate information")
            return None
            
        except Exception as e:
            self.logger.error(f"Error during platform detection: {str(e)}")
            return None

    def scan_domains(self, domains: List[str]) -> List[ScanResult]:
        """
        Scan a list of domains for certificates.
        
        Adds all domains to the scan queue and processes them sequentially.
        
        Args:
            domains (List[str]): List of domains to scan
        
        Returns:
            List[ScanResult]: List of scan results for each domain
        """
        if not domains:
            self.logger.info("No domains provided for scanning")
            return []
            
        results = []
        for domain in domains:
            # Add domain to scan queue
            self.add_scan_target(domain)
            
        # Process all domains in the queue
        while self.has_pending_targets():
            target = self.get_next_target()
            if target:
                domain, port = target
                result = self.scan_certificate(domain, port)
                results.append(result)
                self.tracker.add_scanned_domain(domain)
                self.tracker.add_scanned_endpoint(domain, port)
                
        return results 

    def process_sans_from_certificate(self, session: Session, cert: Certificate, port: int = 443) -> Set[str]:
        """
        Process Subject Alternative Names from a certificate and add them to scan queue.
        
        Args:
            session (Session): Database session
            cert (Certificate): Certificate object to process
            port (int): Port to use for scanning
        
        Returns:
            Set[str]: Set of processed SANs
        """
        processed_sans = set()
        try:
            if cert.san:  # san is stored as JSON string
                sans = json.loads(cert.san)
                for san in sans:
                    # Clean up SAN
                    san = san.strip('*. ')
                    if san and not session.query(Domain).filter_by(domain_name=san).first():
                        processed_sans.add(san)
                        self.logger.info(f"[SANS] Found new domain from certificate: {san}")
        except Exception as e:
            self.logger.error(f"Error processing SANs: {str(e)}")
        
        return processed_sans 

    def get_certificate_sans(self, session: Session) -> List[str]:
        """
        Get all unique SANs from existing certificates in the database.
        
        Args:
            session (Session): Database session
        
        Returns:
            List[str]: List of unique SANs
        """
        all_sans = set()
        try:
            certificates = session.query(Certificate).all()
            for cert in certificates:
                # Use the hybrid property which handles JSON deserialization
                sans = cert.san  # This is already a list thanks to the hybrid property
                all_sans.update(sans)
            return sorted(list(all_sans))
        except Exception as e:
            self.logger.error(f"Error getting certificate SANs: {str(e)}")
            notify(f"Error retrieving SANs from certificates: {str(e)}", "error")
            return [] 