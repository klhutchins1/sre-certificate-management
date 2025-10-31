"""
CRL (Certificate Revocation List) Checker

Provides functionality to check certificate revocation status using CRL.
"""

import logging
import ssl
import socket
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlparse
import http.client
import urllib.request

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None

logger = logging.getLogger(__name__)

# CRL check status values
CRL_STATUS_GOOD = "good"
CRL_STATUS_REVOKED = "revoked"
CRL_STATUS_UNKNOWN = "unknown"
CRL_STATUS_ERROR = "error"
CRL_STATUS_NOT_CHECKED = "not_checked"

class CRLChecker:
    """
    Utility class for checking certificate revocation status via CRL.
    
    Provides methods to:
    - Extract CRL Distribution Points from certificates
    - Download CRL files
    - Parse CRL files
    - Check certificate serial against CRL
    - Cache CRLs with expiration handling
    """
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize CRL checker.
        
        Args:
            timeout: Timeout in seconds for CRL downloads
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required for CRL checking")
        self.timeout = timeout
        self.logger = logger
        self._crl_cache: Dict[str, Tuple[x509.CertificateRevocationList, datetime]] = {}
        self._cache_ttl = 3600  # Cache CRLs for 1 hour
    
    def get_crl_distribution_points(self, cert: x509.Certificate) -> List[str]:
        """
        Extract CRL Distribution Point URLs from certificate.
        
        Args:
            cert: Cryptography X509 certificate object
            
        Returns:
            list: List of CRL Distribution Point URLs
        """
        crl_urls = []
        try:
            try:
                cdp_ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
                )
            except x509.ExtensionNotFound:
                return crl_urls
            
            for dist_point in cdp_ext.value:
                if dist_point.full_name:
                    for name in dist_point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_urls.append(name.value)
            
            return crl_urls
        except Exception as e:
            self.logger.debug(f"Error extracting CRL distribution points: {e}")
            return crl_urls
    
    def download_crl(self, url: str) -> Tuple[Optional[x509.CertificateRevocationList], Optional[str]]:
        """
        Download and parse a CRL from URL.
        
        Args:
            url: CRL URL
            
        Returns:
            tuple: (CRL object or None, error_message or None)
        """
        try:
            parsed_url = urlparse(url)
            scheme = parsed_url.scheme.lower()
            
            # Download CRL data
            if scheme in ('http', 'https'):
                # HTTP(S) download
                if scheme == 'https':
                    # Create SSL context
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE  # CRLs are signed
                    
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Certificate-Management-System/1.0')
                    
                    with urllib.request.urlopen(req, timeout=self.timeout, context=context) as response:
                        crl_data = response.read()
                else:
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Certificate-Management-System/1.0')
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        crl_data = response.read()
                        
            elif scheme == 'ldap':
                # LDAP - not implemented, would need ldap3 library
                return None, "LDAP CRL distribution points not supported"
            else:
                return None, f"Unsupported URL scheme: {scheme}"
            
            # Parse CRL
            try:
                # Try DER format first (most common)
                crl = x509.load_der_x509_crl(crl_data, default_backend())
                return crl, None
            except Exception:
                try:
                    # Try PEM format
                    crl = x509.load_pem_x509_crl(crl_data, default_backend())
                    return crl, None
                except Exception as e:
                    return None, f"Failed to parse CRL: {str(e)}"
                    
        except socket.timeout:
            error_msg = f"CRL download from {url} timed out"
            self.logger.warning(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Error downloading CRL from {url}: {str(e)}"
            self.logger.warning(error_msg)
            return None, error_msg
    
    def get_cached_crl(self, url: str) -> Optional[x509.CertificateRevocationList]:
        """
        Get cached CRL if available and not expired.
        
        Args:
            url: CRL URL
            
        Returns:
            CRL object or None if not cached or expired
        """
        if url in self._crl_cache:
            crl, cached_time = self._crl_cache[url]
            elapsed = (datetime.now(timezone.utc) - cached_time).total_seconds()
            
            # Check if cache is still valid
            if elapsed < self._cache_ttl:
                # Also check CRL's next_update if available
                if hasattr(crl, 'next_update') and crl.next_update:
                    if crl.next_update > datetime.now(crl.next_update.tzinfo):
                        return crl
                    else:
                        # CRL expired, remove from cache
                        del self._crl_cache[url]
                        return None
                else:
                    # No next_update, use cache TTL
                    return crl
            else:
                # Cache expired
                del self._crl_cache[url]
        
        return None
    
    def check_certificate_crl(
        self,
        cert: x509.Certificate,
        crl_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check certificate revocation status via CRL.
        
        Args:
            cert: Certificate to check
            crl_url: CRL URL (if None, will extract from cert)
            
        Returns:
            dict: {
                'status': str ('good', 'revoked', 'unknown', 'error', 'not_checked'),
                'revocation_time': datetime or None,
                'revocation_reason': str or None,
                'crl_url': str or None,
                'crl_next_update': datetime or None,
                'crl_this_update': datetime or None,
                'error': str or None
            }
        """
        result = {
            'status': CRL_STATUS_NOT_CHECKED,
            'revocation_time': None,
            'revocation_reason': None,
            'crl_url': None,
            'crl_next_update': None,
            'crl_this_update': None,
            'error': None
        }
        
        # Get CRL URLs
        if not crl_url:
            crl_urls = self.get_crl_distribution_points(cert)
            if not crl_urls:
                result['error'] = "No CRL Distribution Points found in certificate"
                result['status'] = CRL_STATUS_UNKNOWN
                return result
            crl_url = crl_urls[0]  # Use first URL
        
        result['crl_url'] = crl_url
        
        # Try to get cached CRL
        crl = self.get_cached_crl(crl_url)
        
        if not crl:
            # Download CRL
            crl, error = self.download_crl(crl_url)
            if error:
                result['error'] = error
                result['status'] = CRL_STATUS_ERROR
                return result
            
            if not crl:
                result['error'] = "Failed to download CRL"
                result['status'] = CRL_STATUS_ERROR
                return result
            
            # Cache CRL
            self._crl_cache[crl_url] = (crl, datetime.now(timezone.utc))
        
        # Get CRL metadata
        if hasattr(crl, 'this_update'):
            result['crl_this_update'] = crl.this_update
        if hasattr(crl, 'next_update'):
            result['crl_next_update'] = crl.next_update
        
        # Check if certificate is revoked
        cert_serial = cert.serial_number
        
        try:
            revoked_certs = crl.get_revoked_certificates()
            if revoked_certs:
                for revoked_cert in revoked_certs:
                    if revoked_cert.serial_number == cert_serial:
                        # Certificate is revoked
                        result['status'] = CRL_STATUS_REVOKED
                        if hasattr(revoked_cert, 'revocation_date'):
                            result['revocation_time'] = revoked_cert.revocation_date
                        if hasattr(revoked_cert, 'extensions'):
                            try:
                                reason_ext = revoked_cert.extensions.get_extension_for_oid(
                                    x509.oid.ExtensionOID.CRL_REASON
                                )
                                if hasattr(reason_ext.value, 'reason'):
                                    result['revocation_reason'] = str(reason_ext.value.reason)
                            except x509.ExtensionNotFound:
                                pass
                        return result
        except Exception as e:
            self.logger.error(f"Error checking CRL for revocation: {e}")
            result['error'] = f"CRL check error: {str(e)}"
            result['status'] = CRL_STATUS_ERROR
            return result
        
        # Certificate not found in CRL - assume good
        result['status'] = CRL_STATUS_GOOD
        return result
    
    def check_certificate_from_pem(
        self,
        cert_pem: bytes,
        crl_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check certificate revocation status from PEM-encoded certificate.
        
        Args:
            cert_pem: PEM-encoded certificate bytes
            crl_url: CRL URL (optional, will extract from cert)
            
        Returns:
            dict: Same format as check_certificate_crl
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            return self.check_certificate_crl(cert, crl_url)
        except Exception as e:
            self.logger.error(f"Error parsing certificate for CRL check: {e}")
            return {
                'status': CRL_STATUS_ERROR,
                'error': f"Certificate parsing error: {str(e)}",
                'revocation_time': None,
                'revocation_reason': None,
                'crl_url': None,
                'crl_next_update': None,
                'crl_this_update': None
            }


def check_crl_status(
    cert_pem: bytes,
    crl_url: Optional[str] = None,
    timeout: float = 10.0
) -> Dict[str, Any]:
    """
    Convenience function to check CRL status.
    
    Args:
        cert_pem: PEM-encoded certificate bytes
        crl_url: CRL URL (optional)
        timeout: Request timeout in seconds
        
    Returns:
        dict: CRL check result
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return {
            'status': CRL_STATUS_ERROR,
            'error': "cryptography library not available",
            'revocation_time': None,
            'revocation_reason': None,
            'crl_url': None,
            'crl_next_update': None,
            'crl_this_update': None
        }
    
    checker = CRLChecker(timeout=timeout)
    return checker.check_certificate_from_pem(cert_pem, crl_url)


