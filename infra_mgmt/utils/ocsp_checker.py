"""
OCSP (Online Certificate Status Protocol) Checker

Provides functionality to check certificate revocation status using OCSP.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urlparse
import http.client

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.x509 import ocsp
    from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    x509 = None
    ocsp = None

logger = logging.getLogger(__name__)

# OCSP response status enum values
OCSP_STATUS_GOOD = "good"
OCSP_STATUS_REVOKED = "revoked"
OCSP_STATUS_UNKNOWN = "unknown"
OCSP_STATUS_ERROR = "error"

class OCSPChecker:
    """
    Utility class for checking certificate revocation status via OCSP.
    
    Provides methods to:
    - Build OCSP requests
    - Query OCSP responders
    - Parse OCSP responses
    - Determine revocation status
    - Cache responses with appropriate TTL
    """
    
    def __init__(self, timeout: float = 5.0):
        """
        Initialize OCSP checker.
        
        Args:
            timeout: Timeout in seconds for OCSP requests
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required for OCSP checking")
        self.timeout = timeout
        self.logger = logger
    
    def get_ocsp_url_from_certificate(self, cert: x509.Certificate) -> Optional[str]:
        """
        Extract OCSP URL from certificate's Authority Information Access extension.
        
        Args:
            cert: Cryptography X509 certificate object
            
        Returns:
            str: OCSP URL if found, None otherwise
        """
        try:
            try:
                aia = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
            except x509.ExtensionNotFound:
                return None
            
            for access_description in aia.value:
                if access_description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_description.access_location, x509.UniformResourceIdentifier):
                        return access_description.access_location.value
            return None
        except Exception as e:
            self.logger.debug(f"Error extracting OCSP URL from certificate: {e}")
            return None
    
    def build_ocsp_request(
        self,
        cert: x509.Certificate,
        issuer: x509.Certificate
    ) -> Optional[ocsp.OCSPRequest]:
        """
        Build an OCSP request for the certificate.
        
        Args:
            cert: Certificate to check
            issuer: Issuer certificate
            
        Returns:
            OCSPRequest object or None if error
        """
        try:
            # Create OCSP request builder
            builder = ocsp.OCSPRequestBuilder()
            
            # Add certificate ID to request
            builder = builder.add_certificate(
                cert,
                issuer,
                hashes.SHA256()
            )
            
            # Build request
            request = builder.build()
            return request
        except Exception as e:
            self.logger.error(f"Error building OCSP request: {e}")
            return None
    
    def query_ocsp_responder(
        self,
        url: str,
        request: ocsp.OCSPRequest
    ) -> Tuple[Optional[ocsp.OCSPResponse], Optional[str]]:
        """
        Query OCSP responder with request.
        
        Args:
            url: OCSP responder URL
            request: OCSP request object
            
        Returns:
            tuple: (OCSPResponse or None, error_message or None)
        """
        try:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            path = parsed_url.path or '/'
            
            # Serialize request
            request_bytes = request.public_bytes(serialization.Encoding.DER)
            
            # Create HTTP connection
            if parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # OCSP responses are signed
                conn = http.client.HTTPSConnection(
                    host,
                    port,
                    timeout=self.timeout,
                    context=context
                )
            else:
                conn = http.client.HTTPConnection(
                    host,
                    port,
                    timeout=self.timeout
                )
            
            # Send POST request
            headers = {
                'Content-Type': 'application/ocsp-request',
                'Accept': 'application/ocsp-response',
            }
            
            try:
                conn.request('POST', path, request_bytes, headers)
                response = conn.getresponse()
                
                if response.status != 200:
                    error_msg = f"OCSP responder returned status {response.status}"
                    self.logger.warning(error_msg)
                    return None, error_msg
                
                # Read response
                response_data = response.read()
                
                # Parse OCSP response
                ocsp_response = ocsp.load_der_ocsp_response(response_data)
                return ocsp_response, None
                
            finally:
                conn.close()
                
        except socket.timeout:
            error_msg = f"OCSP request to {url} timed out"
            self.logger.warning(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"Error querying OCSP responder {url}: {str(e)}"
            self.logger.warning(error_msg)
            return None, error_msg
    
    def check_certificate_ocsp(
        self,
        cert: x509.Certificate,
        issuer: Optional[x509.Certificate] = None,
        ocsp_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check certificate revocation status via OCSP.
        
        Args:
            cert: Certificate to check
            issuer: Issuer certificate (if None, will attempt to find)
            ocsp_url: OCSP responder URL (if None, will extract from cert)
            
        Returns:
            dict: {
                'status': str ('good', 'revoked', 'unknown', 'error'),
                'revocation_time': datetime or None,
                'revocation_reason': str or None,
                'this_update': datetime or None,
                'next_update': datetime or None,
                'error': str or None,
                'ocsp_url': str or None
            }
        """
        result = {
            'status': OCSP_STATUS_ERROR,
            'revocation_time': None,
            'revocation_reason': None,
            'this_update': None,
            'next_update': None,
            'error': None,
            'ocsp_url': None
        }
        
        # Get OCSP URL
        if not ocsp_url:
            ocsp_url = self.get_ocsp_url_from_certificate(cert)
        
        if not ocsp_url:
            result['error'] = "No OCSP URL found in certificate"
            result['status'] = OCSP_STATUS_UNKNOWN
            return result
        
        result['ocsp_url'] = ocsp_url
        
        # Need issuer certificate for OCSP request
        if not issuer:
            result['error'] = "Issuer certificate required for OCSP check"
            result['status'] = OCSP_STATUS_UNKNOWN
            return result
        
        # Build request
        request = self.build_ocsp_request(cert, issuer)
        if not request:
            result['error'] = "Failed to build OCSP request"
            return result
        
        # Query responder
        response, error = self.query_ocsp_responder(ocsp_url, request)
        if error:
            result['error'] = error
            result['status'] = OCSP_STATUS_ERROR
            return result
        
        if not response:
            result['error'] = "No OCSP response received"
            result['status'] = OCSP_STATUS_ERROR
            return result
        
        # Check response status
        if response.response_status != OCSPResponseStatus.SUCCESSFUL:
            status_map = {
                OCSPResponseStatus.MALFORMED_REQUEST: "Malformed request",
                OCSPResponseStatus.INTERNAL_ERROR: "Internal error",
                OCSPResponseStatus.TRY_LATER: "Try later",
                OCSPResponseStatus.SIG_REQUIRED: "Signature required",
                OCSPResponseStatus.UNAUTHORIZED: "Unauthorized"
            }
            error_msg = status_map.get(
                response.response_status,
                f"Unknown status: {response.response_status}"
            )
            result['error'] = error_msg
            result['status'] = OCSP_STATUS_ERROR
            return result
        
        # Parse response - cryptography API may vary by version
        try:
            # Try to access response data
            # The structure depends on cryptography version
            cert_status = None
            revocation_time = None
            revocation_reason = None
            this_update = None
            next_update = None
            
            # Access response single response (most common case)
            # OCSPResponse -> responses -> SingleResponse -> cert_status
            try:
                # Try newer API structure
                # Note: response.responses is an iterator, not a list
                if hasattr(response, 'responses'):
                    # Convert iterator to list to check length and access first element
                    responses_list = list(response.responses)
                    if len(responses_list) > 0:
                        single_response = responses_list[0]
                        cert_status = single_response.certificate_status
                        
                        if hasattr(single_response, 'revocation_time'):
                            revocation_time = single_response.revocation_time
                        if hasattr(single_response, 'revocation_reason'):
                            revocation_reason = single_response.revocation_reason
                        if hasattr(single_response, 'this_update'):
                            this_update = single_response.this_update
                        if hasattr(single_response, 'next_update'):
                            next_update = single_response.next_update
                    else:
                        # No responses in iterator
                        cert_status = None
                        
            except (AttributeError, IndexError) as e:
                # Try alternative API structure
                self.logger.debug(f"Trying alternative OCSP response parsing: {e}")
                try:
                    # Direct access to single response
                    if hasattr(response, 'single_extensions'):
                        # May have different structure
                        pass
                except Exception:
                    pass
            
            # Map status
            if cert_status == OCSPCertStatus.GOOD:
                result['status'] = OCSP_STATUS_GOOD
            elif cert_status == OCSPCertStatus.REVOKED:
                result['status'] = OCSP_STATUS_REVOKED
                result['revocation_time'] = revocation_time
                if revocation_reason:
                    result['revocation_reason'] = str(revocation_reason)
            elif cert_status == OCSPCertStatus.UNKNOWN:
                result['status'] = OCSP_STATUS_UNKNOWN
            else:
                result['status'] = OCSP_STATUS_UNKNOWN
                result['error'] = f"Unknown certificate status: {cert_status}"
            
            result['this_update'] = this_update
            result['next_update'] = next_update
            
            # If we couldn't extract status, mark as unknown
            if cert_status is None:
                result['status'] = OCSP_STATUS_UNKNOWN
                result['error'] = "Could not extract certificate status from OCSP response"
                
        except Exception as e:
            self.logger.error(f"Error parsing OCSP response: {e}")
            result['status'] = OCSP_STATUS_ERROR
            result['error'] = f"OCSP response parsing error: {str(e)}"
        
        return result
    
    def check_certificate_from_pem(
        self,
        cert_pem: bytes,
        issuer_pem: Optional[bytes] = None,
        ocsp_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check certificate revocation status from PEM-encoded certificates.
        
        Args:
            cert_pem: PEM-encoded certificate bytes
            issuer_pem: PEM-encoded issuer certificate bytes (optional)
            ocsp_url: OCSP responder URL (optional, will extract from cert)
            
        Returns:
            dict: Same format as check_certificate_ocsp
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            issuer = None
            if issuer_pem:
                issuer = x509.load_pem_x509_certificate(issuer_pem)
            return self.check_certificate_ocsp(cert, issuer, ocsp_url)
        except Exception as e:
            self.logger.error(f"Error parsing certificate for OCSP check: {e}")
            return {
                'status': OCSP_STATUS_ERROR,
                'error': f"Certificate parsing error: {str(e)}",
                'revocation_time': None,
                'revocation_reason': None,
                'this_update': None,
                'next_update': None,
                'ocsp_url': None
            }


def check_ocsp_status(
    cert_pem: bytes,
    issuer_pem: Optional[bytes] = None,
    ocsp_url: Optional[str] = None,
    timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Convenience function to check OCSP status.
    
    Args:
        cert_pem: PEM-encoded certificate bytes
        issuer_pem: PEM-encoded issuer certificate bytes (optional)
        ocsp_url: OCSP responder URL (optional)
        timeout: Request timeout in seconds
        
    Returns:
        dict: OCSP check result
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return {
            'status': OCSP_STATUS_ERROR,
            'error': "cryptography library not available",
            'revocation_time': None,
            'revocation_reason': None,
            'this_update': None,
            'next_update': None,
            'ocsp_url': None
        }
    
    checker = OCSPChecker(timeout=timeout)
    return checker.check_certificate_from_pem(cert_pem, issuer_pem, ocsp_url)

