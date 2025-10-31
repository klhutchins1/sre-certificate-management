"""
Unified Revocation Checker

Provides a unified interface for checking certificate revocation status
using both OCSP and CRL methods with automatic fallback.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from .ocsp_checker import OCSPChecker, OCSP_STATUS_GOOD, OCSP_STATUS_REVOKED, OCSP_STATUS_UNKNOWN, OCSP_STATUS_ERROR
from .crl_checker import CRLChecker, CRL_STATUS_GOOD, CRL_STATUS_REVOKED, CRL_STATUS_UNKNOWN, CRL_STATUS_ERROR
from ..utils.network_detection import is_offline

logger = logging.getLogger(__name__)

class RevocationChecker:
    """
    Unified checker for certificate revocation status using OCSP and/or CRL.
    
    Provides:
    - Automatic OCSP checking with CRL fallback
    - Configurable enable/disable for each method
    - Offline mode support
    - Error handling and logging
    """
    
    def __init__(self, enable_ocsp: bool = True, enable_crl: bool = True,
                 ocsp_timeout: float = 5.0, crl_timeout: float = 10.0,
                 fallback_to_crl: bool = True):
        """
        Initialize revocation checker.
        
        Args:
            enable_ocsp: Enable OCSP checking
            enable_crl: Enable CRL checking
            ocsp_timeout: OCSP request timeout in seconds
            crl_timeout: CRL download timeout in seconds
            fallback_to_crl: If OCSP fails, try CRL as fallback
        """
        self.enable_ocsp = enable_ocsp
        self.enable_crl = enable_crl
        self.fallback_to_crl = fallback_to_crl
        self.ocsp_checker = None
        self.crl_checker = None
        
        try:
            if enable_ocsp:
                self.ocsp_checker = OCSPChecker(timeout=ocsp_timeout)
        except Exception as e:
            logger.warning(f"OCSP checker not available: {e}")
            self.enable_ocsp = False
        
        try:
            if enable_crl:
                self.crl_checker = CRLChecker(timeout=crl_timeout)
        except Exception as e:
            logger.warning(f"CRL checker not available: {e}")
            self.enable_crl = False
    
    def check_revocation_status(
        self,
        cert: x509.Certificate,
        issuer: Optional[x509.Certificate] = None
    ) -> Dict[str, Any]:
        """
        Check certificate revocation status using OCSP and/or CRL.
        
        Args:
            cert: Certificate to check
            issuer: Issuer certificate (required for OCSP, optional for CRL)
            
        Returns:
            dict: {
                'status': str ('good', 'revoked', 'unknown', 'error', 'not_checked'),
                'revocation_date': datetime or None,
                'revocation_reason': str or None,
                'check_method': str ('OCSP', 'CRL', 'both', None),
                'error': str or None,
                'ocsp_result': dict or None,
                'crl_result': dict or None
            }
        """
        result = {
            'status': 'not_checked',
            'revocation_date': None,
            'revocation_reason': None,
            'check_method': None,
            'error': None,
            'ocsp_result': None,
            'crl_result': None
        }
        
        # Check offline mode
        if is_offline(respect_config=True):
            result['status'] = 'unknown'
            result['error'] = 'Offline mode enabled - revocation checking skipped'
            return result
        
        ocsp_result = None
        crl_result = None
        methods_used = []
        
        # Try OCSP first (faster, real-time)
        if self.enable_ocsp and self.ocsp_checker:
            if issuer:
                try:
                    ocsp_result = self.ocsp_checker.check_certificate_ocsp(cert, issuer)
                    result['ocsp_result'] = ocsp_result
                    
                    if ocsp_result['status'] == OCSP_STATUS_GOOD:
                        result['status'] = 'good'
                        result['check_method'] = 'OCSP'
                        methods_used.append('OCSP')
                        return result  # Early return for good status
                    elif ocsp_result['status'] == OCSP_STATUS_REVOKED:
                        result['status'] = 'revoked'
                        result['revocation_date'] = ocsp_result.get('revocation_time')
                        result['revocation_reason'] = ocsp_result.get('revocation_reason')
                        result['check_method'] = 'OCSP'
                        methods_used.append('OCSP')
                        return result  # Early return for revoked status
                    elif ocsp_result['status'] == OCSP_STATUS_UNKNOWN:
                        # OCSP returned unknown - might try CRL as fallback
                        if self.fallback_to_crl and self.enable_crl:
                            logger.debug("OCSP returned unknown, falling back to CRL")
                        else:
                            result['status'] = 'unknown'
                            result['check_method'] = 'OCSP'
                            result['error'] = ocsp_result.get('error')
                            return result
                    elif ocsp_result['status'] == OCSP_STATUS_ERROR:
                        # OCSP failed - try CRL as fallback if enabled
                        if self.fallback_to_crl and self.enable_crl:
                            logger.debug(f"OCSP check failed: {ocsp_result.get('error')}, falling back to CRL")
                        else:
                            result['status'] = 'error'
                            result['check_method'] = 'OCSP'
                            result['error'] = ocsp_result.get('error')
                            return result
                except Exception as e:
                    logger.warning(f"OCSP check exception: {e}")
                    if self.fallback_to_crl and self.enable_crl:
                        logger.debug("OCSP exception, falling back to CRL")
                    else:
                        result['status'] = 'error'
                        result['error'] = f"OCSP check exception: {str(e)}"
                        return result
            else:
                logger.debug("Issuer certificate not available for OCSP check")
        
        # Try CRL (as primary method or fallback)
        if self.enable_crl and self.crl_checker:
            try:
                crl_result = self.crl_checker.check_certificate_crl(cert)
                result['crl_result'] = crl_result
                
                if crl_result['status'] == CRL_STATUS_GOOD:
                    if result['status'] == 'not_checked':
                        result['status'] = 'good'
                        result['check_method'] = 'CRL'
                        methods_used.append('CRL')
                elif crl_result['status'] == CRL_STATUS_REVOKED:
                    result['status'] = 'revoked'
                    result['revocation_date'] = crl_result.get('revocation_time')
                    result['revocation_reason'] = crl_result.get('revocation_reason')
                    if 'OCSP' in methods_used:
                        result['check_method'] = 'both'
                    else:
                        result['check_method'] = 'CRL'
                    methods_used.append('CRL')
                elif crl_result['status'] == CRL_STATUS_UNKNOWN:
                    if result['status'] == 'not_checked':
                        result['status'] = 'unknown'
                        if 'OCSP' in methods_used:
                            result['check_method'] = 'both'
                        else:
                            result['check_method'] = 'CRL'
                        result['error'] = crl_result.get('error')
                        methods_used.append('CRL')
                elif crl_result['status'] == CRL_STATUS_ERROR:
                    if result['status'] == 'not_checked':
                        result['status'] = 'error'
                        result['check_method'] = 'CRL'
                        result['error'] = crl_result.get('error')
                        methods_used.append('CRL')
            except Exception as e:
                logger.warning(f"CRL check exception: {e}")
                if result['status'] == 'not_checked':
                    result['status'] = 'error'
                    result['error'] = f"CRL check exception: {str(e)}"
        
        # If we used both methods, update check_method
        if len(methods_used) > 1:
            result['check_method'] = 'both'
        elif len(methods_used) == 1:
            result['check_method'] = methods_used[0]
        
        # Final status determination
        if result['status'] == 'not_checked':
            if not self.enable_ocsp and not self.enable_crl:
                result['error'] = 'Both OCSP and CRL checking are disabled'
                result['status'] = 'unknown'
            elif not issuer and self.enable_ocsp and not self.enable_crl:
                result['error'] = 'OCSP requires issuer certificate'
                result['status'] = 'unknown'
        
        return result
    
    def check_revocation_from_pem(
        self,
        cert_pem: bytes,
        issuer_pem: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Check revocation status from PEM-encoded certificates.
        
        Args:
            cert_pem: PEM-encoded certificate bytes
            issuer_pem: PEM-encoded issuer certificate bytes (optional)
            
        Returns:
            dict: Same format as check_revocation_status
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            issuer = None
            if issuer_pem:
                issuer = x509.load_pem_x509_certificate(issuer_pem, default_backend())
            return self.check_revocation_status(cert, issuer)
        except Exception as e:
            logger.error(f"Error parsing certificates for revocation check: {e}")
            return {
                'status': 'error',
                'error': f"Certificate parsing error: {str(e)}",
                'revocation_date': None,
                'revocation_reason': None,
                'check_method': None,
                'ocsp_result': None,
                'crl_result': None
            }


