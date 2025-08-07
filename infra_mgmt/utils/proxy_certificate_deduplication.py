"""
Enhanced Proxy Certificate Deduplication System

This module provides advanced deduplication specifically for proxy certificates
that have different serial numbers but are essentially the same certificate
(same CA, same target, same expiration date).
"""

import logging
import json
from typing import Optional, Tuple, List, Dict, Any, Union
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from infra_mgmt.models import Certificate
from infra_mgmt.settings import settings

logger = logging.getLogger(__name__)


class ProxyCertificateIdentity:
    """
    Represents the logical identity of a proxy certificate for deduplication.
    Proxy certificates are identified by their CA issuer, target domain, and expiration date,
    rather than serial number or thumbprint which change with each proxy generation.
    """
    
    def __init__(self, issuer_cn: str, common_name: str, expiration_date: datetime, san: Optional[List[str]] = None):
        self.issuer_cn = issuer_cn.lower().strip() if issuer_cn else ""
        self.common_name = common_name.lower().strip() if common_name else ""
        self.expiration_date = expiration_date
        self.san = sorted([s.lower().strip() for s in (san or []) if s.strip()])
    
    def __eq__(self, other):
        if not isinstance(other, ProxyCertificateIdentity):
            return False
        return (
            self.issuer_cn == other.issuer_cn and
            self.common_name == other.common_name and
            self.expiration_date == other.expiration_date and
            self.san == other.san
        )
    
    def __hash__(self):
        return hash((self.issuer_cn, self.common_name, self.expiration_date, tuple(self.san)))
    
    def __str__(self):
        return f"ProxyCertificateIdentity(issuer={self.issuer_cn}, cn={self.common_name}, exp={self.expiration_date})"


class ProxyCertificateDeduplicator:
    """
    Handles deduplication of proxy certificates to prevent duplicates with different serial numbers.
    """
    
    def __init__(self, session: Session):
        self.session = session
        self.logger = logging.getLogger(__name__)
    
    def parse_issuer_json(self, issuer_str):
        """Parse issuer JSON string and extract common name."""
        if not issuer_str:
            return None
        
        try:
            if isinstance(issuer_str, str):
                issuer_data = json.loads(issuer_str)
            else:
                issuer_data = issuer_str
            
            # Try different possible keys for common name
            cn = (issuer_data.get('commonName') or 
                  issuer_data.get('CN') or 
                  issuer_data.get('common_name'))
            
            return cn
        except:
            return None
    
    def is_proxy_ca(self, issuer_cn: str) -> bool:
        """Check if the issuer is a known proxy CA."""
        if not issuer_cn:
            return False
        
        # Get proxy CA subjects from config
        proxy_subjects = settings.get("proxy_detection.ca_subjects", [])
        if not isinstance(proxy_subjects, list):
            proxy_subjects = []
        
        # Check if issuer matches any proxy CA subjects
        issuer_lower = issuer_cn.lower()
        for proxy_subject in proxy_subjects:
            if proxy_subject.lower() in issuer_lower:
                return True
        
                    # Check for common proxy indicators
        proxy_indicators = ['proxy', 'corporate', 'internal', 'firewall', 'gateway', 'bluecoat', 'zscaler', 'forcepoint']
        for indicator in proxy_indicators:
            if indicator in issuer_lower:
                return True
        
        return False
    
    def get_proxy_certificate_identity(self, cert_info: Any) -> Optional[ProxyCertificateIdentity]:
        """
        Extract the proxy certificate identity if this is a proxy certificate.
        
        Args:
            cert_info: CertificateInfo object or Certificate model
            
        Returns:
            ProxyCertificateIdentity or None if not a proxy certificate
        """
        try:
            # Extract issuer information
            if hasattr(cert_info, 'issuer'):
                if isinstance(cert_info.issuer, str):
                    issuer_cn = self.parse_issuer_json(cert_info.issuer)
                else:
                    issuer_cn = self.parse_issuer_json(cert_info.issuer)
            elif hasattr(cert_info, '_issuer'):
                issuer_cn = self.parse_issuer_json(cert_info._issuer)
            else:
                return None
            
            if not issuer_cn:
                return None
            
            # Check if this is a proxy CA
            if not self.is_proxy_ca(issuer_cn):
                return None
            
            # Extract other certificate information
            if hasattr(cert_info, 'common_name') and hasattr(cert_info, 'expiration_date'):
                # CertificateInfo object
                return ProxyCertificateIdentity(
                    issuer_cn=issuer_cn,
                    common_name=cert_info.common_name or "",
                    expiration_date=cert_info.expiration_date,
                    san=cert_info.san or []
                )
            elif hasattr(cert_info, 'common_name') and hasattr(cert_info, 'valid_until'):
                # Certificate model
                return ProxyCertificateIdentity(
                    issuer_cn=issuer_cn,
                    common_name=cert_info.common_name or "",
                    expiration_date=cert_info.valid_until,
                    san=cert_info.san or []
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting proxy certificate identity: {e}")
            return None
    
    def find_existing_proxy_certificate(self, identity: ProxyCertificateIdentity, tolerance_hours: int = 24) -> Optional[Certificate]:
        """
        Find an existing proxy certificate with the same logical identity.
        
        Args:
            identity: ProxyCertificateIdentity to search for
            tolerance_hours: Hours of tolerance for expiration date matching
            
        Returns:
            Certificate or None if not found
        """
        try:
            # Calculate tolerance window for expiration date
            exp_start = identity.expiration_date - timedelta(hours=tolerance_hours)
            exp_end = identity.expiration_date + timedelta(hours=tolerance_hours)
            
            # Find certificates with same common name and similar expiration
            candidates = self.session.query(Certificate).filter(
                and_(
                    Certificate.common_name == identity.common_name,
                    Certificate.valid_until >= exp_start,
                    Certificate.valid_until <= exp_end
                )
            ).all()
            
            # Check each candidate to see if it's the same proxy certificate
            for cert in candidates:
                cert_identity = self.get_proxy_certificate_identity(cert)
                if cert_identity and cert_identity == identity:
                    return cert
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding existing proxy certificate: {e}")
            return None
    
    def should_merge_proxy_certificates(self, new_cert_info: Any, existing_cert: Certificate) -> Tuple[bool, str]:
        """
        Determine if we should merge the new proxy certificate with the existing one.
        
        Args:
            new_cert_info: New CertificateInfo object
            existing_cert: Existing Certificate model
            
        Returns:
            Tuple[bool, str]: (should_merge, reason)
        """
        # Always merge proxy certificates with the same identity
        # Keep the oldest one and update it with proxy information
        
        new_is_proxied = getattr(new_cert_info, 'proxied', False)
        existing_is_proxied = existing_cert.proxied or False
        
        if new_is_proxied and existing_is_proxied:
            return True, f"Both certificates are proxy certificates - merging to avoid duplicates"
        
        if new_is_proxied and not existing_is_proxied:
            # New is proxy, existing is not - mark existing as proxy and merge
            return True, f"New certificate is proxy, marking existing certificate as proxy and merging"
        
        if not new_is_proxied and existing_is_proxied:
            # New is not proxy, existing is - this shouldn't happen with proxy identity matching
            return False, f"New certificate is not proxy but existing is - keeping existing"
        
        # Default: merge to avoid duplicates
        return True, f"Proxy certificates with same identity - merging to avoid duplicates"
    
    def merge_proxy_certificate_data(self, existing_cert: Certificate, new_cert_info: Any) -> None:
        """
        Merge data from new proxy certificate into existing certificate.
        
        Args:
            existing_cert: Existing Certificate model to update
            new_cert_info: New CertificateInfo object with data to merge
        """
        try:
            # Update proxy information
            new_proxy_info = getattr(new_cert_info, 'proxy_info', '')
            if new_proxy_info:
                if existing_cert.proxy_info:
                    existing_cert.proxy_info += f"; Additional proxy detection: {new_proxy_info}"
                else:
                    existing_cert.proxy_info = f"Proxy certificate detected: {new_proxy_info}"
            
            # Ensure certificate is marked as proxied
            if not existing_cert.proxied:
                existing_cert.proxied = True
            
            # Update timestamp
            existing_cert.updated_at = datetime.now()
            
            self.logger.info(f"Merged proxy certificate data into existing certificate {existing_cert.id}")
            
        except Exception as e:
            self.logger.error(f"Error merging proxy certificate data: {e}")
    
    def process_proxy_certificate_deduplication(self, cert_info: Any, domain: str) -> Tuple[bool, Optional[Certificate], str]:
        """
        Process a certificate for proxy-specific deduplication.
        
        Args:
            cert_info: CertificateInfo object
            domain: Domain being scanned
            
        Returns:
            Tuple[bool, Optional[Certificate], str]: 
                (should_save_new, existing_cert_to_update, reason)
        """
        try:
            # Check if this is a proxy certificate
            proxy_identity = self.get_proxy_certificate_identity(cert_info)
            
            if not proxy_identity:
                # Not a proxy certificate, use normal deduplication
                return True, None, "Not a proxy certificate - using normal deduplication"
            
            self.logger.info(f"Processing proxy certificate for {domain}: {proxy_identity}")
            
            # Find existing proxy certificate with same identity
            existing_cert = self.find_existing_proxy_certificate(proxy_identity)
            
            if not existing_cert:
                # No existing proxy certificate found, safe to save
                return True, None, f"No existing proxy certificate found with same identity: {proxy_identity}"
            
            # Check if we should merge
            should_merge, reason = self.should_merge_proxy_certificates(cert_info, existing_cert)
            
            if should_merge:
                # Merge data into existing certificate
                self.merge_proxy_certificate_data(existing_cert, cert_info)
                
                self.logger.info(f"Merged proxy certificate for {domain}: {reason}")
                return False, existing_cert, reason
            else:
                # Don't merge, keep existing
                self.logger.info(f"Keeping existing proxy certificate for {domain}: {reason}")
                return False, existing_cert, reason
        
        except Exception as e:
            self.logger.error(f"Error processing proxy certificate deduplication: {e}")
            # On error, default to saving to avoid losing data
            return True, None, f"Error during proxy deduplication processing: {e}"
    
    def log_proxy_deduplication_event(self, domain: str, port: int, action: str, reason: str, cert_info: Any = None):
        """
        Log a proxy deduplication event for monitoring and debugging.
        
        Args:
            domain: Domain being scanned
            port: Port being scanned  
            action: Action taken (e.g., "merged", "saved_new", "kept_existing")
            reason: Reason for the action
            cert_info: Certificate info if available
        """
        serial = getattr(cert_info, 'serial_number', 'unknown') if cert_info else 'unknown'
        is_proxied = getattr(cert_info, 'proxied', False) if cert_info else False
        
        self.logger.info(
            f"PROXY_DEDUP: {action} for {domain}:{port} "
            f"[serial={serial}, proxied={is_proxied}] - {reason}"
        )


def deduplicate_proxy_certificate(session: Session, cert_info: Any, domain: str, port: int = 443) -> Tuple[bool, Optional[Certificate], str]:
    """
    Convenience function to deduplicate a proxy certificate.
    
    Args:
        session: Database session
        cert_info: CertificateInfo object
        domain: Domain being scanned
        port: Port being scanned
        
    Returns:
        Tuple[bool, Optional[Certificate], str]: 
            (should_save_new, existing_cert_to_update, reason)
    """
    deduplicator = ProxyCertificateDeduplicator(session)
    result = deduplicator.process_proxy_certificate_deduplication(cert_info, domain)
    
    # If we merged data, commit the changes
    if not result[0] and result[1]:  # Not saving new, but have existing cert to update
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Error committing proxy certificate merge: {e}")
    
    # Log the deduplication event
    action = "saved_new" if result[0] else "merged"
    deduplicator.log_proxy_deduplication_event(domain, port, action, result[2], cert_info)
    
    return result


def enhanced_deduplicate_certificate(session: Session, cert_info: Any, domain: str, port: int = 443) -> Tuple[bool, Optional[Certificate], str]:
    """
    Enhanced certificate deduplication that handles both normal and proxy certificates.
    
    This function first checks if the certificate is a proxy certificate and uses
    proxy-specific deduplication. If not, it falls back to normal deduplication.
    
    Args:
        session: Database session
        cert_info: CertificateInfo object
        domain: Domain being scanned
        port: Port being scanned
        
    Returns:
        Tuple[bool, Optional[Certificate], str]: 
            (should_save_new, existing_cert_to_update, reason)
    """
    # First try proxy-specific deduplication
    proxy_result = deduplicate_proxy_certificate(session, cert_info, domain, port)
    
    # If proxy deduplication determined it's not a proxy certificate, 
    # or if it found a match, return the result
    if proxy_result[2].startswith("Not a proxy certificate") or not proxy_result[0]:
        return proxy_result
    
    # If proxy deduplication didn't find a match and it is a proxy certificate,
    # we can save it as a new proxy certificate
    if proxy_result[0]:
        return proxy_result
    
    # Fallback to normal deduplication (import here to avoid circular imports)
    try:
        from .certificate_deduplication import deduplicate_certificate
        return deduplicate_certificate(session, cert_info, domain, port)
    except ImportError:
        # If normal deduplication is not available, default to saving
        return True, None, "Normal deduplication not available - saving certificate"
