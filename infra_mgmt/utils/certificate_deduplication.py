"""
Certificate Deduplication Utility

This module handles the core issue where the same logical certificate 
(same domain, expiration, SANs) gets saved multiple times due to proxy 
interception providing different serial numbers and thumbprints.
"""

import logging
from typing import Optional, Tuple, List, Dict, Any, Union
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from infra_mgmt.models import Certificate
from infra_mgmt.settings import settings


logger = logging.getLogger(__name__)


class CertificateIdentity:
    """
    Represents the logical identity of a certificate for deduplication purposes.
    Two certificates with the same identity should be considered the same logical certificate,
    even if they have different serial numbers or thumbprints due to proxy interception.
    """
    
    def __init__(self, common_name: str, expiration_date: datetime, san: Optional[List[str]] = None):
        self.common_name = common_name.lower().strip() if common_name else ""
        # Normalize datetime to timezone-naive for consistent operations
        if expiration_date.tzinfo is not None:
            self.expiration_date = expiration_date.replace(tzinfo=None)
        else:
            self.expiration_date = expiration_date
        self.san = sorted([s.lower().strip() for s in (san or []) if s.strip()])
    
    def __eq__(self, other):
        if not isinstance(other, CertificateIdentity):
            return False
        
        # Normalize datetime objects for comparison (handle timezone differences)
        def normalize_datetime(dt):
            if dt is None:
                return None
            if dt.tzinfo is not None:
                return dt.replace(tzinfo=None)
            return dt
        
        return (
            self.common_name == other.common_name and
            normalize_datetime(self.expiration_date) == normalize_datetime(other.expiration_date) and
            self.san == other.san
        )
    
    def __hash__(self):
        return hash((self.common_name, self.expiration_date, tuple(self.san)))
    
    def __str__(self):
        return f"CertificateIdentity(cn={self.common_name}, exp={self.expiration_date}, san={self.san})"


class CertificateDeduplicator:
    """
    Handles deduplication of certificates to prevent proxy-induced duplicates.
    """
    
    def __init__(self, session: Session):
        self.session = session
        self.logger = logging.getLogger(__name__)
    
    def get_certificate_identity(self, cert_info: Any) -> CertificateIdentity:
        """
        Extract the logical identity of a certificate.
        
        Args:
            cert_info: CertificateInfo object or Certificate model
            
        Returns:
            CertificateIdentity: The logical identity of the certificate
        """
        if hasattr(cert_info, 'common_name') and hasattr(cert_info, 'expiration_date'):
            # CertificateInfo object
            return CertificateIdentity(
                common_name=cert_info.common_name or "",
                expiration_date=cert_info.expiration_date,
                san=cert_info.san or []
            )
        elif hasattr(cert_info, 'common_name') and hasattr(cert_info, 'valid_until'):
            # Certificate model
            return CertificateIdentity(
                common_name=cert_info.common_name or "",
                expiration_date=cert_info.valid_until,
                san=cert_info.san or []
            )
        else:
            raise ValueError(f"Unknown certificate type: {type(cert_info)}")
    
    def find_existing_certificate(self, identity: CertificateIdentity, tolerance_hours: int = 24) -> Optional[Certificate]:
        """
        Find an existing certificate with the same logical identity.
        
        Args:
            identity: CertificateIdentity to search for
            tolerance_hours: Hours of tolerance for expiration date matching
            
        Returns:
            Certificate or None if not found
        """
        try:
            # Calculate tolerance window for expiration date
            # Ensure expiration_date is timezone-naive
            exp_date = identity.expiration_date
            if exp_date.tzinfo is not None:
                exp_date = exp_date.replace(tzinfo=None)
            
            exp_start = exp_date - timedelta(hours=tolerance_hours)
            exp_end = exp_date + timedelta(hours=tolerance_hours)
            
            # Find certificates with same common name and similar expiration
            candidates = self.session.query(Certificate).filter(
                and_(
                    Certificate.common_name == identity.common_name,
                    Certificate.valid_until >= exp_start,
                    Certificate.valid_until <= exp_end
                )
            ).all()
            
            # Check SAN matching for each candidate
            for cert in candidates:
                cert_identity = self.get_certificate_identity(cert)
                if cert_identity == identity:
                    return cert
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding existing certificate: {e}")
            return None
    
    def is_better_certificate(self, new_cert_info: Any, existing_cert: Certificate) -> bool:
        """
        Determine if the new certificate is "better" than the existing one.
        
        Better means:
        1. Not proxied vs proxied
        2. More recent scan date
        3. Valid chain vs invalid chain
        
        Args:
            new_cert_info: New CertificateInfo object
            existing_cert: Existing Certificate model
            
        Returns:
            bool: True if new certificate is better
        """
        # Check if new cert is not proxied while existing is proxied
        new_is_proxied = getattr(new_cert_info, 'proxied', False)
        existing_is_proxied = existing_cert.proxied or False
        
        if not new_is_proxied and existing_is_proxied:
            self.logger.info(f"New certificate is not proxied while existing is proxied - new is better")
            return True
        
        if new_is_proxied and not existing_is_proxied:
            self.logger.info(f"New certificate is proxied while existing is not - existing is better")
            return False
        
        # Check chain validity
        new_chain_valid = getattr(new_cert_info, 'chain_valid', False)
        existing_chain_valid = existing_cert.chain_valid or False
        
        if new_chain_valid and not existing_chain_valid:
            self.logger.info(f"New certificate has valid chain while existing does not - new is better")
            return True
        
        if not new_chain_valid and existing_chain_valid:
            self.logger.info(f"New certificate has invalid chain while existing is valid - existing is better")
            return False
        
        # If both are equally proxied/valid, prefer the more recent one
        # (this could be based on scan date, but for now we'll prefer existing to avoid churn)
        self.logger.info(f"Both certificates are equivalent - keeping existing to avoid churn")
        return False
    
    def should_deduplicate(self, cert_info: Any, existing_cert: Certificate) -> Tuple[bool, str]:
        """
        Determine if we should deduplicate (not save) the new certificate.
        
        Args:
            cert_info: New CertificateInfo object
            existing_cert: Existing Certificate model
            
        Returns:
            Tuple[bool, str]: (should_deduplicate, reason)
        """
        new_is_proxied = getattr(cert_info, 'proxied', False)
        existing_is_proxied = existing_cert.proxied or False
        
        # If new cert is proxied but existing is not, deduplicate
        if new_is_proxied and not existing_is_proxied:
            return True, f"New certificate is proxied, existing authentic certificate already exists (serial: {existing_cert.serial_number})"
        
        # If new cert is not proxied but existing is, replace existing
        if not new_is_proxied and existing_is_proxied:
            return False, f"New certificate is authentic, will replace existing proxied certificate (serial: {existing_cert.serial_number})"
        
        # If both are proxied, keep the first one to avoid churn
        if new_is_proxied and existing_is_proxied:
            return True, f"Both certificates are proxied, keeping existing to avoid duplication (serial: {existing_cert.serial_number})"
        
        # If both are authentic but different serials, this might be a certificate renewal
        # Check if they're significantly different in time
        if hasattr(cert_info, 'valid_from') and cert_info.valid_from and existing_cert.valid_from:
            # Normalize datetime objects to avoid timezone mismatch
            new_valid_from = cert_info.valid_from
            existing_valid_from = existing_cert.valid_from
            
            # Convert to timezone-naive if needed
            if new_valid_from.tzinfo is not None:
                new_valid_from = new_valid_from.replace(tzinfo=None)
            if existing_valid_from.tzinfo is not None:
                existing_valid_from = existing_valid_from.replace(tzinfo=None)
            
            time_diff = abs((new_valid_from - existing_valid_from).days)
            if time_diff > 30:  # More than 30 days difference might be a renewal
                return False, f"Certificates have significant time difference ({time_diff} days), might be renewal"
        
        # Default: deduplicate to avoid unnecessary duplicates
        return True, f"Certificate appears to be duplicate of existing certificate (serial: {existing_cert.serial_number})"
    
    def process_certificate_for_deduplication(self, cert_info: Any, domain: str) -> Tuple[bool, Optional[Certificate], str]:
        """
        Process a certificate for deduplication.
        
        Args:
            cert_info: CertificateInfo object
            domain: Domain being scanned
            
        Returns:
            Tuple[bool, Optional[Certificate], str]: 
                (should_save_new, existing_cert_to_update, reason)
        """
        try:
            # Get the logical identity of the new certificate
            identity = self.get_certificate_identity(cert_info)
            
            # Find existing certificate with same identity
            existing_cert = self.find_existing_certificate(identity)
            
            if not existing_cert:
                # No existing certificate found, safe to save
                return True, None, "No existing certificate found with same identity"
            
            # Check if we should deduplicate
            should_dedup, reason = self.should_deduplicate(cert_info, existing_cert)
            
            if should_dedup:
                # Don't save new certificate, but update existing with proxy info if needed
                new_is_proxied = getattr(cert_info, 'proxied', False)
                if new_is_proxied:
                    # Update existing certificate to note proxy interception detected
                    proxy_info = getattr(cert_info, 'proxy_info', '')
                    if existing_cert.proxy_info:
                        existing_cert.proxy_info += f"; Additional proxy interception detected: {proxy_info}"
                    else:
                        existing_cert.proxy_info = f"Proxy interception detected during scan: {proxy_info}"
                    existing_cert.updated_at = datetime.now()
                
                self.logger.info(f"Deduplicated certificate for {domain}: {reason}")
                return False, existing_cert, reason
            else:
                # Replace existing certificate with new one
                self.logger.info(f"Replacing existing certificate for {domain}: {reason}")
                return True, existing_cert, reason
        
        except Exception as e:
            self.logger.error(f"Error processing certificate for deduplication: {e}")
            # On error, default to saving to avoid losing data
            return True, None, f"Error during deduplication processing: {e}"
    
    def log_deduplication_event(self, domain: str, port: int, action: str, reason: str, cert_info: Any = None):
        """
        Log a deduplication event for monitoring and debugging.
        
        Args:
            domain: Domain being scanned
            port: Port being scanned  
            action: Action taken (e.g., "deduplicated", "replaced", "saved_new")
            reason: Reason for the action
            cert_info: Certificate info if available
        """
        serial = getattr(cert_info, 'serial_number', 'unknown') if cert_info else 'unknown'
        is_proxied = getattr(cert_info, 'proxied', False) if cert_info else False
        
        self.logger.info(
            f"CERT_DEDUP: {action} for {domain}:{port} "
            f"[serial={serial}, proxied={is_proxied}] - {reason}"
        )


def deduplicate_certificate(session: Session, cert_info: Any, domain: str, port: int = 443) -> Tuple[bool, Optional[Certificate], str]:
    """
    Convenience function to deduplicate a certificate.
    
    Args:
        session: Database session
        cert_info: CertificateInfo object
        domain: Domain being scanned
        port: Port being scanned
        
    Returns:
        Tuple[bool, Optional[Certificate], str]: 
            (should_save_new, existing_cert_to_update, reason)
    """
    deduplicator = CertificateDeduplicator(session)
    result = deduplicator.process_certificate_for_deduplication(cert_info, domain)
    
    # Log the deduplication event
    action = "saved_new" if result[0] else "deduplicated"
    deduplicator.log_deduplication_event(domain, port, action, result[2], cert_info)
    
    return result