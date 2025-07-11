def detect_proxy_certificate(cert_info, settings):
    """
    Checks if the given certificate matches known proxy CA fingerprints, subjects, or serial numbers.
    Args:
        cert_info: CertificateInfo object (must have issuer, fingerprint, serial_number)
        settings: Settings instance (for proxy_detection config)
    Returns:
        (is_proxy: bool, reason: str)
    """
    if not cert_info:
        return False, None
    if not settings.get("proxy_detection.enabled", True):
        return False, None
    # Get config
    proxy_fingerprints = settings.get("proxy_detection.ca_fingerprints") or []
    proxy_subjects = settings.get("proxy_detection.ca_subjects") or []
    proxy_serials = settings.get("proxy_detection.ca_serials") or []
    # Defensive: ensure all are lists of strings
    if not isinstance(proxy_fingerprints, list):
        proxy_fingerprints = []
    else:
        proxy_fingerprints = [str(fp) for fp in proxy_fingerprints if fp]
    if not isinstance(proxy_subjects, list):
        proxy_subjects = []
    else:
        proxy_subjects = [str(s) for s in proxy_subjects if s]
    if not isinstance(proxy_serials, list):
        proxy_serials = []
    else:
        proxy_serials = [str(sn) for sn in proxy_serials if sn]
    # Check fingerprint
    if hasattr(cert_info, 'fingerprint') and cert_info.fingerprint:
        if cert_info.fingerprint in proxy_fingerprints:
            return True, f"Matched proxy CA fingerprint: {cert_info.fingerprint}"
    # Check subject (issuer)
    issuer_str = None
    if hasattr(cert_info, 'issuer') and cert_info.issuer:
        if isinstance(cert_info.issuer, dict):
            # Try to get a string representation
            issuer_str = cert_info.issuer.get('rfc4514_string') or cert_info.issuer.get('common_name')
            if not issuer_str:
                issuer_str = str(cert_info.issuer)
        elif isinstance(cert_info.issuer, str):
            issuer_str = cert_info.issuer
        if issuer_str:
            for proxy_subj in proxy_subjects:
                if proxy_subj in issuer_str:
                    return True, f"Matched proxy CA subject: {proxy_subj} in {issuer_str}"
    # Check serial number
    if hasattr(cert_info, 'serial_number') and cert_info.serial_number:
        if str(cert_info.serial_number) in proxy_serials:
            return True, f"Matched proxy CA serial number: {cert_info.serial_number}"
    return False, None


def detect_certificate_hostname_mismatch(cert_info, target_hostname, settings):
    """
    Enhanced detection for certificate-hostname mismatches that may indicate proxy interception.
    
    Args:
        cert_info: CertificateInfo object
        target_hostname: The hostname we intended to scan
        settings: Settings instance
    
    Returns:
        (is_mismatch: bool, reason: str)
    """
    if not cert_info or not target_hostname:
        return False, None
    
    # Skip check if proxy detection is disabled
    if not settings.get("proxy_detection.enabled", True):
        return False, None
    
    # Get certificate identifiers
    cert_cn = cert_info.common_name or ""
    cert_sans = cert_info.san or []
    
    # Normalize target hostname
    target_hostname = target_hostname.lower().strip()
    
    # Check if target hostname matches certificate CN or any SAN
    cert_names = [cert_cn.lower()] + [san.lower() for san in cert_sans]
    cert_names = [name for name in cert_names if name]  # Remove empty strings
    
    # Check for exact matches
    if target_hostname in cert_names:
        return False, None
    
    # Check for wildcard matches
    for cert_name in cert_names:
        if cert_name.startswith('*.'):
            wildcard_domain = cert_name[2:]  # Remove '*.'
            if target_hostname.endswith('.' + wildcard_domain) or target_hostname == wildcard_domain:
                return False, None
    
    # Check for common proxy indicators in certificate names
    proxy_indicators = [
        'proxy', 'firewall', 'gateway', 'filter', 'corporate', 'internal',
        'corp', 'company', 'organization', 'bluecoat', 'zscaler', 'forcepoint'
    ]
    
    # Check if any certificate name contains proxy indicators
    for cert_name in cert_names:
        for indicator in proxy_indicators:
            if indicator in cert_name:
                return True, f"Certificate hostname '{cert_name}' contains proxy indicator '{indicator}' but target was '{target_hostname}'"
    
    # Check issuer for corporate/internal indicators
    if hasattr(cert_info, 'issuer') and cert_info.issuer:
        issuer_str = str(cert_info.issuer).lower()
        for indicator in proxy_indicators:
            if indicator in issuer_str:
                return True, f"Certificate issued by '{cert_info.issuer}' with proxy indicator '{indicator}' but target was '{target_hostname}'"
    
    # If hostname doesn't match and we have certificate names, it might be proxy interception
    if cert_names:
        return True, f"Hostname mismatch: certificate for '{', '.join(cert_names)}' but target was '{target_hostname}'"
    
    return False, None


def should_bypass_proxy(target_hostname, settings):
    """
    Determine if scanning should attempt to bypass proxy for the given hostname.
    
    Args:
        target_hostname: The hostname to scan
        settings: Settings instance
    
    Returns:
        bool: True if proxy bypass should be attempted
    """
    if not settings.get("proxy_detection.enabled", True):
        return False
    
    # Get bypass configuration
    bypass_patterns = settings.get("proxy_detection.bypass_patterns", [])
    external_domains = settings.get("scanning.external.domains", [])
    
    if not isinstance(bypass_patterns, list):
        bypass_patterns = []
    
    # Check if hostname matches bypass patterns
    for pattern in bypass_patterns:
        if pattern.startswith('*.'):
            # Wildcard pattern
            domain = pattern[2:]
            if target_hostname.endswith('.' + domain) or target_hostname == domain:
                return True
        elif pattern in target_hostname:
            return True
    
    # Check if hostname is in external domains list
    if external_domains and target_hostname in external_domains:
        return True
    
    # Check if it's a public domain (not internal)
    internal_indicators = ['.local', '.corp', '.internal', '.lan', '.int']
    if not any(indicator in target_hostname for indicator in internal_indicators):
        # Might be external, check if bypass is enabled for external domains
        return settings.get("proxy_detection.bypass_external", False)
    
    return False


def validate_certificate_authenticity(cert_info, target_hostname, settings):
    """
    Comprehensive validation to detect if certificate might be from proxy interception.
    
    Args:
        cert_info: CertificateInfo object
        target_hostname: The hostname we intended to scan
        settings: Settings instance
    
    Returns:
        (is_authentic: bool, warnings: List[str])
    """
    if not cert_info:
        return False, ["No certificate information available"]
    
    warnings = []
    
    # Check for proxy certificate patterns
    is_proxy, proxy_reason = detect_proxy_certificate(cert_info, settings)
    if is_proxy:
        warnings.append(f"Proxy certificate detected: {proxy_reason}")
    
    # Check for hostname mismatch
    is_mismatch, mismatch_reason = detect_certificate_hostname_mismatch(cert_info, target_hostname, settings)
    if is_mismatch:
        warnings.append(f"Certificate hostname mismatch: {mismatch_reason}")
    
    # Check for suspicious certificate characteristics
    if hasattr(cert_info, 'issuer') and cert_info.issuer:
        issuer_cn = cert_info.issuer.get('commonName', '') or cert_info.issuer.get('CN', '')
        if any(indicator in issuer_cn.lower() for indicator in ['proxy', 'corporate', 'internal', 'firewall']):
            warnings.append(f"Certificate issued by potentially internal CA: {issuer_cn}")
    
    # Check for very short validity periods (common with proxy certificates)
    if hasattr(cert_info, 'valid_from') and hasattr(cert_info, 'expiration_date'):
        if cert_info.valid_from and cert_info.expiration_date:
            validity_days = (cert_info.expiration_date - cert_info.valid_from).days
            if validity_days < 90:  # Less than 3 months is suspicious for public certs
                warnings.append(f"Short certificate validity period: {validity_days} days")
    
    # Check for self-signed certificates (common with proxies)
    if hasattr(cert_info, 'issuer') and hasattr(cert_info, 'subject'):
        if cert_info.issuer == cert_info.subject:
            warnings.append("Self-signed certificate detected")
    
    # Check chain validation - proxy certs often fail chain validation
    if hasattr(cert_info, 'chain_valid') and not cert_info.chain_valid:
        warnings.append("Certificate chain validation failed")
    
    # Determine authenticity based on warnings
    is_authentic = len(warnings) == 0
    
    return is_authentic, warnings 