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