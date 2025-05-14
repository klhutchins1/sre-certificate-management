"""
Session-level DNS/WHOIS cache utility for scan orchestration.

Provides a simple, in-memory cache for DNS and WHOIS lookups to avoid redundant queries
within a scan session. Not thread-safe. Intended for use within a single scan session.
"""

from typing import Any, Dict, Optional

class ScanSessionCache:
    """
    Shared cache for DNS and WHOIS lookups during a scan session.
    """
    def __init__(self):
        self.dns_cache: Dict[str, Any] = {}
        self.whois_cache: Dict[str, Any] = {}
        self.certificate_cache: Dict[tuple, tuple] = {}  # (domain, port) -> (serial, thumbprint, ScanResult)

    def get_dns(self, domain: str) -> Optional[Any]:
        return self.dns_cache.get(domain)

    def set_dns(self, domain: str, value: Any):
        self.dns_cache[domain] = value

    def get_whois(self, domain: str) -> Optional[Any]:
        return self.whois_cache.get(domain)

    def set_whois(self, domain: str, value: Any):
        self.whois_cache[domain] = value

    def get_certificate(self, domain: str, port: int):
        entry = self.certificate_cache.get((domain, port))
        if entry:
            return entry[2]  # Return ScanResult
        return None

    def set_certificate(self, domain: str, port: int, serial: str, thumbprint: str, result: Any):
        self.certificate_cache[(domain, port)] = (serial, thumbprint, result)

    def get_certificate_meta(self, domain: str, port: int):
        return self.certificate_cache.get((domain, port))

    def clear(self):
        self.dns_cache.clear()
        self.whois_cache.clear()
        self.certificate_cache.clear()

    def stats(self) -> Dict[str, int]:
        return {
            'dns_cache_size': len(self.dns_cache),
            'whois_cache_size': len(self.whois_cache),
            'certificate_cache_size': len(self.certificate_cache)
        } 