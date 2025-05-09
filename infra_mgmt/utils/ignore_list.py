import logging
from typing import Tuple, Optional
from infra_mgmt.models import IgnoredDomain, IgnoredCertificate

class IgnoreListUtil:
    """
    Utility class for ignore list checks (domains and certificates).
    Provides static methods to check if a domain or certificate CN should be ignored.
    """
    @staticmethod
    def is_domain_ignored(session, domain: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a domain is in the ignore list (supports wildcards, suffix, contains, and exact).
        Args:
            session: SQLAlchemy session
            domain: Domain to check
        Returns:
            (is_ignored, reason)
        """
        try:
            # First check exact and pattern matches using model's matches()
            patterns = session.query(IgnoredDomain).all()
            for pattern in patterns:
                if pattern.matches(domain):
                    return True, pattern.reason
                # Additional contains pattern (*test*)
                if pattern.pattern.startswith('*') and pattern.pattern.endswith('*') and pattern.pattern.count('*') == 2:
                    search_term = pattern.pattern.strip('*')
                    if search_term in domain:
                        return True, pattern.reason
            return False, None
        except Exception as e:
            logging.getLogger(__name__).exception(f"Error checking ignore list for domain {domain}: {str(e)}")
            return False, None

    @staticmethod
    def is_certificate_ignored(session, common_name: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a certificate's Common Name is in the ignore list (supports wildcards, contains, and exact).
        Args:
            session: SQLAlchemy session
            common_name: Certificate Common Name to check
        Returns:
            (is_ignored, reason)
        """
        try:
            patterns = session.query(IgnoredCertificate).all()
            for pattern in patterns:
                if pattern.matches(common_name):
                    return True, pattern.reason
            return False, None
        except Exception as e:
            logging.getLogger(__name__).exception(f"Error checking ignore list for certificate CN {common_name}: {str(e)}")
            return False, None 