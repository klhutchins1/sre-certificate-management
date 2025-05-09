import re

class DomainValidationUtil:
    """
    Utility class for validating domain names according to DNS and RFC rules.
    """
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """
        Validate domain name format according to DNS and RFC rules.
        Handles wildcards, trailing dots, minimum/maximum length, and allowed characters.

        Args:
            domain (str): Domain name to validate

        Returns:
            bool: True if valid, False otherwise

        Edge Cases:
            - Returns False for empty strings, malformed domains, or invalid characters
            - Handles wildcards ("*.") and trailing dots

        Example:
            >>> DomainValidationUtil.is_valid_domain('example.com')
            True
            >>> DomainValidationUtil.is_valid_domain('*.example.com')
            True
            >>> DomainValidationUtil.is_valid_domain('invalid_domain')
            False
        """
        if not domain or len(domain) > 253:
            return False
        # Remove wildcard prefix for validation
        if domain.startswith('*.'):
            domain = domain[2:]
        # Remove trailing dot
        if domain.endswith('.'):
            domain = domain[:-1]
        # Split into parts and validate each
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        label_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')
        for part in parts:
            if not label_regex.match(part):
                return False
        return True 