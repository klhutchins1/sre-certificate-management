"""
Tests for DomainValidationUtil.

Tests domain name validation according to DNS and RFC rules.
"""
import pytest

from infra_mgmt.utils.domain_validation import DomainValidationUtil


class TestDomainValidationUtil:
    """Test suite for DomainValidationUtil."""

    def test_is_valid_domain_simple(self):
        """Test validation of simple domain."""
        assert DomainValidationUtil.is_valid_domain("example.com") is True

    def test_is_valid_domain_subdomain(self):
        """Test validation of subdomain."""
        assert DomainValidationUtil.is_valid_domain("www.example.com") is True

    def test_is_valid_domain_multi_level(self):
        """Test validation of multi-level domain."""
        assert DomainValidationUtil.is_valid_domain("api.v1.example.com") is True

    def test_is_valid_domain_wildcard(self):
        """Test validation of wildcard domain."""
        assert DomainValidationUtil.is_valid_domain("*.example.com") is True

    def test_is_valid_domain_trailing_dot(self):
        """Test validation with trailing dot."""
        assert DomainValidationUtil.is_valid_domain("example.com.") is True

    def test_is_valid_domain_empty_string(self):
        """Test validation of empty string."""
        assert DomainValidationUtil.is_valid_domain("") is False

    def test_is_valid_domain_none(self):
        """Test validation of None."""
        assert DomainValidationUtil.is_valid_domain(None) is False

    def test_is_valid_domain_too_long(self):
        """Test validation of domain that's too long."""
        long_domain = "a" * 254 + ".com"
        assert DomainValidationUtil.is_valid_domain(long_domain) is False

    def test_is_valid_domain_invalid_single_part(self):
        """Test validation of domain with only one part."""
        assert DomainValidationUtil.is_valid_domain("example") is False

    def test_is_valid_domain_invalid_characters(self):
        """Test validation of domain with invalid characters."""
        assert DomainValidationUtil.is_valid_domain("example_com") is False
        assert DomainValidationUtil.is_valid_domain("example.com ") is False

    def test_is_valid_domain_label_starts_with_hyphen(self):
        """Test validation of domain with label starting with hyphen."""
        assert DomainValidationUtil.is_valid_domain("-example.com") is False

    def test_is_valid_domain_label_ends_with_hyphen(self):
        """Test validation of domain with label ending with hyphen."""
        assert DomainValidationUtil.is_valid_domain("example-.com") is False

    def test_is_valid_domain_label_too_long(self):
        """Test validation of domain with label too long."""
        long_label = "a" * 64 + ".com"
        assert DomainValidationUtil.is_valid_domain(long_label) is False

    def test_is_valid_domain_valid_label_length(self):
        """Test validation of domain with valid label length."""
        label = "a" * 63 + ".com"
        assert DomainValidationUtil.is_valid_domain(label) is True

    def test_is_valid_domain_numbers_only(self):
        """Test validation of domain with numbers."""
        assert DomainValidationUtil.is_valid_domain("123.com") is True

    def test_is_valid_domain_mixed_case(self):
        """Test validation of domain with mixed case."""
        assert DomainValidationUtil.is_valid_domain("Example.COM") is True

    def test_is_valid_domain_hyphens(self):
        """Test validation of domain with hyphens in middle."""
        assert DomainValidationUtil.is_valid_domain("example-site.com") is True

    def test_is_valid_domain_short_tld(self):
        """Test validation of domain with short TLD."""
        assert DomainValidationUtil.is_valid_domain("ex.co") is True

    def test_is_valid_domain_long_tld(self):
        """Test validation of domain with long TLD."""
        assert DomainValidationUtil.is_valid_domain("example.example") is True


