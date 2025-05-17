import pytest
from unittest.mock import ANY

# Helper function to test notification logic (to be refactored from domainsView.py if not already)
def any_descendant_has_cert(domain, domain_hierarchy, visited=None):
    if visited is None:
        visited = set()
    if domain.domain_name in visited:
        return False  # Prevent infinite recursion
    visited.add(domain.domain_name)
    subdomains = domain_hierarchy.get(domain.domain_name, [])
    for sub in subdomains:
        if sub.certificates and len(sub.certificates) > 0:
            return True
        if any_descendant_has_cert(sub, domain_hierarchy, visited):
            return True
    return False

def should_notify_no_certificates(domain, domain_hierarchy):
    has_certs = bool(domain.certificates and len(domain.certificates) > 0)
    if has_certs:
        return False
    # For root/parent domains, check all descendants recursively
    if domain.domain_name in domain_hierarchy and len(domain_hierarchy[domain.domain_name]) > 0:
        return not any_descendant_has_cert(domain, domain_hierarchy)
    return True

class MockDomain:
    def __init__(self, domain_name, certificates=None):
        self.domain_name = domain_name
        self.certificates = certificates if certificates is not None else []

# Test cases

def test_root_domain_with_cert():
    root = MockDomain('example.com', certificates=['cert1'])
    domain_hierarchy = {'example.com': []}
    assert not should_notify_no_certificates(root, domain_hierarchy)

def test_root_domain_no_cert_no_subdomains():
    root = MockDomain('example.com')
    domain_hierarchy = {'example.com': []}
    assert should_notify_no_certificates(root, domain_hierarchy)

def test_root_domain_no_cert_with_subdomain_with_cert():
    root = MockDomain('example.com')
    sub = MockDomain('sub.example.com', certificates=['cert2'])
    domain_hierarchy = {'example.com': [sub]}
    assert not should_notify_no_certificates(root, domain_hierarchy)

def test_root_domain_no_cert_with_subdomain_no_cert():
    root = MockDomain('example.com')
    sub = MockDomain('sub.example.com')
    domain_hierarchy = {'example.com': [sub]}
    assert should_notify_no_certificates(root, domain_hierarchy)

def test_subdomain_with_cert():
    sub = MockDomain('sub.example.com', certificates=['cert3'])
    domain_hierarchy = {}
    assert not should_notify_no_certificates(sub, domain_hierarchy)

def test_subdomain_no_cert():
    sub = MockDomain('sub.example.com')
    domain_hierarchy = {}
    assert should_notify_no_certificates(sub, domain_hierarchy)

def test_nested_subdomain_no_cert():
    root = MockDomain('example.com')
    sub1 = MockDomain('sub1.example.com')
    sub2 = MockDomain('sub2.example.com')
    domain_hierarchy = {'example.com': [sub1, sub2]}
    assert should_notify_no_certificates(sub1, domain_hierarchy)
    assert should_notify_no_certificates(sub2, domain_hierarchy)

def test_nested_subdomain_with_cert():
    root = MockDomain('example.com')
    sub1 = MockDomain('sub1.example.com', certificates=['cert4'])
    sub2 = MockDomain('sub2.example.com')
    domain_hierarchy = {'example.com': [sub1, sub2]}
    assert not should_notify_no_certificates(sub1, domain_hierarchy)
    assert should_notify_no_certificates(sub2, domain_hierarchy)

# Additional edge and integration-like tests

def test_multiple_subdomains_mixed_certs():
    root = MockDomain('example.com')
    sub1 = MockDomain('sub1.example.com', certificates=['cert1'])
    sub2 = MockDomain('sub2.example.com')
    sub3 = MockDomain('sub3.example.com', certificates=['cert2'])
    domain_hierarchy = {'example.com': [sub1, sub2, sub3]}
    # Root should not notify (some subdomains have certs)
    assert not should_notify_no_certificates(root, domain_hierarchy)
    # Subdomains with certs should not notify
    assert not should_notify_no_certificates(sub1, domain_hierarchy)
    assert not should_notify_no_certificates(sub3, domain_hierarchy)
    # Subdomain without cert should notify
    assert should_notify_no_certificates(sub2, domain_hierarchy)

def test_empty_certificates_list_vs_none():
    d1 = MockDomain('a.com', certificates=[])
    d2 = MockDomain('b.com', certificates=None)
    domain_hierarchy = {'a.com': [], 'b.com': []}
    assert should_notify_no_certificates(d1, domain_hierarchy)
    assert should_notify_no_certificates(d2, domain_hierarchy)

def test_deeply_nested_subdomains():
    root = MockDomain('root.com')
    sub1 = MockDomain('a.root.com')
    sub2 = MockDomain('b.a.root.com', certificates=['cert'])
    domain_hierarchy = {'root.com': [sub1], 'a.root.com': [sub2]}
    # Root should not notify (descendant has cert)
    assert not should_notify_no_certificates(root, domain_hierarchy)
    # a.root.com should not notify (child has cert)
    assert not should_notify_no_certificates(sub1, domain_hierarchy)
    # b.a.root.com has cert
    assert not should_notify_no_certificates(sub2, domain_hierarchy)

def test_non_string_certificate_objects():
    class Cert: pass
    cert_obj = Cert()
    d = MockDomain('obj.com', certificates=[cert_obj])
    domain_hierarchy = {'obj.com': []}
    assert not should_notify_no_certificates(d, domain_hierarchy)

def test_circular_hierarchy():
    # Should not crash, should treat as no subdomains
    d = MockDomain('circ.com')
    domain_hierarchy = {'circ.com': [d]}  # Circular reference
    assert should_notify_no_certificates(d, domain_hierarchy)

def test_missing_domain_hierarchy_entry():
    d = MockDomain('missing.com')
    domain_hierarchy = {}  # No entry for missing.com
    assert should_notify_no_certificates(d, domain_hierarchy)

def test_large_number_of_subdomains():
    root = MockDomain('big.com')
    subdomains = [MockDomain(f'sub{i}.big.com', certificates=['cert'] if i % 2 == 0 else []) for i in range(100)]
    domain_hierarchy = {'big.com': subdomains}
    # Root should not notify (many subdomains have certs)
    assert not should_notify_no_certificates(root, domain_hierarchy)
    # Odd subdomains (no cert) should notify, even should not
    for i, sub in enumerate(subdomains):
        if i % 2 == 0:
            assert not should_notify_no_certificates(sub, domain_hierarchy)
        else:
            assert should_notify_no_certificates(sub, domain_hierarchy) 