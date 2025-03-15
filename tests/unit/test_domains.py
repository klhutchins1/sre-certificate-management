"""
Tests for domain management functionality.

This module contains tests for:
- Domain model validation
- Domain CRUD operations
- DNS record management
- Domain-certificate relationships
- Subdomain hierarchy
"""

import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cert_scanner.models import Base, Domain, DomainDNSRecord, Certificate
from cert_scanner.db import init_database

@pytest.fixture
def engine():
    """Create a test database engine."""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def session(engine):
    """Create a test database session."""
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_domain_creation(session):
    """Test creating a new domain."""
    domain = Domain(
        domain_name="example.com",
        registrar="Test Registrar",
        registration_date=datetime.now(),
        expiration_date=datetime.now() + timedelta(days=365),
        auto_renew=True,
        owner="Test Owner",
        dns_provider="Test DNS",
        notes="Test notes"
    )
    
    session.add(domain)
    session.commit()
    
    saved_domain = session.query(Domain).filter_by(domain_name="example.com").first()
    assert saved_domain is not None
    assert saved_domain.registrar == "Test Registrar"
    assert saved_domain.auto_renew is True
    assert saved_domain.owner == "Test Owner"

def test_domain_unique_constraint(session):
    """Test that domain names must be unique."""
    domain1 = Domain(domain_name="example.com")
    domain2 = Domain(domain_name="example.com")
    
    session.add(domain1)
    session.commit()
    
    with pytest.raises(Exception):
        session.add(domain2)
        session.commit()

def test_subdomain_relationship(session):
    """Test parent-child domain relationships."""
    parent = Domain(domain_name="example.com")
    child1 = Domain(domain_name="sub1.example.com")
    child2 = Domain(domain_name="sub2.example.com")
    
    session.add(parent)
    session.commit()
    
    child1.parent_domain = parent
    child2.parent_domain = parent
    session.add_all([child1, child2])
    session.commit()
    
    saved_parent = session.query(Domain).filter_by(domain_name="example.com").first()
    assert len(saved_parent.subdomains) == 2
    assert sorted([d.domain_name for d in saved_parent.subdomains]) == [
        "sub1.example.com",
        "sub2.example.com"
    ]

def test_dns_record_management(session):
    """Test managing DNS records for a domain."""
    domain = Domain(domain_name="example.com")
    session.add(domain)
    session.commit()
    
    # Add various types of DNS records
    records = [
        DomainDNSRecord(
            domain=domain,
            record_type="A",
            name="@",
            value="192.0.2.1",
            ttl=3600
        ),
        DomainDNSRecord(
            domain=domain,
            record_type="CNAME",
            name="www",
            value="example.com",
            ttl=3600
        ),
        DomainDNSRecord(
            domain=domain,
            record_type="MX",
            name="@",
            value="mail.example.com",
            ttl=3600,
            priority=10
        )
    ]
    
    session.add_all(records)
    session.commit()
    
    saved_domain = session.query(Domain).filter_by(domain_name="example.com").first()
    assert len(saved_domain.dns_records) == 3
    
    # Test record types and values
    record_types = {r.record_type for r in saved_domain.dns_records}
    assert record_types == {"A", "CNAME", "MX"}
    
    mx_record = next(r for r in saved_domain.dns_records if r.record_type == "MX")
    assert mx_record.priority == 10

def test_certificate_association(session):
    """Test associating certificates with domains."""
    domain = Domain(domain_name="example.com")
    cert1 = Certificate(
        serial_number="123",
        thumbprint="abc",
        common_name="example.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=365)
    )
    cert2 = Certificate(
        serial_number="456",
        thumbprint="def",
        common_name="*.example.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=365)
    )
    
    session.add_all([domain, cert1, cert2])
    domain.certificates.extend([cert1, cert2])
    session.commit()
    
    saved_domain = session.query(Domain).filter_by(domain_name="example.com").first()
    assert len(saved_domain.certificates) == 2
    cert_names = {c.common_name for c in saved_domain.certificates}
    assert cert_names == {"example.com", "*.example.com"}

def test_domain_expiration(session):
    """Test domain expiration date handling."""
    # Create domains with different expiration states
    active = Domain(
        domain_name="active.com",
        expiration_date=datetime.now() + timedelta(days=365)
    )
    expiring_soon = Domain(
        domain_name="expiring.com",
        expiration_date=datetime.now() + timedelta(days=20)
    )
    expired = Domain(
        domain_name="expired.com",
        expiration_date=datetime.now() - timedelta(days=1)
    )
    
    session.add_all([active, expiring_soon, expired])
    session.commit()
    
    # Test expiring soon query
    expiring_domains = session.query(Domain).filter(
        Domain.expiration_date <= datetime.now() + timedelta(days=30),
        Domain.expiration_date > datetime.now()
    ).all()
    assert len(expiring_domains) == 1
    assert expiring_domains[0].domain_name == "expiring.com"
    
    # Test expired query
    expired_domains = session.query(Domain).filter(
        Domain.expiration_date <= datetime.now()
    ).all()
    assert len(expired_domains) == 1
    assert expired_domains[0].domain_name == "expired.com"

def test_domain_deletion_cascade(session):
    """Test that deleting a domain cascades to related records."""
    domain = Domain(domain_name="example.com")
    dns_record = DomainDNSRecord(
        domain=domain,
        record_type="A",
        name="@",
        value="192.0.2.1",
        ttl=3600
    )
    
    session.add_all([domain, dns_record])
    session.commit()
    
    # Delete domain and verify cascade
    session.delete(domain)
    session.commit()
    
    assert session.query(Domain).count() == 0
    assert session.query(DomainDNSRecord).count() == 0

def test_domain_validation(session):
    """Test domain name validation."""
    # Test invalid domain names
    invalid_domains = [
        "",  # Empty
        "invalid",  # No TLD
        "example..com",  # Double dot
        "-example.com",  # Leading hyphen
        "exam!ple.com",  # Invalid character
        "example-.com",  # Ending hyphen in segment
        "example.c",  # Single-char TLD
        "example.-com",  # Segment starting with hyphen
        "--example.com",  # Consecutive hyphens
    ]
    
    for domain_name in invalid_domains:
        try:
            domain = Domain(domain_name=domain_name)
            session.add(domain)
            session.commit()
            pytest.fail(f"Expected validation error for domain: {domain_name}")
        except (ValueError, Exception) as e:
            assert any(msg in str(e).lower() for msg in [
                "invalid domain",
                "empty",
                "invalid format",
                "consecutive dots",
                "cannot start",
                "cannot end",
                "invalid character",
                "must be at least"
            ])
        finally:
            session.rollback()
    
    # Test valid domain names
    valid_domains = [
        "example.com",
        "sub.example.com",
        "example-site.com",
        "example123.com",
        "xn--80akhbyknj4f.com",  # IDN
        "test-1.example.com",
        "a.b.c.example.com",
        "example.co.uk",
        "my-domain.technology"
    ]
    
    # Verify valid domains don't raise exceptions
    for domain_name in valid_domains:
        try:
            domain = Domain(domain_name=domain_name)
            session.add(domain)
            session.commit()
        except Exception as e:
            pytest.fail(f"Valid domain {domain_name} raised error: {str(e)}")
        finally:
            session.rollback() 