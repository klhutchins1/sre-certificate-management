from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, UniqueConstraint, Table
from sqlalchemy.orm import relationship, validates
from datetime import datetime
import re
from .base import Base

class Domain(Base):
    """
    Represents a domain name and its properties.
    """
    __tablename__ = 'domains'
    id = Column(Integer, primary_key=True)
    domain_name = Column(String, unique=True, nullable=False)
    registrar = Column(String)
    registration_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    auto_renew = Column(Boolean, default=False)
    parent_domain_id = Column(Integer, ForeignKey('domains.id'), nullable=True)
    owner = Column(String, nullable=True)
    dns_provider = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    is_active = Column(Boolean, default=True)
    certificates = relationship("Certificate", secondary="domain_certificates")
    parent_domain = relationship("Domain", remote_side=[id], backref="subdomains")
    dns_records = relationship("DomainDNSRecord", back_populates="domain", cascade="all, delete-orphan")
    @validates('domain_name')
    def validate_domain_name(self, key, domain_name):
        if not domain_name:
            raise ValueError("Domain name cannot be empty")
        if domain_name.endswith('.'):
            domain_name = domain_name[:-1]
        pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
        if not re.match(pattern, domain_name):
            raise ValueError("Invalid domain name format")
        if '..' in domain_name:
            raise ValueError("Domain name cannot contain consecutive dots")
        for segment in domain_name.split('.'):
            if not segment:
                raise ValueError("Domain name cannot have empty segments")
            if segment.startswith('-') or segment.endswith('-'):
                raise ValueError("Domain segments cannot start or end with hyphens")
            if not all(c.isalnum() or c == '-' for c in segment):
                raise ValueError("Domain segments can only contain letters, numbers, and hyphens")
            if len(segment) > 63:
                raise ValueError("Domain segments cannot be longer than 63 characters")
        return domain_name

class DomainDNSRecord(Base):
    """
    Represents DNS records associated with a domain.
    """
    __tablename__ = 'domain_dns_records'
    __table_args__ = (
        UniqueConstraint('domain_id', 'record_type', 'name', 'value', name='unique_domain_record'),
    )
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id'))
    record_type = Column(String, nullable=False)
    name = Column(String, nullable=False)
    value = Column(String, nullable=False)
    ttl = Column(Integer, default=3600)
    priority = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    domain = relationship("Domain", back_populates="dns_records")

domain_certificates = Table('domain_certificates', Base.metadata,
    Column('domain_id', Integer, ForeignKey('domains.id'), primary_key=True),
    Column('certificate_id', Integer, ForeignKey('certificates.id'), primary_key=True)
) 