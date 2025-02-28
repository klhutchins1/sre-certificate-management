"""
Database models module for the Certificate Management System.

This module defines the SQLAlchemy ORM models that represent the core data structures
of the application, including:
- Certificates and their properties
- Hosts and IP addresses
- Certificate bindings and deployments
- Applications using certificates
- Certificate tracking and scanning history

The models implement a comprehensive relationship structure that allows tracking of:
- Where certificates are deployed
- How certificates flow through the infrastructure
- Historical certificate scanning results
- Certificate lifecycle management
- Application and host relationships

All models use SQLAlchemy's declarative base and include proper relationship definitions,
constraints, and cascading behaviors for maintaining data integrity.
"""

#------------------------------------------------------------------------------
# Imports and Configuration
#------------------------------------------------------------------------------

# SQLAlchemy imports
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table
from sqlalchemy import UniqueConstraint, Boolean, Text, event
from sqlalchemy.orm import relationship, declarative_base, validates
from sqlalchemy.ext.hybrid import hybrid_property

# Standard library imports
import json
from datetime import datetime
import re

# Local application imports
from .constants import (
    APP_TYPES, HOST_TYPE_SERVER, HOST_TYPE_LOAD_BALANCER, HOST_TYPE_CDN, HOST_TYPE_VIRTUAL,
    ENV_PRODUCTION, ENV_CERT, ENV_DEVELOPMENT, ENV_INTERNAL, ENV_EXTERNAL,
    BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION,
    PLATFORMS
)

#------------------------------------------------------------------------------
# Base Configuration
#------------------------------------------------------------------------------

Base = declarative_base()

#------------------------------------------------------------------------------
# Host Models
#------------------------------------------------------------------------------

class Host(Base):
    """
    Represents a physical or virtual host in the infrastructure.
    
    This model tracks servers, load balancers, CDNs, and other platforms
    that can host certificates. It maintains relationships with IP addresses
    and certificate bindings.
    
    Attributes:
        id (int): Primary key
        name (str): Unique host identifier (e.g., "webserver1", "F5-Internal")
        host_type (str): Type of host (Server, LoadBalancer, CDN, etc.)
        environment (str): Deployment environment (Production, Internal, etc.)
        description (str): Optional description of the host
        last_seen (datetime): Last time the host was detected/scanned
        
    Relationships:
        ip_addresses: List of IP addresses assigned to this host
        certificate_bindings: List of certificates bound to this host
    """
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    host_type = Column(String)
    environment = Column(String)
    description = Column(String, nullable=True)
    last_seen = Column(DateTime)
    
    # Relationships
    ip_addresses = relationship("HostIP", back_populates="host", cascade="all, delete-orphan")
    certificate_bindings = relationship("CertificateBinding", back_populates="host", cascade="all, delete-orphan")

class HostIP(Base):
    """
    Represents IP addresses assigned to hosts.
    
    Tracks the IP addresses associated with hosts and maintains the relationship
    between hosts and their network addresses. Includes tracking of address
    activity and last seen timestamps.
    
    Attributes:
        id (int): Primary key
        host_id (int): Foreign key to associated host
        ip_address (str): The IP address string
        is_active (bool): Whether this IP is currently active
        last_seen (datetime): Last time this IP was detected
        
    Constraints:
        - Unique combination of host_id and ip_address
        
    Relationships:
        host: The host this IP belongs to
        certificate_bindings: Certificates bound to this IP
    """
    __tablename__ = 'host_ips'
    __table_args__ = (
        UniqueConstraint('host_id', 'ip_address', name='unique_host_ip'),
    )
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    ip_address = Column(String)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime)
    
    # Relationships
    host = relationship("Host", back_populates="ip_addresses")
    certificate_bindings = relationship("CertificateBinding", back_populates="host_ip")

#------------------------------------------------------------------------------
# Certificate Models
#------------------------------------------------------------------------------

class CertificateBinding(Base):
    """
    Represents where and how certificates are deployed/used.
    
    This model tracks the relationships between certificates, hosts, and applications,
    including how certificates flow through the infrastructure (e.g., from load
    balancers to backend servers).
    
    Attributes:
        id (int): Primary key
        host_id (int): Foreign key to host
        host_ip_id (int): Foreign key to specific IP (optional)
        certificate_id (int): Foreign key to certificate
        application_id (int): Foreign key to application (optional)
        port (int): Port number for IP-based bindings
        binding_type (str): Type of binding (IP, JWT, Client)
        platform (str): Platform type (F5, IIS, Akamai, etc.)
        site_name (str): Name of the site/service using the certificate
        site_id (str): Platform-specific site identifier
        binding_order (int): Order in certificate flow chain
        parent_binding_id (int): Foreign key to parent binding in flow
        last_seen (datetime): Last time this binding was detected
        manually_added (bool): Whether this was manually configured
        
    Constraints:
        - Unique combination of host_id, host_ip_id, port, and site_name
        
    Relationships:
        host: The host where certificate is bound
        host_ip: Specific IP address for binding
        certificate: The certificate being used
        application: Associated application
        parent_binding: Previous binding in certificate flow
        child_bindings: Next bindings in certificate flow
    """
    __tablename__ = 'certificate_bindings'
    __table_args__ = (
        UniqueConstraint('host_id', 'host_ip_id', 'port', 'site_name', name='unique_host_ip_port_site'),
    )
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    host_ip_id = Column(Integer, ForeignKey('host_ips.id'), nullable=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    application_id = Column(Integer, ForeignKey('applications.id'), nullable=True)
    port = Column(Integer, nullable=True)
    binding_type = Column(String)
    platform = Column(String)
    site_name = Column(String, nullable=True)
    site_id = Column(String, nullable=True)
    binding_order = Column(Integer, nullable=True)
    parent_binding_id = Column(Integer, ForeignKey('certificate_bindings.id'), nullable=True)
    last_seen = Column(DateTime)
    manually_added = Column(Boolean, default=False)
    
    # Relationships
    host = relationship("Host", back_populates="certificate_bindings")
    host_ip = relationship("HostIP", back_populates="certificate_bindings")
    certificate = relationship("Certificate", back_populates="certificate_bindings")
    application = relationship("Application", back_populates="certificate_bindings")
    parent_binding = relationship("CertificateBinding", remote_side=[id], backref="child_bindings")

class Certificate(Base):
    """
    Represents an SSL/TLS certificate.
    
    This model stores comprehensive certificate information including basic
    fields, usage flags, and relationships to deployments and tracking data.
    Uses hybrid properties for complex fields stored as JSON.
    
    Attributes:
        id (int): Primary key
        serial_number (str): Unique certificate serial number
        thumbprint (str): SHA1 thumbprint
        common_name (str): Certificate Common Name
        valid_from (datetime): Start of validity period
        valid_until (datetime): End of validity period
        _issuer (str): Certificate issuer information
        _subject (str): Certificate subject information
        _san (str): Subject Alternative Names
        key_usage (str): Key usage flags
        signature_algorithm (str): Signature algorithm used
        chain_valid (bool): Chain validation status
        sans_scanned (bool): Whether SANs were scanned
        created_at (datetime): When the certificate was added
        updated_at (datetime): When the certificate was last updated
        notes (str): Additional notes for manual entries
        version (int): X.509 version number
        
    Hybrid Properties:
        issuer (dict): Certificate issuer information
        subject (dict): Certificate subject information
        san (list): Subject Alternative Names
        
    Relationships:
        certificate_bindings: Where this certificate is deployed
        tracking_entries: Lifecycle tracking entries
        scans: Scanning history
    """
    __tablename__ = 'certificates'
    
    id = Column(Integer, primary_key=True)
    serial_number = Column(String, unique=True, nullable=False)
    thumbprint = Column(String, unique=True, nullable=False)
    common_name = Column(String)
    valid_from = Column(DateTime, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    _issuer = Column('issuer', String)
    _subject = Column('subject', String)
    _san = Column('san', String)
    key_usage = Column(String)
    signature_algorithm = Column(String)
    chain_valid = Column(Boolean, default=False)
    sans_scanned = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    notes = Column(Text, nullable=True)
    version = Column(Integer, nullable=True)  # X.509 version number
    
    # Relationships
    certificate_bindings = relationship("CertificateBinding", back_populates="certificate", cascade="all, delete-orphan")
    tracking_entries = relationship("CertificateTracking", back_populates="certificate", cascade="all, delete-orphan")
    scans = relationship("CertificateScan", back_populates="certificate", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Certificate(id={self.id}, common_name='{self.common_name}', chain_valid={self.chain_valid})>"

    @hybrid_property
    def issuer(self):
        """
        Get certificate issuer information.
        
        Returns:
            dict: Dictionary of issuer attributes
        """
        if self._issuer:
            try:
                return json.loads(self._issuer)
            except:
                return {}
        return {}

    @issuer.setter
    def issuer(self, value):
        """
        Set certificate issuer information.
        
        Args:
            value: Dictionary of issuer attributes
        """
        if isinstance(value, str):
            self._issuer = value
        elif value is not None:
            self._issuer = json.dumps(value)
        else:
            self._issuer = None

    @hybrid_property
    def subject(self):
        """
        Get certificate subject information.
        
        Returns:
            dict: Dictionary of subject attributes
        """
        if self._subject:
            try:
                return json.loads(self._subject)
            except:
                return {}
        return {}

    @subject.setter
    def subject(self, value):
        """
        Set certificate subject information.
        
        Args:
            value: Dictionary of subject attributes
        """
        if isinstance(value, str):
            self._subject = value
        elif value is not None:
            self._subject = json.dumps(value)
        else:
            self._subject = None

    @hybrid_property
    def san(self):
        """
        Get Subject Alternative Names.
        
        Returns:
            list: List of SANs
        """
        if self._san:
            try:
                san_data = json.loads(self._san)
                if isinstance(san_data, list):
                    return san_data
                elif isinstance(san_data, str):
                    # Handle string format (legacy data)
                    return [s.strip() for s in san_data.split(',') if s.strip()]
                return []
            except:
                # Handle legacy string format or invalid JSON
                if isinstance(self._san, str):
                    return [s.strip() for s in self._san.split(',') if s.strip()]
                return []
        return []

    @san.setter
    def san(self, value):
        """
        Set Subject Alternative Names.
        
        Args:
            value: List of SANs or string representation
        """
        if isinstance(value, str):
            if value.startswith('[') and value.endswith(']'):
                # Already JSON formatted
                self._san = value
            else:
                # Convert comma-separated string to JSON list
                sans = [s.strip() for s in value.split(',') if s.strip()]
                self._san = json.dumps(sans)
        elif isinstance(value, (list, tuple)):
            self._san = json.dumps(list(value))
        else:
            self._san = None

#------------------------------------------------------------------------------
# Scanning and Tracking Models
#------------------------------------------------------------------------------

class CertificateScan(Base):
    """
    Represents a certificate scanning operation.
    
    Tracks the history of certificate scanning operations, including
    the results and status of each scan.
    
    Attributes:
        id (int): Primary key
        certificate_id (int): Foreign key to scanned certificate
        host_id (int): Foreign key to scanned host
        scan_date (datetime): When the scan occurred
        status (str): Scan result status
        port (int): Port that was scanned
        
    Relationships:
        certificate: The certificate that was scanned
        host: The host that was scanned
    """
    __tablename__ = 'certificate_scans'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'), nullable=True)
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=True)
    scan_date = Column(DateTime)
    status = Column(String)
    port = Column(Integer)
    
    certificate = relationship("Certificate", back_populates="scans")
    host = relationship("Host", backref="scans")

class CertificateTracking(Base):
    """
    Tracks changes and lifecycle events for certificates.
    
    This model maintains the history of planned and completed changes
    to certificates, including renewals, replacements, and other
    lifecycle events.
    
    Attributes:
        id (int): Primary key
        certificate_id (int): Foreign key to certificate
        change_number (str): Change/ticket reference number
        planned_change_date (datetime): When change is scheduled
        notes (str): Additional information about the change
        status (str): Current status (Pending, Completed, etc.)
        created_at (datetime): When this tracking entry was created
        updated_at (datetime): When this entry was last updated
        
    Relationships:
        certificate: The certificate being tracked
    """
    __tablename__ = 'certificate_tracking'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    change_number = Column(String)
    planned_change_date = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    status = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    
    certificate = relationship("Certificate", back_populates="tracking_entries")

#------------------------------------------------------------------------------
# Application Model
#------------------------------------------------------------------------------

class Application(Base):
    """
    Represents an application using certificates.
    
    This model tracks applications that use certificates, including
    their type, ownership, and relationships to certificate bindings.
    
    Attributes:
        id (int): Primary key
        name (str): Unique application name
        app_type (str): Application type (Web, API, Service, etc.)
        description (str): Optional application description
        owner (str): Team/individual responsible for the application
        created_at (datetime): When the application was added
        updated_at (datetime): When the application was last updated
        
    Relationships:
        certificate_bindings: Certificates used by this application
    """
    __tablename__ = 'applications'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    app_type = Column(String)
    description = Column(String, nullable=True)
    owner = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    certificate_bindings = relationship("CertificateBinding", back_populates="application")

#------------------------------------------------------------------------------
# Domain Models
#------------------------------------------------------------------------------

class Domain(Base):
    """
    Represents a domain name and its properties.
    
    This model tracks domain names, their registration details, and relationships
    to certificates and subdomains. It provides domain lifecycle management
    and monitoring capabilities.
    
    Attributes:
        id (int): Primary key
        domain_name (str): The domain name (e.g., example.com)
        registrar (str): Domain registrar (e.g., GoDaddy, Namecheap)
        registration_date (datetime): When the domain was registered
        expiration_date (datetime): When the domain registration expires
        auto_renew (bool): Whether domain auto-renews
        parent_domain_id (int): Foreign key to parent domain for subdomains
        owner (str): Team/individual responsible for the domain
        dns_provider (str): DNS service provider
        notes (str): Additional domain-related notes
        created_at (datetime): When this record was created
        updated_at (datetime): When this record was last updated
        is_active (bool): Whether the domain is currently active
        
    Relationships:
        certificates: Certificates securing this domain
        parent_domain: Parent domain for subdomains
        subdomains: Child domains (subdomains)
        dns_records: Associated DNS records
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
    
    # Relationships
    certificates = relationship("Certificate", secondary="domain_certificates")
    parent_domain = relationship("Domain", remote_side=[id], backref="subdomains")
    dns_records = relationship("DomainDNSRecord", back_populates="domain", cascade="all, delete-orphan")
    
    @validates('domain_name')
    def validate_domain_name(self, key, domain_name):
        """
        Validate domain name format.
        
        Args:
            key: Field name being validated
            domain_name: Domain name to validate
            
        Returns:
            str: Validated domain name
            
        Raises:
            ValueError: If domain name is invalid
        """
        if not domain_name:
            raise ValueError("Domain name cannot be empty")
            
        # Remove trailing dot if present
        if domain_name.endswith('.'):
            domain_name = domain_name[:-1]
            
        # Basic domain name validation
        pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
        if not re.match(pattern, domain_name):
            raise ValueError("Invalid domain name format")
            
        # Check for double dots
        if '..' in domain_name:
            raise ValueError("Domain name cannot contain consecutive dots")
            
        # Check each segment
        for segment in domain_name.split('.'):
            # Check for empty segments
            if not segment:
                raise ValueError("Domain name cannot have empty segments")
                
            # Check for hyphens at start/end
            if segment.startswith('-') or segment.endswith('-'):
                raise ValueError("Domain segments cannot start or end with hyphens")
                
            # Check for invalid characters
            if not all(c.isalnum() or c == '-' for c in segment):
                raise ValueError("Domain segments can only contain letters, numbers, and hyphens")
                
            # Check segment length
            if len(segment) > 63:
                raise ValueError("Domain segments cannot be longer than 63 characters")
        
        return domain_name

class DomainDNSRecord(Base):
    """
    Represents DNS records associated with a domain.
    
    This model tracks DNS records for domains, including record types,
    values, and TTL settings.
    
    Attributes:
        id (int): Primary key
        domain_id (int): Foreign key to associated domain
        record_type (str): DNS record type (A, CNAME, MX, etc.)
        name (str): Record name/host
        value (str): Record value/target
        ttl (int): Time to live in seconds
        priority (int): Priority for MX/SRV records
        created_at (datetime): When this record was created
        updated_at (datetime): When this record was last updated
        
    Relationships:
        domain: The domain this record belongs to
    """
    __tablename__ = 'domain_dns_records'
    __table_args__ = (
        UniqueConstraint('domain_id', 'record_type', 'name', name='unique_domain_record'),
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
    
    # Relationships
    domain = relationship("Domain", back_populates="dns_records")

# Association table for domains and certificates
domain_certificates = Table('domain_certificates', Base.metadata,
    Column('domain_id', Integer, ForeignKey('domains.id'), primary_key=True),
    Column('certificate_id', Integer, ForeignKey('certificates.id'), primary_key=True)
)

#------------------------------------------------------------------------------
# Ignore List Models
#------------------------------------------------------------------------------

class IgnoredDomain(Base):
    """
    Represents a domain pattern that should be ignored during scanning.
    
    This model tracks domains that should be skipped during scanning operations.
    It supports both exact matches and wildcard patterns.
    
    Attributes:
        id (int): Primary key
        pattern (str): Domain pattern to ignore (e.g., "test.example.com" or "*.test.com")
        reason (str): Optional reason for ignoring this domain
        created_at (datetime): When this ignore rule was created
        created_by (str): Who created this ignore rule (for future use)
    """
    __tablename__ = 'ignored_domains'
    
    id = Column(Integer, primary_key=True)
    pattern = Column(String, nullable=False, unique=True)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    created_by = Column(String, nullable=True)
    
    def matches(self, domain: str) -> bool:
        """Check if a domain matches this ignore pattern."""
        if self.pattern.startswith('*.'):
            # Wildcard pattern
            suffix = self.pattern[2:]  # Remove *. from pattern
            return domain.endswith(suffix)
        else:
            # Exact match
            return domain == self.pattern

class IgnoredCertificate(Base):
    """
    Represents a certificate that should be ignored.
    
    This model tracks certificates that should be hidden from views
    and skipped during scanning operations based on their Common Name (CN)
    pattern.
    
    Attributes:
        id (int): Primary key
        pattern (str): Common Name pattern to ignore (supports wildcards)
        reason (str): Optional reason for ignoring this certificate
        created_at (datetime): When this ignore rule was created
        created_by (str): Who created this ignore rule (for future use)
    """
    __tablename__ = 'ignored_certificates'
    
    id = Column(Integer, primary_key=True)
    pattern = Column(String, nullable=False, unique=True)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    created_by = Column(String, nullable=True)
    
    def matches(self, common_name: str) -> bool:
        """
        Check if a certificate's Common Name matches this ignore pattern.
        
        Args:
            common_name: The certificate's Common Name to check
            
        Returns:
            bool: True if the CN matches the ignore pattern
            
        Examples:
            - pattern="*test*" matches "test.example.com" and "mytest.com"
            - pattern="*.test.com" matches "sub.test.com" but not "test.com"
            - pattern="test.com" only matches "test.com" exactly
        """
        if not common_name:
            return False
            
        pattern = self.pattern.lower()
        common_name = common_name.lower()
        
        # Handle different pattern types
        if pattern.startswith('*.') and pattern.count('*') == 1:
            # Suffix wildcard (*.example.com)
            suffix = pattern[2:]
            return common_name.endswith(suffix) and '.' in common_name
        elif pattern.startswith('*') and pattern.endswith('*'):
            # Contains pattern (*test*)
            search_term = pattern.strip('*')
            return search_term in common_name
        elif pattern.startswith('*'):
            # Prefix wildcard (*test.com)
            suffix = pattern[1:]
            return common_name.endswith(suffix)
        elif pattern.endswith('*'):
            # Suffix wildcard (test*)
            prefix = pattern[:-1]
            return common_name.startswith(prefix)
        else:
            # Exact match
            return common_name == pattern 