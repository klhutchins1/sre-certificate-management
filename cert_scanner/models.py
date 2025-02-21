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
from sqlalchemy import UniqueConstraint, Boolean, Text
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.ext.hybrid import hybrid_property

# Standard library imports
import json
from datetime import datetime

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