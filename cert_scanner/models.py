from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, UniqueConstraint, Boolean, Text
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
import json
from datetime import datetime
from .constants import (
    APP_TYPES, HOST_TYPE_SERVER, HOST_TYPE_LOAD_BALANCER, HOST_TYPE_CDN, HOST_TYPE_VIRTUAL,
    ENV_PRODUCTION, ENV_CERT, ENV_DEVELOPMENT, ENV_INTERNAL, ENV_EXTERNAL,
    BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION,
    PLATFORMS
)

Base = declarative_base()

class Host(Base):
    """Represents a physical or virtual host (computer/platform)"""
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)  # e.g., "webserver1", "F5-Internal", "Akamai-CDN"
    host_type = Column(String)  # e.g., "Server", "LoadBalancer", "CDN"
    environment = Column(String)  # e.g., "Production", "Internal", "External"
    description = Column(String, nullable=True)
    last_seen = Column(DateTime)
    
    # Relationships
    ip_addresses = relationship("HostIP", back_populates="host", cascade="all, delete-orphan")
    certificate_bindings = relationship("CertificateBinding", back_populates="host", cascade="all, delete-orphan")

class HostIP(Base):
    """Represents IP addresses assigned to a host"""
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

class CertificateBinding(Base):
    """Represents where a certificate is deployed/used"""
    __tablename__ = 'certificate_bindings'
    __table_args__ = (
        UniqueConstraint('host_id', 'host_ip_id', 'port', 'site_name', name='unique_host_ip_port_site'),
    )
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    host_ip_id = Column(Integer, ForeignKey('host_ips.id'), nullable=True)  # Null for offline certs
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    application_id = Column(Integer, ForeignKey('applications.id'), nullable=True)
    port = Column(Integer, nullable=True)      # Null for non-IP certs
    binding_type = Column(String)  # 'IP', 'JWT', 'Client', etc.
    platform = Column(String)      # 'F5', 'IIS', 'Akamai', etc.
    site_name = Column(String, nullable=True)  # e.g., "Default Web Site", "API Service"
    site_id = Column(String, nullable=True)    # IIS site ID or other platform-specific identifier
    binding_order = Column(Integer, nullable=True)  # For tracking certificate flow order
    parent_binding_id = Column(Integer, ForeignKey('certificate_bindings.id'), nullable=True)  # For certificate flow
    last_seen = Column(DateTime)
    manually_added = Column(Boolean, default=False)  # Track if binding was manually added
    
    # Relationships
    host = relationship("Host", back_populates="certificate_bindings")
    host_ip = relationship("HostIP", back_populates="certificate_bindings")
    certificate = relationship("Certificate", back_populates="certificate_bindings")
    application = relationship("Application", back_populates="certificate_bindings")
    parent_binding = relationship("CertificateBinding", remote_side=[id], backref="child_bindings")

class Certificate(Base):
    __tablename__ = 'certificates'
    
    id = Column(Integer, primary_key=True)
    serial_number = Column(String, unique=True)
    thumbprint = Column(String, unique=True)
    common_name = Column(String)
    valid_from = Column(DateTime)
    valid_until = Column(DateTime)
    _issuer = Column('issuer', String)
    _subject = Column('subject', String)
    _san = Column('san', String)
    key_usage = Column(String)
    signature_algorithm = Column(String)
    sans_scanned = Column(Boolean, default=False)  # Track if SANs have been scanned
    manually_added = Column(Boolean, default=False)  # Track if certificate was manually added
    notes = Column(Text, nullable=True)  # For storing notes about manually added certificates
    
    # Relationships
    certificate_bindings = relationship("CertificateBinding", back_populates="certificate", cascade="all, delete-orphan")
    tracking_entries = relationship("CertificateTracking", back_populates="certificate", cascade="all, delete-orphan")
    scans = relationship("CertificateScan", back_populates="certificate", cascade="all, delete-orphan")

    @hybrid_property
    def issuer(self):
        if self._issuer:
            try:
                return json.loads(self._issuer)
            except:
                return {}
        return {}

    @issuer.setter
    def issuer(self, value):
        if value is not None:
            self._issuer = json.dumps(value)
        else:
            self._issuer = None

    @hybrid_property
    def subject(self):
        if self._subject:
            try:
                return json.loads(self._subject)
            except:
                return {}
        return {}

    @subject.setter
    def subject(self, value):
        if value is not None:
            self._subject = json.dumps(value)
        else:
            self._subject = None

    @hybrid_property
    def san(self):
        if self._san:
            try:
                return json.loads(self._san)
            except:
                return []
        return []

    @san.setter
    def san(self, value):
        if value is not None:
            self._san = json.dumps(value)
        else:
            self._san = None

class CertificateScan(Base):
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
    """Tracks changes and upcoming changes for certificates"""
    __tablename__ = 'certificate_tracking'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    change_number = Column(String)  # Change/ticket number
    planned_change_date = Column(DateTime, nullable=True)  # When the change is scheduled
    notes = Column(Text, nullable=True)  # Any additional notes
    status = Column(String)  # e.g., 'Pending', 'Completed', 'Cancelled'
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    
    certificate = relationship("Certificate", back_populates="tracking_entries")

class Application(Base):
    """Represents an application"""
    __tablename__ = 'applications'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)  # Make name unique since we're removing suites
    app_type = Column(String)  # Web, API, Service, etc.
    description = Column(String, nullable=True)
    owner = Column(String, nullable=True)  # Team or individual responsible for this application
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    certificate_bindings = relationship("CertificateBinding", back_populates="application") 