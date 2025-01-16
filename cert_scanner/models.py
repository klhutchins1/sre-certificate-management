from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, UniqueConstraint, Boolean, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

# Host Types
HOST_TYPE_SERVER = 'Server'
HOST_TYPE_LOAD_BALANCER = 'LoadBalancer'
HOST_TYPE_CDN = 'CDN'
HOST_TYPE_VIRTUAL = 'Virtual'

HOST_TYPES = [
    HOST_TYPE_SERVER,
    HOST_TYPE_LOAD_BALANCER,
    HOST_TYPE_CDN,
    HOST_TYPE_VIRTUAL
]

# Environments
ENV_PRODUCTION = 'Production'
ENV_STAGING = 'Staging'
ENV_DEVELOPMENT = 'Development'
ENV_INTERNAL = 'Internal'
ENV_EXTERNAL = 'External'

ENVIRONMENTS = [
    ENV_PRODUCTION,
    ENV_STAGING,
    ENV_DEVELOPMENT,
    ENV_INTERNAL,
    ENV_EXTERNAL
]

# Binding Types
BINDING_TYPE_IP = 'IP'
BINDING_TYPE_JWT = 'JWT'
BINDING_TYPE_CLIENT = 'Client'

BINDING_TYPES = [
    BINDING_TYPE_IP,
    BINDING_TYPE_JWT,
    BINDING_TYPE_CLIENT
]

# Platform Types
PLATFORM_F5 = 'F5'
PLATFORM_AKAMAI = 'Akamai'
PLATFORM_CLOUDFLARE = 'Cloudflare'
PLATFORM_IIS = 'IIS'
PLATFORM_CONNECTION = 'Connection'

PLATFORMS = [
    PLATFORM_F5,
    PLATFORM_AKAMAI,
    PLATFORM_CLOUDFLARE,
    PLATFORM_IIS,
    PLATFORM_CONNECTION
]

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
    ip_addresses = relationship("HostIP", back_populates="host")
    certificate_bindings = relationship("CertificateBinding", back_populates="host")

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
        UniqueConstraint('host_id', 'host_ip_id', 'port', name='unique_host_ip_port'),
    )
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    host_ip_id = Column(Integer, ForeignKey('host_ips.id'), nullable=True)  # Null for offline certs
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    port = Column(Integer, nullable=True)      # Null for non-IP certs
    binding_type = Column(String)  # 'IP', 'JWT', 'Client', etc.
    platform = Column(String)      # 'F5', 'IIS', 'Akamai', etc.
    service_name = Column(String, nullable=True)  # e.g., "Default Web Site", "API Service"
    last_seen = Column(DateTime)
    
    host = relationship("Host", back_populates="certificate_bindings")
    host_ip = relationship("HostIP", back_populates="certificate_bindings")
    certificate = relationship("Certificate", back_populates="certificate_bindings")

class Certificate(Base):
    __tablename__ = 'certificates'
    
    id = Column(Integer, primary_key=True)
    serial_number = Column(String, unique=True)
    thumbprint = Column(String, unique=True)
    common_name = Column(String)
    valid_from = Column(DateTime)
    valid_until = Column(DateTime)
    issuer = Column(String)
    subject = Column(String)
    san = Column(String)
    key_usage = Column(String)
    signature_algorithm = Column(String)
    certificate_bindings = relationship("CertificateBinding", back_populates="certificate")
    scans = relationship("CertificateScan", back_populates="certificate")
    tracking_entries = relationship("CertificateTracking", back_populates="certificate", order_by="CertificateTracking.planned_change_date")

class CertificateScan(Base):
    __tablename__ = 'certificate_scans'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    scan_date = Column(DateTime)
    status = Column(String)
    port = Column(Integer)
    
    certificate = relationship("Certificate", back_populates="scans")

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