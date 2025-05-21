from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from .base import Base

class Host(Base):
    """
    Represents a physical or virtual host in the infrastructure.
    """
    __tablename__ = 'hosts'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    host_type = Column(String)
    environment = Column(String)
    description = Column(String, nullable=True)
    last_seen = Column(DateTime)
    ip_addresses = relationship("HostIP", back_populates="host", cascade="all, delete-orphan")
    certificate_bindings = relationship("CertificateBinding", back_populates="host", cascade="all, delete-orphan")

class HostIP(Base):
    """
    Represents IP addresses assigned to hosts.
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
    host = relationship("Host", back_populates="ip_addresses")
    certificate_bindings = relationship("CertificateBinding", back_populates="host_ip") 