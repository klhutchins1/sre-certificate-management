from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property
import json
from datetime import datetime
from .base import Base

class CertificateBinding(Base):
    """
    Represents where and how certificates are deployed/used.
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
    host = relationship("Host", back_populates="certificate_bindings")
    host_ip = relationship("HostIP", back_populates="certificate_bindings")
    certificate = relationship("Certificate", back_populates="certificate_bindings")
    application = relationship("Application", back_populates="certificate_bindings")
    parent_binding = relationship("CertificateBinding", remote_side=[id], backref="child_bindings")

class Certificate(Base):
    """
    Represents an SSL/TLS certificate.
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
    version = Column(Integer, nullable=True)
    certificate_bindings = relationship("CertificateBinding", back_populates="certificate", cascade="all, delete-orphan")
    tracking_entries = relationship("CertificateTracking", back_populates="certificate", cascade="all, delete-orphan")
    scans = relationship("CertificateScan", back_populates="certificate", cascade="all, delete-orphan")
    def __repr__(self):
        return f"<Certificate(id={self.id}, common_name='{self.common_name}', chain_valid={self.chain_valid})>"
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
        if isinstance(value, str):
            self._issuer = value
        elif value is not None:
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
        if isinstance(value, str):
            self._subject = value
        elif value is not None:
            self._subject = json.dumps(value)
        else:
            self._subject = None
    @hybrid_property
    def san(self):
        if self._san:
            try:
                san_data = json.loads(self._san)
                if isinstance(san_data, list):
                    return san_data
                elif isinstance(san_data, str):
                    return [s.strip() for s in san_data.split(',') if s.strip()]
                return []
            except:
                if isinstance(self._san, str):
                    return [s.strip() for s in self._san.split(',') if s.strip()]
                return []
        return []
    @san.setter
    def san(self, value):
        if isinstance(value, str):
            if value.startswith('[') and value.endswith(']'):
                self._san = value
            else:
                sans = [s.strip() for s in value.split(',') if s.strip()]
                self._san = json.dumps(sans)
        elif isinstance(value, (list, tuple)):
            self._san = json.dumps(list(value))
        else:
            self._san = None

class CertificateScan(Base):
    """
    Represents a certificate scanning operation.
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