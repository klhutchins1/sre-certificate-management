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
    proxied = Column(Boolean, default=False)  # True if detected as proxy/MITM cert
    proxy_info = Column(Text, nullable=True)  # Info about proxy detection (e.g., matched CA, fingerprint, etc)
    
    # Proxy override fields for real certificate information
    real_serial_number = Column(String, nullable=True)  # Real serial number when behind proxy
    real_thumbprint = Column(String, nullable=True)  # Real thumbprint when behind proxy
    real_issuer = Column(Text, nullable=True)  # Real issuer info when behind proxy
    real_subject = Column(Text, nullable=True)  # Real subject info when behind proxy
    real_valid_from = Column(DateTime, nullable=True)  # Real valid from date when behind proxy
    real_valid_until = Column(DateTime, nullable=True)  # Real valid until date when behind proxy
    override_notes = Column(Text, nullable=True)  # Notes about the override
    override_created_at = Column(DateTime, nullable=True)  # When override was created
    
    # Revocation status fields
    revocation_status = Column(String, nullable=True)  # 'good', 'revoked', 'unknown', 'error', 'not_checked'
    revocation_date = Column(DateTime, nullable=True)  # When certificate was revoked
    revocation_reason = Column(String, nullable=True)  # Reason for revocation
    revocation_check_method = Column(String, nullable=True)  # 'OCSP', 'CRL', or 'both'
    revocation_last_checked = Column(DateTime, nullable=True)  # Last time revocation was checked
    ocsp_response_cached_until = Column(DateTime, nullable=True)  # OCSP response cache expiration
    
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
    
    @hybrid_property
    def real_issuer_dict(self):
        """Get real issuer as dictionary when behind proxy."""
        if self.real_issuer:
            try:
                return json.loads(self.real_issuer)
            except:
                return {}
        return {}
    
    @real_issuer_dict.setter
    def real_issuer_dict(self, value):
        """Set real issuer from dictionary when behind proxy."""
        if isinstance(value, str):
            self.real_issuer = value
        elif value is not None:
            self.real_issuer = json.dumps(value)
        else:
            self.real_issuer = None
    
    @hybrid_property
    def real_subject_dict(self):
        """Get real subject as dictionary when behind proxy."""
        if self.real_subject:
            try:
                return json.loads(self.real_subject)
            except:
                return {}
        return {}
    
    @real_subject_dict.setter
    def real_subject_dict(self, value):
        """Set real subject from dictionary when behind proxy."""
        if isinstance(value, str):
            self.real_subject = value
        elif value is not None:
            self.real_subject = json.dumps(value)
        else:
            self.real_subject = None

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
    # Change tracking fields
    change_id = Column(Integer, ForeignKey('certificate_tracking.id'), nullable=True)  # Associated change entry
    scan_type = Column(String, nullable=True)  # 'before' or 'after' - indicates if this is a before/after scan for a change
    certificate = relationship("Certificate", back_populates="scans")
    host = relationship("Host", backref="scans")
    change = relationship("CertificateTracking", backref="scans")

class CertificateTracking(Base):
    """
    Tracks changes and lifecycle events for certificates.
    """
    __tablename__ = 'certificate_tracking'
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'), nullable=True)  # Allow None for changes before certificate exists
    change_number = Column(String)
    planned_change_date = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    status = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    certificate = relationship("Certificate", back_populates="tracking_entries") 