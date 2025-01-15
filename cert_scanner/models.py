from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Association tables
cert_hostname = Table('cert_hostname', Base.metadata,
    Column('cert_id', Integer, ForeignKey('certificates.id')),
    Column('hostname_id', Integer, ForeignKey('hostnames.id'))
)

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
    san = Column(String)  # Store SANs as JSON string
    key_usage = Column(String)
    signature_algorithm = Column(String)
    
    hostnames = relationship(
        "Hostname",
        secondary=cert_hostname,
        back_populates="certificates"
    )
    scans = relationship("CertificateScan", back_populates="certificate")

class Hostname(Base):
    __tablename__ = 'hostnames'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    ip_addresses = Column(String)  # Stored as JSON
    last_seen = Column(DateTime)
    
    certificates = relationship(
        "Certificate",
        secondary=cert_hostname,
        back_populates="hostnames"
    )

class CertificateScan(Base):
    __tablename__ = 'certificate_scans'
    
    id = Column(Integer, primary_key=True)
    certificate_id = Column(Integer, ForeignKey('certificates.id'))
    scan_date = Column(DateTime)
    status = Column(String)
    port = Column(Integer)
    
    certificate = relationship("Certificate", back_populates="scans") 