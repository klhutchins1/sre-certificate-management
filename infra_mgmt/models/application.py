from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .base import Base

class Application(Base):
    """
    Represents an application using certificates.
    """
    __tablename__ = 'applications'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    app_type = Column(String)
    description = Column(String, nullable=True)
    owner = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    certificate_bindings = relationship("CertificateBinding", back_populates="application") 