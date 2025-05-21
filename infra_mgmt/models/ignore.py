from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from .base import Base

class IgnoredDomain(Base):
    """
    Represents a domain pattern that should be ignored during scanning.
    """
    __tablename__ = 'ignored_domains'
    id = Column(Integer, primary_key=True)
    pattern = Column(String, nullable=False, unique=True)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    created_by = Column(String, nullable=True)
    def matches(self, domain: str) -> bool:
        if self.pattern.startswith('*.'):
            suffix = self.pattern[2:]
            return domain.endswith(suffix)
        else:
            return domain == self.pattern

class IgnoredCertificate(Base):
    """
    Represents a certificate that should be ignored.
    """
    __tablename__ = 'ignored_certificates'
    id = Column(Integer, primary_key=True)
    pattern = Column(String, nullable=False, unique=True)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    created_by = Column(String, nullable=True)
    def matches(self, common_name: str) -> bool:
        if not common_name:
            return False
        pattern = self.pattern.lower()
        common_name = common_name.lower()
        if pattern.startswith('*.') and pattern.count('*') == 1:
            suffix = pattern[2:]
            return common_name.endswith(suffix) and '.' in common_name
        elif pattern.startswith('*') and pattern.endswith('*'):
            search_term = pattern.strip('*')
            return search_term in common_name
        elif pattern.startswith('*'):
            suffix = pattern[1:]
            return common_name.endswith(suffix)
        elif pattern.endswith('*'):
            prefix = pattern[:-1]
            return common_name.startswith(prefix)
        else:
            return common_name == pattern 