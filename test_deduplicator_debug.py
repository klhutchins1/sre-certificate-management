#!/usr/bin/env python3
"""
Simple test to debug the deduplicator logic
"""

import sys
import os
sys.path.append('.')

from datetime import datetime, timezone, timedelta
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate
from infra_mgmt.utils.proxy_certificate_deduplication import ProxyCertificateDeduplicator

def test_deduplicator():
    print("Testing deduplicator logic...")
    
    # Create a test session
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    session = Session(bind=engine)
    
    # Create a test certificate
    now = datetime.now(timezone.utc)
    cert = Certificate(
        serial_number='test_serial_123',
        thumbprint='test_thumbprint_456',
        common_name='example.com',
        valid_from=now - timedelta(days=30),
        valid_until=now + timedelta(days=365),
        issuer=json.dumps({'CN': 'Corporate Proxy CA'}),
        subject=json.dumps({'CN': 'example.com'}),
        san=json.dumps(['example.com', 'www.example.com']),
        proxied=True,
        proxy_info='Test proxy certificate'
    )
    session.add(cert)
    session.commit()
    
    print(f"Created certificate: {cert.id}")
    print(f"Issuer: {cert.issuer}")
    print(f"Common name: {cert.common_name}")
    print(f"Valid until: {cert.valid_until}")
    
    # Test the deduplicator
    deduplicator = ProxyCertificateDeduplicator(session)
    
    # Test finding the certificate
    identity = deduplicator.get_proxy_certificate_identity(cert)
    print(f"Identity: {identity}")
    
    if identity:
        existing = deduplicator.find_existing_proxy_certificate(identity)
        print(f"Found existing: {existing}")
        if existing:
            print(f"Existing certificate ID: {existing.id}")
        else:
            print("No existing certificate found")
    else:
        print("No identity found")
    
    session.close()

if __name__ == "__main__":
    test_deduplicator()











