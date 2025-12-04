#!/usr/bin/env python3
"""
Examine certificates in detail to find duplicates
"""

import sqlite3
import json
import sys
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Add scripts directory to path to import common utilities
# _common.py is in scripts/, so we need to add scripts/ directory to path
scripts_dir = Path(__file__).parent.parent  # scripts/ directory
sys.path.insert(0, str(scripts_dir))
try:
    from _common import get_database_path_from_config
except ImportError:
    def get_database_path_from_config():
        """Get database path from config.yaml file."""
        return None

def main():
    # Try to get database path from config, fallback to default
    db_path = get_database_path_from_config() or './data/certificates.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get all certificates
    cursor.execute('''
        SELECT id, serial_number, thumbprint, common_name, valid_from, valid_until, 
               issuer, subject, proxied, proxy_info, created_at
        FROM certificates 
        ORDER BY common_name, valid_until
    ''')

    certs = cursor.fetchall()
    print(f'📊 Total certificates: {len(certs)}')
    print('=' * 80)

    # Look for certificates with similar characteristics
    cn_groups = defaultdict(list)
    issuer_groups = defaultdict(list)
    
    for cert in certs:
        cert_id, serial, thumbprint, cn, valid_from, valid_until, issuer, subject, proxied, proxy_info, created_at = cert
        
        # Parse issuer
        try:
            issuer_data = json.loads(issuer) if issuer else {}
            issuer_cn = issuer_data.get('commonName', 'Unknown')
        except:
            issuer_cn = 'Parse Error'
        
        # Group by common name
        if cn:
            cn_groups[cn].append({
                'id': cert_id,
                'serial': serial,
                'thumbprint': thumbprint,
                'issuer_cn': issuer_cn,
                'valid_until': valid_until,
                'created_at': created_at,
                'proxied': proxied,
                'proxy_info': proxy_info
            })
        
        # Group by issuer
        issuer_groups[issuer_cn].append({
            'id': cert_id,
            'cn': cn,
            'serial': serial,
            'valid_until': valid_until,
            'created_at': created_at
        })

    # Show certificates grouped by common name
    print("🔍 Certificates by Common Name:")
    print("-" * 40)
    for cn, cert_list in sorted(cn_groups.items()):
        if len(cert_list) > 1:
            print(f"\n📋 {cn} ({len(cert_list)} certificates)")
            for i, cert in enumerate(cert_list, 1):
                print(f"   {i}. ID: {cert['id']}, Serial: {cert['serial'][:16]}...")
                print(f"      Issuer: {cert['issuer_cn']}, Expiry: {cert['valid_until']}")
                print(f"      Created: {cert['created_at']}, Proxied: {cert['proxied']}")

    # Show duplicates by exact match criteria
    print(f"\n🔍 Looking for potential proxy certificate patterns...")
    print("-" * 50)
    
    # Group by CN + expiry + issuer for exact logical duplicates
    logical_groups = defaultdict(list)
    for cn, cert_list in cn_groups.items():
        for cert in cert_list:
            key = f"{cert['issuer_cn']}|{cn}|{cert['valid_until']}"
            logical_groups[key].append(cert)
    
    duplicate_groups = {k: v for k, v in logical_groups.items() if len(v) > 1}
    
    if duplicate_groups:
        print(f"Found {len(duplicate_groups)} groups with logical duplicates:")
        for key, certs in duplicate_groups.items():
            issuer_cn, cn, valid_until = key.split('|')
            print(f"\n📋 {cn}")
            print(f"   Issuer: {issuer_cn}")
            print(f"   Expiry: {valid_until}")
            print(f"   Duplicates: {len(certs)}")
            
            # Show differences
            serials = set(cert['serial'] for cert in certs)
            thumbprints = set(cert['thumbprint'] for cert in certs)
            
            if len(serials) > 1:
                print(f"   ⚠️  Different serial numbers: {len(serials)} unique")
            if len(thumbprints) > 1:
                print(f"   ⚠️  Different thumbprints: {len(thumbprints)} unique")
            
            for i, cert in enumerate(certs, 1):
                print(f"   {i}. ID: {cert['id']}, Serial: {cert['serial'][:16]}...")
                print(f"      Thumbprint: {cert['thumbprint'][:16]}...")
                print(f"      Created: {cert['created_at']}")
    else:
        print("No logical duplicate groups found")

    # Show top issuers
    print(f"\n🔍 Top Certificate Issuers:")
    print("-" * 30)
    issuer_counts = {k: len(v) for k, v in issuer_groups.items()}
    for issuer, count in sorted(issuer_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   {issuer}: {count} certificates")

    conn.close()

if __name__ == "__main__":
    main()
