#!/usr/bin/env python3
"""
Proxy Certificate Diagnostic Script

This script analyzes the database to identify potential proxy certificates
and suggests configuration for proxy detection.

Usage:
    python diagnose_proxy_certificates.py [--db-path PATH]
"""

import argparse
import sqlite3
import sys
import os
import yaml
import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

def load_config():
    """Load configuration from config.yaml file."""
    config_path = 'config.yaml'
    if not os.path.exists(config_path):
        print(f"⚠️  Warning: config.yaml not found at {config_path}")
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"⚠️  Warning: Could not load config.yaml: {e}")
        return None

def get_database_path_from_config():
    """Get database path from config.yaml file."""
    config = load_config()
    if config and 'paths' in config and 'database' in config['paths']:
        db_path = config['paths']['database']
        # Handle relative paths
        if not os.path.isabs(db_path):
            db_path = os.path.join(os.getcwd(), db_path)
        return db_path
    return None

def parse_issuer_json(issuer_str):
    """Parse issuer JSON string and extract common name."""
    if not issuer_str:
        return None
    
    try:
        if isinstance(issuer_str, str):
            issuer_data = json.loads(issuer_str)
        else:
            issuer_data = issuer_str
        
        # Try different possible keys for common name
        cn = (issuer_data.get('commonName') or 
              issuer_data.get('CN') or 
              issuer_data.get('common_name'))
        
        return cn
    except:
        return None

def is_likely_proxy_ca(issuer_cn):
    """Check if issuer CN contains common proxy indicators."""
    if not issuer_cn:
        return False
    
    proxy_indicators = [
        'proxy', 'corporate', 'internal', 'firewall', 'gateway', 
        'bluecoat', 'zscaler', 'forcepoint', 'filter', 'ssl', 'ca',
        'corp', 'company', 'organization', 'enterprise'
    ]
    
    issuer_lower = issuer_cn.lower()
    for indicator in proxy_indicators:
        if indicator in issuer_lower:
            return True
    
    return False

def analyze_certificates(db_path):
    """Analyze all certificates in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all certificates with their details
    cursor.execute("""
        SELECT id, serial_number, thumbprint, common_name, valid_from, valid_until, 
               issuer, subject, proxied, proxy_info, created_at
        FROM certificates
        ORDER BY created_at
    """)
    
    certificates = cursor.fetchall()
    conn.close()
    
    print(f"📊 Found {len(certificates)} total certificates in database")
    
    # Analyze issuers
    issuer_counter = Counter()
    proxy_issuer_counter = Counter()
    likely_proxy_issuers = []
    
    for cert in certificates:
        (cert_id, serial, thumbprint, cn, valid_from, valid_until, 
         issuer, subject, proxied, proxy_info, created_at) = cert
        
        # Parse issuer
        issuer_cn = parse_issuer_json(issuer)
        if issuer_cn:
            issuer_counter[issuer_cn] += 1
            
            # Check if this looks like a proxy CA
            if is_likely_proxy_ca(issuer_cn):
                proxy_issuer_counter[issuer_cn] += 1
                likely_proxy_issuers.append({
                    'issuer_cn': issuer_cn,
                    'cert_id': cert_id,
                    'cn': cn,
                    'proxied': proxied,
                    'proxy_info': proxy_info,
                    'created_at': created_at
                })
    
    print(f"\n🔍 Issuer Analysis:")
    print(f"   Unique issuers: {len(issuer_counter)}")
    print(f"   Likely proxy issuers: {len(proxy_issuer_counter)}")
    
    if proxy_issuer_counter:
        print(f"\n🚨 Likely Proxy CAs Found:")
        for issuer_cn, count in proxy_issuer_counter.most_common():
            print(f"   {issuer_cn}: {count} certificates")
    
    # Look for potential duplicates
    print(f"\n🔍 Potential Duplicate Analysis:")
    
    # Group by common characteristics
    potential_duplicates = defaultdict(list)
    
    for cert in certificates:
        (cert_id, serial, thumbprint, cn, valid_from, valid_until, 
         issuer, subject, proxied, proxy_info, created_at) = cert
        
        issuer_cn = parse_issuer_json(issuer)
        if issuer_cn and is_likely_proxy_ca(issuer_cn):
            # Group by issuer + common_name + expiration
            group_key = f"{issuer_cn}|{cn}|{valid_until}"
            potential_duplicates[group_key].append({
                'id': cert_id,
                'serial': serial,
                'thumbprint': thumbprint,
                'cn': cn,
                'issuer_cn': issuer_cn,
                'valid_until': valid_until,
                'proxied': proxied,
                'proxy_info': proxy_info,
                'created_at': created_at
            })
    
    # Show groups with multiple certificates
    duplicate_groups = {key: certs for key, certs in potential_duplicates.items() 
                       if len(certs) > 1}
    
    if duplicate_groups:
        print(f"   Found {len(duplicate_groups)} groups with potential duplicates:")
        for group_key, certs in duplicate_groups.items():
            issuer_cn, cn, valid_until = group_key.split('|')
            print(f"\n   📋 Group: {cn}")
            print(f"      CA: {issuer_cn}")
            print(f"      Expiration: {valid_until}")
            print(f"      Duplicates: {len(certs)} certificates")
            
            for i, cert in enumerate(certs, 1):
                print(f"      {i}. ID: {cert['id']}, Serial: {cert['serial'][:16]}..., "
                      f"Thumbprint: {cert['thumbprint'][:16]}...")
                if cert['proxied']:
                    print(f"         Already marked as proxied: {cert['proxy_info']}")
    else:
        print("   No obvious duplicate groups found")
    
    return likely_proxy_issuers, duplicate_groups

def suggest_configuration(likely_proxy_issuers, duplicate_groups):
    """Suggest configuration based on analysis."""
    print(f"\n💡 Configuration Suggestions:")
    
    # Get unique likely proxy issuers
    unique_proxy_issuers = list(set(cert['issuer_cn'] for cert in likely_proxy_issuers))
    
    if unique_proxy_issuers:
        print(f"\n📝 Add these to your config.yaml proxy_detection.ca_subjects:")
        print("proxy_detection:")
        print("  ca_subjects:")
        for issuer in unique_proxy_issuers:
            print(f"    - '{issuer}'")
    
    if duplicate_groups:
        print(f"\n🔧 After adding the CA subjects above, run:")
        print("python proxy_certificate_deduplication_advanced.py --dry-run")
        print("python proxy_certificate_deduplication_advanced.py")
    else:
        print(f"\n✅ No duplicate groups found - your database may already be clean!")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Diagnose proxy certificates in the database",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--db-path',
        type=str,
        help='Path to the SQLite database file (default: from config.yaml)'
    )
    
    args = parser.parse_args()
    
    # Get database path
    if args.db_path:
        db_path = Path(args.db_path).resolve()
        print(f"ℹ️  Using database path from command line: {db_path}")
    else:
        db_path = get_database_path_from_config()
        if db_path:
            db_path = Path(db_path).resolve()
            print(f"ℹ️  Using database path from config.yaml: {db_path}")
        else:
            print("❌ Error: No database path specified and not found in config.yaml")
            print("Please specify --db-path or ensure config.yaml contains paths.database")
            sys.exit(1)
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"❌ Error: Database file not found at {db_path}")
        sys.exit(1)
    
    print("=" * 60)
    print("🔍 Proxy Certificate Diagnostic Tool")
    print("=" * 60)
    print(f"Database path: {db_path}")
    print("=" * 60)
    
    # Analyze the database
    likely_proxy_issuers, duplicate_groups = analyze_certificates(str(db_path))
    
    # Suggest configuration
    suggest_configuration(likely_proxy_issuers, duplicate_groups)
    
    print(f"\n" + "=" * 60)
    print("✅ Diagnostic complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
