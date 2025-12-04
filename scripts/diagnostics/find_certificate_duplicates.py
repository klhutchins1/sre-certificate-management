#!/usr/bin/env python3
"""
Find Certificate Duplicates Script

This script finds duplicate certificates based on common characteristics,
regardless of proxy detection status.

Usage:
    python find_certificate_duplicates.py [--db-path PATH]
"""

import argparse
import sqlite3
import sys
import os
import yaml
import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Add scripts directory to path to import common utilities
# _common.py is in scripts/, so we need to add scripts/ directory to path
scripts_dir = Path(__file__).parent.parent  # scripts/ directory
sys.path.insert(0, str(scripts_dir))
try:
    from _common import find_project_root, load_config, get_database_path_from_config
except ImportError:
    # Fallback if _common.py not available
    def find_project_root():
        """Find the project root directory (where config.yaml is located)."""
        current = Path(__file__).resolve()
        # Script is in scripts/diagnostics/, so go up 3 levels to reach project root
        project_root = current.parent.parent.parent
        return project_root
    
    def load_config():
        """Load configuration from config.yaml file."""
        project_root = find_project_root()
        config_path = project_root / 'config.yaml'
        if not config_path.exists():
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
            if not os.path.isabs(db_path):
                project_root = find_project_root()
                db_path = os.path.join(project_root, db_path)
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

def find_duplicate_groups(db_path):
    """Find groups of certificates that might be duplicates."""
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
    
    # Group by different characteristics
    groups_by_cn_expiry = defaultdict(list)
    groups_by_issuer_cn_expiry = defaultdict(list)
    groups_by_thumbprint = defaultdict(list)
    groups_by_serial = defaultdict(list)
    
    for cert in certificates:
        (cert_id, serial, thumbprint, cn, valid_from, valid_until, 
         issuer, subject, proxied, proxy_info, created_at) = cert
        
        issuer_cn = parse_issuer_json(issuer)
        
        # Group by common name + expiration
        if cn and valid_until:
            key = f"{cn}|{valid_until}"
            groups_by_cn_expiry[key].append({
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
        
        # Group by issuer + common name + expiration
        if issuer_cn and cn and valid_until:
            key = f"{issuer_cn}|{cn}|{valid_until}"
            groups_by_issuer_cn_expiry[key].append({
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
        
        # Group by thumbprint
        if thumbprint:
            groups_by_thumbprint[thumbprint].append({
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
        
        # Group by serial number
        if serial:
            groups_by_serial[serial].append({
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
    
    return {
        'by_cn_expiry': groups_by_cn_expiry,
        'by_issuer_cn_expiry': groups_by_issuer_cn_expiry,
        'by_thumbprint': groups_by_thumbprint,
        'by_serial': groups_by_serial
    }

def analyze_duplicates(groups):
    """Analyze and display duplicate groups."""
    print(f"\n🔍 Duplicate Analysis:")
    
    # Check for exact thumbprint duplicates
    thumbprint_duplicates = {k: v for k, v in groups['by_thumbprint'].items() if len(v) > 1}
    if thumbprint_duplicates:
        print(f"\n🚨 EXACT DUPLICATES (same thumbprint): {len(thumbprint_duplicates)} groups")
        for thumbprint, certs in thumbprint_duplicates.items():
            print(f"\n   📋 Thumbprint: {thumbprint[:16]}...")
            print(f"      Count: {len(certs)} certificates")
            for i, cert in enumerate(certs, 1):
                print(f"      {i}. ID: {cert['id']}, CN: {cert['cn']}, Serial: {cert['serial'][:16]}...")
                if cert['proxied']:
                    print(f"         Marked as proxied: {cert['proxy_info']}")
    
    # Check for exact serial duplicates
    serial_duplicates = {k: v for k, v in groups['by_serial'].items() if len(v) > 1}
    if serial_duplicates:
        print(f"\n🚨 EXACT DUPLICATES (same serial): {len(serial_duplicates)} groups")
        for serial, certs in serial_duplicates.items():
            print(f"\n   📋 Serial: {serial[:16]}...")
            print(f"      Count: {len(certs)} certificates")
            for i, cert in enumerate(certs, 1):
                print(f"      {i}. ID: {cert['id']}, CN: {cert['cn']}, Thumbprint: {cert['thumbprint'][:16]}...")
                if cert['proxied']:
                    print(f"         Marked as proxied: {cert['proxy_info']}")
    
    # Check for logical duplicates (same CN + expiry + issuer)
    logical_duplicates = {k: v for k, v in groups['by_issuer_cn_expiry'].items() if len(v) > 1}
    if logical_duplicates:
        print(f"\n🔍 LOGICAL DUPLICATES (same issuer + CN + expiry): {len(logical_duplicates)} groups")
        for group_key, certs in logical_duplicates.items():
            issuer_cn, cn, valid_until = group_key.split('|')
            print(f"\n   📋 CN: {cn}")
            print(f"      Issuer: {issuer_cn}")
            print(f"      Expiry: {valid_until}")
            print(f"      Count: {len(certs)} certificates")
            
            # Check if they have different serials/thumbprints
            serials = set(cert['serial'] for cert in certs)
            thumbprints = set(cert['thumbprint'] for cert in certs)
            
            if len(serials) > 1:
                print(f"      ⚠️  Different serial numbers: {len(serials)} unique")
            if len(thumbprints) > 1:
                print(f"      ⚠️  Different thumbprints: {len(thumbprints)} unique")
            
            for i, cert in enumerate(certs, 1):
                print(f"      {i}. ID: {cert['id']}, Serial: {cert['serial'][:16]}..., Thumbprint: {cert['thumbprint'][:16]}...")
                if cert['proxied']:
                    print(f"         Marked as proxied: {cert['proxy_info']}")
    
    # Check for simple CN + expiry duplicates
    cn_expiry_duplicates = {k: v for k, v in groups['by_cn_expiry'].items() if len(v) > 1}
    if cn_expiry_duplicates:
        print(f"\n🔍 SIMPLE DUPLICATES (same CN + expiry): {len(cn_expiry_duplicates)} groups")
        for group_key, certs in cn_expiry_duplicates.items():
            cn, valid_until = group_key.split('|')
            print(f"\n   📋 CN: {cn}")
            print(f"      Expiry: {valid_until}")
            print(f"      Count: {len(certs)} certificates")
            
            # Check issuers
            issuers = set(cert['issuer_cn'] for cert in certs if cert['issuer_cn'])
            if len(issuers) > 1:
                print(f"      ⚠️  Different issuers: {', '.join(issuers)}")
            
            for i, cert in enumerate(certs, 1):
                print(f"      {i}. ID: {cert['id']}, Issuer: {cert['issuer_cn']}, Serial: {cert['serial'][:16]}...")
                if cert['proxied']:
                    print(f"         Marked as proxied: {cert['proxy_info']}")
    
    return {
        'thumbprint_duplicates': thumbprint_duplicates,
        'serial_duplicates': serial_duplicates,
        'logical_duplicates': logical_duplicates,
        'cn_expiry_duplicates': cn_expiry_duplicates
    }

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Find certificate duplicates in the database",
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
    print("🔍 Certificate Duplicate Finder")
    print("=" * 60)
    print(f"Database path: {db_path}")
    print("=" * 60)
    
    # Find duplicate groups
    groups = find_duplicate_groups(str(db_path))
    
    # Analyze duplicates
    duplicates = analyze_duplicates(groups)
    
    # Summary
    total_duplicates = (len(duplicates['thumbprint_duplicates']) + 
                       len(duplicates['serial_duplicates']) + 
                       len(duplicates['logical_duplicates']) + 
                       len(duplicates['cn_expiry_duplicates']))
    
    print(f"\n" + "=" * 60)
    print("📊 Summary:")
    print(f"   Total duplicate groups found: {total_duplicates}")
    print(f"   Exact thumbprint duplicates: {len(duplicates['thumbprint_duplicates'])}")
    print(f"   Exact serial duplicates: {len(duplicates['serial_duplicates'])}")
    print(f"   Logical duplicates: {len(duplicates['logical_duplicates'])}")
    print(f"   Simple CN+expiry duplicates: {len(duplicates['cn_expiry_duplicates'])}")
    print("=" * 60)
    
    if total_duplicates == 0:
        print("✅ No duplicates found!")
    else:
        print("💡 Consider running deduplication if appropriate duplicates are found.")
    
    print("✅ Analysis complete!")

if __name__ == "__main__":
    main()
