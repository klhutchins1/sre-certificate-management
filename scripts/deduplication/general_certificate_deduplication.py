#!/usr/bin/env python3
"""
General Certificate Deduplication Script

This script identifies and merges duplicate certificates based on logical identity,
regardless of whether they're proxy certificates or legitimate duplicates.

Usage:
    python general_certificate_deduplication.py [--dry-run] [--db-path PATH]
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
        # Script is in scripts/deduplication/, so go up 3 levels to reach project root
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
        
        cn = (issuer_data.get('commonName') or 
              issuer_data.get('CN') or 
              issuer_data.get('common_name'))
        
        return cn
    except:
        return None

def find_duplicate_certificate_groups(db_path):
    """Find groups of certificates that are logical duplicates."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all certificates
    cursor.execute("""
        SELECT id, serial_number, thumbprint, common_name, valid_from, valid_until, 
               issuer, subject, proxied, proxy_info, created_at
        FROM certificates
        ORDER BY created_at
    """)
    
    certificates = cursor.fetchall()
    conn.close()
    
    print(f"📊 Found {len(certificates)} total certificates in database")
    
    # Group certificates by logical identity
    exact_duplicate_groups = defaultdict(list)  # Same CN + issuer + expiry
    renewal_groups = defaultdict(list)          # Same CN + issuer, different expiry
    
    for cert in certificates:
        (cert_id, serial, thumbprint, cn, valid_from, valid_until, 
         issuer, subject, proxied, proxy_info, created_at) = cert
        
        issuer_cn = parse_issuer_json(issuer)
        
        if cn and issuer_cn and valid_until:
            # Exact duplicate key: same CN + issuer + expiry
            exact_key = f"{issuer_cn}|{cn}|{valid_until}"
            exact_duplicate_groups[exact_key].append({
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
            
            # Renewal group key: same CN + issuer (different expiry dates)
            renewal_key = f"{issuer_cn}|{cn}"
            renewal_groups[renewal_key].append({
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
    
    # Filter to only groups with duplicates
    exact_duplicates = {key: certs for key, certs in exact_duplicate_groups.items() 
                       if len(certs) > 1}
    
    return exact_duplicates, renewal_groups

def get_certificate_related_data(db_path, certificate_id):
    """Get all related data for a certificate."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get bindings
    cursor.execute("""
        SELECT id FROM certificate_bindings WHERE certificate_id = ?
    """, (certificate_id,))
    bindings = cursor.fetchall()
    
    # Get scans
    cursor.execute("""
        SELECT id FROM certificate_scans WHERE certificate_id = ?
    """, (certificate_id,))
    scans = cursor.fetchall()
    
    # Get tracking
    cursor.execute("""
        SELECT id FROM certificate_tracking WHERE certificate_id = ?
    """, (certificate_id,))
    tracking = cursor.fetchall()
    
    conn.close()
    
    return len(bindings), len(scans), len(tracking)

def analyze_duplicate_groups(exact_duplicates, renewal_groups, db_path):
    """Analyze and display duplicate groups."""
    print(f"\n🔍 Duplicate Analysis:")
    
    # Exact duplicates (same CN + issuer + expiry)
    if exact_duplicates:
        print(f"\n🚨 EXACT DUPLICATES (same CN + issuer + expiry): {len(exact_duplicates)} groups")
        total_exact_dupes = 0
        
        for group_key, certs in exact_duplicates.items():
            issuer_cn, cn, valid_until = group_key.split('|')
            print(f"\n   📋 {cn}")
            print(f"      Issuer: {issuer_cn}")
            print(f"      Expiry: {valid_until}")
            print(f"      Duplicates: {len(certs)} certificates")
            
            # Check for different serials/thumbprints (indicating true duplicates vs. database errors)
            serials = set(cert['serial'] for cert in certs)
            thumbprints = set(cert['thumbprint'] for cert in certs)
            
            if len(serials) > 1:
                print(f"      ⚠️  Different serial numbers: {len(serials)} unique")
            if len(thumbprints) > 1:
                print(f"      ⚠️  Different thumbprints: {len(thumbprints)} unique")
            
            for i, cert in enumerate(certs, 1):
                bindings, scans, tracking = get_certificate_related_data(db_path, cert['id'])
                print(f"      {i}. ID: {cert['id']}, Serial: {cert['serial'][:16]}...")
                print(f"         Created: {cert['created_at']}")
                print(f"         Related data: {bindings} bindings, {scans} scans, {tracking} tracking")
                if cert['proxied']:
                    print(f"         Marked as proxied: {cert['proxy_info']}")
            
            total_exact_dupes += len(certs) - 1  # -1 because we keep one
        
        print(f"\n   📈 Total exact duplicates that can be removed: {total_exact_dupes}")
    
    # Show renewal groups for information (not necessarily duplicates)
    renewal_duplicates = {key: certs for key, certs in renewal_groups.items() 
                         if len(certs) > 1}
    
    if renewal_duplicates:
        print(f"\n📊 CERTIFICATE RENEWALS (same CN + issuer): {len(renewal_duplicates)} groups")
        for group_key, certs in renewal_duplicates.items():
            issuer_cn, cn = group_key.split('|')
            if len(certs) > 3:  # Only show groups with many certificates
                print(f"\n   📋 {cn} (Issuer: {issuer_cn})")
                print(f"      Total certificates: {len(certs)}")
                
                # Sort by expiry date
                sorted_certs = sorted(certs, key=lambda x: x['valid_until'])
                
                print(f"      Oldest: {sorted_certs[0]['valid_until']}")
                print(f"      Newest: {sorted_certs[-1]['valid_until']}")
    
    return exact_duplicates

def merge_certificate_duplicates(db_path, group_key, certificates, dry_run=True):
    """Merge duplicate certificates, keeping the oldest one."""
    if len(certificates) < 2:
        return True
    
    # Sort by creation date - keep the oldest one
    sorted_certs = sorted(certificates, key=lambda x: x['created_at'])
    keep_cert = sorted_certs[0]
    remove_certs = sorted_certs[1:]
    
    issuer_cn, cn, valid_until = group_key.split('|')
    
    print(f"\n🔄 Merging duplicates: {cn}")
    print(f"   Keeping: ID {keep_cert['id']} (created: {keep_cert['created_at']})")
    print(f"   Removing: {len(remove_certs)} duplicates")
    
    if dry_run:
        print("   [DRY RUN] - No changes made")
        return True
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Start transaction
        cursor.execute("BEGIN TRANSACTION")
        
        total_migrated = 0
        
        # Migrate related data from duplicates to the certificate we're keeping
        for remove_cert in remove_certs:
            # Migrate certificate bindings
            cursor.execute("""
                UPDATE certificate_bindings 
                SET certificate_id = ? 
                WHERE certificate_id = ?
            """, (keep_cert['id'], remove_cert['id']))
            bindings_migrated = cursor.rowcount
            
            # Migrate certificate scans
            cursor.execute("""
                UPDATE certificate_scans 
                SET certificate_id = ? 
                WHERE certificate_id = ?
            """, (keep_cert['id'], remove_cert['id']))
            scans_migrated = cursor.rowcount
            
            # Migrate certificate tracking
            cursor.execute("""
                UPDATE certificate_tracking 
                SET certificate_id = ? 
                WHERE certificate_id = ?
            """, (keep_cert['id'], remove_cert['id']))
            tracking_migrated = cursor.rowcount
            
            total_migrated += bindings_migrated + scans_migrated + tracking_migrated
            
            print(f"   📦 Migrated from cert {remove_cert['id']}: "
                  f"{bindings_migrated} bindings, {scans_migrated} scans, {tracking_migrated} tracking")
        
        # Remove the duplicate certificates
        remove_ids = [cert['id'] for cert in remove_certs]
        placeholders = ','.join(['?' for _ in remove_ids])
        
        cursor.execute(f"""
            DELETE FROM certificates 
            WHERE id IN ({placeholders})
        """, remove_ids)
        
        deleted_count = cursor.rowcount
        
        # Commit transaction
        cursor.execute("COMMIT")
        conn.close()
        
        print(f"   ✅ Removed {deleted_count} duplicate certificates")
        print(f"   ✅ Migrated {total_migrated} related records")
        return True
        
    except Exception as e:
        print(f"   ❌ Error merging certificates: {e}")
        if 'conn' in locals():
            cursor.execute("ROLLBACK")
            conn.close()
        return False

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="General certificate deduplication for all duplicate types",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python general_certificate_deduplication.py --dry-run
  python general_certificate_deduplication.py --db-path data/certificates.db
        """
    )
    
    parser.add_argument(
        '--db-path',
        type=str,
        help='Path to the SQLite database file (default: from config.yaml)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force execution without confirmation'
    )
    
    args = parser.parse_args()
    
    # Get database path
    if args.db_path:
        db_path = Path(args.db_path).resolve()
    else:
        db_path = get_database_path_from_config()
        if db_path:
            db_path = Path(db_path).resolve()
        else:
            print("❌ Error: No database path specified and not found in config.yaml")
            sys.exit(1)
    
    if not os.path.exists(db_path):
        print(f"❌ Error: Database file not found at {db_path}")
        sys.exit(1)
    
    print("=" * 60)
    print("🔧 General Certificate Deduplication Tool")
    print("=" * 60)
    print(f"Database path: {db_path}")
    print(f"Dry run: {args.dry_run}")
    print("=" * 60)
    
    # Find duplicates
    print("🔍 Scanning for duplicate certificates...")
    exact_duplicates, renewal_groups = find_duplicate_certificate_groups(str(db_path))
    
    if not exact_duplicates:
        print("✅ No exact duplicate certificates found!")
        return
    
    # Analyze duplicates
    duplicate_groups = analyze_duplicate_groups(exact_duplicates, renewal_groups, str(db_path))
    
    if args.dry_run:
        print(f"\n💡 This was a dry run. To actually merge duplicates, run without --dry-run")
        return
    
    # Calculate totals
    total_duplicates = sum(len(certs) - 1 for certs in duplicate_groups.values())
    
    # Ask for confirmation
    if not args.force:
        print(f"\n⚠️  This will remove {total_duplicates} duplicate certificates.")
        response = input("Do you want to continue? (y/N): ")
        if response.lower() not in ['y', 'yes']:
            print("Operation cancelled.")
            return
    
    # Perform the merges
    print(f"\n🔄 Starting deduplication...")
    success_count = 0
    total_groups = len(duplicate_groups)
    
    for group_key, certificates in duplicate_groups.items():
        success = merge_certificate_duplicates(str(db_path), group_key, certificates, dry_run=False)
        if success:
            success_count += 1
    
    print(f"\n" + "=" * 60)
    print("✅ Certificate deduplication completed!")
    print("=" * 60)
    print(f"Successfully processed: {success_count}/{total_groups} groups")
    print(f"Removed approximately: {total_duplicates} duplicate certificates")
    
    if success_count == total_groups:
        print("🎉 All duplicate certificates have been merged!")
    else:
        print("⚠️  Some groups could not be processed. Check the logs above.")

if __name__ == "__main__":
    main()
