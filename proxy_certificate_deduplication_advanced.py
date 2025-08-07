#!/usr/bin/env python3
"""
Advanced Proxy Certificate Deduplication Script

This script identifies and merges duplicate proxy certificates, including handling
certificate bindings and other related data to ensure data integrity.

Usage:
    python proxy_certificate_deduplication_advanced.py [--dry-run] [--db-path PATH]
    
Example:
    python proxy_certificate_deduplication_advanced.py --dry-run
    python proxy_certificate_deduplication_advanced.py --db-path data/certificates.db
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

def is_proxy_ca(issuer_cn, settings):
    """Check if the issuer is a known proxy CA."""
    if not issuer_cn:
        return False
    
    # Get proxy CA subjects from config
    proxy_subjects = settings.get("proxy_detection.ca_subjects", [])
    if not isinstance(proxy_subjects, list):
        proxy_subjects = []
    
    # Check if issuer matches any proxy CA subjects
    issuer_lower = issuer_cn.lower()
    for proxy_subject in proxy_subjects:
        if proxy_subject.lower() in issuer_lower:
            return True
    
    # Check for common proxy indicators
    proxy_indicators = ['proxy', 'corporate', 'internal', 'firewall', 'gateway', 'bluecoat', 'zscaler']
    for indicator in proxy_indicators:
        if indicator in issuer_lower:
            return True
    
    return False

def get_certificate_bindings(db_path, certificate_id):
    """Get all bindings for a specific certificate."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, host_id, host_ip_id, application_id, port, binding_type, 
               platform, site_name, site_id, binding_order, parent_binding_id, 
               last_seen, manually_added
        FROM certificate_bindings 
        WHERE certificate_id = ?
    """, (certificate_id,))
    
    bindings = cursor.fetchall()
    conn.close()
    
    return bindings

def get_certificate_scans(db_path, certificate_id):
    """Get all scans for a specific certificate."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, host_id, scan_date, status, port
        FROM certificate_scans 
        WHERE certificate_id = ?
    """, (certificate_id,))
    
    scans = cursor.fetchall()
    conn.close()
    
    return scans

def get_certificate_tracking(db_path, certificate_id):
    """Get all tracking entries for a specific certificate."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, change_number, planned_change_date, notes, status, 
               created_at, updated_at
        FROM certificate_tracking 
        WHERE certificate_id = ?
    """, (certificate_id,))
    
    tracking = cursor.fetchall()
    conn.close()
    
    return tracking

def find_proxy_certificate_groups(db_path, settings):
    """
    Find groups of certificates that are likely the same proxy certificate.
    
    Returns:
        list: Groups of certificate IDs that should be merged
    """
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
    
    # Group certificates by proxy characteristics
    proxy_groups = defaultdict(list)
    
    for cert in certificates:
        (cert_id, serial, thumbprint, cn, valid_from, valid_until, 
         issuer, subject, proxied, proxy_info, created_at) = cert
        
        # Parse issuer to get CA name
        issuer_cn = parse_issuer_json(issuer)
        
        # Check if this is a proxy CA
        if is_proxy_ca(issuer_cn, settings):
            # Create a grouping key based on common characteristics
            # This helps identify certificates that are essentially the same
            group_key = f"{issuer_cn}|{cn}|{valid_until}"
            
            proxy_groups[group_key].append({
                'id': cert_id,
                'serial': serial,
                'thumbprint': thumbprint,
                'cn': cn,
                'issuer_cn': issuer_cn,
                'valid_from': valid_from,
                'valid_until': valid_until,
                'proxied': proxied,
                'proxy_info': proxy_info,
                'created_at': created_at
            })
    
    # Filter to only groups with multiple certificates
    duplicate_groups = {key: certs for key, certs in proxy_groups.items() 
                       if len(certs) > 1}
    
    return duplicate_groups

def analyze_duplicate_groups(duplicate_groups, db_path):
    """Analyze duplicate groups and provide detailed statistics."""
    total_duplicates = 0
    total_certificates = 0
    total_bindings = 0
    total_scans = 0
    total_tracking = 0
    
    print(f"\n📊 Found {len(duplicate_groups)} groups of duplicate proxy certificates:")
    
    for group_key, certs in duplicate_groups.items():
        issuer_cn, cn, valid_until = group_key.split('|')
        print(f"\n🔍 Group: {cn} (CA: {issuer_cn})")
        print(f"   Expiration: {valid_until}")
        print(f"   Duplicates: {len(certs)} certificates")
        
        group_bindings = 0
        group_scans = 0
        group_tracking = 0
        
        # Show the certificates in this group
        for i, cert in enumerate(certs, 1):
            print(f"   {i}. ID: {cert['id']}, Serial: {cert['serial'][:16]}..., "
                  f"Created: {cert['created_at']}")
            
            # Get related data counts
            bindings = get_certificate_bindings(db_path, cert['id'])
            scans = get_certificate_scans(db_path, cert['id'])
            tracking = get_certificate_tracking(db_path, cert['id'])
            
            group_bindings += len(bindings)
            group_scans += len(scans)
            group_tracking += len(tracking)
            
            print(f"      Bindings: {len(bindings)}, Scans: {len(scans)}, Tracking: {len(tracking)}")
            
            if cert['proxied']:
                print(f"      Already marked as proxied: {cert['proxy_info']}")
        
        print(f"   Group totals - Bindings: {group_bindings}, Scans: {group_scans}, Tracking: {group_tracking}")
        
        total_duplicates += len(certs) - 1  # -1 because one is the "original"
        total_certificates += len(certs)
        total_bindings += group_bindings
        total_scans += group_scans
        total_tracking += group_tracking
    
    print(f"\n📈 Summary:")
    print(f"   Total certificates in duplicate groups: {total_certificates}")
    print(f"   Total duplicates that can be removed: {total_duplicates}")
    print(f"   Total bindings to migrate: {total_bindings}")
    print(f"   Total scans to migrate: {total_scans}")
    print(f"   Total tracking entries to migrate: {total_tracking}")
    print(f"   Space savings: ~{total_duplicates * 0.5:.1f} KB")
    
    return total_duplicates, total_bindings, total_scans, total_tracking

def merge_proxy_certificate_group_advanced(db_path, group_key, certificates, dry_run=True):
    """
    Merge a group of duplicate proxy certificates with all related data.
    
    Args:
        db_path: Database path
        group_key: Group identifier
        certificates: List of certificate dictionaries
        dry_run: If True, only show what would be done
    
    Returns:
        bool: True if successful
    """
    if len(certificates) < 2:
        return True
    
    # Sort by creation date - keep the oldest one
    sorted_certs = sorted(certificates, key=lambda x: x['created_at'])
    keep_cert = sorted_certs[0]  # Oldest certificate
    remove_certs = sorted_certs[1:]  # Newer duplicates
    
    issuer_cn, cn, valid_until = group_key.split('|')
    
    print(f"\n🔄 Merging group: {cn} (CA: {issuer_cn})")
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
        
        # Update the certificate we're keeping to ensure it's marked as proxied
        if not keep_cert['proxied']:
            proxy_info = f"Detected as proxy certificate: CA '{issuer_cn}' - merged from {len(remove_certs)} duplicates"
            cursor.execute("""
                UPDATE certificates 
                SET proxied = 1, proxy_info = ?
                WHERE id = ?
            """, (proxy_info, keep_cert['id']))
            print(f"   ✅ Marked certificate {keep_cert['id']} as proxied")
        
        # Migrate related data from duplicates to the certificate we're keeping
        total_migrated = 0
        
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
    """Main function to handle command line arguments and run deduplication."""
    parser = argparse.ArgumentParser(
        description="Advanced deduplication of proxy certificates with related data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python proxy_certificate_deduplication_advanced.py --dry-run
  python proxy_certificate_deduplication_advanced.py --db-path data/certificates.db
  python proxy_certificate_deduplication_advanced.py --dry-run --db-path \\\\server\\share\\certificates.db
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
        help='Force execution without confirmation (use with caution)'
    )
    
    args = parser.parse_args()
    
    # Get database path from config or command line
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
    
    # Load settings for proxy detection
    config = load_config()
    settings = config or {}
    
    print("=" * 60)
    print("🔧 Advanced Proxy Certificate Deduplication Tool")
    print("=" * 60)
    print(f"Database path: {db_path}")
    print(f"Dry run: {args.dry_run}")
    print(f"Force: {args.force}")
    print("=" * 60)
    
    # Find duplicate groups
    print("🔍 Scanning for duplicate proxy certificates...")
    duplicate_groups = find_proxy_certificate_groups(str(db_path), settings)
    
    if not duplicate_groups:
        print("✅ No duplicate proxy certificates found!")
        sys.exit(0)
    
    # Analyze duplicates
    total_duplicates, total_bindings, total_scans, total_tracking = analyze_duplicate_groups(duplicate_groups, str(db_path))
    
    if args.dry_run:
        print(f"\n💡 This was a dry run. To actually merge duplicates, run without --dry-run")
        sys.exit(0)
    
    # Ask for confirmation
    if not args.force:
        print(f"\n⚠️  This will:")
        print(f"   - Remove {total_duplicates} duplicate certificates")
        print(f"   - Migrate {total_bindings} certificate bindings")
        print(f"   - Migrate {total_scans} certificate scans")
        print(f"   - Migrate {total_tracking} tracking entries")
        response = input("Do you want to continue? (y/N): ")
        if response.lower() not in ['y', 'yes']:
            print("Operation cancelled.")
            sys.exit(0)
    
    # Perform the merges
    print(f"\n🔄 Starting advanced deduplication...")
    success_count = 0
    total_groups = len(duplicate_groups)
    
    for group_key, certificates in duplicate_groups.items():
        success = merge_proxy_certificate_group_advanced(str(db_path), group_key, certificates, dry_run=False)
        if success:
            success_count += 1
    
    print(f"\n" + "=" * 60)
    print("✅ Advanced deduplication completed!")
    print("=" * 60)
    print(f"Successfully processed: {success_count}/{total_groups} groups")
    print(f"Removed approximately: {total_duplicates} duplicate certificates")
    print(f"Migrated approximately: {total_bindings + total_scans + total_tracking} related records")
    
    if success_count == total_groups:
        print("🎉 All duplicate proxy certificates have been merged!")
    else:
        print("⚠️  Some groups could not be processed. Check the logs above.")
    
    sys.exit(0 if success_count == total_groups else 1)

if __name__ == "__main__":
    main()

