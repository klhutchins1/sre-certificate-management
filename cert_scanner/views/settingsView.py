import streamlit as st
from ..settings import settings
import os
from pathlib import Path
import shutil
from datetime import datetime
import json
import glob

def list_backups():
    """List all available backups with their details"""
    backup_dir = Path(settings.get("paths.backups"))
    if not backup_dir.exists():
        return []
    
    backups = []
    for manifest_file in backup_dir.glob("backup_*.json"):
        try:
            with open(manifest_file, 'r') as f:
                manifest = json.load(f)
                # Add manifest filename for reference
                manifest['manifest_file'] = str(manifest_file)
                backups.append(manifest)
        except Exception:
            continue
    
    # Sort backups by timestamp, newest first
    return sorted(backups, key=lambda x: x['timestamp'], reverse=True)

def restore_backup(manifest):
    """Restore database and config from a backup"""
    try:
        # Verify backup files exist
        config_file = Path(manifest['config'])
        if not config_file.exists():
            return False, "Config backup file not found"
        
        # Create backup of current state before restore
        current_backup_success, _ = create_backup()
        if not current_backup_success:
            return False, "Failed to backup current state before restore"
        
        # Restore config
        shutil.copy2(config_file, "config.yaml")
        
        # Restore database if it exists in backup
        if manifest['database']:
            db_file = Path(manifest['database'])
            if db_file.exists():
                db_path = Path(settings.get("paths.database"))
                # Ensure target directory exists
                db_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(db_file, db_path)
        
        return True, "Backup restored successfully"
    except Exception as e:
        return False, f"Failed to restore backup: {str(e)}"

def create_backup():
    """Create a backup of database and configuration"""
    try:
        # Ensure backup directory exists
        backup_dir = Path(settings.get("paths.backups"))
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Create timestamp for backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Backup database
        db_path = Path(settings.get("paths.database"))
        if db_path.exists():
            db_backup = backup_dir / f"certificates_{timestamp}.db"
            shutil.copy2(db_path, db_backup)
        
        # Backup config
        config_backup = backup_dir / f"config_{timestamp}.yaml"
        shutil.copy2("config.yaml", config_backup)
        
        # Create backup manifest
        manifest = {
            "timestamp": timestamp,
            "database": str(db_backup) if db_path.exists() else None,
            "config": str(config_backup),
            "created": datetime.now().isoformat()
        }
        
        manifest_file = backup_dir / f"backup_{timestamp}.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return True, f"Backup created successfully at {backup_dir}"
    except Exception as e:
        return False, f"Failed to create backup: {str(e)}"

def render_settings_view():
    st.title("Settings")
    
    # Backup and Restore section
    st.subheader("Backup & Restore")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Create Backup")
        if st.button("Create New Backup", help="Create a backup of database and configuration"):
            success, message = create_backup()
            if success:
                st.success(message)
            else:
                st.error(message)
    
    with col2:
        st.markdown("#### Restore Backup")
        backups = list_backups()
        if not backups:
            st.info("No backups found")
        else:
            # Create a list of backup options with formatted timestamps
            backup_options = {
                f"Backup from {datetime.fromisoformat(b['created']).strftime('%Y-%m-%d %H:%M:%S')}": b 
                for b in backups
            }
            
            selected_backup = st.selectbox(
                "Select Backup to Restore",
                options=list(backup_options.keys()),
                help="Choose a backup to restore from"
            )
            
            if st.button("Restore Selected Backup", help="Restore the selected backup"):
                if st.warning("This will overwrite current settings and database. Are you sure?"):
                    success, message = restore_backup(backup_options[selected_backup])
                    if success:
                        st.success(message)
                        st.warning("Please restart the application for changes to take effect")
                    else:
                        st.error(message)
    
    st.markdown("---")
    
    # Create tabs for different settings categories
    tabs = st.tabs(["Paths", "Scanning", "Alerts", "Exports"])
    
    with tabs[0]:  # Paths
        st.header("Database & Backup Paths")
        
        db_path = st.text_input(
            "Database Path",
            value=settings.get("paths.database"),
            help="Path where the certificate database is stored"
        )
        backup_path = st.text_input(
            "Backups Directory",
            value=settings.get("paths.backups"),
            help="Directory where backups will be stored"
        )
        
        if st.button("Save Paths"):
            settings.update("paths.database", db_path)
            settings.update("paths.backups", backup_path)
            if settings.save():
                st.success("Paths updated successfully!")
            else:
                st.error("Failed to save path settings")
    
    with tabs[1]:  # Scanning
        st.header("Scanning Settings")
        
        # Internal scanning profile
        st.subheader("Internal Scanning Profile")
        internal_rate = st.number_input(
            "Rate Limit (requests/minute)",
            min_value=1,
            value=settings.get("scanning.internal.rate_limit"),
            key="internal_rate"
        )
        internal_delay = st.number_input(
            "Delay Between Requests (seconds)",
            min_value=0,
            value=settings.get("scanning.internal.delay"),
            key="internal_delay"
        )
        internal_domains = st.text_area(
            "Internal Domains (one per line)",
            value="\n".join(settings.get("scanning.internal.domains", [])),
            help="List of internal domains to scan",
            key="internal_domains"
        )
        
        # External scanning profile
        st.subheader("External Scanning Profile")
        external_rate = st.number_input(
            "Rate Limit (requests/minute)",
            min_value=1,
            value=settings.get("scanning.external.rate_limit"),
            key="external_rate"
        )
        external_delay = st.number_input(
            "Delay Between Requests (seconds)",
            min_value=0,
            value=settings.get("scanning.external.delay"),
            key="external_delay"
        )
        external_domains = st.text_area(
            "External Domains (one per line)",
            value="\n".join(settings.get("scanning.external.domains", [])),
            help="List of external domains to scan",
            key="external_domains"
        )
        
        if st.button("Save Scanning Settings"):
            # Update internal settings
            settings.update("scanning.internal.rate_limit", internal_rate)
            settings.update("scanning.internal.delay", internal_delay)
            settings.update("scanning.internal.domains", [d.strip() for d in internal_domains.split("\n") if d.strip()])
            
            # Update external settings
            settings.update("scanning.external.rate_limit", external_rate)
            settings.update("scanning.external.delay", external_delay)
            settings.update("scanning.external.domains", [d.strip() for d in external_domains.split("\n") if d.strip()])
            
            if settings.save():
                st.success("Scanning settings updated successfully!")
            else:
                st.error("Failed to save scanning settings")
    
    with tabs[2]:  # Alerts
        st.header("Alert Settings")
        
        # Expiry warnings
        st.subheader("Certificate Expiry Warnings")
        expiry_warnings = settings.get("alerts.expiry_warnings", [])
        
        col1, col2 = st.columns(2)
        with col1:
            days_90 = st.number_input("Info Alert (days)", value=90, min_value=1)
            days_30 = st.number_input("Warning Alert (days)", value=30, min_value=1)
            days_7 = st.number_input("Critical Alert (days)", value=7, min_value=1)
        
        with col2:
            st.write("Alert Levels")
            st.info("Info Alert")
            st.warning("Warning Alert")
            st.error("Critical Alert")
        
        # Failed scans
        st.subheader("Failed Scan Alerts")
        consecutive_failures = st.number_input(
            "Consecutive Failures Before Alert",
            min_value=1,
            value=settings.get("alerts.failed_scans.consecutive_failures"),
        )
        
        if st.button("Save Alert Settings"):
            # Update expiry warnings
            new_expiry_warnings = [
                {"days": days_90, "level": "info"},
                {"days": days_30, "level": "warning"},
                {"days": days_7, "level": "critical"}
            ]
            settings.update("alerts.expiry_warnings", new_expiry_warnings)
            settings.update("alerts.failed_scans.consecutive_failures", consecutive_failures)
            
            if settings.save():
                st.success("Alert settings updated successfully!")
            else:
                st.error("Failed to save alert settings")
    
    with tabs[3]:  # Exports
        st.header("Export Settings")
        
        # PDF settings
        st.subheader("PDF Export Settings")
        pdf_template = st.text_input(
            "PDF Template Path",
            value=settings.get("exports.pdf.template"),
            help="Path to the HTML template for PDF reports"
        )
        pdf_logo = st.text_input(
            "Logo Path",
            value=settings.get("exports.pdf.logo"),
            help="Path to the logo image for PDF reports"
        )
        
        # CSV settings
        st.subheader("CSV Export Settings")
        csv_delimiter = st.text_input(
            "CSV Delimiter",
            value=settings.get("exports.csv.delimiter"),
            help="Character used to separate values in CSV exports"
        )
        csv_encoding = st.text_input(
            "CSV Encoding",
            value=settings.get("exports.csv.encoding"),
            help="Character encoding for CSV files"
        )
        
        if st.button("Save Export Settings"):
            settings.update("exports.pdf.template", pdf_template)
            settings.update("exports.pdf.logo", pdf_logo)
            settings.update("exports.csv.delimiter", csv_delimiter)
            settings.update("exports.csv.encoding", csv_encoding)
            
            if settings.save():
                st.success("Export settings updated successfully!")
            else:
                st.error("Failed to save export settings") 