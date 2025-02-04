import streamlit as st
from ..settings import Settings
import os
from pathlib import Path
import shutil
from datetime import datetime
import json
import glob
import logging
import yaml
import time
from ..db import SessionManager
from ..exports import (
    export_certificates_to_csv,
    export_certificates_to_pdf,
    export_hosts_to_csv,
    export_hosts_to_pdf
)
from ..static.styles import load_warning_suppression, load_css


logger = logging.getLogger(__name__)

def list_backups():
    """List all available backups with their details"""
    try:
        settings = Settings()
        backup_dir = Path(settings.get("paths.backups", "data/backups"))
        if not backup_dir.exists():
            backup_dir.mkdir(parents=True, exist_ok=True)
        
        backups = []
        # List all files in backup directory for debugging
        all_files = list(backup_dir.glob("*"))
        logger.debug(f"All files in backup directory: {[str(f) for f in all_files]}")
        
        # Find all manifest files
        manifest_files = list(backup_dir.glob("backup_*.json"))
        logger.debug(f"Found manifest files: {[str(f) for f in manifest_files]}")
        
        for manifest_file in manifest_files:
            try:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                    # Add manifest filename for reference
                    manifest['manifest_file'] = str(manifest_file)
                    # Ensure both timestamp and created fields exist
                    if 'created' not in manifest and 'timestamp' in manifest:
                        manifest['created'] = datetime.strptime(
                            manifest['timestamp'], 
                            "%Y%m%d_%H%M%S"
                        ).isoformat()
                    backups.append(manifest)
            except Exception as e:
                logger.error(f"Error reading manifest {manifest_file}: {str(e)}")
                continue
        
        # Sort backups by created timestamp, newest first
        sorted_backups = sorted(backups, key=lambda x: x.get('created', x.get('timestamp', '')), reverse=True)
        logger.debug(f"Returning {len(sorted_backups)} backups")
        return sorted_backups
        
    except Exception as e:
        logger.error(f"Error listing backups: {str(e)}")
        return []

def restore_backup(manifest):
    """Restore database and config from a backup"""
    try:
        settings = Settings()
        logger.info("Starting database restore process")
        logger.info(f"Manifest contents: {manifest}")
        
        # Verify backup files exist
        config_file = Path(manifest.get('config', ''))
        if not config_file.exists():
            logger.error(f"Config backup file not found: {config_file}")
            return False, "Config backup file not found"
        
        # Restore database if it exists in backup
        db_file = manifest.get('database')
        if db_file:
            logger.info(f"Database backup file found in manifest: {db_file}")
            db_file = Path(db_file)
            logger.info(f"Restoring from backup file: {db_file}")
            
            if not db_file.exists():
                logger.error(f"Database backup file not found: {db_file}")
                return False, "Database backup file not found"
                
            db_path = Path(settings.get("paths.database", "data/certificates.db"))
            logger.info(f"Target database path: {db_path}")
            
            # Ensure target directory exists
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                # Close all existing database connections
                from sqlalchemy import create_engine
                from sqlalchemy.orm import Session, sessionmaker
                from ..models import Base, Certificate
                
                # Drop all tables and recreate them
                engine = create_engine(f"sqlite:///{db_path}")
                logger.info("Closing all existing database sessions")
                Session.close_all()
                
                logger.info("Dropping all tables")
                Base.metadata.drop_all(engine)
                engine.dispose()
                
                # Wait a moment for connections to fully close
                time.sleep(0.1)
                
                logger.info("Copying backup file")
                if db_path.exists():
                    logger.info("Removing existing database file")
                    db_path.unlink()
                shutil.copy2(db_file, db_path)
                
                # Create a new engine and ensure tables exist
                logger.info("Creating tables in restored database")
                engine = create_engine(f"sqlite:///{db_path}")
                Base.metadata.create_all(engine)
                
                # Verify the restored database
                with Session(engine) as session:
                    cert_count = session.query(Certificate).count()
                    logger.info(f"Found {cert_count} certificates in restored database")
                
                engine.dispose()
                logger.info("Database restore completed")
                
            except Exception as e:
                logger.error(f"Failed to restore database: {str(e)}")
                return False, f"Failed to restore database: {str(e)}"
        
        # Restore config
        try:
            logger.info("Restoring configuration")
            # First verify the backup config is valid YAML
            with open(config_file, 'r') as f:
                backup_config = yaml.safe_load(f)
            if not isinstance(backup_config, dict):
                logger.error("Invalid backup configuration format")
                return False, "Invalid backup configuration format"
            
            # Update settings with backup config
            settings._config = backup_config.copy()
            settings.save()  # This will write to config.yaml
            logger.info("Configuration restored successfully")
            
            return True, "Backup restored successfully"
        except Exception as e:
            logger.error(f"Failed to restore config: {str(e)}")
            return False, f"Failed to restore config: {str(e)}"
            
    except Exception as e:
        logger.error(f"Failed to restore backup: {str(e)}")
        return False, f"Failed to restore backup: {str(e)}"

def create_backup():
    """Create a backup of database and configuration"""
    try:
        settings = Settings()
        logger.info("Starting backup creation")
        
        # Ensure backup directory exists
        backup_dir = Path(settings.get("paths.backups", "data/backups"))
        backup_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Using backup directory: {backup_dir}")
        
        # Create timestamp for backup with microsecond precision
        now = datetime.now()
        timestamp = now.strftime("%Y%m%d_%H%M%S_%f")
        
        # Initialize backup paths
        db_backup = None
        config_backup = backup_dir / f"config_{timestamp}.yaml"
        
        # Backup database if it exists
        db_path = Path(settings.get("paths.database", "data/certificates.db"))
        logger.info(f"Database path to backup: {db_path}")
        if db_path.exists():
            db_backup = backup_dir / f"certificates_{timestamp}.db"
            try:
                logger.info(f"Creating database backup at: {db_backup}")
                shutil.copy2(db_path, db_backup)
            except Exception as e:
                logger.error(f"Failed to backup database: {str(e)}")
                return False, f"Failed to backup database: {str(e)}"
        else:
            logger.warning(f"Database file not found at {db_path}")
        
        # Backup config
        try:
            logger.info("Creating config backup")
            current_config = settings._config.copy()
            with open(config_backup, 'w') as f:
                yaml.safe_dump(current_config, f)
        except Exception as e:
            logger.error(f"Failed to backup config: {str(e)}")
            if db_backup and db_backup.exists():
                db_backup.unlink()  # Clean up database backup if config fails
            return False, f"Failed to backup config: {str(e)}"
        
        # Create backup manifest
        try:
            manifest = {
                "timestamp": timestamp,
                "database": str(db_backup) if db_backup else None,
                "config": str(config_backup),
                "created": now.isoformat()
            }
            logger.info(f"Creating manifest with contents: {manifest}")
            
            manifest_file = backup_dir / f"backup_{timestamp}.json"
            with open(manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            # Verify all files were created
            expected_files = [manifest_file, config_backup]
            if db_backup:
                expected_files.append(db_backup)
                
            for file in expected_files:
                if not file.exists():
                    logger.error(f"Expected backup file not found: {file}")
                    return False, f"Failed to verify backup files"
            
            logger.info("Backup created successfully")
            return True, f"Backup created successfully at {backup_dir}"
        except Exception as e:
            logger.error(f"Failed to create manifest: {str(e)}")
            # Clean up any created files
            for file in [db_backup, config_backup]:
                if file and file.exists():
                    file.unlink()
            return False, f"Failed to create manifest: {str(e)}"
            
    except Exception as e:
        logger.error(f"Failed to create backup: {str(e)}")
        return False, f"Failed to create backup: {str(e)}"

def render_settings_view(engine):
    """Render the settings interface""" 
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
    # Create title row with columns
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Settings")
    
    settings = Settings()
    
    # Create tabs for different settings sections
    tabs = st.tabs(["Paths", "Scanning", "Alerts", "Exports"])
    
    with tabs[0]:  # Paths
        st.header("Path Settings")
        
        database_path = st.text_input(
            "Database Path",
            value=settings.get("paths.database"),
            help="Path to the SQLite database file"
        )
        
        backup_path = st.text_input(
            "Backup Path",
            value=settings.get("paths.backups"),
            help="Path for storing backup files"
        )
        
        if st.button("Save Path Settings"):
            settings.update("paths.database", database_path)
            settings.update("paths.backups", backup_path)
            
            if settings.save():
                st.success("Path settings updated successfully!")
            else:
                st.error("Failed to save path settings")
    
    with tabs[1]:  # Scanning
        st.header("Scanning Settings")
        
        # Rate limit settings
        st.markdown("""
        Configure rate limits for certificate scanning. Values represent requests per minute.
        
        Examples:
        - 60 = 1 request per second
        - 30 = 1 request every 2 seconds
        - 120 = 2 requests per second
        """)
        
        # Default rate limit
        default_rate_limit = st.number_input(
            "Default Rate Limit (requests/minute)",
            min_value=1,
            value=int(settings.get("scanning.default_rate_limit", 60)),
            help="Default rate limit for domains that don't match internal or external patterns"
        )
        
        st.divider()
        
        # Internal scanning settings
        st.subheader("Internal Domain Settings")
        st.markdown("""
        Settings for internal domains (e.g., `.local`, `.lan`, `.internal`, `.corp`).
        """)
        
        internal_rate_limit = st.number_input(
            "Internal Rate Limit (requests/minute)",
            min_value=1,
            value=int(settings.get("scanning.internal.rate_limit", 60)),
            help="Rate limit for internal domains"
        )
        
        internal_domains = st.text_area(
            "Custom Internal Domains (one per line)",
            value="\n".join(settings.get("scanning.internal.domains", [])),
            help="List of custom internal domain patterns (e.g., .internal.company.com)"
        )
        
        # External scanning settings
        st.subheader("External Domain Settings")
        st.markdown("""
        Settings for external domains (e.g., `.com`, `.org`, `.net`).
        """)
        
        external_rate_limit = st.number_input(
            "External Rate Limit (requests/minute)",
            min_value=1,
            value=int(settings.get("scanning.external.rate_limit", 30)),
            help="Rate limit for external domains"
        )
        
        external_domains = st.text_area(
            "Custom External Domains (one per line)",
            value="\n".join(settings.get("scanning.external.domains", [])),
            help="List of custom external domain patterns"
        )
        
        if st.button("Save Scanning Settings"):
            # Update rate limits
            settings.update("scanning.default_rate_limit", default_rate_limit)
            
            # Update internal scanning settings
            settings.update("scanning.internal.rate_limit", internal_rate_limit)
            settings.update("scanning.internal.domains", [d.strip() for d in internal_domains.split("\n") if d.strip()])
            
            # Update external scanning settings
            settings.update("scanning.external.rate_limit", external_rate_limit)
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
        
        for i, warning in enumerate(expiry_warnings):
            col1, col2, col3 = st.columns([2, 2, 1])
            with col1:
                days = st.number_input(
                    f"Days before expiry {i+1}",
                    min_value=1,
                    value=warning.get("days", 30)
                )
            with col2:
                level = st.selectbox(
                    f"Alert level {i+1}",
                    options=["info", "warning", "critical"],
                    index=["info", "warning", "critical"].index(warning.get("level", "warning"))
                )
            with col3:
                if st.button(f"Remove Warning {i+1}"):
                    expiry_warnings.pop(i)
                    settings.update("alerts.expiry_warnings", expiry_warnings)
                    settings.save()
                    st.rerun()
        
        if st.button("Add Expiry Warning"):
            expiry_warnings.append({"days": 30, "level": "warning"})
            settings.update("alerts.expiry_warnings", expiry_warnings)
            settings.save()
            st.rerun()
        
        # Failed scan alerts
        st.subheader("Failed Scan Alerts")
        consecutive_failures = st.number_input(
            "Consecutive failures before alert",
            min_value=1,
            value=settings.get("alerts.failed_scans.consecutive_failures", 3)
        )
        
        if st.button("Save Alert Settings"):
            settings.update("alerts.failed_scans.consecutive_failures", consecutive_failures)
            if settings.save():
                st.success("Alert settings updated successfully!")
            else:
                st.error("Failed to save alert settings")
    
    with tabs[3]:  # Exports
        st.header("Export Settings")
        
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
            settings.update("exports.csv.delimiter", csv_delimiter)
            settings.update("exports.csv.encoding", csv_encoding)
            
            if settings.save():
                st.success("Export settings updated successfully!")
            else:
                st.error("Failed to save export settings")
        
        # Export functionality
        st.divider()
        st.subheader("Generate Reports")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("Certificate Reports")
            if st.button("Export Certificates to CSV"):
                try:
                    with SessionManager(engine) as session:
                        output_path = export_certificates_to_csv(session)
                        st.success(f"Certificates exported to CSV: {output_path}")
                except Exception as e:
                    st.error(f"Failed to export certificates to CSV: {str(e)}")
            
            if st.button("Export Certificates to PDF"):
                try:
                    with SessionManager(engine) as session:
                        output_path = export_certificates_to_pdf(session)
                        st.success(f"Certificates exported to PDF: {output_path}")
                except Exception as e:
                    st.error(f"Failed to export certificates to PDF: {str(e)}")
        
        with col2:
            st.write("Host Reports")
            if st.button("Export Hosts to CSV"):
                try:
                    with SessionManager(engine) as session:
                        output_path = export_hosts_to_csv(session)
                        st.success(f"Hosts exported to CSV: {output_path}")
                except Exception as e:
                    st.error(f"Failed to export hosts to CSV: {str(e)}")
            
            if st.button("Export Hosts to PDF"):
                try:
                    with SessionManager(engine) as session:
                        output_path = export_hosts_to_pdf(session)
                        st.success(f"Hosts exported to PDF: {output_path}")
                except Exception as e:
                    st.error(f"Failed to export hosts to PDF: {str(e)}") 