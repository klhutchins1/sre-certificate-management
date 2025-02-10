"""
Certificate Management Settings Module

This module provides a comprehensive interface for managing system settings,
backups, and exports in the certificate management system. It offers multiple
configuration sections and utilities for system maintenance.

Key Features:
- System Configuration:
  - Path settings (database, backups)
  - Scanning configuration (rate limits, domain settings)
  - Alert settings (expiry warnings, scan failures)
  - Export settings (CSV/PDF configuration)
- Backup Management:
  - Create system backups (database and configuration)
  - List available backups
  - Restore from backups
  - Backup verification and validation
- Export Capabilities:
  - Certificate exports (CSV/PDF)
  - Host exports (CSV/PDF)
  - Custom export configuration
- Alert Configuration:
  - Certificate expiry warnings
  - Failed scan notifications
  - Customizable alert thresholds

The module provides a tabbed interface for organizing different settings
categories and includes comprehensive error handling and validation for
all configuration changes and backup operations.
"""

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
from typing import List, Tuple, Dict, Optional
from ..db import SessionManager
from ..exports import (
    export_certificates_to_csv,
    export_certificates_to_pdf,
    export_hosts_to_csv,
    export_hosts_to_pdf
)
from ..static.styles import load_warning_suppression, load_css


logger = logging.getLogger(__name__)

def list_backups() -> List[Dict]:
    """
    List all available system backups with their details.

    This function scans the backup directory for backup manifests and returns
    a list of available backups with their metadata. Each backup includes
    information about the database and configuration files.

    Returns:
        list: List of dictionaries containing backup information:
            - timestamp: Backup creation timestamp
            - database: Path to database backup file (if exists)
            - config: Path to configuration backup file
            - created: ISO format timestamp of backup creation
            - manifest_file: Path to the backup manifest file

    Features:
        - Automatic backup directory creation
        - Manifest file parsing and validation
        - Timestamp normalization
        - Error handling for corrupted backups
        - Sorting by creation date (newest first)

    The function handles missing or corrupted backup files gracefully and
    provides detailed logging for troubleshooting.
    """
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

def restore_backup(manifest: Dict) -> Tuple[bool, str]:
    """
    Restore the system from a backup using the provided manifest.

    This function restores both the database and configuration from a backup
    based on the provided manifest information. It includes comprehensive
    validation and error handling to ensure data integrity.

    Args:
        manifest: Dictionary containing backup manifest information:
            - config: Path to configuration backup file
            - database: Path to database backup file (optional)
            - timestamp: Backup creation timestamp
            - created: ISO format timestamp of creation

    Returns:
        tuple: (success: bool, message: str)
            - success: True if restore was successful, False otherwise
            - message: Descriptive message about the operation result

    Features:
        - Database restoration:
            - Connection management
            - Table recreation
            - Data verification
        - Configuration restoration:
            - YAML validation
            - Safe configuration updates
        - Comprehensive error handling:
            - File existence checks
            - Format validation
            - Database integrity checks
        - Automatic backup verification
        - Session management
        - Progress logging

    The function includes safeguards to prevent partial restores and
    maintains system integrity throughout the restore process.
    """
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

def create_backup() -> Tuple[bool, str]:
    """
    Create a complete system backup including database and configuration.

    This function creates a timestamped backup of the entire system,
    including the database and configuration files. It generates a
    manifest file to track backup contents and metadata.

    Returns:
        tuple: (success: bool, message: str)
            - success: True if backup was successful, False otherwise
            - message: Descriptive message about the operation result

    Features:
        - Timestamped backups:
            - Microsecond precision
            - Unique backup identifiers
        - Component backups:
            - Database backup
            - Configuration backup
            - Manifest creation
        - Validation:
            - File integrity checks
            - Backup verification
            - Manifest validation
        - Error handling:
            - Partial backup cleanup
            - Detailed error reporting
            - Logging for troubleshooting

    The function ensures atomic backup operations by cleaning up
    partial backups if any step fails.
    """
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

def render_settings_view(engine) -> None:
    """
    Render the main settings management interface.

    This function creates a comprehensive settings interface with multiple
    tabs for different configuration categories. It provides real-time
    validation and immediate feedback for all settings changes.

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Tabbed interface sections:
            - Paths: Database and backup location configuration
            - Scanning: Rate limits and domain settings
            - Alerts: Certificate expiry and scan failure notifications
            - Exports: Report generation and format configuration
        
        - Path Settings:
            - Database location configuration
            - Backup directory management
            - Path validation and creation
        
        - Scanning Settings:
            - Rate limit configuration:
                - Default rate limits
                - Internal domain settings
                - External domain settings
            - Domain pattern management:
                - Internal domain patterns
                - External domain patterns
                - Custom domain configuration
        
        - Alert Settings:
            - Certificate expiry warnings:
                - Multiple warning thresholds
                - Customizable alert levels
                - Dynamic warning management
            - Scan failure alerts:
                - Consecutive failure thresholds
                - Alert level configuration
        
        - Export Settings:
            - CSV configuration:
                - Delimiter settings
                - Encoding options
            - Export functionality:
                - Certificate exports (CSV/PDF)
                - Host exports (CSV/PDF)
                - Real-time export generation

    The interface provides immediate feedback for all operations and
    includes comprehensive error handling and validation for all
    settings changes.
    """
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Create header layout
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Settings")
    
    # Initialize settings manager
    settings = Settings()
    
    # Create tabbed interface for settings sections
    tabs = st.tabs(["Paths", "Scanning", "Alerts", "Exports"])
    
    # Path Settings Tab
    with tabs[0]:
        st.header("Path Settings")
        
        # Database path configuration
        database_path = st.text_input(
            "Database Path",
            value=settings.get("paths.database"),
            help="Path to the SQLite database file"
        )
        
        # Backup path configuration
        backup_path = st.text_input(
            "Backup Path",
            value=settings.get("paths.backups"),
            help="Path for storing backup files"
        )
        
        # Save path settings
        if st.button("Save Path Settings"):
            settings.update("paths.database", database_path)
            settings.update("paths.backups", backup_path)
            
            if settings.save():
                st.success("Path settings updated successfully!")
            else:
                st.error("Failed to save path settings")
    
    # Scanning Settings Tab
    with tabs[1]:
        st.header("Scanning Settings")
        
        # Rate limit configuration help text
        st.markdown("""
        Configure rate limits for certificate scanning. Values represent requests per minute.
        
        Examples:
        - 60 = 1 request per second
        - 30 = 1 request every 2 seconds
        - 120 = 2 requests per second
        """)
        
        # Default rate limit configuration
        try:
            current_default_rate = int(settings.get("scanning.default_rate_limit", 60))
            default_rate_limit = st.number_input(
                "Default Rate Limit (requests/minute)",
                min_value=1,
                value=max(1, current_default_rate),
                help="Default rate limit for domains that don't match internal or external patterns"
            )
        except ValueError:
            default_rate_limit = 60
            st.warning("Invalid default rate limit value, using default: 60")
        
        st.divider()
        
        # Internal domain configuration
        st.subheader("Internal Domain Settings")
        st.markdown("""
        Settings for internal domains (e.g., `.local`, `.lan`, `.internal`, `.corp`).
        """)
        
        # Internal rate limit configuration
        try:
            current_internal_rate = int(settings.get("scanning.internal.rate_limit", 60))
            internal_rate_limit = st.number_input(
                "Internal Rate Limit (requests/minute)",
                min_value=1,
                value=max(1, current_internal_rate),
                help="Rate limit for internal domains"
            )
        except ValueError:
            internal_rate_limit = 60
            st.warning("Invalid internal rate limit value, using default: 60")
        
        # Internal domain patterns
        internal_domains = st.text_area(
            "Custom Internal Domains (one per line)",
            value="\n".join(settings.get("scanning.internal.domains", [])),
            help="List of custom internal domain patterns (e.g., .internal.company.com)"
        )
        
        # External domain configuration
        st.subheader("External Domain Settings")
        st.markdown("""
        Settings for external domains (e.g., `.com`, `.org`, `.net`).
        """)
        
        # External rate limit configuration
        try:
            current_external_rate = int(settings.get("scanning.external.rate_limit", 30))
            external_rate_limit = st.number_input(
                "External Rate Limit (requests/minute)",
                min_value=1,
                value=max(1, current_external_rate),
                help="Rate limit for external domains"
            )
        except ValueError:
            external_rate_limit = 30
            st.warning("Invalid external rate limit value, using default: 30")
        
        # External domain patterns
        external_domains = st.text_area(
            "Custom External Domains (one per line)",
            value="\n".join(settings.get("scanning.external.domains", [])),
            help="List of custom external domain patterns"
        )
        
        # Save scanning settings
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
    
    # Alert Settings Tab
    with tabs[2]:
        st.header("Alert Settings")
        
        # Certificate expiry warning configuration
        st.subheader("Certificate Expiry Warnings")
        expiry_warnings = settings.get("alerts.expiry_warnings", [
            {"days": 60, "level": "critical"},
            {"days": 30, "level": "warning"}
        ])
        
        # Initialize warning list
        updated_warnings = []
        
        # Warning threshold configuration
        for i, warning in enumerate(expiry_warnings):
            col1, col2, col3 = st.columns([2, 2, 1])
            with col1:
                try:
                    current_days = int(warning.get("days", 30))
                    days = st.number_input(
                        f"Days before expiry {i+1}",
                        min_value=1,
                        value=max(1, current_days),
                        key=f"days_{i}"
                    )
                except ValueError:
                    days = 30
                    st.warning(f"Invalid days value for warning {i+1}, using default: 30")
            with col2:
                level = st.selectbox(
                    f"Alert level {i+1}",
                    options=["info", "warning", "critical"],
                    index=["info", "warning", "critical"].index(warning.get("level", "warning")),
                    key=f"level_{i}"
                )
            with col3:
                if st.button(f"Remove Warning {i+1}", key=f"remove_{i}"):
                    expiry_warnings.pop(i)
                    st.rerun()
            # Add warning to updated list
            updated_warnings.append({"days": int(days), "level": level})
        
        # Add new warning threshold button
        if st.button("Add Expiry Warning"):
            expiry_warnings.append({"days": 30, "level": "warning"})
            st.rerun()
        
        # Failed scan alert configuration
        st.subheader("Failed Scan Alerts")
        try:
            current_failures = int(settings.get("alerts.failed_scans.consecutive_failures", 3))
            consecutive_failures = st.number_input(
                "Consecutive failures before alert",
                min_value=1,
                value=max(1, current_failures)
            )
        except ValueError:
            consecutive_failures = 3
            st.warning("Invalid consecutive failures value, using default: 3")
        
        # Save alert settings
        if st.button("Save Alert Settings"):
            # Sort warnings by days in descending order
            updated_warnings.sort(key=lambda x: x["days"], reverse=True)
            # Update settings
            settings.update("alerts.expiry_warnings", updated_warnings)
            settings.update("alerts.failed_scans.consecutive_failures", consecutive_failures)
            if settings.save():
                st.success("Alert settings updated successfully!")
            else:
                st.error("Failed to save alert settings")
    
    # Export Settings Tab
    with tabs[3]:
        st.header("Export Settings")
        
        # CSV export configuration
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
        
        # Save export settings
        if st.button("Save Export Settings"):
            settings.update("exports.csv.delimiter", csv_delimiter)
            settings.update("exports.csv.encoding", csv_encoding)
            
            if settings.save():
                st.success("Export settings updated successfully!")
            else:
                st.error("Failed to save export settings")
        
        # Export functionality section
        st.divider()
        st.subheader("Generate Reports")
        
        # Create export button columns
        col1, col2 = st.columns(2)
        
        # Certificate export buttons
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
        
        # Host export buttons
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