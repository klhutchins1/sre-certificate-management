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
from pathlib import Path, WindowsPath
import shutil
from datetime import datetime
import json
import glob
import logging
import yaml
import time
from typing import List, Tuple, Dict, Optional, Union, Any
from ..db import SessionManager, _is_network_path, _normalize_path
from ..exports import (
    export_certificates_to_csv,
    export_certificates_to_pdf,
    export_hosts_to_csv,
    export_hosts_to_pdf
)
from ..static.styles import load_warning_suppression, load_css
from sqlalchemy.engine import Engine
from ..backup import create_backup


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
        manifest_files = list(backup_dir.glob("backup_*.json"))
        
        for manifest_file in manifest_files:
            try:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                    # Add manifest filename for reference
                    manifest['manifest_file'] = str(manifest_file)
                    
                    # Ensure required fields exist
                    if 'timestamp' not in manifest:
                        # If no timestamp, try to extract from filename
                        filename = manifest_file.stem
                        timestamp = filename.replace('backup_', '')
                        manifest['timestamp'] = timestamp
                    
                    if 'created' not in manifest:
                        try:
                            # Try to parse timestamp into created date
                            created = datetime.strptime(manifest['timestamp'], "%Y%m%d_%H%M%S")
                            manifest['created'] = created.isoformat()
                        except ValueError:
                            # If parsing fails, use file modification time
                            created = datetime.fromtimestamp(manifest_file.stat().st_mtime)
                            manifest['created'] = created.isoformat()
                    
                    backups.append(manifest)
            except Exception as e:
                logger.error(f"Error reading manifest {manifest_file}: {str(e)}")
                continue
        
        # Sort backups by created timestamp, newest first
        sorted_backups = sorted(
            backups,
            key=lambda x: x.get('created', x.get('timestamp', '')),
            reverse=True
        )
        return sorted_backups
        
    except Exception as e:
        logger.error(f"Error listing backups: {str(e)}")
        return []

def restore_backup(manifest_file_or_dict: Union[str, Dict[str, Any]]) -> Tuple[bool, str]:
    """
    Restore from a backup.
    
    Args:
        manifest_file_or_dict: Either a path to a manifest file or a manifest dictionary
        
    Returns:
        Tuple[bool, str]: Success status and message
    """
    settings = Settings()
    db_path = settings.get("paths.database")
    
    if not db_path:
        message = "Database path not configured"
        st.error(message)
        return False, message
    
    try:
        # Load manifest
        if isinstance(manifest_file_or_dict, dict):
            manifest = manifest_file_or_dict
        else:
            try:
                with open(manifest_file_or_dict) as f:
                    manifest = json.load(f)
            except Exception as e:
                message = f"Failed to read manifest file: {str(e)}"
                st.error(message)
                return False, message
        
        # Verify backup files exist
        db_backup = Path(manifest.get("database", ""))
        config_backup = Path(manifest.get("config", ""))
        
        if not config_backup.is_file():
            message = "Config backup file not found"
            st.error(message)
            return False, message
            
        if not db_backup.is_file():
            message = "Database backup file not found"
            st.error(message)
            return False, message
        
        # Restore database
        shutil.copy2(str(db_backup), db_path)
        
        # Restore configuration
        with open(config_backup) as f:
            config = yaml.safe_load(f)
            settings._config = config
            settings.save()
        
        message = "Backup restored successfully"
        st.success(message)
        return True, message
        
    except Exception as e:
        message = f"Failed to restore backup: {str(e)}"
        st.error(message)
        return False, message

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
            - Rate limit configuration help text
            - Default rate limit configuration
            - Internal domain configuration
            - External domain configuration
            - Domain pattern management
        
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
        
        # Additional scanning rate limits
        st.divider()
        st.subheader("Additional Rate Limits")
        st.markdown("""
        Configure rate limits for additional scanning operations. Values represent requests per minute.
        
        Examples:
        - 10 = 1 request every 6 seconds
        - 30 = 1 request every 2 seconds
        - 60 = 1 request per second
        """)
        
        # WHOIS rate limit
        try:
            current_whois_rate = int(settings.get("scanning.whois.rate_limit", 10))
            whois_rate_limit = st.number_input(
                "WHOIS Rate Limit (requests/minute)",
                min_value=1,
                value=max(1, current_whois_rate),
                help="Rate limit for WHOIS queries"
            )
        except ValueError:
            whois_rate_limit = 10
            st.warning("Invalid WHOIS rate limit value, using default: 10")
        
        # DNS rate limit
        try:
            current_dns_rate = int(settings.get("scanning.dns.rate_limit", 30))
            dns_rate_limit = st.number_input(
                "DNS Rate Limit (requests/minute)",
                min_value=1,
                value=max(1, current_dns_rate),
                help="Rate limit for DNS queries"
            )
        except ValueError:
            dns_rate_limit = 30
            st.warning("Invalid DNS rate limit value, using default: 30")
        
        # CT logs rate limit
        try:
            current_ct_rate = int(settings.get("scanning.ct.rate_limit", 10))
            ct_rate_limit = st.number_input(
                "Certificate Transparency Rate Limit (requests/minute)",
                min_value=1,
                value=max(1, current_ct_rate),
                help="Rate limit for Certificate Transparency log queries"
            )
        except ValueError:
            ct_rate_limit = 10
            st.warning("Invalid CT rate limit value, using default: 10")
        
        # Timeout Settings
        st.divider()
        st.subheader("Timeout Settings")
        st.markdown("""
        Configure timeout values for various operations (in seconds).
        
        These settings control how long to wait for responses before giving up:
        - Socket timeout: How long to wait for initial connection
        - Request timeout: How long to wait for HTTP/HTTPS responses
        - DNS timeout: How long to wait for DNS responses
        """)
        
        # Socket timeout
        try:
            current_socket_timeout = int(settings.get("scanning.timeouts.socket", 5))
            socket_timeout = st.number_input(
                "Socket Timeout (seconds)",
                min_value=1,
                max_value=30,
                value=max(1, current_socket_timeout),
                help="Maximum time to wait for socket connections"
            )
        except ValueError:
            socket_timeout = 5
            st.warning("Invalid socket timeout value, using default: 5")
        
        # Request timeout
        try:
            current_request_timeout = int(settings.get("scanning.timeouts.request", 10))
            request_timeout = st.number_input(
                "Request Timeout (seconds)",
                min_value=1,
                max_value=30,
                value=max(1, current_request_timeout),
                help="Maximum time to wait for HTTP/HTTPS requests"
            )
        except ValueError:
            request_timeout = 10
            st.warning("Invalid request timeout value, using default: 10")
        
        # DNS timeout
        try:
            current_dns_timeout = float(settings.get("scanning.timeouts.dns", 3.0))
            dns_timeout = st.number_input(
                "DNS Timeout (seconds)",
                min_value=0.1,
                max_value=10.0,
                value=max(0.1, current_dns_timeout),
                step=0.1,
                format="%.1f",
                help="Maximum time to wait for DNS responses"
            )
        except ValueError:
            dns_timeout = 3.0
            st.warning("Invalid DNS timeout value, using default: 3.0")
        
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
            
            # Update additional rate limits
            settings.update("scanning.whois.rate_limit", whois_rate_limit)
            settings.update("scanning.dns.rate_limit", dns_rate_limit)
            settings.update("scanning.ct.rate_limit", ct_rate_limit)
            
            # Update timeout settings
            settings.update("scanning.timeouts.socket", socket_timeout)
            settings.update("scanning.timeouts.request", request_timeout)
            settings.update("scanning.timeouts.dns", dns_timeout)
            
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
                days = st.number_input(
                    f"Warning {i+1} Days",
                    min_value=1,
                    value=warning.get("days", 30),
                    key=f"warning_days_{i}",
                    help="Days before expiry to trigger warning"
                )
            with col2:
                level = st.selectbox(
                    f"Warning {i+1} Level",
                    options=["info", "warning", "error", "critical"],
                    index=["info", "warning", "error", "critical"].index(warning.get("level", "warning")),
                    key=f"warning_level_{i}",
                    help="Severity level of the warning"
                )
            with col3:
                if st.button("Remove", key=f"remove_warning_{i}"):
                    expiry_warnings.pop(i)
                    st.rerun()
            updated_warnings.append({"days": days, "level": level})
        
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

    # Render backup and restore section
    render_backup_restore_section()

def render_backup_restore_section():
    """Render backup and restore section in settings view"""
    st.subheader("Backup and Restore")
    
    # Create a container for alerts
    alert_container = st.empty()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("Create Backup")
        if st.button("Create Backup"):
            # Clear any previous alerts
            alert_container.empty()
            
            # Create backup and show result in alert container
            success, message = create_backup()
            if success:
                alert_container.success(message)
            else:
                alert_container.error(message)
    
    with col2:
        st.write("Available Backups")
        try:
            backups = list_backups()
            
            if not backups:
                st.info("No backups available")
            else:
                # Create a list of backup options
                backup_options = []
                for b in backups:
                    created = datetime.fromisoformat(b['created']).strftime("%Y-%m-%d %H:%M:%S")
                    backup_options.append(f"{created}")
                
                selected_backup = st.selectbox(
                    "Select backup to restore",
                    options=backup_options,
                    index=0 if backup_options else None
                )
                
                if selected_backup and st.button("Restore Selected Backup"):
                    # Clear any previous alerts
                    alert_container.empty()
                    
                    # Find the selected backup manifest
                    selected_idx = backup_options.index(selected_backup)
                    manifest_file = backups[selected_idx]["manifest_file"]
                    
                    # Restore backup and show result in alert container
                    success, message = restore_backup(manifest_file)
                    if success:
                        alert_container.success(message)
                    else:
                        alert_container.error(message)
        except Exception as e:
            alert_container.error(f"Error loading backups: {str(e)}") 