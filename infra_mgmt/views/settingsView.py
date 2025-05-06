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
from ..db import SessionManager, is_network_path, normalize_path
from ..exports import (
    export_certificates_to_csv,
    export_certificates_to_pdf,
    export_hosts_to_csv,
    export_hosts_to_pdf
)
from ..static.styles import load_warning_suppression, load_css
from sqlalchemy.engine import Engine
from ..backup import create_backup
from ..models import IgnoredDomain, IgnoredCertificate
from sqlalchemy.orm import Session
import re
from infra_mgmt.notifications import initialize_notifications, show_notifications, notify


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
            except Exception as e:  # Only Exception is possible here due to file IO or JSON errors
                logger.error(f"Error reading manifest {manifest_file}: {str(e)}")
                continue
        
        # Sort backups by created timestamp, newest first
        sorted_backups = sorted(
            backups,
            key=lambda x: x.get('created', x.get('timestamp', '')),
            reverse=True
        )
        return sorted_backups
        
    except Exception as e:  # Only Exception is possible here due to file IO or DB errors
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
        notify(message, "error")
        return False, message
    
    try:
        # Load manifest
        if isinstance(manifest_file_or_dict, dict):
            manifest = manifest_file_or_dict
        else:
            try:
                with open(manifest_file_or_dict) as f:
                    manifest = json.load(f)
            except Exception as e:  # Only Exception is possible here due to file IO or JSON errors
                message = f"Failed to read manifest file: {str(e)}"
                notify(message, "error")
                return False, message
        
        # Verify backup files exist
        db_backup = Path(manifest.get("database", ""))
        config_backup = Path(manifest.get("config", ""))
        
        if not config_backup.is_file():
            message = "Config backup file not found"
            notify(message, "error")
            return False, message
            
        if not db_backup.is_file():
            message = "Database backup file not found"
            notify(message, "error")
            return False, message
        
        # Restore database
        shutil.copy2(str(db_backup), db_path)
        
        # Restore configuration
        with open(config_backup) as f:
            config = yaml.safe_load(f)
            settings._config = config
            settings.save()
        
        message = "Backup restored successfully"
        notify(message, "success")
        return True, message
        
    except Exception as e:  # Only Exception is possible here due to file IO or DB errors
        message = f"Failed to restore backup: {str(e)}"
        notify(message, "error")
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
    
    # Initialize notifications at the very beginning
    initialize_notifications()
    
    # Create header layout
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Settings")
    
    # Initialize settings manager
    settings = Settings()
    
    # Create tabbed interface for settings sections
    tabs = st.tabs(["Paths", "Scanning", "Alerts", "Exports", "Ignore Lists"])
    
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
                notify("Path settings updated successfully!", "success")
            else:
                notify("Failed to save path settings", "error")
    
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
            notify("Invalid default rate limit value, using default: 60", "warning")
        
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
            notify("Invalid internal rate limit value, using default: 60", "warning")
        
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
            notify("Invalid external rate limit value, using default: 30", "warning")
        
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
            notify("Invalid WHOIS rate limit value, using default: 10", "warning")
        
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
            notify("Invalid DNS rate limit value, using default: 30", "warning")
        
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
            notify("Invalid CT rate limit value, using default: 10", "warning")
        
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
            current_socket_timeout = int(settings.get("scanning.timeouts.socket", 10))
            socket_timeout = st.number_input(
                "Socket Timeout (seconds)",
                min_value=1,
                max_value=30,
                value=max(1, current_socket_timeout),
                help="Maximum time to wait for socket connections"
            )
        except ValueError:
            socket_timeout = 10
            notify("Invalid socket timeout value, using default: 10", "warning")
        
        # Request timeout
        try:
            current_request_timeout = int(settings.get("scanning.timeouts.request", 15))
            request_timeout = st.number_input(
                "Request Timeout (seconds)",
                min_value=1,
                max_value=30,
                value=max(1, current_request_timeout),
                help="Maximum time to wait for HTTP/HTTPS requests"
            )
        except ValueError:
            request_timeout = 15
            notify("Invalid request timeout value, using default: 15", "warning")
        
        # DNS timeout
        try:
            current_dns_timeout = float(settings.get("scanning.timeouts.dns", 5.0))
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
            dns_timeout = 5.0
            notify("Invalid DNS timeout value, using default: 5.0", "warning")
        
        # Save scanning settings
        if st.button("Save Scanning Settings"):
            # Validate rate limits
            if default_rate_limit < 1:
                notify("Invalid rate limit: Default rate limit must be at least 1", "error")
                return
            if internal_rate_limit < 1:
                notify("Invalid rate limit: Internal rate limit must be at least 1", "error")
                return
            if external_rate_limit < 1:
                notify("Invalid rate limit: External rate limit must be at least 1", "error")
                return
            if whois_rate_limit < 1:
                notify("Invalid rate limit: WHOIS rate limit must be at least 1", "error")
                return
            if dns_rate_limit < 1:
                notify("Invalid rate limit: DNS rate limit must be at least 1", "error")
                return
            if ct_rate_limit < 1:
                notify("Invalid rate limit: CT rate limit must be at least 1", "error")
                return
            
            # Update rate limits
            settings.update("scanning.default_rate_limit", default_rate_limit)
            settings.update("scanning.internal.rate_limit", internal_rate_limit)
            settings.update("scanning.internal.domains", [d.strip() for d in internal_domains.split("\n") if d.strip()])
            settings.update("scanning.external.rate_limit", external_rate_limit)
            settings.update("scanning.external.domains", [d.strip() for d in external_domains.split("\n") if d.strip()])
            settings.update("scanning.whois.rate_limit", whois_rate_limit)
            settings.update("scanning.dns.rate_limit", dns_rate_limit)
            settings.update("scanning.ct.rate_limit", ct_rate_limit)
            settings.update("scanning.timeouts.socket", socket_timeout)
            settings.update("scanning.timeouts.request", request_timeout)
            settings.update("scanning.timeouts.dns", dns_timeout)
            
            if settings.save():
                notify("Scanning settings updated successfully!", "success")
            else:
                notify("Failed to save scanning settings", "error")
    
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
            notify("Invalid consecutive failures value, using default: 3", "warning")
        
        # Save alert settings
        if st.button("Save Alert Settings"):
            # Sort warnings by days in descending order
            updated_warnings.sort(key=lambda x: x["days"], reverse=True)
            # Update settings
            settings.update("alerts.expiry_warnings", updated_warnings)
            settings.update("alerts.failed_scans.consecutive_failures", consecutive_failures)
            if settings.save():
                notify("Alert settings updated successfully!", "success")
            else:
                notify("Failed to save alert settings", "error")
    
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
                notify("Export settings updated successfully!", "success")
            else:
                notify("Failed to save export settings", "error")
        
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
                        notify(f"Certificates exported to CSV: {output_path}", "success")
                except Exception as e:  # Only Exception is possible here due to file IO or DB errors
                    notify(f"Failed to export certificates to CSV: {str(e)}", "error")
            
            if st.button("Export Certificates to PDF"):
                try:
                    with SessionManager(engine) as session:
                        output_path = export_certificates_to_pdf(session)
                        notify(f"Certificates exported to PDF: {output_path}", "success")
                except Exception as e:  # Only Exception is possible here due to file IO or DB errors
                    notify(f"Failed to export certificates to PDF: {str(e)}", "error")
        
        # Host export buttons
        with col2:
            st.write("Host Reports")
            if st.button("Export Hosts to CSV"):
                try:
                    with SessionManager(engine) as session:
                        output_path = export_hosts_to_csv(session)
                        notify(f"Hosts exported to CSV: {output_path}", "success")
                except Exception as e:  # Only Exception is possible here due to file IO or DB errors
                    notify(f"Failed to export hosts to CSV: {str(e)}", "error")
            
            if st.button("Export Hosts to PDF"):
                try:
                    with SessionManager(engine) as session:
                        output_path = export_hosts_to_pdf(session)
                        notify(f"Hosts exported to PDF: {output_path}", "success")
                except Exception as e:  # Only Exception is possible here due to file IO or DB errors
                    notify(f"Failed to export hosts to PDF: {str(e)}", "error")

    # Ignore Lists Tab
    with tabs[4]:
        st.header("Ignore Lists")
        
        # Create tabs for different ignore lists
        ignore_tabs = st.tabs(["🚫 Domains", "🔒 Certificates"])
        
        # Ignored Domains tab
        with ignore_tabs[0]:
            st.subheader("Ignored Domains")
            st.markdown("""
            Add domains or patterns to ignore during scanning. Supports:
            - Exact matches (e.g., test.example.com)
            - Wildcard patterns (e.g., *.test.com)
            """)
            
            # Add new domain pattern
            with st.form(key="domain_form"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    new_domain_pattern = st.text_input(
                        "Domain Pattern",
                        value="",
                        key="new_domain_pattern",
                        placeholder="example.com or *.example.com"
                    )
                    domain_reason = st.text_input(
                        "Reason (optional)",
                        value="",
                        key="domain_reason",
                        placeholder="Why should this domain be ignored?"
                    )
                with col2:
                    submit_domain = st.form_submit_button("Add Domain")
                
                if submit_domain:
                    if new_domain_pattern:
                        try:
                            with Session(engine) as session:
                                # Check if pattern already exists
                                existing = session.query(IgnoredDomain).filter_by(pattern=new_domain_pattern).first()
                                if existing:
                                    notify(f"Pattern '{new_domain_pattern}' is already in the ignore list", "error")
                                else:
                                    # Validate pattern format
                                    if new_domain_pattern.startswith('*') and new_domain_pattern.endswith('*'):
                                        # Contains pattern (*test*)
                                        search_term = new_domain_pattern.strip('*')
                                        if not re.match(r'^[a-zA-Z0-9-]+$', search_term):
                                            notify("Invalid contains pattern: Can only contain letters, numbers, and hyphens", "error")
                                            return
                                    elif new_domain_pattern.startswith("*."):
                                        # Prefix wildcard (*.example.com)
                                        base_domain = new_domain_pattern[2:]
                                        if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', base_domain):
                                            notify("Invalid wildcard domain pattern", "error")
                                            return
                                    elif new_domain_pattern.startswith('*'):
                                        # Suffix match (*test.com)
                                        suffix = new_domain_pattern[1:]
                                        if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', suffix):
                                            notify("Invalid suffix pattern", "error")
                                            return
                                    elif new_domain_pattern.endswith('*'):
                                        # Prefix match (test*)
                                        prefix = new_domain_pattern[:-1]
                                        if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', prefix):
                                            notify("Invalid prefix pattern", "error")
                                            return
                                    else:
                                        # Exact domain match
                                        if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', new_domain_pattern):
                                            notify("Invalid domain format", "error")
                                            return
                                    
                                    # Add new ignored domain
                                    ignored = IgnoredDomain(
                                        pattern=new_domain_pattern,
                                        reason=domain_reason if domain_reason else None,
                                        created_at=datetime.now()
                                    )
                                    session.add(ignored)
                                    session.commit()
                                    notify(f"Added '{new_domain_pattern}' to ignore list", "success")
                                    st.rerun()  # Rerun to clear the form and refresh the list
                        except Exception as e:  # Only Exception is possible here due to DB errors
                            notify(f"Error adding domain pattern: {str(e)}", "error")
                    else:
                        notify("Please enter a domain pattern", "error")
            
            # Show existing ignored domains
            st.divider()
            try:
                # First show default patterns from config
                settings = Settings()
                default_patterns = settings.get("ignore_lists.domains.default_patterns", [])
                if default_patterns:
                    st.subheader("Default Ignore Patterns")
                    st.caption("These patterns are defined in the configuration file. Removing them will update the configuration.")
                    with Session(engine) as session:
                        ignored_domains = session.query(IgnoredDomain).order_by(IgnoredDomain.created_at.desc()).all()
                        if ignored_domains:
                            for domain in ignored_domains:
                                col1, col2 = st.columns([4, 1])
                                with col1:
                                    st.markdown(f"**{domain.pattern}**")
                                    if domain.reason:
                                        st.caption(f"Reason: {domain.reason}")
                                    st.caption(f"Added: {domain.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
                                with col2:
                                    if st.button("Remove", key=f"remove_domain_{domain.id}"):
                                        try:
                                            session.delete(domain)
                                            session.commit()
                                            notify(f"Removed '{domain.pattern}' from ignore list", "success")
                                            st.rerun()
                                        except Exception as e:  # Only Exception is possible here due to DB errors
                                            notify(f"Error removing domain: {str(e)}", "error")
                        else:
                            notify("No custom ignored domains configured.\nDefault patterns will still be applied.", "info")
            except Exception as e:  # Only Exception is possible here due to DB/config errors
                notify(f"Error loading ignored domains: {str(e)}", "error")
        
        # Ignored Certificates tab
        with ignore_tabs[1]:
            st.subheader("Ignored Certificates")
            st.markdown("""
            Add certificate patterns to ignore based on Common Name (CN). Supports:
            - Contains pattern: *test* (matches any CN containing 'test')
            - Prefix wildcard: *.example.com (matches any subdomain)
            - Suffix wildcard: test* (matches CNs starting with 'test')
            - Exact match: test.example.com
            
            Examples:
            - *dev* will match: dev.example.com, mydev.com, devtest.com
            - *test* will match: test.com, mytest.example.com, testing.com
            """)
            
            # Add new certificate pattern
            with st.form(key="cert_form"):
                col1, col2 = st.columns([3, 1])
                with col1:
                    new_pattern = st.text_input(
                        "Certificate CN Pattern",
                        value="",
                        key="new_pattern",
                        placeholder="e.g., *test* or *.example.com"
                    )
                    cert_reason = st.text_input(
                        "Reason (optional)",
                        value="",
                        key="cert_reason",
                        placeholder="Why should certificates matching this pattern be ignored?"
                    )
                with col2:
                    submit_cert = st.form_submit_button("Add Pattern")
                
                if submit_cert:
                    if new_pattern:
                        try:
                            with Session(engine) as session:
                                # Check if pattern already exists
                                existing = session.query(IgnoredCertificate).filter_by(pattern=new_pattern).first()
                                if existing:
                                    notify(f"Pattern '{new_pattern}' is already in the ignore list", "error")
                                else:
                                    # Basic pattern validation
                                    if new_pattern.count('*') > 2:
                                        notify("Invalid pattern: Maximum of two wildcards allowed", "error")
                                        return
                                    
                                    # Add new ignored certificate pattern
                                    ignored = IgnoredCertificate(
                                        pattern=new_pattern,
                                        reason=cert_reason if cert_reason else None,
                                        created_at=datetime.now()
                                    )
                                    session.add(ignored)
                                    session.commit()
                                    notify(f"Added pattern '{new_pattern}' to ignore list", "success")
                                    st.rerun()  # Rerun to clear the form and refresh the list
                        except Exception as e:  # Only Exception is possible here due to DB errors
                            notify(f"Error adding certificate pattern: {str(e)}", "error")
                    else:
                        notify("Please enter a certificate pattern", "error")
            
            # Show existing ignored certificates
            st.divider()
            try:
                with Session(engine) as session:
                    ignored_certs = session.query(IgnoredCertificate).order_by(IgnoredCertificate.created_at.desc()).all()
                    if ignored_certs:
                        for cert in ignored_certs:
                            col1, col2 = st.columns([4, 1])
                            with col1:
                                st.markdown(f"**{cert.pattern}**")
                                if cert.reason:
                                    st.caption(f"Reason: {cert.reason}")
                                st.caption(f"Added: {cert.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
                            with col2:
                                if st.button("Remove", key=f"remove_cert_{cert.id}"):
                                    try:
                                        session.delete(cert)
                                        session.commit()
                                        notify(f"Removed pattern '{cert.pattern}' from ignore list", "success")
                                        st.rerun()
                                    except Exception as e:  # Only Exception is possible here due to DB errors
                                        notify(f"Error removing certificate pattern: {str(e)}", "error")
                    else:
                        notify("No ignored certificate patterns configured.\n", "info")
            except Exception as e:  # Only Exception is possible here due to DB errors
                notify(f"Error loading ignored certificates: {str(e)}", "error")

    # Render backup and restore section
    render_backup_restore_section()

    # Show notifications at the end
    show_notifications()

def render_backup_restore_section():
    """Render backup and restore section in settings view"""
    st.subheader("Backup and Restore")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("Create Backup")
        if st.button("Create Backup"):
            # Create backup
            success, message = create_backup()
            if success:
                notify(message, "success")
            else:
                notify(message, "error")
    
    with col2:
        st.write("Available Backups")
        try:
            backups = list_backups()
            
            if not backups:
                notify("No backups available.\n", "info")
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
                    # Find the selected backup manifest
                    selected_idx = backup_options.index(selected_backup)
                    manifest_file = backups[selected_idx]["manifest_file"]
                    
                    # Restore backup
                    success, message = restore_backup(manifest_file)
                    if success:
                        notify(message, "success")
                    else:
                        notify(message, "error")
        except Exception as e:  # Only Exception is possible here due to file IO or DB errors
            notify(f"Error loading backups: {str(e)}", "error") 