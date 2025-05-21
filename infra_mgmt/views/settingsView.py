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

import logging
import streamlit as st

from infra_mgmt.backup import create_backup
from ..settings import Settings
from infra_mgmt.services.SettingsService import SettingsService
from infra_mgmt.notifications import initialize_notifications, show_notifications, notify
from ..static.styles import load_warning_suppression, load_css
from sqlalchemy.engine import Engine
from datetime import datetime
import re
from infra_mgmt.components.page_header import render_page_header

logger = logging.getLogger(__name__)

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
    load_warning_suppression()
    load_css()
    initialize_notifications()
    render_page_header(title="Settings")
 

    settings = Settings()
    tabs = st.tabs(["Paths", "Scanning", "Alerts", "Exports", "Ignore Lists"])

    # Path Settings Tab
    with tabs[0]:
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
            success = SettingsService.save_path_settings(settings, database_path, backup_path)
            if success:
                notify("Path settings updated successfully!", "success")
            else:
                notify("Failed to save path settings", "error")

    # Scanning Settings Tab
    with tabs[1]:
        st.header("Scanning Settings")
        st.markdown("""
        Configure rate limits for certificate scanning. Values represent requests per minute.
        Examples:
        - 60 = 1 request per second
        - 30 = 1 request every 2 seconds
        - 120 = 2 requests per second
        """)
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
        st.subheader("Internal Domain Settings")
        st.markdown("""
        Settings for internal domains (e.g., `.local`, `.lan`, `.internal`, `.corp`).
        """)
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
        internal_domains = st.text_area(
            "Custom Internal Domains (one per line)",
            value="\n".join(settings.get("scanning.internal.domains", [])),
            help="List of custom internal domain patterns (e.g., .internal.company.com)"
        )
        st.subheader("External Domain Settings")
        st.markdown("""
        Settings for external domains (e.g., `.com`, `.org`, `.net`).
        """)
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
        external_domains = st.text_area(
            "Custom External Domains (one per line)",
            value="\n".join(settings.get("scanning.external.domains", [])),
            help="List of custom external domain patterns"
        )
        st.divider()
        st.subheader("Additional Rate Limits")
        st.markdown("""
        Configure rate limits for additional scanning operations. Values represent requests per minute.
        Examples:
        - 10 = 1 request every 6 seconds
        - 30 = 1 request every 2 seconds
        - 60 = 1 request per second
        """)
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
        # Global CT enable/disable option
        ct_enabled = settings.get("scanning.ct.enabled", True)
        enable_ct_checkbox = st.checkbox(
            "Enable Certificate Transparency (CT) for Subdomain Discovery (Global Default)",
            value=ct_enabled,
            help="If disabled, CT logs will not be used for subdomain discovery unless overridden in the scan UI."
        )
        st.divider()
        st.subheader("Timeout Settings")
        st.markdown("""
        Configure timeout values for various operations (in seconds).
        These settings control how long to wait for responses before giving up:
        - Socket timeout: How long to wait for initial connection
        - Request timeout: How long to wait for HTTP/HTTPS responses
        - DNS timeout: How long to wait for DNS responses
        """)
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
        if st.button("Save Scanning Settings"):
            if default_rate_limit < 1 or internal_rate_limit < 1 or external_rate_limit < 1 or whois_rate_limit < 1 or dns_rate_limit < 1 or ct_rate_limit < 1:
                notify("Invalid rate limit: All rate limits must be at least 1", "error")
                return
            success = SettingsService.save_scanning_settings(
                settings,
                default_rate_limit,
                internal_rate_limit,
                [d.strip() for d in internal_domains.split("\n") if d.strip()],
                external_rate_limit,
                [d.strip() for d in external_domains.split("\n") if d.strip()],
                whois_rate_limit,
                dns_rate_limit,
                ct_rate_limit,
                socket_timeout,
                request_timeout,
                dns_timeout,
                ct_enabled=enable_ct_checkbox
            )
            if success:
                notify("Scanning settings updated successfully!", "success")
            else:
                notify("Failed to save scanning settings", "error")

    # Alert Settings Tab
    with tabs[2]:
        st.header("Alert Settings")
        st.subheader("Certificate Expiry Warnings")
        expiry_warnings = settings.get("alerts.expiry_warnings", [
            {"days": 60, "level": "critical"},
            {"days": 30, "level": "warning"}
        ])
        updated_warnings = []
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
        if st.button("Add Expiry Warning"):
            expiry_warnings.append({"days": 30, "level": "warning"})
            st.rerun()
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
        if st.button("Save Alert Settings"):
            success = SettingsService.save_alert_settings(settings, updated_warnings, consecutive_failures)
            if success:
                notify("Alert settings updated successfully!", "success")
            else:
                notify("Failed to save alert settings", "error")

    # Export Settings Tab
    with tabs[3]:
        st.header("Export Settings")
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
            success = SettingsService.save_export_settings(settings, csv_delimiter, csv_encoding)
            if success:
                notify("Export settings updated successfully!", "success")
            else:
                notify("Failed to save export settings", "error")
        st.divider()
        st.subheader("Generate Reports")
        col1, col2 = st.columns(2)
        with col1:
            st.write("Certificate Reports")
            if st.button("Export Certificates to CSV"):
                success, result = SettingsService.export_certificates_to_csv(engine)
                if success:
                    notify(f"Certificates exported to CSV: {result}", "success")
                else:
                    notify(f"Failed to export certificates to CSV: {result}", "error")
            if st.button("Export Certificates to PDF"):
                success, result = SettingsService.export_certificates_to_pdf(engine)
                if success:
                    notify(f"Certificates exported to PDF: {result}", "success")
                else:
                    notify(f"Failed to export certificates to PDF: {result}", "error")
        with col2:
            st.write("Host Reports")
            if st.button("Export Hosts to CSV"):
                success, result = SettingsService.export_hosts_to_csv(engine)
                if success:
                    notify(f"Hosts exported to CSV: {result}", "success")
                else:
                    notify(f"Failed to export hosts to CSV: {result}", "error")
            if st.button("Export Hosts to PDF"):
                success, result = SettingsService.export_hosts_to_pdf(engine)
                if success:
                    notify(f"Hosts exported to PDF: {result}", "success")
                else:
                    notify(f"Failed to export hosts to PDF: {result}", "error")

    # Ignore Lists Tab
    with tabs[4]:
        st.header("Ignore Lists")
        ignore_tabs = st.tabs(["🚫 Domains", "🔒 Certificates"])
        # Ignored Domains tab
        with ignore_tabs[0]:
            st.subheader("Ignored Domains")
            st.markdown("""
            Add domains or patterns to ignore during scanning. Supports:
            - Exact matches (e.g., test.example.com)
            - Wildcard patterns (e.g., *.test.com)
            """)
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
                        success, message = SettingsService.add_ignored_domain(engine, new_domain_pattern, domain_reason)
                        if success:
                            notify(message, "success")
                            st.rerun()
                        else:
                            notify(message, "error")
                    else:
                        notify("Please enter a domain pattern", "error")
            st.divider()
            try:
                ignored_domains = SettingsService.get_ignored_domains(engine)
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
                                success, message = SettingsService.remove_ignored_domain(engine, domain.id)
                                if success:
                                    notify(message, "success")
                                    st.rerun()
                                else:
                                    notify(message, "error")
                else:
                    notify("No custom ignored domains configured.", "info")
            except Exception as e:
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
            """)
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
                        success, message = SettingsService.add_ignored_certificate(engine, new_pattern, cert_reason)
                        if success:
                            notify(message, "success")
                            st.rerun()
                        else:
                            notify(message, "error")
                    else:
                        notify("Please enter a certificate pattern", "error")
            st.divider()
            try:
                ignored_certs = SettingsService.get_ignored_certificates(engine)
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
                                success, message = SettingsService.remove_ignored_certificate(engine, cert.id)
                                if success:
                                    notify(message, "success")
                                    st.rerun()
                                else:
                                    notify(message, "error")
                else:
                    notify("No ignored certificate patterns configured.", "info")
            except Exception as e:
                notify(f"Error loading ignored certificates: {str(e)}", "error")

    render_backup_restore_section(engine, settings)
    show_notifications()

def render_backup_restore_section(engine, settings):
    st.subheader("Backup and Restore")
    col1, col2 = st.columns(2)
    with col1:
        st.write("Create Backup")
        if st.button("Create Backup"):
            success, message = create_backup()
            if success:
                notify(message, "success")
            else:
                notify(message, "error")
    with col2:
        st.write("Available Backups")
        try:
            backups = SettingsService.list_backups(settings)
            if not backups:
                notify("No backups available.", "info")
            else:
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
                    selected_idx = backup_options.index(selected_backup)
                    manifest_file = backups[selected_idx]["manifest_file"]
                    success, message = SettingsService.restore_backup(manifest_file, settings)
                    if success:
                        notify(message, "success")
                    else:
                        notify(message, "error")
        except Exception as e:
            notify(f"Error loading backups: {str(e)}", "error") 