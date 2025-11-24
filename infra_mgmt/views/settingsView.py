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
  - Export settings (CSV configuration)
- Backup Management:
  - Create system backups (database and configuration)
  - List available backups
  - Restore from backups
  - Backup verification and validation
- Export Capabilities:
  - Certificate exports (CSV)
  - Host exports (CSV)
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
from infra_mgmt.notifications import initialize_page_notifications, show_notifications, notify, clear_page_notifications
from ..static.styles import load_warning_suppression, load_css
from ..db.engine import get_cache_manager, is_cache_enabled, force_sync, get_sync_status
from sqlalchemy.engine import Engine
from datetime import datetime
import re
from infra_mgmt.components.page_header import render_page_header

logger = logging.getLogger(__name__)

SETTINGS_PAGE_KEY = "settings"

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
                - Certificate exports (CSV)
                - Host exports (CSV)
                - Real-time export generation

    The interface provides immediate feedback for all operations and
    includes comprehensive error handling and validation for all
    settings changes.
    """
    load_warning_suppression()
    load_css()
    clear_page_notifications(SETTINGS_PAGE_KEY)  # Clear notifications at the start
    initialize_page_notifications(SETTINGS_PAGE_KEY)
    render_page_header(title="Settings")
    
    # Create a placeholder for notifications at the top of settings page
    notification_placeholder = st.empty()
    with notification_placeholder.container():
        show_notifications(SETTINGS_PAGE_KEY)
 
    settings = Settings()
    tabs = st.tabs([
        "Paths", "Scanning", "Alerts", "Exports", "Ignore Lists", "Proxy Detection", "Cache", "Backup & Restore"
    ])

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
            clear_page_notifications(SETTINGS_PAGE_KEY)
            success = SettingsService.save_path_settings(settings, database_path, backup_path)
            if success:
                notify("Path settings updated successfully!", "success", page_key=SETTINGS_PAGE_KEY)
            else:
                notify("Failed to save path settings", "error", page_key=SETTINGS_PAGE_KEY)

    # Scanning Settings Tab
    with tabs[1]:
        st.header("Scanning Settings")
        
        # Offline Mode Toggle
        offline_mode_enabled = settings.get("scanning.offline_mode", False)
        offline_mode_checkbox = st.checkbox(
            "Enable Offline Scanning Mode (disables external lookups like CT logs, public Whois)",
            value=offline_mode_enabled,
            help="If enabled, scans will not attempt to reach external services for information like Certificate Transparency logs or public Whois records."
        )
        st.markdown("---")
        
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
            notify("Invalid default rate limit value, using default: 60", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid internal rate limit value, using default: 60", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid external rate limit value, using default: 30", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid WHOIS rate limit value, using default: 10", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid DNS rate limit value, using default: 30", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid CT rate limit value, using default: 10", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid socket timeout value, using default: 10", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid request timeout value, using default: 15", "warning", page_key=SETTINGS_PAGE_KEY)
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
            notify("Invalid DNS timeout value, using default: 5.0", "warning", page_key=SETTINGS_PAGE_KEY)
        if st.button("Save Scanning Settings"):
            clear_page_notifications(SETTINGS_PAGE_KEY)
            if default_rate_limit < 1 or internal_rate_limit < 1 or external_rate_limit < 1 or whois_rate_limit < 1 or dns_rate_limit < 1 or ct_rate_limit < 1:
                notify("Invalid rate limit: All rate limits must be at least 1", "error", page_key=SETTINGS_PAGE_KEY)
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
                ct_enabled=enable_ct_checkbox,
                offline_mode=offline_mode_checkbox
            )
            if success:
                notify("Scanning settings updated successfully!", "success", page_key=SETTINGS_PAGE_KEY)
            else:
                notify("Failed to save scanning settings", "error", page_key=SETTINGS_PAGE_KEY)

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
            notify("Invalid consecutive failures value, using default: 3", "warning", page_key=SETTINGS_PAGE_KEY)
        if st.button("Save Alert Settings"):
            clear_page_notifications(SETTINGS_PAGE_KEY)
            success = SettingsService.save_alert_settings(settings, updated_warnings, consecutive_failures)
            if success:
                notify("Alert settings updated successfully!", "success", page_key=SETTINGS_PAGE_KEY)
            else:
                notify("Failed to save alert settings", "error", page_key=SETTINGS_PAGE_KEY)

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
            clear_page_notifications(SETTINGS_PAGE_KEY)
            success = SettingsService.save_export_settings(settings, csv_delimiter, csv_encoding)
            if success:
                notify("Export settings updated successfully!", "success", page_key=SETTINGS_PAGE_KEY)
            else:
                notify("Failed to save export settings", "error", page_key=SETTINGS_PAGE_KEY)
        st.divider()
        st.subheader("Generate Reports")
        
        # Initialize session state for export files if not exists
        if 'export_cert_csv' not in st.session_state:
            st.session_state.export_cert_csv = None
        if 'export_host_csv' not in st.session_state:
            st.session_state.export_host_csv = None
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("Certificate Reports")
            if st.button("Export Certificates to CSV"):
                clear_page_notifications(SETTINGS_PAGE_KEY)
                success, result = SettingsService.export_certificates_to_csv(engine)
                if success:
                    file_data, filename = result
                    st.session_state.export_cert_csv = (file_data, filename)
                    notify(f"Certificates exported to CSV: {filename}", "success", page_key=SETTINGS_PAGE_KEY)
                else:
                    st.session_state.export_cert_csv = None
                    notify(f"Failed to export certificates to CSV: {result}", "error", page_key=SETTINGS_PAGE_KEY)
            
            # Show download button if file is available
            if st.session_state.export_cert_csv is not None:
                file_data, filename = st.session_state.export_cert_csv
                st.download_button(
                    label="📥 Download Certificates CSV",
                    data=file_data,
                    file_name=filename,
                    mime="text/csv",
                    key="download_cert_csv"
                )
        with col2:
            st.write("Host Reports")
            if st.button("Export Hosts to CSV"):
                clear_page_notifications(SETTINGS_PAGE_KEY)
                success, result = SettingsService.export_hosts_to_csv(engine)
                if success:
                    file_data, filename = result
                    st.session_state.export_host_csv = (file_data, filename)
                    notify(f"Hosts exported to CSV: {filename}", "success", page_key=SETTINGS_PAGE_KEY)
                else:
                    st.session_state.export_host_csv = None
                    notify(f"Failed to export hosts to CSV: {result}", "error", page_key=SETTINGS_PAGE_KEY)
            
            # Show download button if file is available
            if st.session_state.export_host_csv is not None:
                file_data, filename = st.session_state.export_host_csv
                st.download_button(
                    label="📥 Download Hosts CSV",
                    data=file_data,
                    file_name=filename,
                    mime="text/csv",
                    key="download_host_csv"
                )

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
                    clear_page_notifications(SETTINGS_PAGE_KEY)
                    if new_domain_pattern:
                        success, message = SettingsService.add_ignored_domain(engine, new_domain_pattern, domain_reason)
                        if success:
                            notify(message, "success", page_key=SETTINGS_PAGE_KEY)
                            st.rerun()
                        else:
                            notify(message, "error", page_key=SETTINGS_PAGE_KEY)
                    else:
                        notify("Please enter a domain pattern", "error", page_key=SETTINGS_PAGE_KEY)
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
                                clear_page_notifications(SETTINGS_PAGE_KEY)
                                success, message = SettingsService.remove_ignored_domain(engine, domain.id)
                                if success:
                                    notify(message, "success", page_key=SETTINGS_PAGE_KEY)
                                    st.rerun()
                                else:
                                    notify(message, "error", page_key=SETTINGS_PAGE_KEY)
                else:
                    notify("No custom ignored domains configured.", "info", page_key=SETTINGS_PAGE_KEY)
            except Exception as e:
                notify(f"Error loading ignored domains: {str(e)}", "error", page_key=SETTINGS_PAGE_KEY)
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
                    clear_page_notifications(SETTINGS_PAGE_KEY)
                    if new_pattern:
                        success, message = SettingsService.add_ignored_certificate(engine, new_pattern, cert_reason)
                        if success:
                            notify(message, "success", page_key=SETTINGS_PAGE_KEY)
                            st.rerun()
                        else:
                            notify(message, "error", page_key=SETTINGS_PAGE_KEY)
                    else:
                        notify("Please enter a certificate pattern", "error", page_key=SETTINGS_PAGE_KEY)
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
                                clear_page_notifications(SETTINGS_PAGE_KEY)
                                success, message = SettingsService.remove_ignored_certificate(engine, cert.id)
                                if success:
                                    notify(message, "success", page_key=SETTINGS_PAGE_KEY)
                                    st.rerun()
                                else:
                                    notify(message, "error", page_key=SETTINGS_PAGE_KEY)
                else:
                    notify("No ignored certificate patterns configured.", "info", page_key=SETTINGS_PAGE_KEY)
            except Exception as e:
                notify(f"Error loading ignored certificates: {str(e)}", "error", page_key=SETTINGS_PAGE_KEY)

    # Proxy Detection Tab
    with tabs[5]:
        st.header("Proxy Detection Settings")
        try:
            # Use correct keys with "ca_" prefix
            current_fingerprints = settings.get("proxy_detection.ca_fingerprints", [])
            current_subjects = settings.get("proxy_detection.ca_subjects", [])
            current_serials = settings.get("proxy_detection.ca_serials", [])
            proxy_enabled = settings.get("proxy_detection.enabled", True)
            summary_md = f"""
**Proxy Detection Enabled:** {proxy_enabled}
**Known Proxy CA Fingerprints:** {len(current_fingerprints)} configured  
**Known Proxy CA Subjects:** {len(current_subjects)} configured  
**Known Proxy CA Serial Numbers:** {len(current_serials)} configured  
"""
            st.info(summary_md)
        except Exception as e:
            notify(f"Could not display proxy detection summary: {e}", "warning", page_key=SETTINGS_PAGE_KEY)

        st.markdown("""
        Configure detection of proxy/MITM certificates. If enabled, the system will check scanned certificates against known proxy CA fingerprints, subjects, and serial numbers.
        """)
        proxy_enabled = st.checkbox(
            "Enable Proxy Detection",
            value=settings.get("proxy_detection.enabled", True),
            help="If disabled, proxy/MITM detection will not be performed."
        )
        ca_fingerprints = st.text_area(
            "Known Proxy CA Fingerprints (one per line, SHA256)",
            value="\n".join(current_fingerprints) if current_fingerprints else "",
            help="Add SHA256 fingerprints of known proxy CA certificates. One per line."
        )
        ca_subjects = st.text_area(
            "Known Proxy CA Subjects (one per line)",
            value="\n".join(current_subjects) if current_subjects else "",
            help="Add subject strings of known proxy CA certificates. One per line."
        )
        ca_serials = st.text_area(
            "Known Proxy CA Serial Numbers (one per line)",
            value="\n".join(current_serials) if current_serials else "",
            help="Add serial numbers of known proxy CA certificates. One per line."
        )
        if st.button("Save Proxy Detection Settings"):
            clear_page_notifications(SETTINGS_PAGE_KEY)
            try:
                # Get other proxy detection settings to preserve them
                bypass_external = settings.get("proxy_detection.bypass_external", False)
                bypass_patterns = settings.get("proxy_detection.bypass_patterns", [])
                proxy_hostnames = settings.get("proxy_detection.proxy_hostnames", [])
                enable_hostname_validation = settings.get("proxy_detection.enable_hostname_validation", True)
                enable_authenticity_validation = settings.get("proxy_detection.enable_authenticity_validation", True)
                warn_on_proxy_detection = settings.get("proxy_detection.warn_on_proxy_detection", True)
                
                success = SettingsService.save_proxy_detection_settings(
                    settings,
                    proxy_enabled,
                    [f.strip() for f in ca_fingerprints.split("\n") if f.strip()],
                    [s.strip() for s in ca_subjects.split("\n") if s.strip()],
                    [sn.strip() for sn in ca_serials.split("\n") if sn.strip()],
                    bypass_external=bypass_external,
                    bypass_patterns=bypass_patterns,
                    proxy_hostnames=proxy_hostnames,
                    enable_hostname_validation=enable_hostname_validation,
                    enable_authenticity_validation=enable_authenticity_validation,
                    warn_on_proxy_detection=warn_on_proxy_detection
                )
                if success:
                    notify("Proxy detection settings updated successfully!", "success", page_key=SETTINGS_PAGE_KEY)
                    st.rerun()  # Refresh the page to show updated values
                else:
                    notify("Failed to save proxy detection settings", "error", page_key=SETTINGS_PAGE_KEY)
            except Exception as e:
                notify(f"Error saving proxy detection settings: {str(e)}", "error", page_key=SETTINGS_PAGE_KEY)

    # Cache Management Tab
    with tabs[6]:
        render_cache_management_section(engine, settings)

    # Backup & Restore Tab
    with tabs[7]:
        render_backup_restore_section(engine, settings)

def render_cache_management_section(engine, settings):
    """Render the cache management section."""
    st.subheader("Database Cache Management")
    
    # Check if cache is enabled
    if not is_cache_enabled():
        notify("⚠️ Database caching is not enabled", "warning", page_key=SETTINGS_PAGE_KEY)
        notify(
            """
Caching is only enabled when:
- The database path is a network (UNC) path
- Cache initialization was successful

To enable caching, ensure your database is located on a network share.
            """,
            "info",
            page_key=SETTINGS_PAGE_KEY
        )
        return
    
    # Get cache manager
    cache_manager = get_cache_manager()
    if not cache_manager:
        notify("❌ Cache manager not available", "error", page_key=SETTINGS_PAGE_KEY)
        return
    
    # Cache status overview
    st.markdown("### 📊 Cache Status")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Sync Status",
            value=cache_manager.sync_status.value.upper(),
            delta=None
        )
    
    with col2:
        st.metric(
            label="Pending Writes",
            value=len(cache_manager.pending_writes),
            delta=None
        )
    
    with col3:
        if cache_manager.last_sync:
            st.metric(
                label="Last Sync",
                value=cache_manager.last_sync.strftime("%H:%M:%S"),
                delta=None
            )
        else:
            st.metric(
                label="Last Sync",
                value="Never",
                delta=None
            )
    
    with col4:
        st.metric(
            label="Sync Interval",
            value=f"{cache_manager.sync_interval}s",
            delta=None
        )
    
    st.markdown("---")
    
    # Network status
    st.markdown("### 🌐 Network Status")
    
    network_available = cache_manager._is_network_available()
    if network_available:
        notify("✅ Network connection available", "success", page_key=SETTINGS_PAGE_KEY)
    else:
        notify("❌ Network connection unavailable - operating in offline mode", "error", page_key=SETTINGS_PAGE_KEY)
    
    st.markdown("---")
    
    # Manual sync controls
    st.markdown("### 🔄 Manual Sync")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔄 Force Sync Now", type="primary"):
            with st.spinner("Syncing..."):
                result = force_sync()
                if result:
                    if result.status.value == "success":
                        notify(f"Sync completed successfully! {result.records_synced} records synced.", 
                              "success", page_key=SETTINGS_PAGE_KEY)
                    else:
                        notify(f"Sync failed: {result.errors[0] if result.errors else 'Unknown error'}", 
                              "error", page_key=SETTINGS_PAGE_KEY)
    
    with col2:
        if st.button("🗑️ Clear Cache"):
            if st.checkbox("I understand this will clear all local cached data"):
                with st.spinner("Clearing cache..."):
                    cache_manager.clear_cache()
                    notify("Cache cleared successfully!", "success", page_key=SETTINGS_PAGE_KEY)
    
    st.markdown("---")
    
    # Cache configuration
    st.markdown("### ⚙️ Cache Configuration")
    
    # Display current settings
    st.write("**Current Settings:**")
    st.write(f"- **Local Cache Path:** `{cache_manager.local_db_path}`")
    st.write(f"- **Remote Database Path:** `{cache_manager.remote_db_path}`")
    st.write(f"- **Sync Interval:** {cache_manager.sync_interval} seconds")
    
    # Sync interval adjustment
    st.write("**Adjust Sync Interval:**")
    new_interval = st.slider(
        "Sync Interval (seconds)",
        min_value=10,
        max_value=300,
        value=cache_manager.sync_interval,
        step=10,
        help="How often to sync with the remote database"
    )
    
    if new_interval != cache_manager.sync_interval:
        if st.button("Update Sync Interval"):
            cache_manager.sync_interval = new_interval
            notify(f"Sync interval updated to {new_interval} seconds", "success", page_key=SETTINGS_PAGE_KEY)
    
    st.markdown("---")
    
    # Recent sync history
    st.markdown("### 📋 Recent Sync History")
    
    if cache_manager.sync_results:
        # Create DataFrame for sync results
        import pandas as pd
        sync_data = []
        for result in cache_manager.sync_results[-10:]:  # Last 10 results
            sync_data.append({
                'Timestamp': result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'Status': result.status.value.upper(),
                'Records Synced': result.records_synced,
                'Conflicts Resolved': result.conflicts_resolved,
                'Duration (s)': f"{result.duration:.2f}",
                'Errors': '; '.join(result.errors) if result.errors else 'None'
            })
        
        df = pd.DataFrame(sync_data)
        st.dataframe(df, use_container_width=True)
    else:
        notify("No sync history available", "info", page_key=SETTINGS_PAGE_KEY)
    
    st.markdown("---")
    
    # Cache statistics
    st.markdown("### 📈 Cache Statistics")
    
    # Get sync status details
    status_details = get_sync_status()
    if status_details:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Sync Performance:**")
            if status_details.get('recent_results'):
                recent_results = status_details['recent_results']
                if recent_results:
                    avg_duration = sum(r.get('duration', 0) for r in recent_results) / len(recent_results)
                    st.write(f"- Average sync duration: {avg_duration:.2f} seconds")
                    
                    successful_syncs = sum(1 for r in recent_results if r.get('status') == 'success')
                    st.write(f"- Success rate: {successful_syncs}/{len(recent_results)} ({successful_syncs/len(recent_results)*100:.1f}%)")
        
        with col2:
            st.write("**Network Status:**")
            st.write(f"- Network available: {'Yes' if status_details.get('network_available') else 'No'}")
            st.write(f"- Pending writes: {status_details.get('pending_writes', 0)}")

def render_backup_restore_section(engine, settings):
    st.subheader("Backup and Restore")
    col1, col2 = st.columns(2)
    with col1:
        st.write("Create Backup")
        if st.button("Create Backup"):
            clear_page_notifications(SETTINGS_PAGE_KEY)
            success, message = create_backup()
            if success:
                notify(message, "success", page_key=SETTINGS_PAGE_KEY)
            else:
                notify(message, "error", page_key=SETTINGS_PAGE_KEY)
    with col2:
        st.write("Available Backups")
        try:
            backups = SettingsService.list_backups(settings)
            if not backups:
                notify("No backups available.", "info", page_key=SETTINGS_PAGE_KEY)
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
                    clear_page_notifications(SETTINGS_PAGE_KEY)
                    selected_idx = backup_options.index(selected_backup)
                    manifest_file = backups[selected_idx]["manifest_file"]
                    success, message = SettingsService.restore_backup(manifest_file, settings)
                    if success:
                        notify(message, "success", page_key=SETTINGS_PAGE_KEY)
                    else:
                        notify(message, "error", page_key=SETTINGS_PAGE_KEY)
        except Exception as e:
            notify(f"Error loading backups: {str(e)}", "error", page_key=SETTINGS_PAGE_KEY) 