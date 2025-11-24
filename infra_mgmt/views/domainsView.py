"""
Domain management view for the Certificate Management System.

This module provides the UI components and logic for managing domains, including:
- Listing all domains and their properties
- Viewing domain details
- Viewing certificate associations
- Viewing DNS records
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy import or_
from sqlalchemy.orm import Session
from collections import defaultdict
import logging

from ..models import Domain, DomainDNSRecord, Certificate, IgnoredDomain
from ..components.deletion_dialog import render_danger_zone
from ..notifications import notify, show_notifications, initialize_page_notifications, clear_page_notifications
from ..services.DomainService import DomainService, VirtualDomain
from ..services.ViewDataService import ViewDataService
from infra_mgmt.utils.SessionManager import SessionManager
from ..static.styles import load_warning_suppression, load_css
from infra_mgmt.components.page_header import render_page_header
from infra_mgmt.components.metrics_row import render_metrics_row

logger = logging.getLogger(__name__)

DOMAINS_PAGE_KEY = "domains" # Define page key


def _render_domain_list(organized_domains, selected_domain):
    """
    Render a clean, organized domain list grouped by root domains.

    Args:
        organized_domains: List of domain info dicts from DomainService
        selected_domain: Currently selected domain name
    """
    if not organized_domains:
        st.info("No domains to display.")
        return

    # Group domains by root domain for better organization
    root_groups = {}
    for item in organized_domains:
        root = item['root_group']
        if root not in root_groups:
            root_groups[root] = []
        root_groups[root].append(item)

    # Display each root domain group in expanders
    for root_name, domains_in_group in root_groups.items():
        # Create expander for each root domain
        domain_count = len(domains_in_group)

        with st.expander(f"🌐 {root_name} ({domain_count} domain{'s' if domain_count != 1 else ''})", expanded=False):
            # Display domains in this group
            for item in domains_in_group:
                domain = item['domain']
                indent_level = item['indent_level']

                # Create status indicator (only show problems)
                status_indicator = ""
                status_color = ""
                if domain.expiration_date:
                    if domain.expiration_date <= datetime.now():
                        status_indicator = "🔴 Expired"
                        status_color = "red"
                    elif domain.expiration_date <= datetime.now() + timedelta(days=30):
                        status_indicator = "🟡 Expiring Soon"
                        status_color = "orange"

                # Create display name with indentation
                indent = "  " * indent_level if indent_level > 0 else ""
                domain_name = domain.domain_name

                # Create columns for domain name and status
                col1, col2 = st.columns([0.7, 0.3])

                with col1:
                    display_name = f"{indent}• {domain_name}"
                    if selected_domain == domain.domain_name:
                        # Selected domain - styled as selected with good contrast
                        st.markdown(f'<div style="background-color: #e6f7ff; padding: 8px; border-radius: 4px; border-left: 4px solid #1890ff; margin: 2px 0; color: #001529;"><strong>{display_name}</strong></div>', unsafe_allow_html=True)
                    else:
                        # Unselected domain - normal button
                        if st.button(display_name, key=f"domain_{domain.domain_name.replace('.', '_')}", use_container_width=True, help=f"Click to view details for {domain_name}"):
                            st.session_state['domain_selection'] = domain.domain_name
                            st.rerun()

                with col2:
                    if status_indicator:
                        st.markdown(f"<span style='color: {status_color};'>{status_indicator}</span>", unsafe_allow_html=True)
                    else:
                        st.markdown("")

def _render_domain_details(domain, visible_domains, engine):
    """
    Render detailed information for a selected domain.

    Args:
        domain: Domain object to display
        visible_domains: List of all visible domains for context
        engine: SQLAlchemy engine
    """
    st.subheader(f"🌐 {domain.domain_name}")

    # Domain Information Section
    st.markdown("### 📋 Domain Information")
    col1, col2 = st.columns(2)

    with col1:
        # Get root domain info for display
        root_domain = DomainService.get_root_domain_info(domain.domain_name, visible_domains)
        display_domain = root_domain if root_domain else domain

        if root_domain and root_domain != domain:
            st.markdown(f"**Root Domain:** `{root_domain.domain_name}`")

        st.markdown(f"**Registrar:** {display_domain.registrar or 'N/A'}")
        st.markdown(f"**Registration Date:** {display_domain.registration_date.strftime('%Y-%m-%d') if display_domain.registration_date else 'N/A'}")
        st.markdown(f"**Owner:** {display_domain.owner or 'N/A'}")

    with col2:
        # Status and dates
        exp_date = display_domain.expiration_date
        if exp_date:
            if exp_date <= datetime.now():
                status_color = "🔴"
                status_text = "Expired"
            elif exp_date <= datetime.now() + timedelta(days=30):
                status_color = "🟡"
                status_text = "Expiring Soon"
            else:
                status_color = "🟢"
                status_text = "Active"
            st.markdown(f"**Status:** {status_color} {status_text}")
            st.markdown(f"**Expiration Date:** {exp_date.strftime('%Y-%m-%d')}")
        else:
            st.markdown("**Status:** ⚪ Unknown")
            st.markdown("**Expiration Date:** N/A")

        st.markdown(f"**Last Updated:** {domain.updated_at.strftime('%Y-%m-%d %H:%M')}")

    st.markdown("---")

    # Certificates Section
    st.markdown("### 🔒 Certificates")
    if domain.certificates and len(domain.certificates) > 0:
        for cert in domain.certificates:
            st.markdown(f"#### `{cert.common_name}`")

            cert_col1, cert_col2 = st.columns(2)
            with cert_col1:
                st.markdown(f"**Valid From:** {cert.valid_from.strftime('%Y-%m-%d')}")
                st.markdown(f"**Valid Until:** {cert.valid_until.strftime('%Y-%m-%d')}")
                st.markdown(f"**Serial Number:** `{cert.serial_number}`")

            with cert_col2:
                issuer_cn = cert.issuer.get('CN', 'Unknown') if cert.issuer else 'Unknown'
                st.markdown(f"**Issuer:** {issuer_cn}")
                chain_status = "✅ Valid" if cert.chain_valid else "❌ Invalid"
                st.markdown(f"**Chain Status:** {chain_status}")
                st.markdown(f"**Signature Algorithm:** {cert.signature_algorithm}")

            if cert.san:
                st.markdown(f"**SANs:** {', '.join(f'`{san}`' for san in cert.san)}")

            st.markdown("---")
    else:
        st.info("No certificates found for this domain.")

    st.markdown("---")

    # DNS Records Section
    st.markdown("### 🌐 DNS Records")
    if domain.dns_records and len(domain.dns_records) > 0:
        records_data = []
        for record in domain.dns_records:
            records_data.append({
                'Type': record.record_type,
                'Name': record.name,
                'Value': record.value,
                'TTL': record.ttl,
                'Priority': record.priority if record.priority is not None else 'N/A'
            })

        if records_data:
            st.dataframe(
                pd.DataFrame(records_data),
                hide_index=True,
                use_container_width=True
            )
    else:
        st.info("No DNS records found for this domain.")

    st.markdown("---")

    # Danger Zone
    st.markdown("### ⚠️ Danger Zone")
    st.markdown("**Domain Management Actions**")

    # Check for child domains
    child_domains_info = DomainService.get_child_domains_for_display(engine, domain.id)
    has_child_domains = child_domains_info.get('success', False) and child_domains_info.get('count', 0) > 0

    dependencies = {
        "Certificates": [cert.common_name for cert in domain.certificates] if domain.certificates else [],
        "DNS Records": [f"{r.record_type} {r.name}" for r in domain.dns_records] if domain.dns_records else [],
    }

    # Add recursive deletion option if child domains exist
    recursive_delete = False
    if has_child_domains:
        st.warning(f"⚠️ This domain has {child_domains_info['count']} child domain(s).")
        recursive_delete = st.checkbox(
            f"Also delete {child_domains_info['count']} child domain(s)",
            key=f"recursive_delete_{domain.id}",
            help="When enabled, all subdomains will be deleted along with this domain"
        )
        if recursive_delete and child_domains_info.get('children'):
            st.markdown("**Child domains that will be deleted:**")
            for child_name in child_domains_info['children']:
                st.markdown(f"- `{child_name}`")

    def delete_domain_handler(session=None):
        result = DomainService.delete_domain_by_id(engine, domain.id, recursive=recursive_delete)
        if result['success']:
            deleted_count = result.get('deleted_count', 1)
            if deleted_count > 1:
                notify(f"Successfully deleted {deleted_count} domain(s) (including {deleted_count - 1} child domain(s))", "success", page_key=DOMAINS_PAGE_KEY)
            else:
                notify(f"Domain '{domain.domain_name}' deleted successfully", "success", page_key=DOMAINS_PAGE_KEY)
            st.rerun()
            return True
        else:
            error_msg = result.get('error', 'Unknown error')
            logger.exception(f"Error deleting domain: {error_msg}")
            notify(f"Error deleting domain: {error_msg}", "error", page_key=DOMAINS_PAGE_KEY)
            return False

    def add_to_ignore_list_handler(_):
        result = DomainService.add_to_ignore_list_by_name(engine, domain.domain_name)
        if result['success']:
            notify(f"Added '{domain.domain_name}' to ignore list", "success", page_key=DOMAINS_PAGE_KEY)
            st.rerun()
        else:
            notify(result['error'], "warning", page_key=DOMAINS_PAGE_KEY)
            logger.warning(result['error'])

    render_danger_zone(
        title="Domain Management",
        entity_name=domain.domain_name,
        entity_type="domain",
        dependencies=dependencies,
        on_delete=delete_domain_handler,
        session=None,
        additional_actions=[{
            "title": "🚫 Ignore Domain",
            "callback": add_to_ignore_list_handler,
            "warning": f"This will hide '{domain.domain_name}' from the domain list. You can restore it later from the settings page.",
            "confirmation_required": True,
            "confirmation_text": f"ignore {domain.domain_name}"
        }]
    )

def render_domain_list(engine):
    """
    Render the main domain management interface.

    This function displays:
    - Domain overview statistics
    - Clean list of domains organized by root domain
    - Domain details view
    """
    load_warning_suppression()
    load_css()

    render_page_header(title="Domain Management")
    # Initialize notifications for this page
    initialize_page_notifications(DOMAINS_PAGE_KEY)

    # Create notification placeholder at the top
    notification_placeholder = st.empty()
    with notification_placeholder.container():
        show_notifications(DOMAINS_PAGE_KEY)

    # Create a search box
    search = st.text_input("Search Domains", placeholder="Enter domain name...", key="domain_search")

    # Clear domain selection if search has changed
    if 'last_search' not in st.session_state:
        st.session_state['last_search'] = search
    elif st.session_state['last_search'] != search:
        st.session_state['domain_selection'] = None
        st.session_state['last_search'] = search

    # Use service to get filtered domains for UI
    result = DomainService.get_filtered_domains_for_ui(engine, search)
    if not result['success']:
        notify(result['error'], "error", page_key=DOMAINS_PAGE_KEY)
        return

    data = result['data']
    organized_domains = data['domains']
    visible_domains = data['visible_domains']
    filtered_domains = data['filtered_domains']
    metrics = data['metrics']

    if not visible_domains:
        notify("No domains found in the database.", "info", page_key=DOMAINS_PAGE_KEY)
        return

    # Render metrics
    render_metrics_row([
        {"label": "Total Domains", "value": metrics["total_domains"]},
        {"label": "Active Domains", "value": metrics["active_domains"]},
        {"label": "Expiring Soon", "value": metrics["expiring_soon"]},
        {"label": "Expired", "value": metrics["expired"]},
    ], columns=4)

    if not filtered_domains:
        notify("No domains match your search.", "info", page_key=DOMAINS_PAGE_KEY)
        return

    # Create two columns: domain list and details
    col_list, col_details = st.columns([1, 2])

    with col_list:
        st.subheader("Domains")

        # Initialize session state for domain selection
        if 'domain_selection' not in st.session_state:
            st.session_state['domain_selection'] = None

        selected_domain = st.session_state['domain_selection']

        # Render clean domain list
        _render_domain_list(organized_domains, selected_domain)

        # Get the current selected domain object
        if st.session_state['domain_selection']:
            selected_domain_name = st.session_state['domain_selection']
            selected_domain_obj = next(
                (item['domain'] for item in organized_domains if item['domain'].domain_name == selected_domain_name),
                None
            )
        else:
            selected_domain_obj = None

    with col_details:
        if selected_domain_obj:
            _render_domain_details(selected_domain_obj, visible_domains, engine)
        else:
            st.info("Select a domain from the list to view details.")