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

def get_domain_hierarchy(domains):
    """
    Organize domains into a hierarchy of parent domains and subdomains.
    
    Args:
        domains: List of Domain objects
        
    Returns:
        tuple: (root_domains, hierarchy)
    """
    root_domains_dict = {}  # Store actual Domain objects for root domains
    domain_tree = defaultdict(list)  # Store domain hierarchy
    
    # First pass: identify all domains and their potential parents
    all_domain_names = {domain.domain_name for domain in domains}
    
    # Helper function to get parent domain name
    def get_parent_domain(domain_name):
        parts = domain_name.split('.')
        if len(parts) > 2:
            return '.'.join(parts[1:])  # Remove leftmost part
        return None
    
    # First, identify all potential parent domains
    potential_parents = set()
    for domain in domains:
        parent = get_parent_domain(domain.domain_name)
        if parent:
            potential_parents.add(parent)
    
    # Now organize domains
    for domain in domains:
        parent_name = get_parent_domain(domain.domain_name)
        if parent_name:
            # This is a subdomain
            if parent_name in all_domain_names:
                # Parent exists in our list
                domain_tree[parent_name].append(domain)
            else:
                # Parent doesn't exist in our list
                if parent_name in potential_parents:
                    # But it is a parent of another domain
                    domain_tree[parent_name].append(domain)
                else:
                    # No other domains share this parent
                    root_domains_dict[domain.domain_name] = domain
        else:
            # This is a root domain
            root_domains_dict[domain.domain_name] = domain
    
    # Add parent domains that don't exist in our database but have children
    for parent_name in potential_parents:
        if parent_name not in all_domain_names and domain_tree[parent_name]:
            # Create a "virtual" root domain for display purposes
            root_domains_dict[parent_name] = None
    
    # Sort subdomains within each parent
    for parent_name in domain_tree:
        domain_tree[parent_name].sort(key=lambda d: d.domain_name)
    
    # Convert root_domains_dict to sorted list, putting real domains first
    root_domains = sorted(
        [d for d in root_domains_dict.values() if d is not None],
        key=lambda d: d.domain_name
    )
    
    # Add virtual parent domains at the end
    virtual_roots = sorted(
        [name for name, d in root_domains_dict.items() if d is None]
    )
    for name in virtual_roots:
        root_domains.append(VirtualDomain(name))
    
    return root_domains, domain_tree

def get_root_domain_info(domain_name, domains):
    """
    Get registration information from the root domain.
    For example: w1.mercurypay.com would get info from mercurypay.com
    """
    parts = domain_name.split('.')
    if len(parts) > 2:
        root_name = '.'.join(parts[-2:])  # Get root domain (e.g., mercurypay.com)
        # Find the root domain in our domains list
        root_domain = next((d for d in domains if d.domain_name == root_name), None)
        return root_domain
    return None

def any_descendant_has_cert(domain, domain_hierarchy, visited=None):
    if visited is None:
        visited = set()
    if domain.domain_name in visited:
        return False  # Prevent infinite recursion
    visited.add(domain.domain_name)
    subdomains = domain_hierarchy.get(domain.domain_name, [])
    for sub in subdomains:
        if sub.certificates and len(sub.certificates) > 0:
            return True
        if any_descendant_has_cert(sub, domain_hierarchy, visited):
            return True
    return False

def should_notify_no_certificates(domain, domain_hierarchy):
    has_certs = bool(domain.certificates and len(domain.certificates) > 0)
    if has_certs:
        return False
    if domain.domain_name in domain_hierarchy and len(domain_hierarchy[domain.domain_name]) > 0:
        return not any_descendant_has_cert(domain, domain_hierarchy)
    return True

def render_domain_list(engine):
    """
    Render the main domain management interface.
    
    This function displays:
    - Domain overview statistics
    - List of domains with key information
    - Domain details view
    """
    load_warning_suppression()
    load_css()
    
    render_page_header(title="Domain Management")
    # Initialize notifications for this page
    initialize_page_notifications(DOMAINS_PAGE_KEY)
    # clear_page_notifications(DOMAINS_PAGE_KEY) # Clear if needed, or before specific actions
    
    # Create notification placeholder at the top
    notification_placeholder = st.empty()
    with notification_placeholder.container(): # Show notifications for this page
        show_notifications(DOMAINS_PAGE_KEY)
        
    view_data_service = ViewDataService()
    result = view_data_service.get_domain_list_view_data(engine)
    if not result['success']:
        notify(result['error'], "error", page_key=DOMAINS_PAGE_KEY)
        # show_notifications(DOMAINS_PAGE_KEY) # Handled by placeholder
        return
    visible_domains = result['data']['visible_domains']
    metrics = result['data']['metrics']
    ignored_patterns = result['data']['ignored_patterns']
    if not visible_domains:
        notify("No domains found in the database.", "info", page_key=DOMAINS_PAGE_KEY)
        # show_notifications(DOMAINS_PAGE_KEY) # Handled by placeholder
        return
    render_metrics_row([
        {"label": "Total Domains", "value": metrics["total_domains"]},
        {"label": "Active Domains", "value": metrics["active_domains"]},
        {"label": "Expiring Soon", "value": metrics["expiring_soon"]},
        {"label": "Expired", "value": metrics["expired"]},
    ], columns=4)
    # Create a search box
    search = st.text_input("Search Domains", placeholder="Enter domain name...")
    
    # Clear domain selection if search has changed
    if 'last_search' not in st.session_state:
        st.session_state['last_search'] = search
    elif st.session_state['last_search'] != search:
        st.session_state['domain_selection'] = None
        st.session_state['last_search'] = search
    
    # Use service to get filtered domains and hierarchy
    result = DomainService.get_filtered_domain_hierarchy(engine, search)
    if not result['success']:
        notify(result['error'], "error", page_key=DOMAINS_PAGE_KEY)
        # show_notifications(DOMAINS_PAGE_KEY) # Handled by placeholder
        return
    root_domains = result['data']['root_domains']
    domain_hierarchy = result['data']['domain_hierarchy']
    visible_domains = result['data']['visible_domains']
    metrics = result['data']['metrics']
    ignored_patterns = result['data']['ignored_patterns']
    # Create two columns: domain list and details
    col_list, col_details = st.columns([1, 2])
    
    with col_list:
        st.subheader("Domains")
        
        # Initialize session state for domain selection
        if 'domain_selection' not in st.session_state:
            st.session_state['domain_selection'] = None
        
        selected_domain = st.session_state['domain_selection']
        
        # Display all domains in consistent expanders
        for root in root_domains:
            parent_name = root.domain_name
            subdomains = domain_hierarchy.get(parent_name, [])
            
            if subdomains:
                # Create expander for parent domain with subdomains
                with st.expander(f"📁 {parent_name} ({len(subdomains)} subdomains)", expanded=False):
                    # Add parent domain as first option
                    subdomain_options = [parent_name] + [sub.domain_name for sub in subdomains]
                    
                    if selected_domain and selected_domain in subdomain_options:
                        default_index = subdomain_options.index(selected_domain)
                    else:
                        default_index = 0
                    
                    selected_subdomain = st.radio(
                        f"Select from {parent_name}",
                        options=subdomain_options,
                        index=default_index if subdomain_options else None,
                        label_visibility="collapsed",
                        key=f"parent_{parent_name.replace('.', '_')}"
                    )
                    
                    if selected_subdomain:
                        st.session_state['domain_selection'] = selected_subdomain
                        selected_domain = selected_subdomain
            else:
                # Create expander for standalone domain (no subdomains)
                with st.expander(f"🌐 {parent_name}", expanded=False):
                    if selected_domain and selected_domain == parent_name:
                        default_index = 0
                    else:
                        default_index = 0
                    
                    selected_standalone = st.radio(
                        f"Select {parent_name}",
                        options=[parent_name],
                        index=default_index,
                        label_visibility="collapsed",
                        key=f"standalone_{parent_name.replace('.', '_')}"
                    )
                    
                    if selected_standalone:
                        st.session_state['domain_selection'] = selected_standalone
                        selected_domain = selected_standalone
        
        # Update selected_domain from session state and validate it's still available
        if st.session_state['domain_selection']:
            selected_domain = st.session_state['domain_selection']
            
            # Check if selected domain is still available in filtered results
            all_available_domains = []
            for root in root_domains:
                all_available_domains.append(root.domain_name)
                subdomains = domain_hierarchy.get(root.domain_name, [])
                for sub in subdomains:
                    all_available_domains.append(sub.domain_name)
            
            if selected_domain not in all_available_domains:
                # Selected domain is no longer available, clear selection
                st.session_state['domain_selection'] = None
                selected_domain = None
        
        if not selected_domain and root_domains:
            # Auto-select first available domain if none selected
            selected_domain = root_domains[0].domain_name
            st.session_state['domain_selection'] = selected_domain
        
        if not root_domains:
            notify("No domains match your search.", "info", page_key=DOMAINS_PAGE_KEY)
            return
    
    with col_details:
        # Session-state-based fix for notification reset
        if 'last_selected_domain' not in st.session_state:
            st.session_state['last_selected_domain'] = None
        if selected_domain != st.session_state['last_selected_domain']:
            clear_page_notifications(DOMAINS_PAGE_KEY) # Clear when selection changes
            st.session_state['last_selected_domain'] = selected_domain
        if selected_domain:
            # Find the selected domain, handling both real and virtual domains
            try:
                domain = next(d for d in visible_domains if d.domain_name == selected_domain)
            except StopIteration:
                # If not found in filtered_domains, it might be a virtual domain
                domain = next((d for d in root_domains if d.domain_name == selected_domain), None)
            if domain:
                st.subheader(domain.domain_name)
                # Domain Information
                with st.expander("\U0001F310 Domain Information", expanded=True):
                    if not isinstance(domain, VirtualDomain):
                        col_info, col_actions = st.columns([3, 1])
                        with col_info:
                            root_domain = DomainService.get_root_domain_info(domain.domain_name, visible_domains)
                            display_domain = root_domain if root_domain else domain
                            if root_domain:
                                st.markdown("**Root Domain:** `{}`".format(root_domain.domain_name))
                            st.markdown("**Registrar:** {}".format(display_domain.registrar or "N/A"))
                            st.markdown("**Registration Date:** {}".format(
                                display_domain.registration_date.strftime("%Y-%m-%d") if display_domain.registration_date else "N/A"
                            ))
                            st.markdown("**Owner:** {}".format(display_domain.owner or "N/A"))
                            st.write("**Expiration Date:**", display_domain.expiration_date.strftime("%Y-%m-%d") if display_domain.expiration_date else "N/A")
                            st.write("**Status:**", "Active" if domain.is_active else "Inactive")
                            st.write("**Last Updated:**", domain.updated_at.strftime("%Y-%m-%d %H:%M"))
                    else:
                        col1, col2 = st.columns(2)
                        with col1:
                            root_domain = DomainService.get_root_domain_info(domain.domain_name, visible_domains)
                            display_domain = root_domain if root_domain else domain
                            if root_domain:
                                st.markdown("**Root Domain:** `{}`".format(root_domain.domain_name))
                            st.markdown("**Registrar:** {}".format(display_domain.registrar or "N/A"))
                            st.markdown("**Registration Date:** {}".format(
                                display_domain.registration_date.strftime("%Y-%m-%d") if display_domain.registration_date else "N/A"
                            ))
                            st.markdown("**Owner:** {}".format(display_domain.owner or "N/A"))
                        with col2:
                            st.write("**Expiration Date:**", display_domain.expiration_date.strftime("%Y-%m-%d") if display_domain.expiration_date else "N/A")
                            st.write("**Status:**", "Active" if domain.is_active else "Inactive")
                            st.write("**Last Updated:**", domain.updated_at.strftime("%Y-%m-%d %H:%M"))
                # Show subdomains if this is a root domain
                if domain.domain_name in domain_hierarchy:
                    st.markdown("### \U0001F501 Subdomains")
                    for subdomain in sorted(domain_hierarchy[domain.domain_name], key=lambda d: d.domain_name):
                        st.markdown(f"- `{subdomain.domain_name}`")
                # Only show certificates and DNS records for real domains
                if not isinstance(domain, VirtualDomain):
                    # --- Robust notification logic ---
                    if should_notify_no_certificates(domain, domain_hierarchy):
                        notify("No certificates found for this domain.", "info", page_key=DOMAINS_PAGE_KEY)
                    else:
                        st.markdown("### \U0001F510 Certificates")
                        for cert in domain.certificates:
                            st.markdown(f"#### Certificate: `{cert.common_name}`")
                            col1, col2 = st.columns(2)
                            with col1:
                                st.markdown("**Common Name:** `{}`".format(cert.common_name))
                                st.markdown("**Valid From:** {}".format(cert.valid_from.strftime("%Y-%m-%d")))
                                st.markdown("**Valid Until:** {}".format(cert.valid_until.strftime("%Y-%m-%d")))
                                st.markdown("**Serial Number:** {}".format(cert.serial_number))
                            with col2:
                                st.markdown("**Issuer:** {}".format(cert.issuer.get('CN', 'Unknown')))
                                st.markdown("**Chain Valid:** {}".format("\u2705" if cert.chain_valid else "\u274C"))
                                st.markdown("**SANs:** {}".format(", ".join(f"`{san}`" for san in cert.san)))
                                st.markdown("**Signature Algorithm:** {}".format(cert.signature_algorithm))
                            st.markdown("---")
                    # show_notifications(DOMAINS_PAGE_KEY) # Handled by placeholder
                    # DNS Records
                    if domain.dns_records:
                        st.markdown("### \U0001F4DD DNS Records")
                        records_df = []
                        for record in domain.dns_records:
                            records_df.append({
                                'Type': str(record.record_type),
                                'Name': str(record.name),
                                'Value': str(record.value),
                                'TTL': int(record.ttl),
                                'Priority': str(record.priority if record.priority is not None else 'N/A')
                            })
                        if records_df:
                            st.dataframe(
                                pd.DataFrame(records_df),
                                hide_index=True,
                                use_container_width=True
                            )
                    else:
                        notify("No DNS records found for this domain.", "info", page_key=DOMAINS_PAGE_KEY)
                    # Add Danger Zone for domain deletion
                    st.markdown("### \u26A0\uFE0F Danger Zone")
                    dependencies = {
                        "Certificates": [cert.common_name for cert in domain.certificates],
                        "DNS Records": [f"{r.record_type} {r.name}" for r in domain.dns_records],
                        "Subdomains": [d.domain_name for d in domain.subdomains]
                    }
                    def delete_domain(_):
                        result = DomainService.delete_domain_by_id(engine, domain.id)
                        if result['success']:
                            return True
                        else:
                            logger.exception(f"Error deleting domain: {result['error']}")
                            return False
                    def add_to_ignore_list(_):
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
                        on_delete=delete_domain,
                        session=None,
                        additional_actions=[{
                            "title": "\U0001F6AB Ignore Domain",
                            "callback": add_to_ignore_list,
                            "warning": f"This will hide '{domain.domain_name}' from the domain list. You can restore it later from the settings page.",
                            "confirmation_required": True,
                            "confirmation_text": f"ignore {domain.domain_name}"
                        }]
                    )