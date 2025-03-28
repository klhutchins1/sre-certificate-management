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
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session
from collections import defaultdict

from ..models import Domain, DomainDNSRecord, Certificate, IgnoredDomain
from ..components.deletion_dialog import render_danger_zone
from ..notifications import notify, show_notifications, initialize_notifications

class VirtualDomain:
    """Represents a domain that exists as a parent but is not in our database."""
    def __init__(self, domain_name):
        self.domain_name = domain_name
        self.registrar = None
        self.registration_date = None
        self.expiration_date = None
        self.owner = None
        self.is_active = True
        self.updated_at = datetime.now()
        self.certificates = []
        self.dns_records = []

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

def render_domain_list(engine):
    """
    Render the main domain management interface.
    
    This function displays:
    - Domain overview statistics
    - List of domains with key information
    - Domain details view
    """
    # Initialize notifications at the start
    initialize_notifications()
    
    # Show any existing notifications at the top
    show_notifications()
    
    st.title("Domain Management")
    
    with Session(engine) as session:
        try:
            # Get all domains
            domains = session.query(Domain).order_by(Domain.domain_name).all()
            
            # Get ignored domains for filtering
            ignored_domains = session.query(IgnoredDomain).all()
            ignored_patterns = [d.pattern for d in ignored_domains]
            
            # Filter out ignored domains
            visible_domains = []
            for domain in domains:
                # Check if domain matches any ignore patterns
                should_show = True
                for pattern in ignored_patterns:
                    if pattern.startswith('*') and pattern.endswith('*'):
                        # Contains pattern (*test*)
                        search_term = pattern.strip('*')
                        if search_term.lower() in domain.domain_name.lower():
                            should_show = False
                            break
                    elif pattern.startswith('*.'):
                        # Suffix wildcard (*.example.com)
                        suffix = pattern[2:]
                        if domain.domain_name.endswith(suffix):
                            should_show = False
                            break
                    elif pattern == domain.domain_name:
                        # Exact match
                        should_show = False
                        break
                
                if should_show:
                    visible_domains.append(domain)
            
            if not visible_domains:
                notify("No domains found in the database.", "info")
                return
            
            # Create domain overview metrics using visible domains
            total_domains = len(visible_domains)
            active_domains = sum(1 for d in visible_domains if d.is_active)
            expiring_soon = sum(1 for d in visible_domains 
                              if d.expiration_date and d.expiration_date <= datetime.now() + timedelta(days=30)
                              and d.expiration_date > datetime.now())
            expired = sum(1 for d in visible_domains 
                         if d.expiration_date and d.expiration_date <= datetime.now())
            
            # Display metrics in columns
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Domains", total_domains)
            with col2:
                st.metric("Active Domains", active_domains)
            with col3:
                st.metric("Expiring Soon", expiring_soon)
            with col4:
                st.metric("Expired", expired)
            
            # Create a search box
            search = st.text_input("Search Domains", placeholder="Enter domain name...")
            
            # Filter and organize domains
            if search:
                filtered_domains = [d for d in visible_domains if search.lower() in d.domain_name.lower()]
            else:
                filtered_domains = visible_domains
            
            # Organize domains into hierarchy
            root_domains, domain_hierarchy = get_domain_hierarchy(filtered_domains)
            
            # Create two columns: domain list and details
            col_list, col_details = st.columns([1, 2])
            
            with col_list:
                st.subheader("Domains")
                # Create hierarchical domain selection
                domain_options = []
                
                def add_domain_to_options(domain, prefix="", level=0):
                    """Recursively add domain and its subdomains to options."""
                    display_name = domain.domain_name
                    if level == 0:
                        # Always show folder icon for domains that have children
                        if display_name in domain_hierarchy:
                            domain_options.append(f"📁 {display_name}")
                        else:
                            # Only show plain domain if it's a real domain
                            if not isinstance(domain, VirtualDomain):
                                domain_options.append(display_name)
                    else:
                        # Create cascading effect with increasing dashes
                        indent = "└" + ("─" * (level))
                        domain_options.append(f"{indent}{display_name}")
                    
                    # Add subdomains
                    if display_name in domain_hierarchy:
                        for subdomain in domain_hierarchy[display_name]:
                            add_domain_to_options(subdomain, "", level + 1)
                
                # Add all root domains and their hierarchies
                for root in root_domains:
                    if isinstance(root, VirtualDomain) or root.domain_name in domain_hierarchy:
                        add_domain_to_options(root)
                    else:
                        domain_options.append(root.domain_name)
                
                if domain_options:
                    selected_option = st.radio(
                        "Select a domain to view details",
                        options=domain_options,
                        label_visibility="collapsed"
                    )
                    # Extract actual domain name from selection
                    selected_domain = selected_option.replace("📁 ", "").strip()
                    if "└" in selected_domain:
                        selected_domain = selected_domain.split("└")[-1].replace("─", "").strip()
                else:
                    notify("No domains match your search.", "info")
                    return
            
            with col_details:
                if selected_domain:
                    # Find the selected domain, handling both real and virtual domains
                    try:
                        domain = next(d for d in filtered_domains if d.domain_name == selected_domain)
                    except StopIteration:
                        # If not found in filtered_domains, it might be a virtual domain
                        domain = next((d for d in root_domains if d.domain_name == selected_domain), None)
                    
                    if domain:
                        st.subheader(domain.domain_name)
                        
                        # Domain Information
                        with st.expander("🌐 Domain Information", expanded=True):
                            if not isinstance(domain, VirtualDomain):
                                col_info, col_actions = st.columns([3, 1])
                                
                                with col_info:
                                    # Get registration info from root domain if this is a subdomain
                                    root_domain = get_root_domain_info(domain.domain_name, domains)
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
                                # Display info for virtual domains as before
                                col1, col2 = st.columns(2)
                                with col1:
                                    root_domain = get_root_domain_info(domain.domain_name, domains)
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
                            st.markdown("### 🔄 Subdomains")
                            for subdomain in sorted(domain_hierarchy[domain.domain_name], key=lambda d: d.domain_name):
                                st.markdown(f"- `{subdomain.domain_name}`")
                        
                        # Only show certificates and DNS records for real domains
                        if not isinstance(domain, VirtualDomain):
                            # Certificates
                            if domain.certificates:
                                st.markdown("### 🔐 Certificates")
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
                                        st.markdown("**Chain Valid:** {}".format("✅" if cert.chain_valid else "❌"))
                                        st.markdown("**SANs:** {}".format(", ".join(f"`{san}`" for san in cert.san)))
                                        st.markdown("**Signature Algorithm:** {}".format(cert.signature_algorithm))
                                    st.markdown("---")
                            else:
                                notify("No certificates found for this domain.", "info")
                                
                            # DNS Records
                            if domain.dns_records:
                                st.markdown("### 📝 DNS Records")
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
                                notify("No DNS records found for this domain.", "info")
                                
                            # Add Danger Zone for domain deletion
                            st.markdown("### ⚠️ Danger Zone")
                            # Gather dependencies
                            dependencies = {
                                "Certificates": [cert.common_name for cert in domain.certificates],
                                "DNS Records": [f"{r.record_type} {r.name}" for r in domain.dns_records],
                                "Subdomains": [d.domain_name for d in domain.subdomains]
                            }
                            
                            def delete_domain(session):
                                try:
                                    session.delete(domain)
                                    session.commit()
                                    return True
                                except Exception as e:
                                    session.rollback()
                                    return False
                            
                            def add_to_ignore_list(session):
                                try:
                                    # Check if already ignored
                                    existing = session.query(IgnoredDomain).filter_by(pattern=domain.domain_name).first()
                                    if existing:
                                        notify(f"Domain '{domain.domain_name}' is already in the ignore list", "warning")
                                    else:
                                        # Add to ignore list
                                        ignored = IgnoredDomain(
                                            pattern=domain.domain_name,
                                            reason=f"Added from domain view",
                                            created_at=datetime.now()
                                        )
                                        session.add(ignored)
                                        session.commit()
                                        notify(f"Added '{domain.domain_name}' to ignore list", "success")
                                        # Rerun to refresh the view
                                        st.rerun()
                                except Exception as e:
                                    notify(f"Error adding domain to ignore list: {str(e)}", "error")
                            
                            render_danger_zone(
                                title="Domain Management",
                                entity_name=domain.domain_name,
                                entity_type="domain",
                                dependencies=dependencies,
                                on_delete=delete_domain,
                                session=session,
                                additional_actions=[{
                                    "title": "🚫 Ignore Domain",
                                    "callback": add_to_ignore_list,
                                    "warning": f"This will hide '{domain.domain_name}' from the domain list. You can restore it later from the settings page.",
                                    "confirmation_required": True,
                                    "confirmation_text": f"ignore {domain.domain_name}"
                                }]
                            )
                            
        except Exception as e:
            notify(f"An error occurred: {str(e)}", "error")