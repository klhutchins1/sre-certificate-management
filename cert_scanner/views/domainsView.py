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

from ..models import Domain, DomainDNSRecord, Certificate

def get_domain_hierarchy(domains):
    """
    Organize domains into a hierarchy of root domains and subdomains.
    
    Args:
        domains: List of Domain objects
        
    Returns:
        dict: Hierarchical structure of domains
    """
    hierarchy = defaultdict(list)
    root_domains = []
    
    # First pass: identify root domains and build initial hierarchy
    for domain in domains:
        parts = domain.domain_name.split('.')
        if len(parts) == 2:  # Root domain (e.g., example.com)
            root_domains.append(domain)
        else:
            # Find the root domain
            root_name = '.'.join(parts[-2:])  # Get the base domain
            hierarchy[root_name].append(domain)
    
    return root_domains, hierarchy

def render_domain_list(engine):
    """
    Render the main domain management interface.
    
    This function displays:
    - Domain overview statistics
    - List of domains with key information
    - Domain details view
    """
    st.title("Domain Management")
    
    with Session(engine) as session:
        # Get all domains
        domains = session.query(Domain).order_by(Domain.domain_name).all()
        
        if not domains:
            st.info("No domains found in the database.")
            return
        
        # Create domain overview metrics
        total_domains = len(domains)
        active_domains = sum(1 for d in domains if d.is_active)
        expiring_soon = sum(1 for d in domains 
                          if d.expiration_date and d.expiration_date <= datetime.now() + timedelta(days=30)
                          and d.expiration_date > datetime.now())
        expired = sum(1 for d in domains 
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
            filtered_domains = [d for d in domains if search.lower() in d.domain_name.lower()]
        else:
            filtered_domains = domains
        
        # Organize domains into hierarchy
        root_domains, domain_hierarchy = get_domain_hierarchy(filtered_domains)
        
        # Create two columns: domain list and details
        col_list, col_details = st.columns([1, 2])
        
        with col_list:
            st.subheader("Domains")
            # Create hierarchical domain selection
            domain_options = []
            for root in sorted(root_domains, key=lambda d: d.domain_name):
                domain_options.append(f"📁 {root.domain_name}")
                # Add subdomains
                subdomains = domain_hierarchy[root.domain_name]
                for subdomain in sorted(subdomains, key=lambda d: d.domain_name):
                    domain_options.append(f"  └─ {subdomain.domain_name}")
            
            if domain_options:
                selected_option = st.radio(
                    "Select a domain to view details",
                    options=domain_options,
                    label_visibility="collapsed"
                )
                # Extract actual domain name from selection
                selected_domain = selected_option.replace("📁 ", "").replace("  └─ ", "")
            else:
                st.info("No domains match your search.")
                return
        
        with col_details:
            if selected_domain:
                domain = next(d for d in filtered_domains if d.domain_name == selected_domain)
                st.subheader(domain.domain_name)
                
                # Domain Information
                with st.expander("🌐 Domain Information", expanded=True):
                    col1, col2 = st.columns(2)
                    
                    # If this is a subdomain, try to get registrar info from root domain
                    parts = domain.domain_name.split('.')
                    is_subdomain = len(parts) > 2
                    root_domain = None
                    
                    if is_subdomain:
                        root_name = '.'.join(parts[-2:])
                        root_domain = next((d for d in root_domains if d.domain_name == root_name), None)
                    
                    with col1:
                        if is_subdomain and root_domain:
                            st.markdown("**Root Domain:** `{}`".format(root_domain.domain_name))
                            st.markdown("**Registrar:** {}".format(root_domain.registrar or "N/A"))
                            st.markdown("**Registration Date:** {}".format(
                                root_domain.registration_date.strftime("%Y-%m-%d") if root_domain.registration_date else "N/A"
                            ))
                            st.markdown("**Owner:** {}".format(root_domain.owner or "N/A"))
                        else:
                            st.markdown("**Registrar:** {}".format(domain.registrar or "N/A"))
                            st.markdown("**Registration Date:** {}".format(
                                domain.registration_date.strftime("%Y-%m-%d") if domain.registration_date else "N/A"
                            ))
                            st.markdown("**Owner:** {}".format(domain.owner or "N/A"))
                    with col2:
                        if is_subdomain and root_domain:
                            st.write("**Expiration Date:**", root_domain.expiration_date.strftime("%Y-%m-%d") if root_domain.expiration_date else "N/A")
                        else:
                            st.write("**Expiration Date:**", domain.expiration_date.strftime("%Y-%m-%d") if domain.expiration_date else "N/A")
                        st.write("**Status:**", "Active" if domain.is_active else "Inactive")
                        st.write("**Last Updated:**", domain.updated_at.strftime("%Y-%m-%d %H:%M"))
                
                # Show subdomains if this is a root domain
                if not is_subdomain and domain.domain_name in domain_hierarchy:
                    with st.expander("🔄 Subdomains"):
                        for subdomain in sorted(domain_hierarchy[domain.domain_name], key=lambda d: d.domain_name):
                            st.markdown(f"- `{subdomain.domain_name}`")
                
                # Certificates
                if domain.certificates:
                    st.markdown("### 🔐 Certificates")
                    for cert in domain.certificates:
                        with st.expander(f"Certificate: `{cert.common_name}`"):
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
                else:
                    st.info("No certificates found for this domain.")
                
                # DNS Records
                if domain.dns_records:
                    st.markdown("### 📝 DNS Records")
                    records_df = []
                    for record in domain.dns_records:
                        records_df.append({
                            'Type': record.record_type,
                            'Name': record.name,
                            'Value': record.value,
                            'TTL': record.ttl,
                            'Priority': record.priority or 'N/A'
                        })
                    if records_df:
                        st.dataframe(
                            pd.DataFrame(records_df),
                            hide_index=True,
                            use_container_width=True
                        )
                else:
                    st.info("No DNS records found for this domain.") 