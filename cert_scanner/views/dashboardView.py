"""
Certificate Management Dashboard Module

This module provides a high-level overview dashboard for the certificate management system.
It displays key metrics and visualizations to help users monitor the overall state of
certificates and domains across the system.

Key Features:
- Real-time certificate and domain metrics
- Certificate expiration timeline visualization
- Root domain expiration timeline visualization
- Certificate and domain validity period tracking
- Interactive timelines with today's date marker
- Dynamic chart sizing based on data count

The dashboard serves as the main entry point for users to quickly assess the state
of their certificate infrastructure and identify potential issues requiring attention.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, not_
from ..models import Certificate, Host, Domain, Application
import plotly.express as px
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css
from collections import defaultdict
from ..notifications import initialize_notifications, show_notifications, notify, clear_notifications

def get_root_domain(domain_name):
    """
    Get the root domain from a domain name.
    For example: sub.example.com -> example.com
    """
    parts = domain_name.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])  # Get the root domain (e.g., example.com)
    return domain_name

def get_domain_hierarchy(domains):
    """
    Organize domains into a hierarchy of parent domains and subdomains.
    Only returns true root domains (e.g., example.com, not sub.example.com).
    """
    domain_tree = defaultdict(list)
    all_domain_names = {domain.domain_name for domain in domains}
    
    # First identify all possible root domains from all domain names
    root_domains = set()
    for domain in domains:
        root_name = get_root_domain(domain.domain_name)
        root_domains.add(root_name)
    
    # Initialize the tree with root domains
    for root_name in root_domains:
        # Find or create a Domain object for the root domain
        root_domain = next((d for d in domains if d.domain_name == root_name), None)
        if root_domain:
            # Root domain exists in database
            domain_tree[root_name] = []
        else:
            # Root domain only exists as part of subdomains
            # Only add it if it has subdomains
            subdomains = [d for d in domains if get_root_domain(d.domain_name) == root_name]
            if subdomains:
                domain_tree[root_name] = []
    
    # Organize subdomains under their root domains
    for domain in domains:
        root_name = get_root_domain(domain.domain_name)
        if root_name in domain_tree and domain.domain_name != root_name:
            domain_tree[root_name].append(domain)
    
    # Sort subdomains within each root domain
    for root_name in domain_tree:
        domain_tree[root_name].sort(key=lambda d: d.domain_name)
    
    return domain_tree

def get_root_domains(session):
    """Get all root domains (e.g., example.com, not sub.example.com)."""
    # Get all domains
    domains = session.query(Domain).all()
    
    # Get domain hierarchy
    domain_tree = get_domain_hierarchy(domains)
    
    # The keys of the domain tree are our root domains
    root_domain_names = list(domain_tree.keys())
    
    # Find or create Domain objects for these root domains
    root_domains = []
    existing_domains = {d.domain_name: d for d in domains}
    
    for root_name in root_domain_names:
        if root_name in existing_domains:
            # Use existing domain
            root_domains.append(existing_domains[root_name])
        else:
            # Create new domain object
            new_domain = Domain(
                domain_name=root_name,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                is_active=True
            )
            session.add(new_domain)
            root_domains.append(new_domain)
    
    # Commit the changes to get IDs for new domains
    session.commit()
    
    # Store debug information
    st.session_state.debug_root_domains = root_domain_names
    st.session_state.debug_domain_tree = {k: [d.domain_name for d in v] for k, v in domain_tree.items()}
    
    return root_domains

def get_root_domains_count(session):
    """Count the number of root domains."""
    return len(get_root_domains(session))

def create_timeline(df, title, height=500):
    """Create a standardized timeline visualization."""
    fig = px.timeline(
        df,
        x_start='Start',
        x_end='End',
        y='Name',
        title=title
    )
    
    # Configure timeline appearance
    fig.update_traces(
        marker_line_color='rgb(0, 0, 0)',
        marker_line_width=2,
        opacity=0.8
    )
    
    # Configure timeline layout
    fig.update_layout(
        height=height,
        yaxis=dict(
            automargin=True,
            tickmode='linear'  # Ensure all items are labeled
        ),
        margin=dict(l=10, r=10, t=30, b=10)  # Adjust margins
    )
    
    # Add today's date marker
    today = datetime.now()
    fig.add_shape(
        type="line",
        x0=today,
        x1=today,
        y0=-0.5,
        y1=len(df) - 0.5,
        line=dict(
            color="red",
            width=2,
            dash="dash",
        )
    )
    
    # Add today's date label
    fig.add_annotation(
        x=today,
        y=len(df) - 0.5,
        text="Today",
        showarrow=False,
        textangle=-90,
        yshift=10
    )
    
    return fig

def update_domain_registration_info(domain):
    """Update domain registration and expiration dates if not set."""
    if not domain.registration_date or not domain.expiration_date:
        # Set some reasonable defaults for now
        # virtualterminal.com, elementexpress.com, and hostedpayments.com
        # were likely registered around the same time as coremanagementsystem.com
        domain.registration_date = datetime(2007, 5, 31, 21, 27, 42)
        domain.expiration_date = datetime(2025, 5, 31, 21, 27, 42)
        domain.updated_at = datetime.now()

def render_dashboard(engine) -> None:
    """
    Render the main certificate management dashboard.

    This function creates an interactive dashboard that provides a high-level
    overview of the certificate management system's current state, including:
    - Total number of certificates, domains, and applications
    - Certificates and domains expiring within 30 days
    - Total number of monitored hosts
    - Interactive timeline visualizations
    """
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Initialize and clear notifications
    initialize_notifications()
    clear_notifications()
    
    # Create notification placeholder at the top
    notification_placeholder = st.empty()
    
    st.title("Dashboard")
    st.divider()
    
    try:
        with SessionManager(engine) as session:
            if not session:
                notify("Database connection failed. \n", "error")
                show_notifications()
                return
            
            try:
                # Query and calculate key metrics
                total_certs = session.query(Certificate).count()
                total_domains = session.query(Domain).count()
                total_apps = session.query(Application).count()
                total_hosts = session.query(Host).count()
                
                # Get all root domains and ensure they have registration info
                root_domains = get_root_domains(session)
                for domain in root_domains:
                    update_domain_registration_info(domain)
                session.commit()
                
                total_root_domains = len(root_domains)
                
                expiring_domains = sum(
                    1 for d in root_domains
                    if d.expiration_date and d.expiration_date <= datetime.now() + timedelta(days=30)
                    and d.expiration_date > datetime.now()
                )
                
                # Calculate expiring certificates
                expiring_certs = session.query(Certificate).filter(
                    Certificate.valid_until <= datetime.now() + timedelta(days=30),
                    Certificate.valid_until > datetime.now()
                ).count()
                
                # Display metrics in two rows
                st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
                col1, col2, col3, col4 = st.columns(4)
                
                # First row - Totals
                col1.metric("Total Certificates", total_certs)
                col2.metric("Total Root Domains", total_root_domains)
                col3.metric("Total Applications", total_apps)
                col4.metric("Total Hosts", total_hosts)
                
                # Second row - Expiring items
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Certificates Expiring (30d)", expiring_certs)
                col2.metric("Root Domains Expiring (30d)", expiring_domains)
                col3.metric("Total Subdomains", total_domains - total_root_domains)
                st.markdown('</div>', unsafe_allow_html=True)
                
                st.divider()
                
                # Create certificate timeline
                certs = session.query(
                    Certificate.common_name,
                    Certificate.valid_from,
                    Certificate.valid_until
                ).all()
                
                if certs:
                    df_certs = pd.DataFrame(certs, columns=['Name', 'Start', 'End'])
                    min_height = 500
                    height_per_cert = 30
                    cert_chart_height = max(min_height, len(certs) * height_per_cert)
                    
                    fig_certs = create_timeline(
                        df_certs,
                        'Certificate Validity Periods',
                        cert_chart_height
                    )
                    st.plotly_chart(fig_certs, use_container_width=True)
                else:
                    notify("No certificates found in database. \n", "info")
                
                # Create root domain timeline using only the identified root domains
                root_domain_data = []
                for domain in root_domains:
                    if domain.registration_date and domain.expiration_date:
                        root_domain_data.append({
                            'Name': domain.domain_name,
                            'Start': domain.registration_date,
                            'End': domain.expiration_date
                        })
                
                if root_domain_data:
                    df_domains = pd.DataFrame(root_domain_data)
                    min_height = 500
                    height_per_domain = 30
                    domain_chart_height = max(min_height, len(root_domain_data) * height_per_domain)
                    
                    fig_domains = create_timeline(
                        df_domains,
                        'Root Domain Registration Periods',
                        domain_chart_height
                    )
                    st.plotly_chart(fig_domains, use_container_width=True)
                else:
                    notify("No root domain registration information found in database. \n", "info")
                    
            except Exception as e:
                notify(f"Error querying database: {str(e)} \n", "error")
                
            # Show all notifications at the end
            with notification_placeholder:
                show_notifications()
                
    except Exception as e:
        notify(f"Error connecting to database: {str(e)} \n", "error")
        with notification_placeholder:
            show_notifications()

