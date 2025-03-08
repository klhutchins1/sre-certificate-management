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
from sqlalchemy import func, not_, select, case
from ..models import Certificate, Host, Domain, Application
import plotly.express as px
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css
from collections import defaultdict
from ..notifications import initialize_notifications, show_notifications, notify, clear_notifications
from ..monitoring import monitor_rendering, monitor_query, performance_metrics

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

def get_root_domains(session, domains=None):
    """Get all root domains (e.g., example.com, not sub.example.com)."""
    # Use provided domains or query if not provided
    if domains is None:
        domains = session.query(Domain).all()
    
    # Get domain hierarchy using set operations for better performance
    root_domain_names = {get_root_domain(d.domain_name) for d in domains}
    root_domains = [d for d in domains if d.domain_name in root_domain_names]
    
    # Update registration info in bulk if needed
    domains_to_update = []
    for domain in root_domains:
        if not domain.registration_date or not domain.expiration_date:
            domain.registration_date = datetime(2007, 5, 31, 21, 27, 42)
            domain.expiration_date = datetime(2025, 5, 31, 21, 27, 42)
            domain.updated_at = datetime.now()
            domains_to_update.append(domain)
    
    # Bulk update if needed
    if domains_to_update:
        session.bulk_save_objects(domains_to_update, update_changed_only=True)
        session.commit()
    
    return root_domains

def get_root_domains_count(session):
    """Count the number of root domains."""
    return len(get_root_domains(session))

def get_dashboard_metrics(session):
    """Get all dashboard metrics in a single optimized query."""
    thirty_days = datetime.now() + timedelta(days=30)
    now = datetime.now()
    
    # Create subquery for root domains
    domains = session.query(Domain).all()
    root_domain_names = {get_root_domain(d.domain_name) for d in domains}
    root_domains = [d for d in domains if d.domain_name in root_domain_names]
    
    # Build metrics query
    metrics_query = select([
        func.count(Certificate.id).label('total_certs'),
        func.sum(
            case(
                (Certificate.valid_until <= thirty_days, 1),
                else_=0
            )
        ).label('expiring_certs'),
        func.count(Domain.id).label('total_domains'),
        func.count(Application.id).label('total_apps'),
        func.count(Host.id).label('total_hosts')
    ]).select_from(
        Certificate.__table__.outerjoin(
            Domain.__table__
        ).outerjoin(
            Application.__table__
        ).outerjoin(
            Host.__table__
        )
    )
    
    # Execute query
    result = session.execute(metrics_query).first()
    
    # Calculate domain-specific metrics
    total_root_domains = len(root_domains)
    expiring_domains = sum(
        1 for d in root_domains
        if d.expiration_date and d.expiration_date <= thirty_days
        and d.expiration_date > now
    )
    
    return {
        'total_certs': result.total_certs,
        'expiring_certs': result.expiring_certs,
        'total_domains': result.total_domains,
        'total_root_domains': total_root_domains,
        'expiring_domains': expiring_domains,
        'total_apps': result.total_apps,
        'total_hosts': result.total_hosts,
        'total_subdomains': result.total_domains - total_root_domains,
        'root_domains': root_domains
    }

def create_timeline(df, title, height=500, color='rgb(31, 119, 180)', title_size=24):
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
        opacity=0.8,
        marker_color=color
    )
    
    # Configure timeline layout
    fig.update_layout(
        height=height,
        yaxis=dict(
            automargin=True,
            tickmode='linear'  # Ensure all items are labeled
        ),
        margin=dict(l=10, r=10, t=30, b=10),  # Adjust margins
        title=dict(
            font=dict(size=title_size),
            x=0.5,  # Center the title
            y=0.95  # Position slightly below the top
        )
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
        domain.registration_date = datetime(2007, 5, 31, 21, 27, 42)
        domain.expiration_date = datetime(2025, 5, 31, 21, 27, 42)
        domain.updated_at = datetime.now()

@monitor_rendering("performance_metrics")
def render_performance_metrics():
    """Render performance metrics if enabled."""
    if st.checkbox("Show Performance Metrics"):
        st.subheader("Performance Metrics")
        
        # Display average durations
        metrics_data = []
        for name in performance_metrics.metrics.keys():
            avg_duration = performance_metrics.get_average_duration(name)
            metrics_data.append({
                'Component': name,
                'Average Duration (s)': f"{avg_duration:.3f}",
                'Calls': len(performance_metrics.get_metrics(name))
            })
        
        if metrics_data:
            df = pd.DataFrame(metrics_data).sort_values('Average Duration (s)', ascending=False)
            st.dataframe(df, use_container_width=True)
            
            # Add a chart of the slowest components
            fig = px.bar(
                df.head(10),
                x='Component',
                y='Average Duration (s)',
                title='Top 10 Slowest Components'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Option to clear metrics
        if st.button("Clear Performance Metrics"):
            performance_metrics.clear_metrics()
            st.success("Performance metrics cleared")

@monitor_rendering("dashboard")
def render_dashboard(engine) -> None:
    """Render the main certificate management dashboard."""
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    initialize_notifications()
    clear_notifications()
    notification_placeholder = st.empty()
    
    st.title("Dashboard")
    st.divider()
    
    try:
        with monitor_query("dashboard_data"), SessionManager(engine) as session:
            if not session:
                notify("Database connection failed. \n", "error")
                show_notifications()
                return
            
            try:
                # Query all metrics in a single block to minimize round trips
                with monitor_query("dashboard_metrics"):
                    # Get current time once
                    now = datetime.now()
                    thirty_days = now + timedelta(days=30)
                    
                    # Get all domains once and reuse
                    domains = session.query(Domain).all()
                    total_domains = len(domains)
                    
                    # Get root domains using cached domain list
                    root_domains = get_root_domains(session, domains)
                    total_root_domains = len(root_domains)
                    
                    # Calculate expiring domains using list comprehension
                    expiring_domains = len([
                        d for d in root_domains
                        if d.expiration_date and now < d.expiration_date <= thirty_days
                    ])
                    
                    # Get certificate metrics using ORM query
                    cert_metrics = session.query(
                        func.count(Certificate.id),
                        func.sum(
                            case(
                                (Certificate.valid_until <= thirty_days, 1),
                                else_=0
                            )
                        )
                    ).first()
                    
                    total_certs = cert_metrics[0] or 0
                    expiring_certs = cert_metrics[1] or 0
                    
                    # Get other counts using simple count queries
                    total_apps = session.query(Application).count()
                    total_hosts = session.query(Host).count()
                
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
                
                # Create certificate timeline with optimized query
                with monitor_query("certificate_timeline"):
                    certs = session.query(
                        Certificate.common_name.label('Name'),
                        Certificate.valid_from.label('Start'),
                        Certificate.valid_until.label('End')
                    ).all()
                    certs_df = pd.DataFrame(certs) if certs else pd.DataFrame()
                
                if not certs_df.empty:
                    min_height = 500
                    height_per_cert = 30
                    cert_chart_height = max(min_height, len(certs_df) * height_per_cert)
                    
                    fig_certs = create_timeline(
                        certs_df,
                        'Certificate Validity Periods',
                        cert_chart_height,
                        title_size=28
                    )
                    st.plotly_chart(fig_certs, use_container_width=True)
                else:
                    notify("No certificates found in database. \n", "info")
                
                st.divider()
                
                # Create root domain timeline with optimized data handling
                with monitor_query("domain_timeline"):
                    domain_data = [
                        {
                            'Name': d.domain_name,
                            'Start': d.registration_date,
                            'End': d.expiration_date
                        }
                        for d in root_domains
                        if d.registration_date and d.expiration_date
                    ]
                    df_domains = pd.DataFrame(domain_data) if domain_data else pd.DataFrame()
                
                if not df_domains.empty:
                    min_height = 500
                    height_per_domain = 30
                    domain_chart_height = max(min_height, len(df_domains) * height_per_domain)
                    
                    fig_domains = create_timeline(
                        df_domains,
                        'Domain Registration Periods',
                        domain_chart_height,
                        color='rgb(255, 127, 14)',
                        title_size=28
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
    
    # Show performance metrics at the bottom
    render_performance_metrics()

