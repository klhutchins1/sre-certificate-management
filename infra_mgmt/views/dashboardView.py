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
from datetime import datetime
import plotly.express as px
from ..static.styles import load_warning_suppression, load_css
from ..notifications import initialize_page_notifications, show_notifications, notify
from ..monitoring import monitor_rendering, performance_metrics
from ..services.ViewDataService import ViewDataService
from infra_mgmt.components.page_header import render_page_header
from infra_mgmt.components.metrics_row import render_metrics_row

DASHBOARD_PAGE_KEY = "dashboard"  # Define page key

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
            notify("Performance metrics cleared", "success", page_key=DASHBOARD_PAGE_KEY)

@monitor_rendering("dashboard")
def render_dashboard(engine) -> None:
    """Render the main certificate management dashboard."""
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    initialize_page_notifications(DASHBOARD_PAGE_KEY) # Initialize for this page
    # clear_page_notifications(DASHBOARD_PAGE_KEY) # Clear if needed, or before specific actions
    
    notification_placeholder = st.empty() # Create placeholder first
    render_page_header(title="Dashboard")
    
    with notification_placeholder.container(): # Show notifications for this page
        show_notifications(DASHBOARD_PAGE_KEY)
        
    view_data_service = ViewDataService()
    result = view_data_service.get_dashboard_view_data(engine)
    if not result['success']:
        notify(result['error'], "error", page_key=DASHBOARD_PAGE_KEY)
        # with notification_placeholder: # Already handled by the main placeholder
        #     show_notifications(DASHBOARD_PAGE_KEY)
        return
    metrics = result['data']['metrics']
    cert_timeline = result['data']['cert_timeline']
    domain_timeline = result['data']['domain_timeline']
    # Display metrics in two rows
    render_metrics_row([
        {"label": "Total Certificates", "value": metrics['total_certs']},
        {"label": "Total Root Domains", "value": metrics['total_root_domains']},
        {"label": "Total Applications", "value": metrics['total_apps']},
        {"label": "Total Hosts", "value": metrics['total_hosts']},
    ], columns=4, divider=False)
    render_metrics_row([
        {"label": "Certificates Expiring (30d)", "value": metrics['expiring_certs']},
        {"label": "Root Domains Expiring (30d)", "value": metrics['expiring_domains']},
        {"label": "Total Subdomains", "value": metrics['total_subdomains']},
        {"label": "", "value": ""},  # Empty for alignment
    ], columns=4, divider=True)
    # Create certificate timeline
    certs_df = pd.DataFrame(cert_timeline) if cert_timeline else pd.DataFrame()
    if not certs_df.empty:
        min_height = 500
        height_per_cert = 30
        cert_chart_height = max(min_height, len(certs_df) * height_per_cert)
        fig_certs = create_timeline(
            certs_df,
            'Certificate Validity Periods (Top 100)',
            cert_chart_height,
            title_size=28
        )
        st.plotly_chart(fig_certs, use_container_width=True)
    else:
        notify("No certificates found in database. \n", "info", page_key=DASHBOARD_PAGE_KEY)
    st.divider()
    # Create root domain timeline
    df_domains = pd.DataFrame(domain_timeline) if domain_timeline else pd.DataFrame()
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
        notify("No root domain registration information found in database. \n", "info", page_key=DASHBOARD_PAGE_KEY)
    # Show all notifications at the end (now handled by the single placeholder)
    # with notification_placeholder:
    #     show_notifications(DASHBOARD_PAGE_KEY)
    # Show performance metrics at the bottom
    render_performance_metrics()

