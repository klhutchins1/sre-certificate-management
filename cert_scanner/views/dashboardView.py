"""
Certificate Management Dashboard Module

This module provides a high-level overview dashboard for the certificate management system.
It displays key metrics and visualizations to help users monitor the overall state of
certificates across the system.

Key Features:
- Real-time certificate metrics
- Certificate expiration timeline visualization
- Certificate validity period tracking
- Interactive timeline with today's date marker
- Dynamic chart sizing based on certificate count

The dashboard serves as the main entry point for users to quickly assess the state
of their certificate infrastructure and identify potential issues requiring attention.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..models import Certificate, Host
import plotly.express as px
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css


def render_dashboard(engine) -> None:
    """
    Render the main certificate management dashboard.

    This function creates an interactive dashboard that provides a high-level
    overview of the certificate management system's current state, including:
    - Total number of certificates in the system
    - Certificates expiring within 30 days
    - Total number of monitored hosts
    - Interactive timeline visualization of certificate validity periods

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Real-time metric calculations
        - Dynamic timeline visualization
        - Today's date marker on timeline
        - Automatic chart scaling based on certificate count
        - Error handling for database operations
        - Empty state handling for new installations

    The dashboard is designed to help users quickly identify:
    - Overall system scale (total certificates and hosts)
    - Upcoming certificate expirations
    - Certificate validity overlaps and gaps
    - Certificates requiring immediate attention
    """
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    st.title("Dashboard")
    
    # Create metrics layout
    col1, col2, col3 = st.columns([1, 1, 1])
    
    try:
        with SessionManager(engine) as session:
            if not session:
                st.error("Database connection failed")
                return
            
            try:
                # Query and calculate key metrics
                total_certs = session.query(Certificate).count()
                expiring_soon = session.query(Certificate).filter(
                    Certificate.valid_until <= datetime.now() + timedelta(days=30)
                ).count()
                total_hosts = session.query(Host).count()
                
                # Display key metrics
                col1.metric("Total Certificates", total_certs)
                col2.metric("Expiring within 30 days", expiring_soon)
                col3.metric("Total Hosts", total_hosts)
                
                # Query certificate data for timeline
                certs = session.query(
                    Certificate.common_name,
                    Certificate.valid_from,
                    Certificate.valid_until
                ).all()
                
                if certs:
                    # Prepare timeline data
                    df = pd.DataFrame(certs, columns=['Certificate', 'Start', 'End'])
                    # Calculate dynamic chart height
                    min_height = 500  # minimum height in pixels
                    height_per_cert = 30  # pixels per certificate
                    chart_height = max(min_height, len(certs) * height_per_cert)
                    
                    # Create and configure timeline visualization
                    fig = px.timeline(
                        df,
                        x_start='Start',
                        x_end='End',
                        y='Certificate',
                        title='Certificate Validity Periods'
                    )
                    # Configure timeline appearance
                    fig.update_traces(
                        marker_line_color='rgb(0, 0, 0)',
                        marker_line_width=2,
                        opacity=0.8
                    )
                    # Configure timeline layout
                    fig.update_layout(
                        height=chart_height,
                        yaxis=dict(
                            automargin=True,
                            tickmode='linear'  # Ensure all certificates are labeled
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
                        y1=len(certs) - 0.5,
                        line=dict(
                            color="red",
                            width=2,
                            dash="dash",
                        )
                    )
                    # Add today's date label
                    fig.add_annotation(
                        x=today,
                        y=len(certs) - 0.5,
                        text="Today",
                        showarrow=False,
                        textangle=-90,
                        yshift=10
                    )
                    # Display the timeline
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No certificates found in database. Try scanning some certificates first.")
            except Exception as e:
                st.error(f"Error querying database: {str(e)}")
                return
    except Exception as e:
        st.error(f"Error connecting to database: {str(e)}")
        return

