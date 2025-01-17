import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..models import Certificate, Host
import plotly.express as px
from ..db import SessionManager

def render_dashboard(engine):
    """Render the main dashboard"""
    st.title("Certificate Dashboard")
    
    # Create three columns for metrics
    col1, col2, col3 = st.columns([1, 1, 1])
    
    try:
        with SessionManager(engine) as session:
            if not session:
                st.error("Database connection failed")
                return
            
            try:
                total_certs = session.query(Certificate).count()
                expiring_soon = session.query(Certificate).filter(
                    Certificate.valid_until <= datetime.now() + timedelta(days=30)
                ).count()
                total_hosts = session.query(Host).count()
                
                col1.metric("Total Certificates", total_certs)
                col2.metric("Expiring within 30 days", expiring_soon)
                col3.metric("Total Hosts", total_hosts)
                
                # Create expiration timeline
                certs = session.query(
                    Certificate.common_name,
                    Certificate.valid_from,
                    Certificate.valid_until
                ).all()
                
                if certs:
                    df = pd.DataFrame(certs, columns=['Certificate', 'Start', 'End'])
                    fig = px.timeline(
                        df,
                        x_start='Start',
                        x_end='End',
                        y='Certificate',
                        title='Certificate Validity Periods'
                    )
                    # Customize the timeline appearance
                    fig.update_traces(
                        marker_line_color='rgb(0, 0, 0)',
                        marker_line_width=2,
                        opacity=0.8
                    )
                    # Add today's date as a shape instead
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
                    # Add "Today" annotation
                    fig.add_annotation(
                        x=today,
                        y=len(certs) - 0.5,
                        text="Today",
                        showarrow=False,
                        textangle=-90,
                        yshift=10
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No certificates found in database. Try scanning some certificates first.")
            except Exception as e:
                st.error(f"Error querying database: {str(e)}")
                return
    except Exception as e:
        st.error(f"Error connecting to database: {str(e)}")
        return

