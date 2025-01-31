import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc
from ..models import Certificate, CertificateScan, Host, HostIP, CertificateBinding
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css


def render_history_view(engine):
    """Render the certificate scan history view"""
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
    st.title("Certificate History")
    
    # Create tabs for different history views
    scan_tab, host_tab = st.tabs(["Scan History", "Host Certificate History"])
    
    with scan_tab:
        render_scan_history(engine)
    
    with host_tab:
        render_host_certificate_history(engine)

def render_host_certificate_history(engine):
    """Render certificate history by host"""
    with SessionManager(engine) as session:
        # Get all hosts with their bindings and certificates
        hosts = session.query(Host).options(
            joinedload(Host.ip_addresses),
            joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate)
        ).all()
        
        if not hosts:
            st.warning("No host data found")
            return
        
        # Create host selection options
        host_options = {}
        for host in hosts:
            for ip in host.ip_addresses:
                key = f"{host.name} ({ip.ip_address})"
                host_options[key] = (host.id, ip.id)
        
        # Host selection
        selected_host = st.selectbox(
            "Select Host",
            options=list(host_options.keys()),
            index=None,
            placeholder="Choose a host to view certificate history..."
        )
        
        if selected_host:
            host_id, ip_id = host_options[selected_host]
            
            # Get certificate history for this host/IP
            bindings = session.query(CertificateBinding).filter(
                CertificateBinding.host_id == host_id,
                CertificateBinding.host_ip_id == ip_id
            ).join(
                Certificate
            ).order_by(
                CertificateBinding.last_seen.desc()
            ).all()
            
            if bindings:
                # Convert to DataFrame for display
                cert_history = []
                for binding in bindings:
                    cert = binding.certificate
                    cert_history.append({
                        "Certificate": cert.common_name,
                        "Serial Number": cert.serial_number,
                        "Valid From": cert.valid_from,
                        "Valid Until": cert.valid_until,
                        "Last Seen": binding.last_seen,
                        "Port": binding.port,
                        "Platform": binding.platform or "Unknown",
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired"
                    })
                
                df = pd.DataFrame(cert_history)
                
                # Display timeline of certificates
                st.subheader("Certificate Timeline")
                timeline_chart = {
                    "Certificate": df["Certificate"].tolist(),
                    "Start": df["Valid From"].tolist(),
                    "End": df["Valid Until"].tolist()
                }
                st.plotly_chart(create_timeline_chart(timeline_chart))
                
                # Display detailed history
                st.subheader("Detailed History")
                st.dataframe(
                    df,
                    column_config={
                        "Certificate": st.column_config.TextColumn(
                            "Certificate",
                            width="medium"
                        ),
                        "Serial Number": st.column_config.TextColumn(
                            "Serial Number",
                            width="medium"
                        ),
                        "Valid From": st.column_config.DatetimeColumn(
                            "Valid From",
                            format="DD/MM/YYYY"
                        ),
                        "Valid Until": st.column_config.DatetimeColumn(
                            "Valid Until",
                            format="DD/MM/YYYY"
                        ),
                        "Last Seen": st.column_config.DatetimeColumn(
                            "Last Seen",
                            format="DD/MM/YYYY HH:mm"
                        ),
                        "Port": st.column_config.NumberColumn(
                            "Port",
                            width="small"
                        ),
                        "Platform": st.column_config.TextColumn(
                            "Platform",
                            width="small"
                        ),
                        "Status": st.column_config.TextColumn(
                            "Status",
                            width="small"
                        )
                    },
                    hide_index=True,
                    use_container_width=True
                )
            else:
                st.info("No certificate history found for this host")

def create_timeline_chart(data):
    """Create a timeline chart using plotly"""
    import plotly.figure_factory as ff
    import plotly.express as px
    
    # Create timeline data
    df_timeline = []
    for i, (cert, start, end) in enumerate(zip(data["Certificate"], data["Start"], data["End"])):
        df_timeline.append(dict(
            Task=cert,
            Start=start,
            Finish=end,
            Resource="Certificate"
        ))
    
    # Create the figure
    fig = ff.create_gantt(
        df_timeline,
        index_col='Resource',
        show_colorbar=True,
        group_tasks=True,
        showgrid_x=True,
        showgrid_y=True
    )
    
    # Update layout
    fig.update_layout(
        title="Certificate Timeline",
        height=200 + (len(data["Certificate"]) * 30),
        xaxis_title="Date",
        showlegend=False
    )
    
    return fig

def render_scan_history(engine):
    """Render the scan history view"""
    with SessionManager(engine) as session:
        # Get all scans with certificate and host info
        scans = session.query(CertificateScan)\
            .outerjoin(Certificate)\
            .outerjoin(Host)\
            .options(
                joinedload(CertificateScan.certificate),
                joinedload(CertificateScan.host).joinedload(Host.ip_addresses)
            )\
            .order_by(desc(CertificateScan.scan_date))\
            .all()
        
        if not scans:
            st.warning("No scan history found")
            return
        
        # Convert to DataFrame for easier manipulation
        scan_data = []
        for scan in scans:
            # Get host information
            if scan.host:
                host_display = scan.host.name
                # Get IP addresses for the host
                if scan.host.ip_addresses:
                    ip_addresses = [ip.ip_address for ip in scan.host.ip_addresses]
                    if ip_addresses:
                        host_display = f"{host_display} ({', '.join(ip_addresses)})"
            else:
                host_display = "Unknown Host"  # Fallback if no host information
            
            data = {
                "Scan Date": scan.scan_date,
                "Status": scan.status,
                "Port": scan.port,
                "Host": host_display,
            }
            
            # Add certificate info if available
            if scan.certificate:
                data.update({
                    "Certificate": scan.certificate.common_name,
                    "Serial Number": scan.certificate.serial_number,
                    "Valid Until": scan.certificate.valid_until,
                })
            else:
                data.update({
                    "Certificate": "N/A",
                    "Serial Number": "N/A",
                    "Valid Until": None,
                })
            
            scan_data.append(data)
        
        df = pd.DataFrame(scan_data)
        
        # Add filtering options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Date range filter
            date_range = st.selectbox(
                "Time Period",
                ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
                index=2  # Default to Last 30 Days
            )
            
            if date_range != "All Time":
                days = {
                    "Last 24 Hours": 1,
                    "Last 7 Days": 7,
                    "Last 30 Days": 30
                }[date_range]
                cutoff_date = datetime.now() - timedelta(days=days)
                df = df[df["Scan Date"] >= cutoff_date]
        
        with col2:
            # Status filter
            statuses = ["All"] + sorted(df["Status"].unique().tolist())
            status_filter = st.selectbox("Status", statuses)
            if status_filter != "All":
                df = df[df["Status"] == status_filter]
        
        with col3:
            # Host filter - handle None values in sorting
            unique_hosts = df["Host"].unique().tolist()
            unique_hosts = [h for h in unique_hosts if h is not None]  # Remove None values
            hosts = ["All"] + sorted(unique_hosts)
            host_filter = st.selectbox("Host", hosts)
            if host_filter != "All":
                df = df[df["Host"] == host_filter]
        
        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Scans", len(df))
        with col2:
            success_rate = (df["Status"] == "Valid").mean() * 100
            st.metric("Success Rate", f"{success_rate:.1f}%")
        with col3:
            unique_hosts = len(df["Host"].unique())
            st.metric("Unique Hosts", unique_hosts)
        
        # Create a function to color the status
        def color_status(val):
            color = "red" if val == "Failed" else "green"
            return f'color: {color}'
        
        # Reorder columns first, then apply styling
        df = df[['Host', 'Port', 'Status', 'Scan Date', 'Certificate', 'Valid Until', 'Serial Number']]
        
        # Display the scan history table
        st.dataframe(
            df.style.applymap(color_status, subset=['Status']),
            column_config={
                "Host": st.column_config.TextColumn(
                    "Host",
                    width="medium"
                ),
                "Port": st.column_config.NumberColumn(
                    "Port",
                    width="small",
                    format="%d"  # Remove thousand separator (comma)
                ),
                "Status": st.column_config.TextColumn(
                    "Status",
                    width="small"
                ),
                "Scan Date": st.column_config.DatetimeColumn(
                    "Scan Date",
                    format="DD/MM/YYYY HH:mm:ss",
                    width="medium"
                ),
                "Certificate": st.column_config.TextColumn(
                    "Certificate",
                    width="medium"
                ),
                "Valid Until": st.column_config.DatetimeColumn(
                    "Valid Until",
                    format="DD/MM/YYYY",
                    width="medium"
                ),
                "Serial Number": st.column_config.TextColumn(
                    "Serial Number",
                    width="medium"
                )
            },
            hide_index=True,
            use_container_width=True
        )
        
