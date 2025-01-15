import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session
from ..models import Host, HostIP, CertificateBinding

def render_hosts_view(engine):
    """Render the hosts view"""
    st.title("Hosts")
    
    # Use full width for the main content
    st.markdown("""
        <style>
            .block-container {
                padding-top: 1rem;
                padding-right: 1rem;
                padding-left: 1rem;
                padding-bottom: 1rem;
            }
            .stDataFrame {
                width: 100%;
            }
        </style>
    """, unsafe_allow_html=True)
    
    with Session(engine) as session:
        # Get all bindings
        bindings = session.query(CertificateBinding).all()
        
        if not bindings:
            st.warning("No certificate bindings found in database")
            return
        
        # Display total count
        unique_ips = len(set(b.host_ip.ip_address for b in bindings if b.host_ip))
        unique_hosts = len(set(b.host_id for b in bindings))
        st.caption(f"Total IPs: {unique_ips} | Total Hosts: {unique_hosts}")
        
        # Convert to DataFrame for display
        binding_data = []
        for binding in bindings:
            if binding.host_ip:  # IP-based certificates
                binding_data.append({
                    'IP Address': binding.host_ip.ip_address,
                    'Port': binding.port,
                    'Hostname': binding.host.name,
                    'Certificate': binding.certificate.common_name,
                    'Platform': binding.platform or 'Unknown',
                    'Expires': binding.certificate.valid_until,
                    'Last Seen': binding.last_seen,
                    'Status': 'Valid' if binding.certificate.valid_until > datetime.now() else 'Expired'
                })
        
        df = pd.DataFrame(binding_data)
        
        # Add filtering options
        col1, col2, col3 = st.columns(3)
        with col1:
            platforms = ['All'] + sorted(set(df['Platform'].dropna()))
            platform_filter = st.selectbox('Filter by Platform', platforms)
        with col2:
            statuses = ['All'] + sorted(df['Status'].unique().tolist())
            status_filter = st.selectbox('Filter by Status', statuses)
        with col3:
            ports = ['All'] + sorted(df['Port'].unique().tolist())
            port_filter = st.selectbox('Filter by Port', ports)
        
        # Apply filters
        if platform_filter != 'All':
            df = df[df['Platform'] == platform_filter]
        if status_filter != 'All':
            df = df[df['Status'] == status_filter]
        if port_filter != 'All':
            df = df[df['Port'] == port_filter]
        
        st.dataframe(
            df,
            column_config={
                'IP Address': st.column_config.TextColumn(
                    'IP Address',
                    help='Host IP address'
                ),
                'Port': st.column_config.NumberColumn(
                    'Port',
                    help='Port number'
                ),
                'Hostname': st.column_config.TextColumn('Hostname'),
                'Certificate': st.column_config.TextColumn(
                    'Certificate',
                    help='Common Name'
                ),
                'Platform': st.column_config.TextColumn(
                    'Platform',
                    help='Deployment platform'
                ),
                'Status': st.column_config.TextColumn(
                    'Status',
                    help='Certificate validity'
                ),
                'Expires': st.column_config.DatetimeColumn(
                    'Expires',
                    format='DD/MM/YYYY'
                ),
                'Last Seen': st.column_config.DatetimeColumn(
                    'Last Seen',
                    format='DD/MM/YYYY HH:mm'
                )
            },
            use_container_width=True,
            height=400,
            hide_index=True
        )
        
        # Add IP:Port selection for details
        ip_ports = sorted(set(f"{row['IP Address']}:{row['Port']}" for _, row in df.iterrows()))
        selected = st.selectbox("Select IP:Port to view details", ip_ports)
        
        if selected:
            ip, port = selected.split(':')
            port = int(port)
            
            # Find all hosts with this IP
            binding = session.query(CertificateBinding).join(
                HostIP
            ).filter(
                HostIP.ip_address == ip,
                CertificateBinding.port == port
            ).first()
            
            st.divider()
            st.subheader(f"Binding Details: {ip}:{port}")
            
            # Create three columns for basic info
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Platform", binding.platform or "Unknown")
            with col2:
                st.metric("Status", 'Valid' if binding.certificate.valid_until > datetime.now() else 'Expired')
            with col3:
                st.metric("Last Seen", binding.last_seen.strftime('%Y-%m-%d %H:%M'))
            
            # Create tabs for different sections
            tab1, tab2 = st.tabs(["Certificate Details", "History"])
            
            with tab1:
                cert = binding.certificate
                st.markdown(f"""
                    **Common Name:** {cert.common_name}  
                    **Serial Number:** {cert.serial_number}  
                    **Valid From:** {cert.valid_from.strftime('%Y-%m-%d')}  
                    **Valid Until:** {cert.valid_until.strftime('%Y-%m-%d')}  
                    **SANs:** {len(eval(cert.san)) if cert.san else 0} names
                """)
            
            with tab2:
                st.info("Certificate history for this IP:Port coming soon")
