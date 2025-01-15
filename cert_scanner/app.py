import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from cert_scanner.scanner import CertificateScanner, CertificateInfo
from cert_scanner.models import Certificate, Hostname, CertificateScan
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
import plotly.express as px

# Initialize database connection
engine = create_engine('sqlite:///certificates.db')

# Page configuration
st.set_page_config(
    page_title="Certificate Manager",
    page_icon="🔒",
    layout="wide"
)

def init_session_state():
    """Initialize session state variables"""
    if 'scanner' not in st.session_state:
        st.session_state.scanner = CertificateScanner()
    if 'selected_cert' not in st.session_state:
        st.session_state.selected_cert = None

def render_sidebar():
    """Render the sidebar navigation"""
    st.sidebar.title("Certificate Manager")
    
    return st.sidebar.radio(
        "Navigation",
        ["Dashboard", "Certificates", "Scan", "History", "Search"]
    )

def render_dashboard():
    """Render the main dashboard"""
    st.title("Certificate Dashboard")
    
    # Create three columns for metrics
    col1, col2, col3 = st.columns(3)
    
    with Session(engine) as session:
        total_certs = session.query(Certificate).count()
        expiring_soon = session.query(Certificate).filter(
            Certificate.valid_until <= datetime.now() + timedelta(days=30)
        ).count()
        total_hosts = session.query(Hostname).count()
        
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

def render_certificate_list():
    """Render the certificate list view"""
    st.title("Certificates")
    
    with Session(engine) as session:
        certs = session.query(Certificate).all()
        
        if not certs:
            st.warning("No certificates found in database")
            return
        
        # Convert to DataFrame for display
        cert_data = []
        for cert in certs:
            # Convert string representation of SAN back to list
            san_list = eval(cert.san) if cert.san else []
            hostnames_list = [h.name for h in cert.hostnames]
            cert_data.append({
                'Common Name': cert.common_name,
                'Serial Number': cert.serial_number,
                'Expiration': cert.valid_until,
                'Hosts': len(cert.hostnames),
                'SANs': len(san_list),
                'Status': 'Valid' if cert.valid_until > datetime.now() else 'Expired'
            })
        
        df = pd.DataFrame(cert_data)
        st.dataframe(
            df,
            column_config={
                'Common Name': st.column_config.TextColumn('Common Name'),
                'SANs': st.column_config.NumberColumn(
                    'SANs',
                    help='Number of Subject Alternative Names'
                ),
                'Status': st.column_config.TextColumn(
                    'Status',
                    help='Certificate validity status'
                ),
                'Expiration': st.column_config.DatetimeColumn(
                    'Expiration Date',
                    format='DD/MM/YYYY'
                )
            },
            use_container_width=True,
            height=400
        )
        
        # Add a selectbox for certificate selection
        cert_names = [f"{cert.common_name} ({cert.serial_number})" for cert in certs]
        selected_cert = st.selectbox("Select a certificate to view details", cert_names)
        
        # Show details if a row is selected
        if selected_cert:
            # Extract serial number from the selection
            selected_serial = selected_cert.split('(')[1].rstrip(')')
            cert = session.query(Certificate).filter_by(
                serial_number=selected_serial
            ).first()
            
            st.divider()
            st.subheader(f"Certificate Details: {cert.common_name}")
            
            # Create three columns for basic info
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Status", 'Valid' if cert.valid_until > datetime.now() else 'Expired')
            with col2:
                st.metric("Valid From", cert.valid_from.strftime('%Y-%m-%d'))
            with col3:
                st.metric("Valid Until", cert.valid_until.strftime('%Y-%m-%d'))
            
            # Create tabs for different sections
            tab1, tab2, tab3 = st.tabs(["Subject Alternative Names", "Associated Hosts", "Certificate Info"])
            
            with tab1:
                st.subheader("Subject Alternative Names (SANs)")
                san_list = eval(cert.san) if cert.san else []
                if san_list:
                    for san in san_list:
                        st.text(san)
                else:
                    st.info("No SANs found")
            
            with tab2:
                st.subheader("Associated Hostnames")
                if cert.hostnames:
                    for hostname in cert.hostnames:
                        st.markdown(f"""
                            **{hostname.name}**  
                            🌐 IP Addresses: {hostname.ip_addresses}  
                            🕒 Last Seen: {hostname.last_seen.strftime('%Y-%m-%d %H:%M:%S')}
                            ---
                        """)
                else:
                    st.info("No hostnames associated")
            
            with tab3:
                st.subheader("Certificate Information")
                st.json({
                    "Serial Number": cert.serial_number,
                    "Thumbprint": cert.thumbprint,
                    "Issuer": eval(cert.issuer) if cert.issuer else {},
                    "Subject": eval(cert.subject) if cert.subject else {},
                    "Key Usage": cert.key_usage,
                    "Signature Algorithm": cert.signature_algorithm
                })

def render_scan_interface():
    """Render the certificate scanning interface"""
    st.title("Scan Certificates")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        scan_input = st.text_area(
            "Enter hostnames to scan (one per line)",
            height=150,
            help="Enter hostnames without protocol (e.g., example.com)"
        )
        
        if st.button("Start Scan"):
            hostnames = [h.strip() for h in scan_input.split('\n') if h.strip()]
            if hostnames:
                progress = st.progress(0)
                results = []
                for i, hostname in enumerate(hostnames):
                    with st.spinner(f'Scanning {hostname}...'):
                        cert_info = st.session_state.scanner.scan_certificate(hostname)
                        if cert_info:
                            results.append(f"✅ {hostname}: Certificate found and saved")
                            # Save to database
                            with Session(engine) as session:
                                try:
                                    # Create or update certificate
                                    cert = session.query(Certificate).filter_by(
                                        serial_number=cert_info.serial_number
                                    ).first()
                                    
                                    if not cert:
                                        cert = Certificate(
                                            serial_number=cert_info.serial_number,
                                            thumbprint=cert_info.thumbprint,
                                            common_name=cert_info.common_name,
                                            valid_from=cert_info.valid_from,
                                            valid_until=cert_info.expiration_date,
                                            issuer=str(cert_info.issuer),
                                            subject=str(cert_info.subject),
                                            san=str(cert_info.san),
                                            key_usage=cert_info.key_usage,
                                            signature_algorithm=cert_info.signature_algorithm
                                        )
                                        session.add(cert)
                                    
                                    # Create or update hostname
                                    hostname_obj = session.query(Hostname).filter_by(
                                        name=cert_info.hostname
                                    ).first()
                                    
                                    if not hostname_obj:
                                        hostname_obj = Hostname(
                                            name=cert_info.hostname,
                                            ip_addresses=str(cert_info.ip_addresses),
                                            last_seen=datetime.now()
                                        )
                                        session.add(hostname_obj)
                                    else:
                                        hostname_obj.ip_addresses = str(cert_info.ip_addresses)
                                        hostname_obj.last_seen = datetime.now()
                                    
                                    # Associate certificate with hostname
                                    if hostname_obj not in cert.hostnames:
                                        cert.hostnames.append(hostname_obj)
                                    
                                    # Create scan record
                                    scan = CertificateScan(
                                        certificate=cert,
                                        scan_date=datetime.now(),
                                        status='Valid',
                                        port=cert_info.port
                                    )
                                    session.add(scan)
                                    
                                    session.commit()
                                except Exception as e:
                                    results.append(f"⚠️ {hostname}: Database error: {str(e)}")
                                    session.rollback()
                        else:
                            results.append(f"❌ {hostname}: No certificate found or error during scan")
                    
                    progress.progress((i + 1) / len(hostnames))
                
                # Display results
                st.subheader("Scan Results")
                for result in results:
                    st.text(result)
                
                st.success("Scan completed!")
            else:
                st.warning("Please enter at least one hostname to scan")
    
    with col2:
        st.subheader("Recent Scans")
        st.markdown("---")
        with Session(engine) as session:
            recent_scans = session.query(CertificateScan)\
                .order_by(CertificateScan.scan_date.desc())\
                .limit(5)\
                .all()
            
            if recent_scans:
                for scan in recent_scans:
                    scan_time = scan.scan_date.strftime("%Y-%m-%d %H:%M:%S")
                    st.markdown(f"""
                        **{scan.certificate.common_name}**  
                        🕒 {scan_time}  
                        Status: {scan.status}
                        ---
                    """)
            else:
                st.info("No recent scans")

def main():
    init_session_state()
    
    # Render sidebar and get current page
    current_page = render_sidebar()
    
    # Render the selected page
    if current_page == "Dashboard":
        render_dashboard()
    elif current_page == "Certificates":
        render_certificate_list()
    elif current_page == "Scan":
        render_scan_interface()
    elif current_page == "History":
        st.title("Certificate History")
        st.info("History view under development")
    elif current_page == "Search":
        st.title("Search Certificates")
        st.info("Search functionality under development")

if __name__ == "__main__":
    main() 