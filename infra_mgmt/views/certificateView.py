"""
Certificate view module for the Certificate Management System.
"""

import streamlit as st
import pandas as pd
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from ..models import Certificate, Domain, CertificateBinding, CertificateScan
from ..monitoring import monitor_rendering, monitor_query, performance_metrics
import logging

# Add logger setup at the top
logger = logging.getLogger(__name__)

@monitor_rendering("certificate_list")
def render_certificate_list(session: Session):
    """Render the certificate list section."""
    with monitor_query("certificate_list_data"):
        # Get all certificates with their domains
        certificates = session.query(
            Certificate.id,
            Certificate.common_name,
            Certificate.valid_from,
            Certificate.valid_until,
            Certificate.chain_valid,
            func.group_concat(Domain.domain_name).label('domains')
        ).join(
            Certificate.domains
        ).group_by(
            Certificate.id
        ).order_by(
            desc(Certificate.valid_until)
        ).all()
    
    if certificates:
        # Convert to DataFrame for display
        df = pd.DataFrame([{
            'Common Name': cert.common_name,
            'Valid From': cert.valid_from.strftime('%Y-%m-%d'),
            'Valid Until': cert.valid_until.strftime('%Y-%m-%d'),
            'Status': '✅' if cert.chain_valid else '❌',
            'Domains': cert.domains.split(',') if cert.domains else []
        } for cert in certificates])
        
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No certificates found in the database.")

@monitor_rendering("certificate_details")
def render_certificate_details(session: Session, cert_id: int):
    """Render detailed information for a specific certificate."""
    with monitor_query(f"certificate_details_{cert_id}"):
        cert = session.query(Certificate).get(cert_id)
    
    if cert:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Certificate Information")
            st.write("**Common Name:**", cert.common_name)
            st.write("**Valid From:**", cert.valid_from.strftime('%Y-%m-%d'))
            st.write("**Valid Until:**", cert.valid_until.strftime('%Y-%m-%d'))
            st.write("**Chain Valid:**", "✅" if cert.chain_valid else "❌")
            st.write("**Serial Number:**", cert.serial_number)
            st.write("**Signature Algorithm:**", cert.signature_algorithm)
        
        with col2:
            st.subheader("Certificate Details")
            st.write("**Issuer:**", cert.issuer)
            st.write("**Subject:**", cert.subject)
            if cert.key_usage:
                st.write("**Key Usage:**", cert.key_usage)
            if cert.san:
                st.write("**Subject Alternative Names:**")
                for san in cert.san:
                    st.write(f"- {san}")

@monitor_rendering("certificate_bindings")
def render_certificate_bindings(session: Session, cert_id: int):
    """Render certificate bindings information."""
    with monitor_query(f"certificate_bindings_{cert_id}"):
        bindings = session.query(
            CertificateBinding.port,
            CertificateBinding.binding_type,
            CertificateBinding.last_seen,
            Domain.domain_name
        ).join(
            CertificateBinding.host
        ).join(
            Domain,
            Domain.id == CertificateBinding.host_id
        ).filter(
            CertificateBinding.certificate_id == cert_id
        ).all()
    
    if bindings:
        st.subheader("Certificate Bindings")
        
        # Convert to DataFrame for display
        df = pd.DataFrame([{
            'Domain': binding.domain_name,
            'Port': binding.port,
            'Type': binding.binding_type,
            'Last Seen': binding.last_seen.strftime('%Y-%m-%d %H:%M:%S')
        } for binding in bindings])
        
        st.dataframe(df, use_container_width=True)

@monitor_rendering("scan_history")
def render_scan_history(session: Session, cert_id: int):
    """Render scan history for a certificate."""
    with monitor_query(f"scan_history_{cert_id}"):
        scans = session.query(
            CertificateScan.scan_date,
            CertificateScan.status,
            CertificateScan.port,
            Domain.domain_name
        ).join(
            Domain,
            Domain.id == CertificateScan.host_id
        ).filter(
            CertificateScan.certificate_id == cert_id
        ).order_by(
            desc(CertificateScan.scan_date)
        ).limit(10).all()
    
    if scans:
        st.subheader("Recent Scans")
        
        # Convert to DataFrame for display
        df = pd.DataFrame([{
            'Date': scan.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
            'Domain': scan.domain_name,
            'Port': scan.port,
            'Status': scan.status
        } for scan in scans])
        
        st.dataframe(df, use_container_width=True)

def render_certificate_view(engine) -> None:
    """Render the main certificate view interface."""
    st.title("Certificate Management")
    
    with Session(engine) as session:
        # Render certificate list
        render_certificate_list(session)
        
        # Allow selecting a certificate for detailed view
        with monitor_query("certificate_selection"):
            certificates = session.query(
                Certificate.id,
                Certificate.common_name
            ).order_by(Certificate.common_name).all()
        
        if certificates:
            selected = st.selectbox(
                "Select a certificate for details",
                options=[(cert.id, cert.common_name) for cert in certificates],
                format_func=lambda x: x[1]
            )
            
            if selected:
                cert_id = selected[0]
                
                # Create tabs for different views
                tab_details, tab_bindings, tab_history = st.tabs([
                    "Certificate Details",
                    "Bindings",
                    "Scan History"
                ])
                
                with tab_details:
                    render_certificate_details(session, cert_id)
                
                with tab_bindings:
                    render_certificate_bindings(session, cert_id)
                
                with tab_history:
                    render_scan_history(session, cert_id)
        
        # Show performance metrics at the bottom
        render_performance_metrics()

def save_certificate(session, cert_data):
    try:
        # ... existing code ...
        session.commit()
        notify("Certificate saved successfully!", "success")
    except Exception as e:  # Only Exception is possible here due to DB errors
        session.rollback()
        logger.exception(f"Error saving certificate: {str(e)}")
        notify(f"Error saving certificate: {str(e)}", "error") 