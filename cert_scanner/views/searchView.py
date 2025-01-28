import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, and_, String
from ..models import Certificate, Host, HostIP, CertificateBinding
from ..db import SessionManager

def render_search_view(engine):
    """Render the certificate search view"""
    st.title("Search")
    
    # Search input
    search_query = st.text_input(
        "Search certificates, hosts, or IP addresses",
        placeholder="Enter hostname, IP, common name, serial number..."
    ).strip()
    
    # Search filters
    col1, col2, col3 = st.columns(3)
    with col1:
        search_type = st.selectbox(
            "Search In",
            ["All", "Certificates", "Hosts", "IP Addresses"]
        )
    with col2:
        status_filter = st.selectbox(
            "Certificate Status",
            ["All", "Valid", "Expired"]
        )
    with col3:
        platform_filter = st.selectbox(
            "Platform",
            ["All", "F5", "Akamai", "Cloudflare", "IIS", "Connection"]
        )
    
    if search_query:
        with SessionManager(engine) as session:
            results = perform_search(session, search_query, search_type, status_filter, platform_filter)
            
            # Check if there are any actual results
            if not results or (
                ('certificates' not in results or not results['certificates']) and 
                ('hosts' not in results or not results['hosts'])
            ):
                st.info("No results found")
                return
            
            # Display results in sections
            if 'certificates' in results and (search_type in ['All', 'Certificates']):
                st.subheader("Certificates")
                cert_data = []
                for cert in results['certificates']:
                    cert_data.append({
                        "Common Name": cert.common_name,
                        "Serial Number": cert.serial_number,
                        "Valid Until": cert.valid_until,
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                        "Bindings": len(cert.certificate_bindings)
                    })
                if cert_data:
                    df = pd.DataFrame(cert_data)
                    st.dataframe(
                        df,
                        column_config={
                            "Common Name": st.column_config.TextColumn("Common Name", width="large"),
                            "Serial Number": st.column_config.TextColumn("Serial Number", width="medium"),
                            "Valid Until": st.column_config.DatetimeColumn("Valid Until", format="DD/MM/YYYY"),
                            "Status": st.column_config.TextColumn("Status", width="small"),
                            "Bindings": st.column_config.NumberColumn("Bindings", width="small")
                        },
                        hide_index=True,
                        use_container_width=True
                    )
            
            if 'hosts' in results and (search_type in ['All', 'Hosts', 'IP Addresses']):
                st.subheader("Hosts")
                host_data = []
                for host in results['hosts']:
                    for ip in host.ip_addresses:
                        for binding in host.certificate_bindings:
                            # Only show bindings that match the platform filter and IP
                            if binding.host_ip_id == ip.id and (
                                platform_filter == "All" or 
                                binding.platform == platform_filter
                            ):
                                # Check status filter
                                is_valid = binding.certificate.valid_until > datetime.now()
                                if status_filter == "All" or (
                                    (status_filter == "Valid") == is_valid
                                ):
                                    host_data.append({
                                        "Hostname": host.name,
                                        "IP Address": ip.ip_address,
                                        "Port": binding.port,
                                        "Certificate": binding.certificate.common_name,
                                        "Platform": binding.platform or "Unknown",
                                        "Last Seen": binding.last_seen
                                    })
                if host_data:
                    df = pd.DataFrame(host_data)
                    st.dataframe(
                        df,
                        column_config={
                            "Hostname": st.column_config.TextColumn("Hostname", width="large"),
                            "IP Address": st.column_config.TextColumn("IP Address", width="medium"),
                            "Port": st.column_config.NumberColumn("Port", width="small"),
                            "Certificate": st.column_config.TextColumn("Certificate", width="large"),
                            "Platform": st.column_config.TextColumn("Platform", width="small"),
                            "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="DD/MM/YYYY HH:mm")
                        },
                        hide_index=True,
                        use_container_width=True
                    )

def perform_search(session, query, search_type, status_filter, platform_filter):
    """Perform search across the database"""
    results = {}
    now = datetime.now()
    
    # Build certificate query
    cert_query = session.query(Certificate).options(
        joinedload(Certificate.certificate_bindings)
        .joinedload(CertificateBinding.host)
        .joinedload(Host.ip_addresses)
    )
    
    # Add status filter
    if status_filter != "All":
        is_valid = status_filter == "Valid"
        cert_query = cert_query.filter(
            Certificate.valid_until > now if is_valid else Certificate.valid_until <= now
        )
    
    # Add platform filter to certificate bindings
    if platform_filter != "All":
        cert_query = cert_query.join(CertificateBinding).filter(
            CertificateBinding.platform == platform_filter
        )
    
    # Search certificates
    if search_type in ['All', 'Certificates']:
        results['certificates'] = cert_query.filter(
            or_(
                Certificate.common_name.ilike(f"%{query}%"),
                Certificate.serial_number.ilike(f"%{query}%"),
                Certificate._subject.ilike(f"%{query}%"),
                Certificate._san.ilike(f"%{query}%")
            )
        ).all()
    
    # Search hosts and IPs
    if search_type in ['All', 'Hosts', 'IP Addresses']:
        host_query = session.query(Host).options(
            joinedload(Host.ip_addresses),
            joinedload(Host.certificate_bindings)
            .joinedload(CertificateBinding.certificate)
        )
        
        # Add platform filter
        if platform_filter != "All":
            host_query = host_query.join(
                CertificateBinding,
                Host.certificate_bindings
            ).filter(
                CertificateBinding.platform == platform_filter
            )
        
        # Add status filter
        if status_filter != "All":
            is_valid = status_filter == "Valid"
            host_query = host_query.join(
                CertificateBinding,
                Host.certificate_bindings
            ).join(
                Certificate,
                CertificateBinding.certificate
            ).filter(
                Certificate.valid_until > now if is_valid else Certificate.valid_until <= now
            )
        
        results['hosts'] = host_query.filter(
            or_(
                Host.name.ilike(f"%{query}%"),
                Host.ip_addresses.any(HostIP.ip_address.ilike(f"%{query}%"))
            )
        ).all()
    
    return results
