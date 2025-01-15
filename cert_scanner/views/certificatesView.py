import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.orm import joinedload
from ..models import (
    Certificate, Host, HostIP, CertificateBinding,
    HOST_TYPE_VIRTUAL, BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    ENV_INTERNAL
)
from ..constants import platform_options  # Import platform options from app
from ..db import SessionManager  # Import SessionManager for database sessions

def render_certificate_list(engine):
    """Render the certificate list view"""
    st.title("Certificates")
    
    # Create tabs for different views
    list_tab, detail_tab = st.tabs(["Certificate List", "Certificate Details"])
    
    with list_tab:
        # Add button for manual certificate entry
        if st.button("➕ Add Manual Certificate", type="primary"):
            st.session_state.show_manual_entry = True
        
        # Show manual entry form if button was clicked
        if st.session_state.get('show_manual_entry', False):
            with SessionManager(engine) as session:
                render_manual_entry_form(session)
        
        st.divider()
        
        # Create a placeholder for the table
        table_placeholder = st.empty()
        
        with st.spinner("Loading certificates..."):
            with SessionManager(engine) as session:
                if not session:
                    st.error("Database connection failed")
                    return
                
                # Fetch certificates for the table view
                certs_data = []
                for cert in session.query(Certificate).all():
                    certs_data.append({
                        "Common Name": cert.common_name,
                        "Serial Number": cert.serial_number,
                        "Valid From": cert.valid_from.strftime("%Y-%m-%d"),
                        "Valid Until": cert.valid_until.strftime("%Y-%m-%d"),
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                        "Bindings": len(cert.certificate_bindings),
                        "ID": cert.id  # Hidden column for reference
                    })
                
                if certs_data:
                    df = pd.DataFrame(certs_data)
                    
                    # Add styling
                    def color_status(val):
                        return 'color: red' if val == 'Expired' else 'color: green'
                    
                    # Style the dataframe
                    styled_df = df.style.applymap(color_status, subset=['Status'])
                    
                    # Display the table
                    st.dataframe(
                        styled_df,
                        column_config={
                            "Common Name": st.column_config.TextColumn("Common Name", width="large"),
                            "Serial Number": st.column_config.TextColumn("Serial Number", width="medium"),
                            "Valid From": st.column_config.DateColumn("Valid From"),
                            "Valid Until": st.column_config.DateColumn("Valid Until"),
                            "Status": st.column_config.TextColumn("Status", width="small"),
                            "Bindings": st.column_config.NumberColumn("Bindings", width="small"),
                            "ID": st.column_config.Column("ID", disabled=True)
                        },
                        hide_index=True,
                        use_container_width=True
                    )
                else:
                    st.warning("No certificates found in database")
    
    with detail_tab:
        # Show loading state
        with st.spinner("Loading certificates..."):
            with SessionManager(engine) as session:
                if not session:
                    st.error("Database connection failed")
                    return
                
                # Fetch all certificates once with relationships eagerly loaded
                certificates = (
                    session.query(Certificate)
                    .options(
                        joinedload(Certificate.certificate_bindings)
                        .joinedload(CertificateBinding.host)
                        .joinedload(Host.ip_addresses),
                        joinedload(Certificate.certificate_bindings)
                        .joinedload(CertificateBinding.host_ip)
                    )
                    .all()
                )
                
                if not certificates:
                    st.warning("No certificates found in database")
                    return
                
                # Display all certificates with their details
                for cert in certificates:
                    render_certificate_card(cert, session)

def render_certificate_card(cert, session):
    """Render a single certificate card with details"""
    with st.expander(
        f"📜 {cert.common_name}"
    ):
        tab1, tab2, tab3 = st.tabs(["Overview", "Bindings", "Details"])
        
        with tab1:
            render_certificate_overview(cert)
        
        with tab2:
            render_certificate_bindings(cert, session)
            
        with tab3:
            render_certificate_details(cert)

def render_certificate_overview(cert):
    """Render the certificate overview tab"""
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"""
            **Common Name:** {cert.common_name}  
            **Valid From:** {cert.valid_from.strftime('%Y-%m-%d')}  
            **Valid Until:** {cert.valid_until.strftime('%Y-%m-%d')}  
            **Status:** {"Valid" if cert.valid_until > datetime.now() else "Expired"}
        """)
    with col2:
        # Safely get bindings data
        bindings = getattr(cert, 'certificate_bindings', []) or []
        platforms = [b.platform for b in bindings if b.platform]
        st.markdown(f"""
            **Total Bindings:** {len(bindings)}  
            **Platforms:** {", ".join(set(platforms)) or "None"}  
            **SANs:** {len(eval(cert.san)) if cert.san else 0} names
        """)

def render_certificate_bindings(cert, session):
    """Render the certificate bindings tab"""
    # Show current bindings first
    if cert.certificate_bindings:
        st.markdown("### Current Bindings")
        for binding in cert.certificate_bindings:
            # Safely get binding information
            host_name = binding.host.name if binding.host else "Unknown Host"
            host_ip = getattr(binding, 'host_ip', None)
            ip_address = host_ip.ip_address if host_ip else "No IP"
            port = binding.port if binding.port else "N/A"
            
            # Create a container for each binding
            binding_container = st.container()
            with binding_container:
                st.markdown(f"#### 🔗 {host_name}")
                if binding.binding_type == BINDING_TYPE_IP:
                    st.caption(f"IP: {ip_address}, Port: {port}")
                else:
                    st.caption(f"Type: {binding.binding_type}")
                
                current_platform = binding.platform
                new_platform = st.selectbox(
                    "Platform",
                    options=[''] + list(platform_options.keys()),
                    format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                    key=f"platform_select_{cert.id}_{binding.id}",
                    index=list(platform_options.keys()).index(current_platform) + 1 if current_platform else 0
                )
                
                # Show current binding details
                if binding.binding_type == BINDING_TYPE_IP:
                    details = f"""
                        **Current Platform:** {platform_options.get(current_platform, 'Not Set')}
                        **Port:** {binding.port}
                        **Last Seen:** {binding.last_seen.strftime('%Y-%m-%d %H:%M')}
                    """
                else:
                    details = f"""
                        **Current Platform:** {platform_options.get(current_platform, 'Not Set')}
                        **Binding Type:** {binding.binding_type}
                        **Last Seen:** {binding.last_seen.strftime('%Y-%m-%d %H:%M')}
                    """
                st.markdown(details)
                
                if new_platform != current_platform:
                    if st.button("Update Platform", key=f"update_platform_{cert.id}_{binding.id}"):
                        binding.platform = new_platform
                        session.commit()
                        st.success("Platform updated!")
                        st.rerun()
                
                st.divider()  # Add a visual separator between bindings
    
    # Add new binding section
    st.markdown("### Add New Binding")
    # Add host management section
    col1, col2 = st.columns(2)
    with col1:
        new_hostname = st.text_input("Hostname", key=f"hostname_{cert.id}")
        new_ip = st.text_input("IP Address (optional)", key=f"ip_{cert.id}")
        new_port = st.number_input(
            "Port (optional)", 
            min_value=1, 
            max_value=65535, 
            value=443, 
            key=f"port_{cert.id}"
        )
    with col2:
        new_platform = st.selectbox(
            "Platform",
            options=[''] + list(platform_options.keys()),
            format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
            key=f"new_platform_{cert.id}"
        )
        binding_type = st.selectbox(
            "Binding Type",
            [BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT],
            help="Type of certificate binding",
            key=f"binding_type_{cert.id}"
        )
    
    if st.button("Add Host", key=f"add_host_{cert.id}"):
        add_host_to_certificate(cert, new_hostname, new_ip, new_port, new_platform, binding_type, session)

def render_certificate_details(cert):
    """Render the certificate details tab"""
    st.json({
        "Serial Number": cert.serial_number,
        "Thumbprint": cert.thumbprint,
        "Issuer": eval(cert.issuer) if cert.issuer else {},
        "Subject": eval(cert.subject) if cert.subject else {},
        "Key Usage": cert.key_usage,
        "Signature Algorithm": cert.signature_algorithm
    })

def render_manual_entry_form(session):
    """Render the manual certificate entry form"""
    with st.form("manual_certificate_entry"):
        st.subheader("Manual Certificate Entry")
        
        col1, col2 = st.columns(2)
        with col1:
            cert_type = st.selectbox(
                "Certificate Type",
                ["SSL/TLS", "JWT", "Client"],
                help="Select the type of certificate you're adding",
                key="manual_cert_type"
            )
            common_name = st.text_input(
                "Common Name",
                help="The main domain name or identifier for this certificate",
                key="manual_common_name"
            )
            serial_number = st.text_input(
                "Serial Number",
                help="The certificate's serial number",
                key="manual_serial_number"
            )
            thumbprint = st.text_input(
                "Thumbprint/Fingerprint",
                help="SHA1 or SHA256 fingerprint of the certificate",
                key="manual_thumbprint"
            )
        
        with col2:
            valid_from = st.date_input(
                "Valid From",
                help="Certificate validity start date",
                key="manual_valid_from"
            )
            valid_until = st.date_input(
                "Valid Until",
                help="Certificate expiration date",
                key="manual_valid_until"
            )
            platform = st.selectbox(
                "Platform",
                [''] + list(platform_options.keys()),
                format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                key="manual_platform"
            )
        
        submitted = st.form_submit_button("Save Certificate")
        if submitted:
            save_manual_certificate(cert_type, common_name, serial_number, thumbprint, 
                                 valid_from, valid_until, platform, session)

def add_host_to_certificate(cert, hostname, ip, port, platform, binding_type, session):
    """Add a new host binding to a certificate"""
    try:
        # Create or get host
        host = session.query(Host).filter_by(name=hostname).first()
        if not host:
            host = Host(
                name=hostname,
                host_type=HOST_TYPE_VIRTUAL if binding_type != BINDING_TYPE_IP else HOST_TYPE_SERVER,
                environment=ENV_INTERNAL,
                last_seen=datetime.now()
            )
            session.add(host)
            session.flush()
        
        # Create HostIP if provided
        host_ip = None
        if ip:
            host_ip = session.query(HostIP).filter_by(
                host_id=host.id,
                ip_address=ip
            ).first()
            
            if not host_ip:
                host_ip = HostIP(
                    host_id=host.id,
                    ip_address=ip,
                    last_seen=datetime.now()
                )
                session.add(host_ip)
                session.flush()
        
        # Create binding
        binding = CertificateBinding(
            host_id=host.id,
            host_ip_id=host_ip.id if host_ip else None,
            certificate_id=cert.id,
            port=port if binding_type == BINDING_TYPE_IP else None,
            binding_type=binding_type,
            platform=platform,
            last_seen=datetime.now()
        )
        session.add(binding)
        session.commit()
        st.success("Host added successfully!")
        st.rerun()
    except Exception as e:
        st.error(f"Error adding host: {str(e)}")
        session.rollback()

def save_manual_certificate(cert_type, common_name, serial_number, thumbprint, 
                          valid_from, valid_until, platform, session):
    """Save a manually entered certificate"""
    try:
        # Create certificate
        cert = Certificate(
            serial_number=serial_number,
            thumbprint=thumbprint,
            common_name=common_name,
            valid_from=datetime.combine(valid_from, datetime.min.time()),
            valid_until=datetime.combine(valid_until, datetime.max.time())
        )
        session.add(cert)
        session.commit()
        st.success("Certificate added successfully!")
        st.session_state.show_manual_entry = False
        st.rerun()
    except Exception as e:
        st.error(f"Error saving certificate: {str(e)}")
        session.rollback()

