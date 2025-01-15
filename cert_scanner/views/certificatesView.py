import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session
from ..models import (
    Certificate, Host, HostIP, CertificateBinding,
    HOST_TYPE_VIRTUAL, BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    ENV_INTERNAL
)
from ..constants import platform_options  # Import platform options from app

def render_certificate_list(engine):
    """Render the certificate list view"""
    st.title("Certificates")
        # Use full width for the main content
    st.markdown("""
        <style>
            .block-container {
                padding-top: 1rem;
                padding-right: 1rem;
                padding-left: 1rem;
                padding-bottom: 1rem;
            }
        </style>
    """, unsafe_allow_html=True)
    
    # Add button for manual certificate entry
    if st.button("➕ Add Manual Certificate", type="primary"):
        st.session_state.show_manual_entry = True
    
    # Show manual entry form if button was clicked
    if st.session_state.get('show_manual_entry', False):
        with st.form("manual_certificate_entry"):
            st.subheader("Manual Certificate Entry")
            
            col1, col2 = st.columns(2)
            with col1:
                cert_type = st.selectbox(
                    "Certificate Type",
                    ["SSL/TLS", "JWT", "Client"],
                    help="Select the type of certificate you're adding"
                )
                common_name = st.text_input(
                    "Common Name",
                    help="The main domain name or identifier for this certificate"
                )
                serial_number = st.text_input(
                    "Serial Number",
                    help="The certificate's serial number"
                )
                thumbprint = st.text_input(
                    "Thumbprint/Fingerprint",
                    help="SHA1 or SHA256 fingerprint of the certificate"
                )
            
            with col2:
                valid_from = st.date_input(
                    "Valid From",
                    help="Certificate validity start date"
                )
                valid_until = st.date_input(
                    "Valid Until",
                    help="Certificate expiration date"
                )
                platform = st.selectbox(
                    "Platform",
                    [''] + list(platform_options.keys()),
                    format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform'
                )
            
            # Additional fields based on certificate type
            if cert_type in ["JWT", "Client"]:
                issuer = st.text_input(
                    "Issuer",
                    help="Who issued this certificate"
                )
                subject = st.text_input(
                    "Subject",
                    help="The subject of this certificate"
                )
                key_usage = st.text_input(
                    "Key Usage",
                    help="How this certificate can be used"
                )
            
            submitted = st.form_submit_button("Save Certificate")
            
            if submitted:
                with Session(engine) as session:
                    try:
                        # Create certificate
                        cert = Certificate(
                            serial_number=serial_number,
                            thumbprint=thumbprint,
                            common_name=common_name,
                            valid_from=datetime.combine(valid_from, datetime.min.time()),
                            valid_until=datetime.combine(valid_until, datetime.max.time()),
                            issuer=str({'CN': issuer}) if cert_type in ["JWT", "Client"] else None,
                            subject=str({'CN': subject}) if cert_type in ["JWT", "Client"] else None,
                            key_usage=key_usage if cert_type in ["JWT", "Client"] else None,
                            signature_algorithm=None
                        )
                        session.add(cert)
                        
                        # Create a host entry for non-SSL certificates
                        if cert_type in ["JWT", "Client"]:
                            host = Host(
                                name=common_name,
                                host_type=HOST_TYPE_VIRTUAL,
                                environment=ENV_INTERNAL,
                                description=f"Manual {cert_type} certificate entry"
                            )
                            session.add(host)
                            
                            # Create binding without IP
                            binding = CertificateBinding(
                                host_id=host.id,
                                certificate_id=cert.id,
                                binding_type=cert_type.upper(),
                                platform=platform
                            )
                            session.add(binding)
                        
                        session.commit()
                        st.success("Certificate added successfully!")
                        st.session_state.show_manual_entry = False
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error saving certificate: {str(e)}")
                        session.rollback()
    
    st.divider()
    
    with Session(engine) as session:
        certs = session.query(Certificate).all()
        
        if not certs:
            st.warning("No certificates found in database")
            return
        
        # Display total count
        st.caption(f"Total Certificates: {len(certs)}")
        
        # Convert to DataFrame for display
        cert_data = []
        for cert in certs:
            # Convert string representation of SAN back to list
            san_list = eval(cert.san) if cert.san else []
            # Get unique hostnames from bindings
            hostnames = set(binding.host.name for binding in cert.bindings)
            # Get unique platforms from bindings
            platforms = set(binding.platform for binding in cert.bindings if binding.platform)
            
            cert_data.append({
                'Common Name': cert.common_name,
                'Serial Number': cert.serial_number,
                'Expiration': cert.valid_until,
                'Hosts': len(hostnames),
                'SANs': len(san_list),
                'Platforms': len(platforms),
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
                'Platforms': st.column_config.NumberColumn(
                    'Platforms',
                    help='Number of deployment platforms'
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
            height=400,
            hide_index=True
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
                # Group bindings by hostname
                hostname_bindings = {}
                for binding in cert.bindings:
                    if binding.host.name not in hostname_bindings:
                        hostname_bindings[binding.host.name] = []
                    hostname_bindings[binding.host.name].append(binding)
                
                if hostname_bindings:
                    for hostname, bindings in hostname_bindings.items():
                        # Get all IP:Port combinations for this hostname
                        ip_ports = [f"{b.host_ip.ip_address}:{b.port}" for b in bindings if b.host_ip]
                        st.markdown(
                            f"**{hostname}** "
                            f"<span style='color:gray; font-size:0.9em'>"
                            f"(🌐 {', '.join(ip_ports)} • "
                            f"🕒 {max(b.last_seen for b in bindings).strftime('%Y-%m-%d %H:%M')})</span>",
                            unsafe_allow_html=True
                        )
                else:
                    st.info("No hostnames associated")
            
            with tab3:
                st.subheader("Certificate Information")
                st.markdown("### Deployment Platforms")
                
                # Show current platforms and allow adding/removing
                for binding in cert.bindings:
                    # Create a descriptive title based on binding type
                    if binding.binding_type == BINDING_TYPE_IP:
                        title = f"🔗 {binding.host.name} ({binding.host_ip.ip_address if binding.host_ip else 'No IP'}:{binding.port})"
                    else:
                        title = f"🔗 {binding.host.name} ({binding.binding_type})"
                    
                    with st.expander(title):
                        current_platform = binding.platform
                        new_platform = st.selectbox(
                            "Select Platform",
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
                        st.caption(details)
                        
                        if new_platform != current_platform:
                            if st.button("Update Platform", key=f"update_platform_{cert.id}_{binding.id}"):
                                with Session(engine) as session:
                                    binding_update = session.query(CertificateBinding).filter_by(id=binding.id).first()
                                    binding_update.platform = new_platform
                                    session.commit()
                                    st.success("Platform updated!")
                                    st.rerun()
                
                st.divider()
                st.json({
                    "Serial Number": cert.serial_number,
                    "Thumbprint": cert.thumbprint,
                    "Issuer": eval(cert.issuer) if cert.issuer else {},
                    "Subject": eval(cert.subject) if cert.subject else {},
                    "Key Usage": cert.key_usage,
                    "Signature Algorithm": cert.signature_algorithm
                })

