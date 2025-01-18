import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy.orm import joinedload
from ..models import (
    Certificate, Host, HostIP, CertificateBinding, CertificateTracking,
    HOST_TYPE_VIRTUAL, BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    ENV_INTERNAL
)
from ..constants import platform_options
from ..db import SessionManager

def render_certificate_list(engine):
    """Render the certificate list view"""
    # Add custom CSS to align the button with the title
    st.markdown("""
        <style>
        div[data-testid="stHorizontalBlock"] {
            align-items: center;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Create title row with columns
    col1, col2 = st.columns([0.7, 0.3])
    with col1:
        st.title("Certificates")
    with col2:
        if st.button("➕ Add Certificate", type="primary", use_container_width=True):
            st.session_state.show_manual_entry = True
    
    # Show manual entry form if button was clicked
    if st.session_state.get('show_manual_entry', False):
        with SessionManager(engine) as session:
            render_manual_entry_form(session)
            st.divider()
    
    # Create a placeholder for the table
    with st.spinner("Loading certificates..."):
        with SessionManager(engine) as session:
            if not session:
                st.error("Database connection failed")
                return
            
            # Fetch certificates for the table view
            certs_data = []
            certificates_dict = {}  # Store certificates for quick lookup
            
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
            
            for cert in certificates:
                certs_data.append({
                    "Common Name": cert.common_name,
                    "Serial Number": cert.serial_number,
                    "Valid From": cert.valid_from.strftime("%Y-%m-%d"),
                    "Valid Until": cert.valid_until.strftime("%Y-%m-%d"),
                    "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                    "Bindings": len(cert.certificate_bindings),
                    "_id": cert.id  # Hidden ID for internal use
                })
                certificates_dict[cert.id] = cert
            
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
                        "_id": st.column_config.Column("ID", disabled=True, required=False)
                    },
                    hide_index=True,
                    use_container_width=True
                )
                
                # Add certificate selection dropdown
                cert_options = {f"{cert['Common Name']} ({cert['Serial Number']})": cert['_id'] 
                              for cert in certs_data}
                selected_cert_name = st.selectbox(
                    "Select a certificate to view details",
                    options=list(cert_options.keys()),
                    index=None
                )
                
                # Show certificate details if one is selected
                if selected_cert_name:
                    selected_cert_id = cert_options[selected_cert_name]
                    selected_cert = certificates_dict[selected_cert_id]
                    
                    st.divider()
                    render_certificate_card(selected_cert, session)
            else:
                st.warning("No certificates found in database")

def render_certificate_card(cert, session):
    """Render a single certificate card with details"""
    st.subheader(f"📜 {cert.common_name}")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Bindings", "Details", "Change Tracking"])
    
    with tab1:
        render_certificate_overview(cert, session)
    
    with tab2:
        render_certificate_bindings(cert, session)
        
    with tab3:
        render_certificate_details(cert)
        
    with tab4:
        render_certificate_tracking(cert, session)

def render_certificate_overview(cert, session):
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
            **SANs Scanned:** {"Yes" if cert.sans_scanned else "No"}
        """)
    
    # Add SAN section with expander and scan button
    with st.expander("Subject Alternative Names", expanded=True):
        if cert.san:
            try:
                # Get SANs and ensure it's a list
                san_list = cert.san
                
                # Handle string-formatted SANs (legacy data)
                if isinstance(san_list, str):
                    # Try to clean up the string format
                    san_list = san_list.replace("'", "").replace("[", "").replace("]", "").split(",")
                
                # Clean up the list - remove any formatting artifacts and empty entries
                san_list = [
                    domain.strip(" '\"[]") 
                    for domain in san_list 
                    if domain and domain.strip()
                ]
                
                if san_list:
                    col1, col2 = st.columns([0.7, 0.3])
                    with col1:
                        # Display each SAN on a new line with proper formatting
                        content_height = max(68, 35 + (21 * len(san_list)))
                        formatted_sans = "\n".join(sorted(set(san_list)))  # Sort domains and remove duplicates
                        st.text_area(
                            "",
                            value=formatted_sans,
                            height=content_height,
                            disabled=True
                        )
                    with col2:
                        if st.button("🔍 Scan SANs", type="primary", key=f"scan_sans_{cert.id}"):
                            # Store SANs in session state for scan page
                            st.session_state.scan_targets = san_list
                            # Mark certificate as scanned and commit to database
                            cert.sans_scanned = True
                            session.commit()
                            # Navigate to scan view
                            st.session_state.current_view = "Scan"
                            st.rerun()
                else:
                    st.info("No Subject Alternative Names")
            except Exception as e:
                st.error(f"Error parsing Subject Alternative Names: {str(e)}")
        else:
            st.info("No Subject Alternative Names")

def render_certificate_bindings(cert, session):
    """Render the certificate bindings tab"""
    # Add custom CSS to reduce spacing and fix alignment
    st.markdown("""
        <style>
        /* Reduce spacing between columns */
        [data-testid="column"] {
            padding: 0 !important;
            margin: 0 !important;
        }
        /* Make form elements more compact and aligned */
        [data-testid="stVerticalBlock"] > div {
            padding-bottom: 0.5rem !important;
        }
        /* Align form inputs */
        .stTextInput, .stNumberInput, .stSelectbox {
            margin-top: 0 !important;
            padding-top: 0 !important;
            padding-bottom: 0.5rem !important;
        }
        /* Fix label alignment */
        .stTextInput > label, .stNumberInput > label, .stSelectbox > label {
            padding-bottom: 0.5rem !important;
        }
        /* Make inputs same height */
        .stTextInput > div > div > input, .stNumberInput > div > div > input {
            line-height: 1.6 !important;
        }
        /* Remove form border */
        [data-testid="stForm"] {
            border: none !important;
            padding: 0 !important;
        }
        /* Add space above button row */
        .stButton {
            margin-top: 1rem !important;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Add new binding section at the top with expander
    with st.expander("➕ Add New Binding", expanded=False):
        with st.form(key=f"binding_form_{cert.id}", clear_on_submit=True):
            # First row - all inputs in one line
            col1, col2, col3, col4, col5 = st.columns([0.2, 0.2, 0.2, 0.2, 0.2])
            
            with col1:
                new_hostname = st.text_input(
                    "Hostname",
                    key=f"hostname_{cert.id}",
                    placeholder="Enter hostname"
                )
            
            with col2:
                new_ip = st.text_input(
                    "IP Address",
                    key=f"ip_{cert.id}",
                    placeholder="Optional"
                )
            
            with col3:
                new_port = st.number_input(
                    "Port",
                    min_value=1,
                    max_value=65535,
                    value=443,
                    key=f"port_{cert.id}"
                )
            
            with col4:
                binding_type = st.selectbox(
                    "Binding Type",
                    [BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT],
                    help="Type of certificate binding",
                    key=f"binding_type_{cert.id}"
                )
            
            with col5:
                new_platform = st.selectbox(
                    "Platform",
                    options=[''] + list(platform_options.keys()),
                    format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                    key=f"new_platform_{cert.id}"
                )
            
            # Second row - button centered
            _, col_btn, _ = st.columns([0.4, 0.2, 0.4])
            with col_btn:
                submitted = st.form_submit_button("Add Binding", type="primary", use_container_width=True)
            
            if submitted:
                add_host_to_certificate(cert, new_hostname, new_ip, new_port, new_platform, binding_type, session)
    
    st.divider()  # Add a visual separator
    
    # Show current bindings
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
                
                # Create columns for platform selection with adjusted widths
                col1, col2, col3 = st.columns([0.15, 0.3, 0.15])
                
                with col1:
                    st.markdown("**Platform:**")
                
                current_platform = binding.platform
                with col2:
                    new_platform = st.selectbox(
                        f"Platform for {host_name}",  # Descriptive label for accessibility
                        options=[''] + list(platform_options.keys()),
                        format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                        key=f"platform_select_{cert.id}_{binding.id}",
                        index=list(platform_options.keys()).index(current_platform) + 1 if current_platform else 0,
                        label_visibility="collapsed"
                    )
                
                with col3:
                    if new_platform != current_platform:
                        if st.button("Update", key=f"update_platform_{cert.id}_{binding.id}", type="primary"):
                            binding.platform = new_platform
                            session.commit()
                            st.success("Platform updated!")
                            st.rerun()
                
                # Show current binding details
                if binding.binding_type == BINDING_TYPE_IP:
                    details = f"""
                        **Port:** {binding.port}  
                        **Last Seen:** {binding.last_seen.strftime('%Y-%m-%d %H:%M')}
                    """
                else:
                    details = f"""
                        **Binding Type:** {binding.binding_type}  
                        **Last Seen:** {binding.last_seen.strftime('%Y-%m-%d %H:%M')}
                    """
                st.markdown(details)
                
                st.divider()  # Add a visual separator between bindings

def render_certificate_details(cert):
    """Render the certificate details tab"""
    st.json({
        "Serial Number": cert.serial_number,
        "Thumbprint": cert.thumbprint,
        "Issuer": cert.issuer,  # Already returns a dict from hybrid_property
        "Subject": cert.subject,  # Already returns a dict from hybrid_property
        "Key Usage": cert.key_usage,
        "Signature Algorithm": cert.signature_algorithm
    })

def render_certificate_tracking(cert, session):
    """Render the certificate tracking tab"""
    col1, col2 = st.columns([0.7, 0.3])
    
    with col1:
        st.subheader("Change History")
    with col2:
        if st.button("➕ Add Change Entry", type="primary", use_container_width=True):
            st.session_state.show_tracking_entry = True
            st.session_state.editing_cert_id = cert.id
    
    # Show tracking entry form if button was clicked
    if st.session_state.get('show_tracking_entry', False) and st.session_state.get('editing_cert_id') == cert.id:
        with st.form("tracking_entry_form"):
            st.subheader("Add Change Entry")
            
            change_number = st.text_input(
                "Change/Ticket Number",
                placeholder="e.g., CHG0012345",
                key=f"change_number_{cert.id}"
            )
            planned_date = st.date_input(
                "Planned Change Date",
                key=f"planned_date_{cert.id}"
            )
            status = st.selectbox(
                "Change Status",  # Changed from "Status" to be more descriptive
                options=["Pending", "Completed", "Cancelled"],
                key=f"status_{cert.id}"
            )
            notes = st.text_area(
                "Change Notes",  # Changed from "Notes" to be more descriptive
                placeholder="Enter any additional notes about this change...",
                key=f"notes_{cert.id}"
            )
            
            submitted = st.form_submit_button("Save Entry")
            if submitted:
                # Create new tracking entry
                from datetime import datetime
                new_entry = CertificateTracking(
                    certificate_id=cert.id,
                    change_number=change_number,
                    planned_change_date=datetime.combine(planned_date, datetime.min.time()),
                    notes=notes,
                    status=status,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                session.add(new_entry)
                session.commit()
                st.success("Change entry added!")
                st.session_state.show_tracking_entry = False
                st.rerun()
    
    # Display existing tracking entries
    if cert.tracking_entries:
        # Create DataFrame for display
        tracking_data = []
        for entry in cert.tracking_entries:
            tracking_data.append({
                "Change Number": entry.change_number,
                "Planned Date": entry.planned_change_date,
                "Status": entry.status,
                "Notes": entry.notes,
                "Created": entry.created_at,
                "Updated": entry.updated_at
            })
        
        df = pd.DataFrame(tracking_data)
        st.dataframe(
            df,
            column_config={
                "Change Number": st.column_config.TextColumn(
                    "Change Number",
                    width="medium"
                ),
                "Planned Date": st.column_config.DatetimeColumn(
                    "Planned Date",
                    format="DD/MM/YYYY"
                ),
                "Status": st.column_config.TextColumn(
                    "Status",
                    width="small"
                ),
                "Notes": st.column_config.TextColumn(
                    "Notes",
                    width="large"
                ),
                "Created": st.column_config.DatetimeColumn(
                    "Created",
                    format="DD/MM/YYYY HH:mm"
                ),
                "Updated": st.column_config.DatetimeColumn(
                    "Updated",
                    format="DD/MM/YYYY HH:mm"
                )
            },
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("No change entries found for this certificate")

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

def export_certificate_to_pdf(cert, filename):
    """Export certificate details to PDF"""
    from fpdf import FPDF
    from datetime import datetime
    
    # Create PDF object
    pdf = FPDF()
    pdf.add_page()
    
    # Set font
    pdf.set_font('helvetica', 'B', 16)
    
    # Title
    pdf.cell(0, 10, f'Certificate Details: {cert.common_name}', ln=True, align='C')
    pdf.ln(10)
    
    # Set font for content
    pdf.set_font('helvetica', '', 12)
    
    # Certificate Overview
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'Overview', ln=True)
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 8, f'Common Name: {cert.common_name}', ln=True)
    pdf.cell(0, 8, f'Serial Number: {cert.serial_number}', ln=True)
    pdf.cell(0, 8, f'Valid From: {cert.valid_from.strftime("%Y-%m-%d")}', ln=True)
    pdf.cell(0, 8, f'Valid Until: {cert.valid_until.strftime("%Y-%m-%d")}', ln=True)
    pdf.cell(0, 8, f'Status: {"Valid" if cert.valid_until > datetime.now() else "Expired"}', ln=True)
    pdf.ln(5)
    
    # Bindings
    if cert.certificate_bindings:
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, 'Bindings', ln=True)
        pdf.set_font('helvetica', '', 12)
        for binding in cert.certificate_bindings:
            host_name = binding.host.name if binding.host else "Unknown Host"
            host_ip = getattr(binding, 'host_ip', None)
            ip_address = host_ip.ip_address if host_ip else "No IP"
            port = binding.port if binding.port else "N/A"
            
            pdf.cell(0, 8, f'Host: {host_name}', ln=True)
            if binding.binding_type == BINDING_TYPE_IP:
                pdf.cell(0, 8, f'IP: {ip_address}, Port: {port}', ln=True)
            pdf.cell(0, 8, f'Type: {binding.binding_type}', ln=True)
            pdf.cell(0, 8, f'Platform: {binding.platform or "Not Set"}', ln=True)
            pdf.cell(0, 8, f'Last Seen: {binding.last_seen.strftime("%Y-%m-%d %H:%M")}', ln=True)
            pdf.ln(5)
    
    # Subject Alternative Names
    if cert.san:
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, 'Subject Alternative Names', ln=True)
        pdf.set_font('helvetica', '', 12)
        try:
            san_list = cert.san
            if isinstance(san_list, str):
                try:
                    san_list = eval(san_list)
                except:
                    san_list = cert.san.split(',')
            
            san_list = [s.strip() for s in san_list if s.strip()]
            for san in san_list:
                pdf.cell(0, 8, san, ln=True)
        except Exception as e:
            pdf.cell(0, 8, f'Error parsing SANs: {str(e)}', ln=True)
        pdf.ln(5)
    
    # Certificate Details
    pdf.set_font('helvetica', 'B', 14)
    pdf.cell(0, 10, 'Technical Details', ln=True)
    pdf.set_font('helvetica', '', 12)
    pdf.cell(0, 8, f'Thumbprint: {cert.thumbprint}', ln=True)
    if cert.issuer:
        issuer_dict = eval(cert.issuer)
        pdf.cell(0, 8, f'Issuer: {", ".join(f"{k}={v}" for k, v in issuer_dict.items())}', ln=True)
    if cert.subject:
        subject_dict = eval(cert.subject)
        pdf.cell(0, 8, f'Subject: {", ".join(f"{k}={v}" for k, v in subject_dict.items())}', ln=True)
    pdf.cell(0, 8, f'Key Usage: {cert.key_usage}', ln=True)
    pdf.cell(0, 8, f'Signature Algorithm: {cert.signature_algorithm}', ln=True)
    
    # Save the PDF
    pdf.output(filename)

def export_certificates_to_pdf(certificates, filename):
    """Export multiple certificates to a single PDF"""
    from fpdf import FPDF
    from datetime import datetime
    
    # Create PDF object
    pdf = FPDF()
    
    # For each certificate
    for i, cert in enumerate(certificates):
        pdf.add_page()
        
        # Set font
        pdf.set_font('helvetica', 'B', 16)
        
        # Title
        pdf.cell(0, 10, f'Certificate Details: {cert.common_name}', ln=True, align='C')
        pdf.ln(10)
        
        # Set font for content
        pdf.set_font('helvetica', '', 12)
        
        # Certificate Overview
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, 'Overview', ln=True)
        pdf.set_font('helvetica', '', 12)
        pdf.cell(0, 8, f'Common Name: {cert.common_name}', ln=True)
        pdf.cell(0, 8, f'Serial Number: {cert.serial_number}', ln=True)
        pdf.cell(0, 8, f'Valid From: {cert.valid_from.strftime("%Y-%m-%d")}', ln=True)
        pdf.cell(0, 8, f'Valid Until: {cert.valid_until.strftime("%Y-%m-%d")}', ln=True)
        pdf.cell(0, 8, f'Status: {"Valid" if cert.valid_until > datetime.now() else "Expired"}', ln=True)
        pdf.ln(5)
        
        # Bindings
        if cert.certificate_bindings:
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Bindings', ln=True)
            pdf.set_font('helvetica', '', 12)
            for binding in cert.certificate_bindings:
                host_name = binding.host.name if binding.host else "Unknown Host"
                host_ip = getattr(binding, 'host_ip', None)
                ip_address = host_ip.ip_address if host_ip else "No IP"
                port = binding.port if binding.port else "N/A"
                
                pdf.cell(0, 8, f'Host: {host_name}', ln=True)
                if binding.binding_type == BINDING_TYPE_IP:
                    pdf.cell(0, 8, f'IP: {ip_address}, Port: {port}', ln=True)
                pdf.cell(0, 8, f'Type: {binding.binding_type}', ln=True)
                pdf.cell(0, 8, f'Platform: {binding.platform or "Not Set"}', ln=True)
                pdf.cell(0, 8, f'Last Seen: {binding.last_seen.strftime("%Y-%m-%d %H:%M")}', ln=True)
                pdf.ln(5)
        
        # Subject Alternative Names
        if cert.san:
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Subject Alternative Names', ln=True)
            pdf.set_font('helvetica', '', 12)
            try:
                san_list = cert.san
                if isinstance(san_list, str):
                    try:
                        san_list = eval(san_list)
                    except:
                        san_list = cert.san.split(',')
                
                san_list = [s.strip() for s in san_list if s.strip()]
                for san in san_list:
                    pdf.cell(0, 8, san, ln=True)
            except Exception as e:
                pdf.cell(0, 8, f'Error parsing SANs: {str(e)}', ln=True)
            pdf.ln(5)
        
        # Certificate Details
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, 'Technical Details', ln=True)
        pdf.set_font('helvetica', '', 12)
        pdf.cell(0, 8, f'Thumbprint: {cert.thumbprint}', ln=True)
        if cert.issuer:
            issuer_dict = eval(cert.issuer)
            pdf.cell(0, 8, f'Issuer: {", ".join(f"{k}={v}" for k, v in issuer_dict.items())}', ln=True)
        if cert.subject:
            subject_dict = eval(cert.subject)
            pdf.cell(0, 8, f'Subject: {", ".join(f"{k}={v}" for k, v in subject_dict.items())}', ln=True)
        pdf.cell(0, 8, f'Key Usage: {cert.key_usage}', ln=True)
        pdf.cell(0, 8, f'Signature Algorithm: {cert.signature_algorithm}', ln=True)
        
        # Add page number
        pdf.set_y(-15)
        pdf.set_font('helvetica', 'I', 8)
        pdf.cell(0, 10, f'Page {i+1} of {len(certificates)}', 0, 0, 'C')
    
    # Save the PDF
    pdf.output(filename)

def render_certificate_scans(cert):
    """Render the scan history for a certificate"""
    if not cert.scans:
        st.warning("No scan history found for this certificate.")
        return

    scan_data = []
    for scan in cert.scans:
        scan_data.append({
            "Scan Date": scan.scan_date,
            "Status": scan.status,
            "Port": scan.port,
        })

    if scan_data:
        df = pd.DataFrame(scan_data)
        st.dataframe(df)
    else:
        st.warning("No scan history found for this certificate.")

