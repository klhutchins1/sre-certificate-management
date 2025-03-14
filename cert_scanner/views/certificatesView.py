"""
Certificate management view module for the Certificate Management System.

This module provides the Streamlit-based user interface for managing SSL/TLS certificates,
including:
- Certificate listing and filtering
- Detailed certificate information display
- Certificate binding management
- Manual certificate entry
- Certificate tracking and change management
- Certificate export functionality

The view implements a responsive grid-based interface using AG Grid for certificate
listing and provides detailed card views for individual certificates. It supports:
- Real-time certificate status monitoring
- Interactive platform selection
- Certificate binding management
- Change tracking
- PDF export capabilities

All database operations are handled through SQLAlchemy sessions with proper
error handling and state management.
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
from ..models import (
    Certificate, CertificateBinding, Host, HostIP, CertificateScan,
    HOST_TYPE_VIRTUAL, BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    ENV_INTERNAL, ENV_PRODUCTION, CertificateTracking, Application
)
from ..constants import platform_options
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css
from ..components.deletion_dialog import render_deletion_dialog, render_danger_zone
from ..notifications import initialize_notifications, show_notifications, notify, clear_notifications
import json

def render_certificate_list(engine):
    """Render the certificate list view"""
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
    # Initialize and clear notifications
    initialize_notifications()
    clear_notifications()
    
    # Create notification placeholder at the top
    notification_placeholder = st.empty()
    
    # Add custom progress bar color
    st.markdown("""
        <style>
        .stProgress > div > div > div > div {
            background-color: #0066ff;
        }
        </style>
        """, unsafe_allow_html=True)
    
    # Create title row with columns
    st.markdown('<div class="title-row">', unsafe_allow_html=True)
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Certificates")
    with col2:
        if st.button("➕ Add Certificate" if not st.session_state.get('show_manual_entry', False) else "❌ Cancel", 
                    type="primary" if not st.session_state.get('show_manual_entry', False) else "secondary",
                    use_container_width=True):
            # Toggle the form visibility
            st.session_state['show_manual_entry'] = not st.session_state.get('show_manual_entry', False)
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Show any pending success messages
    if 'success_message' in st.session_state:
        notify(st.session_state.success_message, "success")
        del st.session_state.success_message
    
    # Show manual entry form if button was clicked
    if st.session_state.get('show_manual_entry', False):
        st.markdown('<div class="form-container">', unsafe_allow_html=True)
        with SessionManager(engine) as session:
            render_manual_entry_form(session)
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Create metrics columns with minimal spacing
    st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    
    with SessionManager(engine) as session:
        if not session:
            notify("Database connection failed", "error")
            show_notifications()
            return
        
        # Calculate metrics
        total_certs = session.query(Certificate).count()
        valid_certs = session.query(Certificate).filter(
            Certificate.valid_until > datetime.now()
        ).count()
        total_bindings = session.query(CertificateBinding).count()
        
        # Display metrics
        col1.metric("Total Certificates", total_certs)
        col2.metric("Valid Certificates", valid_certs)
        col3.metric("Total Bindings", total_bindings)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    with SessionManager(engine) as session:
        if not session:
            notify("Database connection failed", "error")
            show_notifications()
            return
        
        # Fetch certificates for the table view
        certs_data = []
        certificates_dict = {}  # Store certificates for quick lookup
        
        # Query all certificates without joins first
        certificates = session.query(Certificate).options(
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.application),
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host),
            joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host_ip)
        ).all()
        
        if not certificates:
            notify("No certificates found in database", "info")
            show_notifications()
            return
        
        for cert in certificates:
            # Remove the refresh as we've already eager loaded the relationships
            certs_data.append({
                "Common Name": str(cert.common_name),
                "Serial Number": str(cert.serial_number),
                "Valid From": cert.valid_from.strftime("%Y-%m-%d"),
                "Valid Until": cert.valid_until.strftime("%Y-%m-%d"),
                "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                "Bindings": int(len(cert.certificate_bindings)),
                "_id": int(cert.id)  # Ensure ID is integer
            })
            certificates_dict[cert.id] = cert
        
        if certs_data:
            # Create DataFrame with explicit data types and clean data
            df = pd.DataFrame(certs_data)
                       
            # Configure AG Grid
            gb = GridOptionsBuilder.from_dataframe(df)
            
            # Configure default settings for all columns
            gb.configure_default_column(
                resizable=True,
                sortable=True,
                filter=True,
                editable=False
            )
            
            # Configure specific columns
            gb.configure_column(
                "Common Name",
                minWidth=200,
                flex=2
            )
            gb.configure_column(
                "Serial Number",
                minWidth=150,
                flex=1
            )
            gb.configure_column(
                "Valid From",
                type=["dateColumnFilter"],
                minWidth=120,
                valueFormatter="value ? new Date(value).toLocaleDateString() : ''"
            )
            gb.configure_column(
                "Valid Until",
                type=["dateColumnFilter"],
                minWidth=120,
                valueFormatter="value ? new Date(value).toLocaleDateString() : ''",
                cellClass=JsCode("""
                function(params) {
                    if (!params.data) return ['ag-date-cell'];
                    if (params.data.Status === 'Expired') return ['ag-date-cell', 'ag-date-cell-expired'];
                    return ['ag-date-cell'];
                }
                """)
            )
            gb.configure_column(
                "Status",
                minWidth=100,
                cellClass=JsCode("""
                function(params) {
                    if (!params.data) return [];
                    if (params.value === 'Expired') return ['ag-status-expired'];
                    if (params.value === 'Valid') return ['ag-status-valid'];
                    return [];
                }
                """)
            )
            gb.configure_column(
                "Bindings",
                type=["numericColumn"],
                minWidth=100,
                cellClass='ag-numeric-cell'
            )
            gb.configure_column("_id", hide=True)
            
            # Configure selection
            gb.configure_selection(
                selection_mode="single",
                use_checkbox=False,
                pre_selected_rows=[]
            )
            
            # Configure grid options
            grid_options = {
                'animateRows': True,
                'enableRangeSelection': True,
                'suppressAggFuncInHeader': True,
                'suppressMovableColumns': True,
                'rowHeight': 35,
                'headerHeight': 40,
                'domLayout': 'normal',
                'pagination': True,
                'paginationPageSize': 15,
                'paginationAutoPageSize': False
            }
            
            gb.configure_grid_options(**grid_options)
            
            gridOptions = gb.build()
            
            # Display the AG Grid
            grid_response = AgGrid(
                df,
                gridOptions=gridOptions,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                fit_columns_on_grid_load=True,
                theme="streamlit",
                allow_unsafe_jscode=True,
                key="cert_grid",
                reload_data=False,
                height=600
            )
            
            # Handle selection without extra spacing
            try:
                selected_rows = grid_response['selected_rows']
                
                if isinstance(selected_rows, pd.DataFrame):
                    if not selected_rows.empty:
                        selected_row = selected_rows.iloc[0].to_dict()
                        selected_cert_id = int(selected_row['_id'])
                        if selected_cert_id in certificates_dict:
                            selected_cert = certificates_dict[selected_cert_id]
                            render_certificate_card(selected_cert, session)
                elif isinstance(selected_rows, list) and selected_rows:
                    selected_row = selected_rows[0]
                    if isinstance(selected_row, dict) and '_id' in selected_row:
                        selected_cert_id = int(selected_row['_id'])
                        if selected_cert_id in certificates_dict:
                            selected_cert = certificates_dict[selected_cert_id]
                            render_certificate_card(selected_cert, session)
            except Exception as e:
                notify(f"Error handling selection: {str(e)}", "error")
                show_notifications()

    # Show all notifications at the end
    with notification_placeholder:
        show_notifications()

def render_certificate_card(cert, session):
    """
    Render a detailed certificate information card.
    """
    # Ensure relationships are loaded
    if not session.is_active:
        session.begin()
    
    # Refresh the certificate with all necessary relationships
    session.refresh(cert, ['certificate_bindings'])
    cert = session.query(Certificate).options(
        joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.application),
        joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host),
        joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host_ip)
    ).get(cert.id)
    
    # Create header with title and delete button
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader(f"📜 {cert.common_name}")
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Overview", "Bindings", "Details", "Change Tracking", "Danger Zone"])
    
    with tab1:
        render_certificate_overview(cert, session)
    
    with tab2:
        render_certificate_bindings(cert, session)
        
    with tab3:
        render_certificate_details(cert)
        
    with tab4:
        render_certificate_tracking(cert, session)
        
    with tab5:
        st.markdown("### ⚠️ Danger Zone")
        
        dependencies = {
            "Bindings": [
                f"{b.host.name if b.host else 'Unknown Host'}:{b.port if b.port else 'N/A'}" 
                for b in cert.certificate_bindings
            ],
            "Scan Records": [
                f"Scan on {s.scan_date.strftime('%Y-%m-%d %H:%M')}" 
                for s in cert.scans
            ]
        }
        
        def delete_certificate(session):
            session.delete(cert)
            session.commit()
            return True
        
        render_danger_zone(
            title="Delete Certificate",
            entity_name=cert.common_name,
            entity_type="certificate",
            dependencies=dependencies,
            on_delete=delete_certificate,
            session=session
        )

def render_certificate_overview(cert: Certificate, session) -> None:
    """Render the certificate overview tab."""
    # Ensure we have the latest data with all relationships
    session.refresh(cert, ['certificate_bindings', 'scans'])
    cert = session.query(Certificate).options(
        joinedload(Certificate.scans).joinedload(CertificateScan.host),
        joinedload(Certificate.scans).joinedload(CertificateScan.host).joinedload(Host.ip_addresses)
    ).get(cert.id)
    
    st.subheader("Certificate Overview")
    
    # Create columns for layout
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"**Common Name:** {cert.common_name}")
        st.markdown(f"**Valid From:** {cert.valid_from.strftime('%Y-%m-%d')}")
        
        expiry_date = cert.valid_until.strftime("%Y-%m-%d")
        if cert.valid_until < datetime.now():
            st.markdown(f"**Valid Until:** {expiry_date} <span class='text-danger'>(Expired)</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"**Valid Until:** {expiry_date} <span class='cert-status cert-valid'>Valid</span>", unsafe_allow_html=True)
        
        st.markdown(f"**Serial Number:** `{cert.serial_number}`")
        st.markdown(f"**Total Bindings:** {len(cert.certificate_bindings)}")
    
    with col2:
        st.markdown(f"**Thumbprint:** `{cert.thumbprint}`")
        st.markdown(f"**Chain Status:** {'🔒 Valid Chain' if cert.chain_valid else '⚠️ Unverified Chain'}")
        st.markdown(f"**Key Usage:** {cert.key_usage if cert.key_usage else '*Not specified*'}")
        
        # Add platforms
        platforms = sorted(set(b.platform for b in cert.certificate_bindings if b.platform))
        st.markdown(f"**Platforms:** {', '.join(platforms) if platforms else '*None*'}")
    
    # Add SAN section with expander and scan button
    with st.expander("Subject Alternative Names", expanded=True):
        san_list = cert.san  # This now returns a list due to the hybrid property
        if san_list:
            # Calculate height based on number of SANs
            content_height = max(68, 35 + (21 * len(san_list)))
            formatted_sans = "\n".join(sorted(san_list))
            
            col1, col2 = st.columns([0.7, 0.3])
            with col1:
                st.text_area(
                    "Subject Alternative Names",
                    value=formatted_sans,
                    height=content_height,
                    disabled=True,
                    label_visibility="collapsed"
                )
            with col2:
                if st.button("🔍 Scan SANs", type="primary", key=f"scan_sans_{cert.id}"):
                    # Store SANs in session state for scan page
                    st.session_state.scan_targets = san_list
                    # Navigate to scan view
                    st.session_state.current_view = "Scanner"
                    st.rerun()
        else:
            notify("No Subject Alternative Names found", "info")

def render_certificate_bindings(cert, session):
    """Render the certificate bindings section."""
    st.markdown("### Certificate Usage Tracking")

    # Add New Usage Record
    with st.expander("➕ Add New Usage Record"):
        st.markdown("""
        **Available Binding Types:**
        - **IP-Based Usage**: For certificates installed on web servers or load balancers, requiring hostname/IP and port
        - **Application Usage**: For certificates used by applications for JWT (JSON Web Token) signing
        - **Client Certificate Usage**: For certificates used for client authentication
        """)
        
        cols = st.columns([2, 3])
        with cols[0]:
            platform = st.selectbox(
                "Platform",
                options=["IIS", "F5", "Akamai", "Cloudflare", "Connection"],
                help="Select the platform where this certificate is used"
            )
            binding_type = st.selectbox(
                "Usage Type",
                ["IP-Based Usage", "Application Usage", "Client Certificate Usage"],
                help="Select how this certificate is being used"
            )
        
        # Fields based on binding type
        if binding_type == "IP-Based Usage":
            with cols[1]:
                hostname = st.text_input("Hostname", help="Name of the server where this certificate is installed")
                ip = st.text_input("IP Address", help="IP address where this certificate is installed")
                port = st.number_input("Port", min_value=1, max_value=65535, value=443)
        else:
            with cols[1]:
                hostname = st.text_input("Service/Application Name", help="Name of the service or application using this certificate")
                ip = ""
                port = None
            
        if st.button("Save Usage Record"):
            binding_type_map = {
                "IP-Based Usage": "IP",
                "Application Usage": "JWT",
                "Client Certificate Usage": "CLIENT"
            }
            try:
                add_host_to_certificate(cert, hostname, ip, port, platform, binding_type_map[binding_type], session)
                notify("Usage record added successfully", "success")
                st.rerun()
            except Exception as e:
                notify(f"Failed to add usage record: {str(e)}", "error")
    
    # Current Usage Records
    if not cert.certificate_bindings:
        notify("No usage records found for this certificate", "info")
        return
        
    # Load all applications once for efficiency
    applications = {app.id: app.name for app in session.query(Application).all()}
    
    # Create a clean table-like display for bindings
    for binding in cert.certificate_bindings:
        with st.container():
            cols = st.columns([4, 2, 1])
            
            # Column 1: Main Info (Hostname/IP/Port or Application) with binding type
            with cols[0]:
                if binding.binding_type == "IP":
                    # For IP bindings, show hostname if available, otherwise IP
                    display_name = binding.host.name if binding.host and binding.host.name else binding.host_ip.ip_address if binding.host_ip else ""
                    port_text = f":{binding.port}" if binding.port else ""
                    st.write(f"**Hostname/IP:** {display_name}{port_text} (IP-Based)")
                else:
                    # For JWT and Client Certificate bindings, show app name
                    app_name = applications.get(binding.application_id, "Unknown Application")
                    binding_type = "(JWT-Based)" if binding.binding_type == "JWT" else "(Client Certificate)"
                    st.write(f"**Application:** {app_name} {binding_type}")
            
            # Column 2: Platform dropdown
            with cols[1]:
                platform = st.selectbox(
                    "Platform",
                    ["F5", "IIS", "Akamai", "Cloudflare", "Connection"],
                    key=f"platform_{binding.id}",
                    index=["F5", "IIS", "Akamai", "Cloudflare", "Connection"].index(binding.platform) if binding.platform in ["F5", "IIS", "Akamai", "Cloudflare", "Connection"] else 0
                )
                if platform != binding.platform:
                    binding.platform = platform
                    session.commit()
            
            # Column 3: Delete button
            with cols[2]:
                if st.button("🗑️", key=f"delete_{binding.id}", help="Remove this usage record"):
                    session.delete(binding)
                    session.commit()
                    notify("Usage record deleted", "success")
                    st.rerun()
            st.divider()  # Add visual separation between bindings

def render_certificate_details(cert):
    """
    Render the technical certificate details tab.
    
    Args:
        cert (Certificate): The certificate object to display
        
    Displays:
    - Serial number and thumbprint
    - Issuer and subject information
    - Key usage flags
    - Signature algorithm details
    """
    # Add debug logging
    #print(f"DEBUG: Certificate details for {cert.common_name}:")
    #print(f"DEBUG: Signature Algorithm: {cert.signature_algorithm}")
    #print(f"DEBUG: Raw certificate data: {cert.__dict__}")
    
    # Prepare details with proper handling of None values
    details = {
        "Serial Number": cert.serial_number or "Not Available",
        "Thumbprint": cert.thumbprint or "Not Available",
        "Issuer": cert.issuer or {},  # Already returns a dict from hybrid_property
        "Subject": cert.subject or {},  # Already returns a dict from hybrid_property
        "Key Usage": cert.key_usage or "Not Specified",
        "Signature Algorithm": cert.signature_algorithm or "Not Available"
    }
    
    #print(f"DEBUG: Details to display: {details}")
    st.json(details)

def render_certificate_tracking(cert, session):
    """Render the certificate change tracking tab."""
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
                "Change Status",
                options=["Pending", "Completed", "Cancelled"],
                key=f"status_{cert.id}"
            )
            notes = st.text_area(
                "Change Notes",
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
                notify("Change entry added successfully!", "success")
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
        notify("No change entries found for this certificate", "info")

def render_manual_entry_form(session):
    """
    Render the manual certificate entry form.
    
    Args:
        session (Session): Database session for saving the certificate
        
    Features:
    - Input fields for certificate details
    - Certificate type selection
    - Platform selection
    - Validity period selection
    - Form validation and error handling
    """
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
    """Add a new host binding to a certificate."""
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
        notify("Host added successfully!", "success")
        st.rerun()
    except Exception as e:
        notify(f"Error adding host: {str(e)}", "error")
        session.rollback()

def save_manual_certificate(cert_type, common_name, serial_number, thumbprint, 
                          valid_from, valid_until, platform, session):
    """Save a manually entered certificate to the database."""
    try:
        # Create certificate
        cert = Certificate(
            serial_number=serial_number,
            thumbprint=thumbprint,
            common_name=common_name,
            valid_from=datetime.combine(valid_from, datetime.min.time()),
            valid_until=datetime.combine(valid_until, datetime.max.time()),
            sans_scanned=False,
            _san=json.dumps([])
        )
        session.add(cert)
        session.commit()
        notify("Certificate added successfully!", "success")
        st.session_state.show_manual_entry = False
        st.rerun()
    except Exception as e:
        notify(f"Error saving certificate: {str(e)}", "error")
        session.rollback()

def export_certificates_to_pdf(certificates, filename):
    """
    Export certificate information to PDF format.
    
    Args:
        certificates: Single Certificate object or list of Certificate objects
        filename (str): Output PDF file path
        
    Creates a detailed PDF report including:
    - Certificate overview
    - Binding information
    - Technical details
    - Subject Alternative Names
    - Current status
    
    Features:
    - Multi-certificate support
    - Page numbering
    - Structured sections
    - Error handling for malformed data
    """
    from fpdf import FPDF
    from datetime import datetime
    
    # Convert single certificate to list for consistent handling
    if not isinstance(certificates, (list, tuple)):
        certificates = [certificates]
    
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
    """
    Render the scanning history for a certificate.
    
    Args:
        cert (Certificate): The certificate object to display scan history for
        
    Displays:
    - Scan dates and times
    - Scan results and status
    - Port information
    - Historical scan data in tabular format
    """
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

def execute_scan(scan_targets, session):
    """Execute certificate scanning for the given targets."""
    # Get ALL certificates
    certs = session.query(Certificate).all()
    
    # For each certificate
    for cert in certs:
        # Get SANs
        sans = cert.san
        if not sans:
            continue
            
        # Create Host and CertificateScan records for each SAN
        for san in sans:
            # Create Host record
            host = Host(
                name=san.lower(),
                host_type=HOST_TYPE_SERVER,
                environment=ENV_PRODUCTION,
                last_seen=datetime.now()
            )
            session.add(host)
            
            # Create scan record
            scan = CertificateScan(
                certificate=cert,
                host=host,
                scan_date=datetime.now(),
                status='Attempted',
                port=443
            )
            session.add(scan)
    
    # Commit all changes
    session.commit()

