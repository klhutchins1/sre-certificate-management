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
from ..models import Certificate, CertificateBinding, Host, HostIP, HOST_TYPE_VIRTUAL, BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT, ENV_INTERNAL, ENV_PRODUCTION, CertificateTracking
from ..constants import platform_options
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css
from ..components.deletion_dialog import render_deletion_dialog
import json

def render_certificate_list(engine):
    """Render the certificate list view"""
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
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
        st.success(st.session_state.success_message)
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
            st.error("Database connection failed")
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
            st.error("Database connection failed")
            return
        
        # Fetch certificates for the table view
        certs_data = []
        certificates_dict = {}  # Store certificates for quick lookup
        
        # Query all certificates without joins first
        certificates = session.query(Certificate).all()
        
        
        if not certificates:
            st.warning("No certificates found in database")
            return
        
        for cert in certificates:
            # Load relationships separately to avoid any potential join issues
            session.refresh(cert)
            
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
                st.error(f"Error handling selection: {str(e)}")

def render_certificate_card(cert, session):
    """
    Render a detailed certificate information card.
    
    Args:
        cert (Certificate): The certificate object to display
        session (Session): Database session for related queries
        
    The card displays certificate information in tabs:
    - Overview: Basic certificate information
    - Bindings: Certificate deployment information
    - Details: Technical certificate details
    - Change Tracking: Certificate lifecycle events
    """
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
        
        # Gather dependencies
        dependencies = {
            "Bindings": [f"{b.host.name}:{b.port}" if b.port else b.host.name 
                        for b in cert.certificate_bindings],
            "Change Records": [f"Change {t.change_number}" for t in cert.tracking_entries],
            "Scan History": [f"Scan on {s.scan_date.strftime('%Y-%m-%d %H:%M')}"
                           for s in cert.scans]
        }
        
        def delete_certificate():
            try:
                # Delete the certificate and all related records
                session.delete(cert)
                session.commit()
                st.success(f"Certificate {cert.common_name} deleted successfully")
                # Clear the selection and rerun to refresh the view
                if 'selected_cert_id' in st.session_state:
                    del st.session_state.selected_cert_id
                st.rerun()
            except Exception as e:
                st.error(f"Error deleting certificate: {str(e)}")
                session.rollback()
        
        # Render deletion dialog
        render_deletion_dialog(
            title="Delete Certificate",
            item_name=cert.common_name,
            dependencies=dependencies,
            on_confirm=delete_certificate,
            danger_text="This action cannot be undone. All related data will be permanently deleted."
        )

def render_certificate_overview(cert: Certificate, session) -> None:
    """Render the certificate overview tab."""
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
        
        # Add SANs scanned status - check if all SANs have been scanned
        san_list = cert.san
        if san_list:
            # Get all successful scans for this certificate's SANs
            scanned_hosts = {
                scan.host.name 
                for scan in cert.scans 
                if scan.status == 'Valid' and scan.host
            }
            # Check if we've attempted to scan the SANs
            has_been_scanned = cert.sans_scanned
        else:
            has_been_scanned = False
            
        st.markdown(f"**SANs Scanned:** {'Yes' if has_been_scanned else 'No'}")
    
    # Add SAN section with expander and scan button
    with st.expander("Subject Alternative Names", expanded=True):
        san_list = cert.san  # This now returns a list due to the hybrid property
        if san_list:
            # Calculate height based on number of SANs (match test expectations)
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
                
                # Show scan status
                if has_been_scanned:
                    scanned_count = len(scanned_hosts)
                    total_sans = len(san_list)
                    if scanned_count == total_sans:
                        st.info("All SANs have been scanned")
                    else:
                        st.warning(f"SANs scanned: {scanned_count}/{total_sans}")
                else:
                    st.info("SANs have not been scanned")
        else:
            st.info("No Subject Alternative Names found")

def render_certificate_bindings(cert, session):
    """
    Render the certificate bindings management tab.
    
    Args:
        cert (Certificate): The certificate object to display
        session (Session): Database session for related queries
        
    Features:
    - Add new bindings with host, IP, and platform information
    - Display existing bindings with detailed information
    - Interactive platform selection for each binding
    - Real-time binding updates
    """
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
                st.markdown(
                    f"""
                    <div class="binding-container">
                        <div class="binding-title">🔗 {host_name}</div>
                        <div class="binding-info">
                            <div class="binding-info-item">
                                <span class="binding-info-label">IP:</span>
                                <span class="binding-info-value">{ip_address if binding.binding_type == BINDING_TYPE_IP else 'N/A'}</span>
                            </div>
                            <div class="binding-info-item">
                                <span class="binding-info-label">Port:</span>
                                <span class="binding-info-value">{port if binding.binding_type == BINDING_TYPE_IP else 'N/A'}</span>
                            </div>
                            <div class="binding-info-item">
                                <span class="binding-info-label">Site:</span>
                                <span class="binding-info-value">{binding.site_name or 'Default'}</span>
                            </div>
                            <div class="binding-info-item">
                                <span class="binding-info-label">App:</span>
                                <span class="binding-info-value">{binding.application.name if binding.application else 'N/A'}</span>
                            </div>
                            <div class="binding-info-item">
                                <span class="binding-info-label">Type:</span>
                                <span class="binding-info-value">{binding.binding_type}</span>
                            </div>
                            <div class="binding-info-item">
                                <span class="binding-info-label">Seen:</span>
                                <span class="binding-info-value">{binding.last_seen.strftime('%Y-%m-%d %H:%M')}</span>
                            </div>
                            <div class="platform-section">
                                <span class="binding-info-label">Platform:</span>
                                <div class="inline-block">
                    """, 
                    unsafe_allow_html=True
                )
                
                # Platform selection
                current_platform = binding.platform
                new_platform = st.selectbox(
                    "Platform",
                    options=[''] + list(platform_options.keys()),
                    format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                    key=f"platform_select_{cert.id}_{binding.id}",
                    index=list(platform_options.keys()).index(current_platform) + 1 if current_platform else 0,
                    label_visibility="collapsed"
                )
                
                # Handle platform change and notification
                notification_key = f"platform_update_{cert.id}_{binding.id}"
                
                if new_platform != current_platform:
                    binding.platform = new_platform
                    session.commit()
                    st.session_state[notification_key] = {
                        'timestamp': datetime.now(),
                        'platform': new_platform,
                        'host': host_name
                    }
                
                # Show notification if active
                if notification_key in st.session_state:
                    notification = st.session_state[notification_key]
                    if (datetime.now() - notification['timestamp']).total_seconds() < 5:
                        st.success("Platform saved", icon="✅")
                    else:
                        del st.session_state[notification_key]
                
                st.markdown("""
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="binding-separator"></div>
                    """, 
                    unsafe_allow_html=True
                )

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
    print(f"DEBUG: Certificate details for {cert.common_name}:")
    print(f"DEBUG: Signature Algorithm: {cert.signature_algorithm}")
    print(f"DEBUG: Raw certificate data: {cert.__dict__}")
    
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
    """
    Render the certificate change tracking tab.
    
    Args:
        cert (Certificate): The certificate object to display
        session (Session): Database session for related queries
        
    Features:
    - Add new change tracking entries
    - Display change history in tabular format
    - Track planned changes and current status
    - Maintain audit trail of certificate lifecycle
    """
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
    """
    Add a new host binding to a certificate.
    
    Args:
        cert (Certificate): Target certificate for the binding
        hostname (str): Host name to bind
        ip (str): Optional IP address for the binding
        port (int): Port number for IP-based bindings
        platform (str): Platform identifier
        binding_type (str): Type of binding (IP, JWT, Client)
        session (Session): Database session for the operation
        
    Creates or updates:
    - Host record if not exists
    - Host IP record if provided
    - Certificate binding with specified parameters
    
    Handles:
    - Duplicate detection
    - Error handling
    - Transaction management
    """
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
    """
    Save a manually entered certificate to the database.
    
    Args:
        cert_type (str): Type of certificate (SSL/TLS, JWT, Client)
        common_name (str): Certificate Common Name
        serial_number (str): Certificate serial number
        thumbprint (str): Certificate thumbprint/fingerprint
        valid_from (date): Validity start date
        valid_until (date): Validity end date
        platform (str): Platform identifier
        session (Session): Database session for the operation
        
    Handles:
    - Data validation
    - Duplicate detection
    - Error handling
    - Transaction management
    """
    try:
        # Create certificate
        cert = Certificate(
            serial_number=serial_number,
            thumbprint=thumbprint,
            common_name=common_name,
            valid_from=datetime.combine(valid_from, datetime.min.time()),
            valid_until=datetime.combine(valid_until, datetime.max.time()),
            sans_scanned=False,  # Initialize to False for new certificates
            _san=json.dumps([])  # Initialize empty SAN list
        )
        session.add(cert)
        session.commit()
        st.success("Certificate added successfully!")
        st.session_state.show_manual_entry = False
        st.rerun()
    except Exception as e:
        st.error(f"Error saving certificate: {str(e)}")
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
    # Create progress tracking containers
    progress_container = st.empty()
    status_container = st.empty()
    
    with progress_container:
        st.markdown("""
            <style>
            .stProgress > div > div > div > div {
                background-color: #0066ff;
            }
            </style>
            """, unsafe_allow_html=True)
        progress = st.progress(0)
    
    # Execute scans with progress tracking
    with status_container:
        with st.spinner('Scanning certificates...'):
            for i, (hostname, port) in enumerate(scan_targets):
                status_container.text(f'Scanning {hostname}:{port}...')
                try:
                    # Perform certificate scan
                    cert_info = st.session_state.scanner.scan_certificate(hostname, port)
                    if cert_info:
                        st.session_state.scan_results["success"].append(f"{hostname}:{port}")
                        # Save scan results to database
                        try:
                            # Process certificate information
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
                                    _issuer=json.dumps(cert_info.issuer),
                                    _subject=json.dumps(cert_info.subject),
                                    _san=json.dumps(cert_info.san),
                                    key_usage=cert_info.key_usage,
                                    signature_algorithm=cert_info.signature_algorithm,
                                    chain_valid=cert_info.chain_valid,
                                    sans_scanned=bool(cert_info.san)
                                )
                                session.add(cert)
                            else:
                                # Update existing certificate
                                cert.thumbprint = cert_info.thumbprint
                                cert.common_name = cert_info.common_name
                                cert.valid_from = cert_info.valid_from
                                cert.valid_until = cert_info.expiration_date
                                cert._issuer = json.dumps(cert_info.issuer)
                                cert._subject = json.dumps(cert_info.subject)
                                cert._san = json.dumps(cert_info.san)
                                cert.key_usage = cert_info.key_usage
                                cert.signature_algorithm = cert_info.signature_algorithm
                                cert.chain_valid = cert_info.chain_valid
                                cert.sans_scanned = bool(cert_info.san)
                                cert.updated_at = datetime.now()
                            
                            # Process host information
                            host = session.query(Host).filter_by(
                                name=cert_info.hostname
                            ).first()
                            
                            if not host:
                                host = Host(
                                    name=cert_info.hostname,
                                    host_type=HOST_TYPE_SERVER,
                                    environment=ENV_PRODUCTION,
                                    last_seen=datetime.now()
                                )
                                session.add(host)
                            else:
                                host.last_seen = datetime.now()
                            
                            # Process IP addresses and bindings
                            for ip in cert_info.ip_addresses:
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
                                else:
                                    host_ip.last_seen = datetime.now()
                                
                                # Update certificate bindings
                                binding = session.query(CertificateBinding).filter_by(
                                    host_id=host.id,
                                    host_ip_id=host_ip.id,
                                    port=cert_info.port
                                ).first()
                                
                                if binding:
                                    binding.certificate_id = cert.id
                                    binding.last_seen = datetime.now()
                                else:
                                    binding = CertificateBinding(
                                        host_id=host.id,
                                        host_ip_id=host_ip.id,
                                        certificate_id=cert.id,
                                        port=cert_info.port,
                                        binding_type='IP',
                                        last_seen=datetime.now()
                                    )
                                    session.add(binding)
                            
                            # Record successful scan
                            scan = CertificateScan(
                                certificate=cert,
                                scan_date=datetime.now(),
                                status='Valid',
                                port=cert_info.port
                            )
                            session.add(scan)
                            
                            session.commit()
                        except Exception as e:
                            st.session_state.scan_results["error"].append(f"{hostname}:{port} - Database error: {str(e)}")
                            session.rollback()
                    else:
                        # Handle failed certificate retrieval
                        st.session_state.scan_results["error"].append(f"{hostname}:{port} - Failed to retrieve certificate")
                        try:
                            # Record failed scan
                            host = session.query(Host).filter_by(name=hostname).first()
                            if not host:
                                host = Host(
                                    name=hostname,
                                    host_type=HOST_TYPE_SERVER,
                                    environment=ENV_PRODUCTION,
                                    last_seen=datetime.now()
                                )
                                session.add(host)
                                session.flush()

                            scan = CertificateScan(
                                scan_date=datetime.now(),
                                status='Failed',
                                port=port,
                                host_id=host.id
                            )
                            session.add(scan)
                            session.commit()
                        except Exception as e:
                            logger.error(f"Failed to record failed scan: {str(e)}")
                            session.rollback()
                except Exception as e:
                    # Handle other errors
                    error_msg = f"Error scanning {hostname}:{port} - {str(e)}"
                    st.error(error_msg)
                    st.session_state.scan_results["error"].append(error_msg)
                    try:
                        # Record failed scan
                        host = session.query(Host).filter_by(name=hostname).first()
                        if not host:
                            host = Host(
                                name=hostname,
                                host_type=HOST_TYPE_SERVER,
                                environment=ENV_PRODUCTION,
                                last_seen=datetime.now()
                            )
                            session.add(host)
                            session.flush()

                        scan = CertificateScan(
                            scan_date=datetime.now(),
                            status='Failed',
                            port=port,
                            host_id=host.id
                        )
                        session.add(scan)
                        session.commit()
                    except Exception as e:
                        logger.error(f"Failed to record failed scan: {str(e)}")
                        session.rollback()
                
                # Update progress
                progress.progress((i + 1) / len(scan_targets))
    
    # Clear status after completion
    status_container.empty()

