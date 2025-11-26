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
    CertificateTracking, Application
)
from ..constants import HOST_TYPE_SERVER, HOST_TYPE_VIRTUAL, ENV_PRODUCTION, BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT, platform_options
from infra_mgmt.utils.SessionManager import SessionManager
from ..static.styles import load_warning_suppression, load_css
from ..notifications import initialize_page_notifications, show_notifications, notify, clear_page_notifications
import json
import logging
from ..services.CertificateService import CertificateService
from ..services.ViewDataService import ViewDataService
from ..components.deletion_dialog import render_danger_zone
from infra_mgmt.components.page_header import render_page_header
from infra_mgmt.components.metrics_row import render_metrics_row

logger = logging.getLogger(__name__)

CERTIFICATES_PAGE_KEY = "certificates" # Define page key

def render_certificate_list(engine):
    """Render the certificate list view"""
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
    # Initialize notifications for this page
    initialize_page_notifications(CERTIFICATES_PAGE_KEY)
    # clear_page_notifications(CERTIFICATES_PAGE_KEY) # Decide if clearing upfront is needed
    
    # Create notification placeholder at the top
    notification_placeholder = st.empty()
    with notification_placeholder.container():
        show_notifications(CERTIFICATES_PAGE_KEY) # Show notifications for this page

    
    # Standardized page header
    def toggle_manual_entry():
        st.session_state['show_manual_entry'] = not st.session_state.get('show_manual_entry', False)
    
    render_page_header(
        title="Certificates",
        button_label="➕ Add Certificate" if not st.session_state.get('show_manual_entry', False) else "❌ Cancel",
        button_callback=toggle_manual_entry,
        button_type="primary" if not st.session_state.get('show_manual_entry', False) else "secondary"
    )
    
    # Show any pending success messages (now handled by the placeholder)
    # if 'success_message' in st.session_state:
    #     notify(st.session_state.success_message, "success", page_key=CERTIFICATES_PAGE_KEY)
    #     del st.session_state.success_message
    
    # Show manual entry form if button was clicked
    if st.session_state.get('show_manual_entry', False):
        with SessionManager(engine) as session:
            render_manual_entry_form(session)
        return  # Prevent rendering the rest of the page when the form is shown
    

    
    # Use ViewDataService for metrics and table data
    view_data_service = ViewDataService()
    result = view_data_service.get_certificate_list_view_data(engine)
    if not result['success']:
        notify(result['error'], "error", page_key=CERTIFICATES_PAGE_KEY)
        # with notification_placeholder: # Already handled by the main placeholder
        #     show_notifications(CERTIFICATES_PAGE_KEY)
        return
    metrics = result['data']['metrics']
    df = result['data']['df']
    
    # Add Proxy/MITM column for quick scanning
    if 'Proxy/MITM' not in df.columns:
        def proxy_icon(row):
            if hasattr(row, 'proxied') and row.proxied:
                return '⚠️'
            if isinstance(row, dict) and row.get('proxied'):
                return '⚠️'
            return ''
        if hasattr(df, 'apply'):
            df['Proxy/MITM'] = df.apply(lambda row: proxy_icon(row), axis=1)
        else:
            df['Proxy/MITM'] = ''

    render_metrics_row([
        {"label": "Total Certificates", "value": metrics["total_certs"]},
        {"label": "Valid Certificates", "value": metrics["valid_certs"]},
        {"label": "Total Bindings", "value": metrics["total_bindings"]},
    ], columns=3)
    if df.empty:
        notify("No certificates found in database", "info", page_key=CERTIFICATES_PAGE_KEY)
        # with notification_placeholder: # Already handled
        #     show_notifications(CERTIFICATES_PAGE_KEY)
        return
    
    # Configure AG Grid
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(
        resizable=True,
        sortable=True,
        filter=True,
        editable=False
    )
    gb.configure_column("Proxy/MITM", minWidth=80, maxWidth=100, flex=0, type=["textColumn"],
        cellStyle={"textAlign": "center", "fontSize": "1.5em"},
        headerTooltip="Flagged as proxy/MITM certificate", filter=True, sortable=True)
    gb.configure_column("Common Name", minWidth=200, flex=2)
    gb.configure_column("Serial Number", minWidth=150, flex=1)
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
    gb.configure_selection(
        selection_mode="single",
        use_checkbox=False,
        pre_selected_rows=[]
    )
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
                with SessionManager(engine) as session:
                    cert_obj = session.get(Certificate, selected_cert_id)
                    if cert_obj is not None:
                        render_certificate_card(cert_obj, session)
        elif isinstance(selected_rows, list) and selected_rows:
            selected_row = selected_rows[0]
            if isinstance(selected_row, dict) and '_id' in selected_row:
                selected_cert_id = int(selected_row['_id'])
                with SessionManager(engine) as session:
                    cert_obj = session.get(Certificate, selected_cert_id)
                    if cert_obj is not None:
                        render_certificate_card(cert_obj, session)
    except Exception as e:
        notify(f"Error handling selection: {str(e)}", "error", page_key=CERTIFICATES_PAGE_KEY)
        # with notification_placeholder: # Already handled
        #     show_notifications(CERTIFICATES_PAGE_KEY)
    # Show all notifications at the end (now handled by the single placeholder at the top)
    # with notification_placeholder:
    #     show_notifications(CERTIFICATES_PAGE_KEY)

def render_certificate_card(cert, session):
    """
    Render a detailed certificate information card.
    """
    if cert is None:
        return
    # Ensure relationships are loaded
    if not session.is_active:
        session.begin()
    
    # Refresh the certificate with all necessary relationships
    session.refresh(cert, ['certificate_bindings'])
    cert = session.query(Certificate).options(
        joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.application),
        joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host),
        joinedload(Certificate.certificate_bindings).joinedload(CertificateBinding.host_ip)
    ).filter(Certificate.id == cert.id).first()
    
    # Create header with title and delete button
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader(f"📜 {cert.common_name}")
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Overview", "Bindings", "Details", "Change Tracking", "Danger Zone"])
    
    with tab1:
        render_certificate_overview(cert, session)
    
    with tab2:
        render_certificate_bindings(cert, session, session.bind)
        
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
        
        def delete_certificate(_):
            from ..services.CertificateService import CertificateService
            service = CertificateService()
            result = service.delete_certificate(cert, session)
            if result['success']:
                # Clear any selected certificate from session state and rerun to refresh UI
                st.session_state.pop('selected_cert_id', None)
                st.rerun()
            return result['success']
        
        render_danger_zone(
            title="Delete Certificate",
            entity_name=cert.common_name,
            entity_type="certificate",
            dependencies=dependencies,
            on_delete=delete_certificate, # This callback might call notify internally; ensure it uses page_key
            session=session
        )

def render_certificate_overview(cert: Certificate, session) -> None:
    """Render the certificate overview tab."""
    # Ensure we have the latest data with all relationships
    session.refresh(cert, ['certificate_bindings', 'scans'])
    cert = session.query(Certificate).options(
        joinedload(Certificate.scans).joinedload(CertificateScan.host),
        joinedload(Certificate.scans).joinedload(CertificateScan.host).joinedload(Host.ip_addresses)
    ).filter(Certificate.id == cert.id).first()
    
    st.subheader("Certificate Overview")
    
    # Proxy/MITM indicator
    if getattr(cert, 'proxied', False):
        notify(f"⚠️ This certificate is flagged as a PROXY/MITM certificate!\n\nReason: {cert.proxy_info or 'Matched proxy CA'}", "warning", page_key=CERTIFICATES_PAGE_KEY)
    
    # Proxy Override Section
    if getattr(cert, 'proxied', False) or cert.real_serial_number:
        with st.expander("🔧 Proxy Override Information", expanded=bool(cert.real_serial_number)):
            if cert.real_serial_number:
                st.success("✅ Real certificate information has been provided")
                st.markdown("**Real Certificate Information:**")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Real Serial Number:** `{cert.real_serial_number}`")
                    st.markdown(f"**Real Thumbprint:** `{cert.real_thumbprint}`")
                    if cert.real_valid_from:
                        st.markdown(f"**Real Valid From:** {cert.real_valid_from.strftime('%Y-%m-%d')}")
                    if cert.real_valid_until:
                        st.markdown(f"**Real Valid Until:** {cert.real_valid_until.strftime('%Y-%m-%d')}")
                
                with col2:
                    real_issuer = cert.real_issuer_dict
                    if real_issuer:
                        issuer_cn = real_issuer.get('commonName') or real_issuer.get('CN') or '*Not specified*'
                        st.markdown(f"**Real Issuer:** {issuer_cn}")
                    
                    real_subject = cert.real_subject_dict
                    if real_subject:
                        subject_cn = real_subject.get('commonName') or real_subject.get('CN') or '*Not specified*'
                        st.markdown(f"**Real Subject:** {subject_cn}")
                
                if cert.override_notes:
                    st.markdown(f"**Override Notes:** {cert.override_notes}")
                
                if cert.override_created_at:
                    st.markdown(f"**Override Created:** {cert.override_created_at.strftime('%Y-%m-%d %H:%M')}")
                
                # Show "Promote Real Values" button only when all required fields are set
                # Backend requires: real_serial_number, real_thumbprint, real_valid_from, real_valid_until
                can_promote = (
                    cert.real_serial_number and 
                    cert.real_thumbprint and 
                    cert.real_valid_from is not None and 
                    cert.real_valid_until is not None
                )
                
                col1, col2 = st.columns(2)
                with col1:
                    if can_promote:
                        if st.button("⬆️ Promote Real Values", type="primary", key=f"promote_real_{cert.id}"):
                            service = CertificateService()
                            result = service.promote_real_values_to_primary(cert.id, session)
                            if result['success']:
                                notify("Real values promoted to primary successfully", "success", page_key=CERTIFICATES_PAGE_KEY)
                                st.rerun()
                            else:
                                notify(result['error'], "error", page_key=CERTIFICATES_PAGE_KEY)
                    else:
                        missing_fields = []
                        if not cert.real_serial_number:
                            missing_fields.append("serial number")
                        if not cert.real_thumbprint:
                            missing_fields.append("thumbprint")
                        if cert.real_valid_from is None:
                            missing_fields.append("valid from date")
                        if cert.real_valid_until is None:
                            missing_fields.append("valid until date")
                        st.info(f"⚠️ Cannot promote: Missing {', '.join(missing_fields)}")
                
                with col2:
                    if st.button("🗑️ Clear Override", type="secondary", key=f"clear_override_{cert.id}"):
                        service = CertificateService()
                        result = service.clear_proxy_override(cert.id, session)
                        if result['success']:
                            notify("Override information cleared", "success", page_key=CERTIFICATES_PAGE_KEY)
                            st.rerun()
                        else:
                            notify(result['error'], "error", page_key=CERTIFICATES_PAGE_KEY)
            else:
                st.info("This certificate was detected behind a proxy. You can provide the real certificate information below.")
                
                with st.form("proxy_override_form"):
                    st.markdown("**Enter Real Certificate Information:**")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        real_serial = st.text_input("Real Serial Number", key=f"real_serial_{cert.id}")
                        real_thumbprint = st.text_input("Real Thumbprint", key=f"real_thumbprint_{cert.id}")
                        real_valid_from = st.date_input("Real Valid From", key=f"real_valid_from_{cert.id}")
                        real_valid_until = st.date_input("Real Valid Until", key=f"real_valid_until_{cert.id}")
                    
                    with col2:
                        real_issuer_cn = st.text_input("Real Issuer Common Name", key=f"real_issuer_cn_{cert.id}")
                        real_issuer_org = st.text_input("Real Issuer Organization", key=f"real_issuer_org_{cert.id}")
                        real_subject_cn = st.text_input("Real Subject Common Name", key=f"real_subject_cn_{cert.id}")
                        real_subject_org = st.text_input("Real Subject Organization", key=f"real_subject_org_{cert.id}")
                    
                    override_notes = st.text_area("Override Notes", key=f"override_notes_{cert.id}", 
                                               placeholder="Notes about this override...")
                    
                    submitted = st.form_submit_button("Save Override Information", type="primary")
                    if submitted:
                        if not real_serial or not real_thumbprint:
                            notify("Serial number and thumbprint are required", "error", page_key=CERTIFICATES_PAGE_KEY)
                        else:
                            # Prepare issuer and subject data
                            real_issuer = {}
                            if real_issuer_cn:
                                real_issuer['commonName'] = real_issuer_cn
                            if real_issuer_org:
                                real_issuer['organizationName'] = real_issuer_org
                            
                            real_subject = {}
                            if real_subject_cn:
                                real_subject['commonName'] = real_subject_cn
                            if real_subject_org:
                                real_subject['organizationName'] = real_subject_org
                            
                            # Convert dates to datetime
                            real_valid_from_dt = datetime.combine(real_valid_from, datetime.min.time()) if real_valid_from else None
                            real_valid_until_dt = datetime.combine(real_valid_until, datetime.min.time()) if real_valid_until else None
                            
                            service = CertificateService()
                            result = service.update_proxy_override(
                                cert.id, real_serial, real_thumbprint, real_issuer, real_subject,
                                real_valid_from_dt, real_valid_until_dt, override_notes, session
                            )
                            
                            if result['success']:
                                notify("Override information saved successfully", "success", page_key=CERTIFICATES_PAGE_KEY)
                                st.rerun()
                            else:
                                notify(result['error'], "error", page_key=CERTIFICATES_PAGE_KEY)
    
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
        # Show issuer commonName (or CN) instead of key usage
        issuer = cert.issuer or {}
        issuer_cn = issuer.get('commonName') or issuer.get('CN') or '*Not specified*'
        st.markdown(f"**Issuer Common Name:** {issuer_cn}")
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
            notify("No Subject Alternative Names found", "info", page_key=CERTIFICATES_PAGE_KEY)
            # show_notifications(CERTIFICATES_PAGE_KEY) # Handled by placeholder

def render_certificate_bindings(cert, session, engine):
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
            service = CertificateService()
            result = service.add_usage_record_to_certificate(
                cert.id, platform, binding_type, hostname, ip, port, session
            )
            if result['success']:
                notify("Usage record added successfully", "success", page_key=CERTIFICATES_PAGE_KEY)
                # show_notifications(CERTIFICATES_PAGE_KEY) # Handled by placeholder
                st.rerun()
            else:
                notify(f"Failed to add usage record: {result['error']}", "error", page_key=CERTIFICATES_PAGE_KEY)
                # show_notifications(CERTIFICATES_PAGE_KEY) # Handled by placeholder
    
    # Current Usage Records
    if not cert.certificate_bindings:
        notify("No usage records found for this certificate", "info", page_key=CERTIFICATES_PAGE_KEY)
        # show_notifications(CERTIFICATES_PAGE_KEY) # Handled by placeholder
        return
        
    # Load all applications once for efficiency
    applications = {app.id: app.name for app in session.query(Application).all()}
    
    # Create a clean table-like display for bindings
    service = CertificateService()
    bindings = service.get_certificate_bindings(cert.id, session)
    for binding in bindings:
        with st.container():
            cols = st.columns([4, 2, 1])
            
            # Column 1: Main Info (Hostname/IP/Port or Application) with binding type
            with cols[0]:
                if binding['binding_type'] == "IP":
                    # For IP bindings, show hostname if available, otherwise IP
                    display_name = binding['host_name'] if binding['host_name'] else binding['host_ip'] if binding['host_ip'] else ""
                    port_text = f":{binding['port']}" if binding['port'] else ""
                    st.write(f"**Hostname/IP:** {display_name}{port_text} (IP-Based)")
                else:
                    # For JWT and Client Certificate bindings, show app name
                    app_name = applications.get(binding['application_id'], "Unknown Application")
                    binding_type = "(JWT-Based)" if binding['binding_type'] == "JWT" else "(Client Certificate)"
                    st.write(f"**Application:** {app_name} {binding_type}")
            
            # Column 2: Platform dropdown
            with cols[1]:
                platform = st.selectbox(
                    "Platform",
                    ["F5", "IIS", "Akamai", "Cloudflare", "Connection"],
                    key=f"platform_{binding['id']}",
                    index=["F5", "IIS", "Akamai", "Cloudflare", "Connection"].index(binding['platform']) if binding['platform'] in ["F5", "IIS", "Akamai", "Cloudflare", "Connection"] else 0
                )
                if platform != binding['platform']:
                    binding['platform'] = platform
                    session.commit()
            
            # Column 3: Delete button
            with cols[2]:
                dialog_key = f"show_delete_usage_dialog_{binding['id']}"
                if st.button("🗑️", key=f"delete_{binding['id']}", help="Remove this usage record"):
                    st.session_state[dialog_key] = True
                if st.session_state.get(dialog_key, False):
                    def on_delete_usage(_):
                        from ..services.CertificateService import CertificateService
                        service = CertificateService()
                        # binding['obj'] is expected to be a CertificateBinding ORM object
                        result = service.delete_certificate_binding(binding['id'], session)
                        if result['success']:
                            notify("Usage record deleted", "success", page_key=CERTIFICATES_PAGE_KEY)
                            st.session_state[dialog_key] = False
                            st.rerun()
                        else:
                            notify(result['error'], "error", page_key=CERTIFICATES_PAGE_KEY)
                            st.session_state[dialog_key] = False
                        session.delete(binding['obj']) if 'obj' in binding else session.execute(
                            f"DELETE FROM certificate_binding WHERE id = :id", {{'id': binding['id']}})
                        session.commit()
                        notify("Usage record deleted", "success", page_key=CERTIFICATES_PAGE_KEY) # Duplicated notify? Review service logic
                        st.session_state[dialog_key] = False
                        st.rerun()
                        return True
                    render_danger_zone(
                        title="Delete Usage Record",
                        entity_name=binding.get('host_name') or binding.get('host_ip') or binding.get('application_id', 'Usage'),
                        entity_type="usage record",
                        dependencies={},
                        on_delete=on_delete_usage,
                        session=session,
                        custom_warning="This will permanently remove this usage record from the certificate."
                    )
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
    - Revocation status information
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
                notify("Change entry added successfully!", "success", page_key=CERTIFICATES_PAGE_KEY)
                st.session_state.show_tracking_entry = False
                st.rerun()
    
    # Display existing tracking entries in a compact format
    if cert.tracking_entries:
        st.markdown("### Existing Change Entries")
        
        # Use expanders to save space
        for i, entry in enumerate(cert.tracking_entries):
            with st.expander(f"📋 {entry.change_number or 'Unnamed Change'} - {entry.status or 'Unknown'}", expanded=False):
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**Change Number:** {entry.change_number or 'N/A'}")
                    st.write(f"**Status:** {entry.status or 'N/A'}")
                    st.write(f"**Planned Date:** {entry.planned_change_date.strftime('%Y-%m-%d') if entry.planned_change_date else 'Not set'}")
                    if entry.notes:
                        st.write(f"**Notes:** {entry.notes}")
                    st.caption(f"Created: {entry.created_at.strftime('%Y-%m-%d %H:%M') if entry.created_at else 'N/A'}")
                
                with col2:
                    if st.button("✏️ Edit", key=f"edit_tracking_{entry.id}", type="secondary"):
                        st.session_state.editing_tracking_id = entry.id
                        st.session_state.editing_cert_id = cert.id
                        st.rerun()
                    
                    if st.button("🗑️ Delete", key=f"delete_tracking_{entry.id}", type="secondary"):
                        st.session_state.deleting_tracking_id = entry.id
                        st.session_state.editing_cert_id = cert.id
                        st.rerun()
        
        # Handle edit form in a compact modal-like approach
        if st.session_state.get('editing_tracking_id') and st.session_state.get('editing_cert_id') == cert.id:
            tracking_id = st.session_state.editing_tracking_id
            tracking_entry = next((e for e in cert.tracking_entries if e.id == tracking_id), None)
            
            if tracking_entry:
                st.info("✏️ **Editing Change Entry**")
                with st.form("edit_tracking_form", clear_on_submit=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        change_number = st.text_input(
                            "Change/Ticket Number",
                            value=tracking_entry.change_number or "",
                            placeholder="e.g., CHG0012345",
                            key=f"edit_change_number_{tracking_id}"
                        )
                        planned_date = st.date_input(
                            "Planned Change Date",
                            value=tracking_entry.planned_change_date.date() if tracking_entry.planned_change_date else None,
                            key=f"edit_planned_date_{tracking_id}"
                        )
                    
                    with col2:
                        status = st.selectbox(
                            "Change Status",
                            options=["Pending", "Completed", "Cancelled"],
                            index=["Pending", "Completed", "Cancelled"].index(tracking_entry.status) if tracking_entry.status in ["Pending", "Completed", "Cancelled"] else 0,
                            key=f"edit_status_{tracking_id}"
                        )
                    
                    notes = st.text_area(
                        "Change Notes",
                        value=tracking_entry.notes or "",
                        placeholder="Enter any additional notes about this change...",
                        key=f"edit_notes_{tracking_id}",
                        height=100
                    )
                    
                    col1, col2, col3 = st.columns([1, 1, 2])
                    with col1:
                        if st.form_submit_button("💾 Save", type="primary"):
                            service = CertificateService()
                            # Get current certificate_id (can't change it from certificate view, so use existing)
                            tracking_entry = next((e for e in cert.tracking_entries if e.id == tracking_id), None)
                            current_cert_id = tracking_entry.certificate_id if tracking_entry else cert.id
                            result = service.update_tracking_entry(
                                tracking_id, current_cert_id, change_number, 
                                datetime.combine(planned_date, datetime.min.time()) if planned_date else None,
                                status, notes, session
                            )
                            if result['success']:
                                notify("Change entry updated successfully!", "success", page_key=CERTIFICATES_PAGE_KEY)
                                st.session_state.editing_tracking_id = None
                                st.rerun()
                            else:
                                notify(result['error'], "error", page_key=CERTIFICATES_PAGE_KEY)
                    
                    with col2:
                        if st.form_submit_button("❌ Cancel", type="secondary"):
                            st.session_state.editing_tracking_id = None
                            st.rerun()
        
        # Handle delete confirmation
        if st.session_state.get('deleting_tracking_id') and st.session_state.get('editing_cert_id') == cert.id:
            tracking_id = st.session_state.deleting_tracking_id
            tracking_entry = next((e for e in cert.tracking_entries if e.id == tracking_id), None)
            
            if tracking_entry:
                st.error(f"⚠️ **Delete Confirmation**")
                st.write(f"Are you sure you want to delete the change entry **'{tracking_entry.change_number}'**?")
                st.write("This action cannot be undone.")
                
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("🗑️ Yes, Delete", type="primary", key=f"confirm_delete_{tracking_id}"):
                        service = CertificateService()
                        result = service.delete_tracking_entry(tracking_id, session)
                        if result['success']:
                            notify("Change entry deleted successfully!", "success", page_key=CERTIFICATES_PAGE_KEY)
                            st.session_state.deleting_tracking_id = None
                            st.rerun()
                        else:
                            notify(result['error'], "error", page_key=CERTIFICATES_PAGE_KEY)
                
                with col2:
                    if st.button("❌ Cancel", type="secondary", key=f"cancel_delete_{tracking_id}"):
                        st.session_state.deleting_tracking_id = None
                        st.rerun()
    else:
        st.info("📝 No change entries found for this certificate")

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
    from ..services.CertificateService import CertificateService
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
            service = CertificateService()
            result = service.add_manual_certificate(
                cert_type, common_name, serial_number, thumbprint, valid_from, valid_until, platform, session
            )
            if result['success']:
                notify("Certificate added successfully!", "success", page_key=CERTIFICATES_PAGE_KEY)
                st.session_state.show_manual_entry = False
                st.rerun()
            else:
                notify(f"Error saving certificate: {result['error']}", "error", page_key=CERTIFICATES_PAGE_KEY)

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
        notify("No scan history found for this certificate.", "warning", page_key=CERTIFICATES_PAGE_KEY)
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
        notify("No scan history found for this certificate.", "warning", page_key=CERTIFICATES_PAGE_KEY)

def execute_scan(scan_targets, session):
    """Execute certificate scanning for the given targets."""
    # Get ALL certificates
    certs = session.query(Certificate).all()
    
    # Collect all hosts and scans for bulk insertion
    hosts_to_create = []
    scans_to_create = []
    current_time = datetime.now()
    
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
                last_seen=current_time
            )
            hosts_to_create.append(host)
            
            # Create scan record (will be linked after hosts are inserted)
            scan = CertificateScan(
                certificate=cert,
                host=host,  # This will be resolved after bulk insert
                scan_date=current_time,
                status='Attempted',
                port=443
            )
            scans_to_create.append(scan)
    
    # Bulk insert hosts first
    if hosts_to_create:
        session.bulk_save_objects(hosts_to_create)
        session.flush()  # Ensure hosts get IDs
    
    # Bulk insert scans
    if scans_to_create:
        session.bulk_save_objects(scans_to_create)
    
    # Commit all changes
    session.commit()
