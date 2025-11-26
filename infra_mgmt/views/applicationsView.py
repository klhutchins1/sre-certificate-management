"""
Applications View Module

This module provides the Streamlit interface for managing applications in the certificate management system.
It includes functionality for:
- Viewing all applications with their certificate bindings
- Adding new applications
- Editing existing applications
- Deleting applications
- Viewing detailed application information including certificate status
- Managing certificate bindings

The view supports two display modes:
1. Group by Application Type
2. All Applications (flat view)

Key Features:
- Interactive data grid with sorting and filtering
- Real-time certificate status monitoring
- Certificate expiration visualization
- Detailed application metrics
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
import logging
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
from ..models import Application, CertificateBinding, Certificate, Host, HostIP
from ..constants import APP_TYPES, app_types, HOST_TYPE_VIRTUAL, ENV_PRODUCTION
from ..static.styles import load_warning_suppression, load_css
from infra_mgmt.utils.SessionManager import SessionManager
from ..components.deletion_dialog import render_danger_zone
from infra_mgmt.notifications import initialize_page_notifications, show_notifications, notify, clear_page_notifications
import altair as alt
from ..services.ApplicationService import ApplicationService
from ..services.ViewDataService import ViewDataService
from infra_mgmt.components.page_header import render_page_header
from infra_mgmt.components.metrics_row import render_metrics_row

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configure Altair to use the correct version
alt.data_transformers.disable_max_rows()

# Add custom CSS for consistent heading styles
CUSTOM_CSS = """
<style>
h1 {
    font-size: 2rem !important;
    margin: 1rem 0 !important;
}
h2 {
    font-size: 1.5rem !important;
    margin: 0.75rem 0 !important;
}
h3 {
    font-size: 1.17rem !important;
    margin: 0.5rem 0 !important;
}
</style>
"""

# Add at the top of the file with other constants
BINDING_TYPE_DISPLAY = {
    "IP": "IP-Based Certificate",
    "JWT": "JWT Signing Certificate",
    "CLIENT": "Client Authentication Certificate",
    None: "Unknown Type"
}

APPLICATIONS_PAGE_KEY = "applications" # Define page key

def handle_add_form():
    """Handle the add application form submission."""
    if not st.session_state.app_name:
        notify("Application Name is required", "error", page_key=APPLICATIONS_PAGE_KEY)
        return
    
    if len(st.session_state.app_name) > 255:
        notify("Application Name must be 255 characters or less", "error", page_key=APPLICATIONS_PAGE_KEY)
        return
    
    try:
        with Session(st.session_state.engine) as session:
            result = ApplicationService.add_application(
                session,
                st.session_state.app_name,
                st.session_state.app_type,
                st.session_state.app_description,
                st.session_state.app_owner
            )
            if result['success']:
                app_id = result['app_id']
                
                # Handle bindings if provided
                bindings_added = 0
                cert_ids = st.session_state.get('add_app_bind_cert_ids', [])
                if cert_ids:
                    try:
                        binding_type_map = {
                            "IP-Based": "IP",
                            "JWT-Based": "JWT",
                            "Client Certificate": "CLIENT"
                        }
                        binding_type = binding_type_map.get(st.session_state.get('add_app_binding_type', 'JWT-Based'), 'JWT')
                        binding_method = st.session_state.get('add_app_binding_method', 'By Certificate Only')
                        
                        if binding_method == "By Certificate Only":
                            # Certificate only - bind all at once
                            bind_result = ApplicationService.bind_certificates(
                                st.session_state.engine, app_id,
                                cert_ids,
                                binding_type
                            )
                            if bind_result.get('success'):
                                bindings_added = bind_result.get('count', 0)
                        else:
                            # Process each selected certificate for host/domain bindings
                            for cert_id in cert_ids:
                                if binding_method == "By Certificate + Host":
                                    if st.session_state.get('add_app_bind_host_id'):
                                        bind_result = ApplicationService.bind_certificate_with_host(
                                            st.session_state.engine, app_id,
                                            cert_id,
                                            st.session_state.add_app_bind_host_id,
                                            st.session_state.get('add_app_bind_ip_id'),
                                            st.session_state.get('add_app_bind_port') if binding_type == "IP" else None,
                                            st.session_state.get('add_app_bind_platform', 'F5'),
                                            binding_type
                                        )
                                        if bind_result.get('success'):
                                            bindings_added += 1
                                elif binding_method == "By Certificate + Domain":
                                    if st.session_state.get('add_app_bind_hostname'):
                                        bind_result = ApplicationService.bind_certificate_with_domain(
                                            st.session_state.engine, app_id,
                                            cert_id,
                                            st.session_state.add_app_bind_hostname,
                                            st.session_state.get('add_app_bind_ip_address'),
                                            st.session_state.get('add_app_bind_port') if binding_type == "IP" else None,
                                            st.session_state.get('add_app_bind_platform', 'F5'),
                                            binding_type
                                        )
                                        if bind_result.get('success'):
                                            bindings_added += 1
                    except Exception as bind_error:
                        logger.exception(f"Error adding bindings: {str(bind_error)}")
                        # Don't fail the whole operation if binding fails
                
                st.session_state.show_add_app_form = False
                success_msg = "✅ Application added successfully!"
                if bindings_added > 0:
                    success_msg += f" {bindings_added} binding(s) added."
                notify(success_msg, "success", page_key=APPLICATIONS_PAGE_KEY)
                st.rerun()  # Refresh to hide the form and update the grid
            else:
                notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
    except Exception as e:
        logger.exception(f"Error adding application: {str(e)}")
        notify(f"Error adding application: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)

def toggle_add_form():
    """Toggle the add application form visibility."""
    st.session_state.show_add_app_form = not st.session_state.show_add_app_form
    st.rerun()  # Refresh to show/hide the form

def handle_update_form():
    try:
        application = st.session_state.get('current_app')
        engine = st.session_state.get('engine')
        if application and engine:
            result = ApplicationService.update_application(
                engine,
                application.id,
                st.session_state.new_name,
                st.session_state.new_type,
                st.session_state.new_description,
                st.session_state.new_owner
            )
            if result['success']:
                notify("Application updated successfully!", "success", page_key=APPLICATIONS_PAGE_KEY)
                st.rerun()  # Refresh to update the grid and details view
            else:
                notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
        else:
            notify("Unable to update application: Engine or application not available", "error", page_key=APPLICATIONS_PAGE_KEY)
    except Exception as e:
        logger.exception(f"Error updating application: {str(e)}")
        notify(f"Error updating application: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)

def handle_delete_app():
    try:
        application = st.session_state.get('current_app')
        engine = st.session_state.get('engine')
        if application and engine:
            result = ApplicationService.delete_application(engine, application.id)
            if result['success']:
                st.session_state.current_app = None
                notify("Application deleted successfully!", "success", page_key=APPLICATIONS_PAGE_KEY)
            else:
                notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
        else:
            notify("Unable to delete application: Engine or application not available", "error", page_key=APPLICATIONS_PAGE_KEY)
    except Exception as e:
        logger.exception(f"Error deleting application: {str(e)}")
        notify(f"Error deleting application: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)

def render_applications_view(engine) -> None:
    """Render the main applications management interface."""
    try:
        # Initialize UI components and styles
        load_warning_suppression()
        load_css()
        initialize_page_notifications(APPLICATIONS_PAGE_KEY) # Initialize for this page
        # clear_page_notifications(APPLICATIONS_PAGE_KEY) # Clear at beginning if needed, or before specific actions
        
        st.session_state.engine = engine
        if 'show_add_app_form' not in st.session_state:
            st.session_state.show_add_app_form = False
        
        notification_placeholder = st.empty() # Create placeholder first
        with notification_placeholder.container():
            show_notifications(APPLICATIONS_PAGE_KEY) # Show notifications for this page
            
        render_page_header(
            title="Applications",
            button_label="❌ Cancel" if st.session_state.show_add_app_form else "➕ Add Application",
            button_callback=toggle_add_form,
            button_type="secondary" if st.session_state.show_add_app_form else "primary"
        )
        if st.session_state.show_add_app_form:
            with st.form("add_application_form"):
                st.subheader("Add New Application")
                st.markdown('<div class="form-content">', unsafe_allow_html=True)
                col1, col2 = st.columns(2)
                with col1:
                    st.text_input(
                        "Application Name",
                        key="app_name",
                        help="Name of the application or service (e.g., 'Payment Gateway', 'Customer Portal')"
                    )
                    st.selectbox(
                        "Application Type",
                        options=APP_TYPES,
                        key="app_type",
                        help="The type of application or service"
                    )
                with col2:
                    st.text_input(
                        "Description",
                        key="app_description",
                        help="Brief description of what this application does"
                    )
                    st.text_input(
                        "Owner",
                        key="app_owner",
                        help="Team or individual responsible for this application"
                    )
                st.markdown('</div>', unsafe_allow_html=True)
                
                # Optional: Add bindings during creation - Better layout with more space
                st.markdown("---")
                st.markdown("### 🔗 Certificate Binding (Optional)")
                st.markdown("You can optionally add a certificate binding when creating this application.")
                
                binding_method = st.radio(
                    "Binding Method",
                    options=["By Certificate Only", "By Certificate + Host", "By Certificate + Domain"],
                    key="add_app_binding_method",
                    help="Choose how you want to bind certificates to this application",
                    horizontal=True
                )
                
                # Get available certificates
                available_certs = []
                try:
                    result = ApplicationService.get_available_certificates(engine, None)  # None for new app
                    if result['success']:
                        available_certs = result['data']
                except Exception as e:
                    logger.exception(f"Error loading certificates: {str(e)}")
                
                if available_certs:
                    cert_options = {
                        f"{cert.common_name} (Valid until: {cert.valid_until.strftime('%Y-%m-%d')})": cert.id
                        for cert in available_certs
                    }
                    
                    # Use a better layout - certificate gets full width, then 2 columns for other fields
                    st.markdown("**Certificate Configuration**")
                    
                    # Use multiselect for multiple certificates - better for applications with multiple certs
                    # Add wrapper with custom class for CSS targeting to ensure full width
                    st.markdown('<div class="certificate-multiselect-wrapper">', unsafe_allow_html=True)
                    selected_cert_names = st.multiselect(
                        "Certificates",
                        options=list(cert_options.keys()),
                        key="add_app_bind_certs",
                        help="Select one or more certificates to bind (optional). Applications can have multiple certificates."
                    )
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Store certificate IDs (list for multiple)
                    if selected_cert_names:
                        st.session_state.add_app_bind_cert_ids = [cert_options[name] for name in selected_cert_names]
                    else:
                        st.session_state.add_app_bind_cert_ids = []
                    
                    # Two columns for binding type and platform
                    subcol1, subcol2 = st.columns(2)
                    with subcol1:
                        binding_type = st.selectbox(
                            "Binding Type",
                            options=["IP-Based", "JWT-Based", "Client Certificate"],
                            key="add_app_binding_type",
                            help="How will this certificate be used?"
                        )
                    with subcol2:
                        platform = st.selectbox(
                            "Platform",
                            options=["F5", "IIS", "Akamai", "Cloudflare", "Connection"],
                            key="add_app_bind_platform",
                            help="Platform where this certificate is deployed"
                        )
                    
                    # Use a better layout - 2 columns for main fields, status on the side
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        
                        # Binding method specific fields
                        if binding_method == "By Certificate + Host":
                            st.markdown("**Host Configuration**")
                            hosts_result = ApplicationService.get_available_hosts(engine)
                            if hosts_result['success']:
                                hosts = hosts_result['data']
                                host_options = {f"{h.name}": h.id for h in hosts}
                                if host_options:
                                    selected_host_name = st.selectbox(
                                        "Host",
                                        options=["None"] + list(host_options.keys()),
                                        key="add_app_bind_host",
                                        help="Select a host (optional)"
                                    )
                                    
                                    if selected_host_name and selected_host_name != "None":
                                        selected_host_id = host_options[selected_host_name]
                                        st.session_state.add_app_bind_host_id = selected_host_id
                                        
                                        # Get IPs for selected host
                                        with SessionManager(engine) as session:
                                            host_obj = session.get(Host, selected_host_id)
                                            if host_obj and host_obj.ip_addresses:
                                                ip_options = {f"{ip.ip_address}": ip.id for ip in host_obj.ip_addresses}
                                                ipcol1, ipcol2 = st.columns(2)
                                                with ipcol1:
                                                    selected_ip_name = st.selectbox(
                                                        "IP Address (Optional)",
                                                        options=["None"] + list(ip_options.keys()),
                                                        key="add_app_bind_ip",
                                                        help="Select an IP address"
                                                    )
                                                    if selected_ip_name and selected_ip_name != "None":
                                                        st.session_state.add_app_bind_ip_id = ip_options[selected_ip_name]
                                                    else:
                                                        st.session_state.add_app_bind_ip_id = None
                                                with ipcol2:
                                                    if binding_type == "IP-Based":
                                                        st.number_input("Port", min_value=1, max_value=65535, value=443,
                                                                      key="add_app_bind_port")
                                                    else:
                                                        st.session_state.add_app_bind_port = None
                                            else:
                                                st.info("No IP addresses found for this host")
                                                st.session_state.add_app_bind_ip_id = None
                                                if binding_type == "IP-Based":
                                                    st.number_input("Port", min_value=1, max_value=65535, value=443,
                                                                  key="add_app_bind_port")
                                                else:
                                                    st.session_state.add_app_bind_port = None
                                    else:
                                        st.session_state.add_app_bind_host_id = None
                                        st.session_state.add_app_bind_ip_id = None
                                        st.session_state.add_app_bind_port = None
                                else:
                                    st.info("No hosts available. Please add hosts first.")
                                    st.session_state.add_app_bind_host_id = None
                        elif binding_method == "By Certificate + Domain":
                            st.markdown("**Domain Configuration**")
                            domaincol1, domaincol2 = st.columns(2)
                            with domaincol1:
                                hostname = st.text_input(
                                    "Hostname/Domain",
                                    key="add_app_bind_hostname",
                                    help="Enter the hostname or domain name"
                                )
                            with domaincol2:
                                ip_address = st.text_input(
                                    "IP Address (Optional)",
                                    key="add_app_bind_ip_address",
                                    help="Enter the IP address if known"
                                )
                            if binding_type == "IP-Based":
                                st.number_input("Port", min_value=1, max_value=65535, value=443,
                                              key="add_app_bind_port")
                            else:
                                st.session_state.add_app_bind_port = None
                        else:
                            # Certificate only
                            st.info("💡 Certificate will be bound without host or domain association.")
                    
                    with col2:
                        # Right column: Status and information
                        st.markdown("**Binding Status**")
                        if selected_cert_names:
                            st.success(f"✅ {len(selected_cert_names)} Certificate(s) Selected")
                            st.markdown(f"**Type:** {binding_type}")
                            st.markdown(f"**Platform:** {platform}")
                            
                            if binding_method == "By Certificate + Host":
                                if st.session_state.get('add_app_bind_host_id'):
                                    st.success("✓ Host configured")
                                else:
                                    st.info("Select a host")
                            elif binding_method == "By Certificate + Domain":
                                if st.session_state.get('add_app_bind_hostname'):
                                    st.success("✓ Domain configured")
                                else:
                                    st.info("Enter hostname/domain")
                            else:
                                st.info("Certificate-only binding")
                        else:
                            st.info("👆 Select certificate(s) to configure binding")
                else:
                    st.info("ℹ️ No certificates available to bind. You can add bindings later after creating the application.")
                    st.session_state.add_app_bind_cert_ids = []
                
                st.markdown("---")
                
                # Submit button must be inside the form
                submitted = st.form_submit_button("Add Application", type="primary")
                if submitted:
                    handle_add_form()

        st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        view_data_service = ViewDataService()
        result = view_data_service.get_applications_list_view_data(engine)
        if not result['success']:
            notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
            # show_notifications(APPLICATIONS_PAGE_KEY) # Removed, will show via placeholder on rerun
            return
        df = result['data']['df']
        column_config = result['data']['column_config']
        view_type = result['data'].get('view_type', 'All Applications')
        metrics = result['data'].get('metrics', {})
        render_metrics_row([
            {"label": "Total Applications", "value": metrics.get("total_apps", "")},
            {"label": "Total Bindings", "value": metrics.get("total_bindings", "")},
            {"label": "Active Types", "value": metrics.get("active_types", "")},
        ], columns=3)
        if not df.empty:
            # Keep _id column but hide it in the grid (needed for selection)
            gb = GridOptionsBuilder.from_dataframe(df)
            gb.configure_default_column(
                resizable=True,
                sortable=True,
                filter=True,
                editable=False,
                minWidth=120,
                flex=1
            )
            gb.configure_selection(
                selection_mode='single',
                use_checkbox=False,
                pre_selected_rows=[]
            )
            # Configure columns - hide _id but keep it in the dataframe
            for col in df.columns:
                if col == '_id':
                    gb.configure_column(col, hide=True)
                else:
                    gb.configure_column(col, minWidth=120, flex=1)
            gb.configure_grid_options(
                domLayout='normal',
                enableRangeSelection=True,
                pagination=True,
                paginationPageSize=10,
                paginationAutoPageSize=False,
                suppressRowClickSelection=False,
                rowSelection='single',
                animateRows=True,
                suppressAggFuncInHeader=True,
                suppressMovableColumns=True
            )
            grid_options = gb.build()
            grid_response = AgGrid(
                df,
                gridOptions=grid_options,
                height=400,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                update_mode=GridUpdateMode.SELECTION_CHANGED,
                fit_columns_on_grid_load=True,
                allow_unsafe_jscode=True,
                theme='streamlit',
                key=f"applications_grid_{view_type}",
                reload_data=False
            )
            # Handle selection - match certificatesView pattern exactly
            try:
                selected_rows = grid_response['selected_rows']
                if isinstance(selected_rows, pd.DataFrame):
                    if not selected_rows.empty:
                        selected_row = selected_rows.iloc[0].to_dict()
                        if '_id' in selected_row:
                            selected_app_id = int(selected_row['_id'])
                            with SessionManager(engine) as session:
                                selected_app = session.query(Application).options(
                                    joinedload(Application.certificate_bindings).joinedload(CertificateBinding.certificate),
                                    joinedload(Application.certificate_bindings).joinedload(CertificateBinding.host),
                                    joinedload(Application.certificate_bindings).joinedload(CertificateBinding.host_ip)
                                ).filter(Application.id == selected_app_id).first()
                                
                                if selected_app is not None:
                                    st.divider()
                                    st.session_state['current_app'] = selected_app
                                    render_application_details(selected_app, engine)
                elif isinstance(selected_rows, list) and selected_rows:
                    selected_row = selected_rows[0]
                    if isinstance(selected_row, dict) and '_id' in selected_row:
                        selected_app_id = int(selected_row['_id'])
                        with SessionManager(engine) as session:
                            selected_app = session.query(Application).options(
                                joinedload(Application.certificate_bindings).joinedload(CertificateBinding.certificate),
                                joinedload(Application.certificate_bindings).joinedload(CertificateBinding.host),
                                joinedload(Application.certificate_bindings).joinedload(CertificateBinding.host_ip)
                            ).filter(Application.id == selected_app_id).first()
                            
                            if selected_app is not None:
                                st.divider()
                                st.session_state['current_app'] = selected_app
                                render_application_details(selected_app, engine)
            except Exception as e:
                logger.exception(f"Error handling grid selection: {str(e)}")
                notify(f"Error handling selection: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
    except Exception as e:
        logger.exception(f"Error rendering applications view: {str(e)}")
        notify(f"Error rendering applications view: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
    # show_notifications(APPLICATIONS_PAGE_KEY) # Removed, will show via placeholder on rerun

def render_application_details(application: Application, engine) -> None:
    """
    Render a detailed view for a specific application.

    This function creates a tabbed interface showing detailed information about
    an application, including:
    - Basic application information (name, type, description, owner)
    - All certificates bound to the application
    - All hosts associated with bindings
    - All domains/hostnames
    - Certificate binding management with add/remove capabilities

    Args:
        application: Application model instance to display details for
        engine: Database engine for operations
    """
    if not application:
        return
    
    # Refresh application with all relationships
    with SessionManager(engine) as session:
        application = session.query(Application).options(
            joinedload(Application.certificate_bindings).joinedload(CertificateBinding.certificate),
            joinedload(Application.certificate_bindings).joinedload(CertificateBinding.host).joinedload(Host.ip_addresses),
            joinedload(Application.certificate_bindings).joinedload(CertificateBinding.host_ip).joinedload(HostIP.host).joinedload(Host.ip_addresses)
        ).filter(Application.id == application.id).first()
    
    if not application:
        notify("Application not found", "error", page_key=APPLICATIONS_PAGE_KEY)
        return
    
    st.session_state.current_app = application
    st.session_state.engine = engine
    
    details_container = st.container()
    with details_container:
        st.subheader(f"📱 {application.name}")
        
        # Collect unique certificates, hosts, and domains from bindings
        unique_certs = {}
        unique_hosts = {}
        unique_domains = set()
        
        for binding in application.certificate_bindings:
            if binding.certificate:
                cert_id = binding.certificate.id
                if cert_id not in unique_certs:
                    unique_certs[cert_id] = {
                        'certificate': binding.certificate,
                        'bindings': []
                    }
                unique_certs[cert_id]['bindings'].append(binding)
            
            # Collect hosts from bindings - check both host and host_ip relationships
            if binding.host:
                host_id = binding.host.id
                if host_id not in unique_hosts:
                    unique_hosts[host_id] = {
                        'host': binding.host,
                        'bindings': []
                    }
                unique_hosts[host_id]['bindings'].append(binding)
                if binding.host.name:
                    unique_domains.add(binding.host.name)
            elif binding.host_ip and binding.host_ip.host:
                # If binding has host_ip but not host, get host from host_ip
                host = binding.host_ip.host
                host_id = host.id
                if host_id not in unique_hosts:
                    unique_hosts[host_id] = {
                        'host': host,
                        'bindings': []
                    }
                unique_hosts[host_id]['bindings'].append(binding)
                if host.name:
                    unique_domains.add(host.name)
            
            if binding.host_ip and binding.host_ip.ip_address:
                unique_domains.add(binding.host_ip.ip_address)
        
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["Overview", "Certificates", "Hosts", "Domains", "⚠️ Danger Zone"])
        
        with tab1:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("### Application Information")
                st.markdown(f"**Name:** {application.name}")
                st.markdown(f"**Type:** {app_types.get(application.app_type, application.app_type)}")
                st.markdown(f"**Description:** {application.description or 'No description'}")
                st.markdown(f"**Owner:** {application.owner or 'Not specified'}")
                st.markdown(f"**Created:** {application.created_at.strftime('%Y-%m-%d')}")
            
            with col2:
                st.markdown("### Summary")
                st.metric("Total Certificates", len(unique_certs))
                st.metric("Total Hosts", len(unique_hosts))
                st.metric("Total Bindings", len(application.certificate_bindings))
                st.metric("Unique Domains", len(unique_domains))
            
            # Scan Everything Section
            st.markdown("---")
            st.markdown("### 🔍 Scan Application")
            
            # Collect all scan targets
            scan_targets = []
            
            # Collect from hosts and IPs
            for host_id, host_data in unique_hosts.items():
                host = host_data['host']
                if host.name:
                    # Add hostname with default port 443
                    scan_targets.append(f"{host.name}:443")
                # Add IPs from bindings
                for binding in host_data['bindings']:
                    if binding.host_ip and binding.host_ip.ip_address:
                        port = binding.port if binding.port else 443
                        target = f"{binding.host_ip.ip_address}:{port}"
                        if target not in scan_targets:
                            scan_targets.append(target)
                    elif binding.port:
                        if host.name:
                            target = f"{host.name}:{binding.port}"
                            if target not in scan_targets:
                                scan_targets.append(target)
            
            # Collect from certificate SANs
            for cert_id, cert_data in unique_certs.items():
                cert = cert_data['certificate']
                if hasattr(cert, 'san') and cert.san:
                    san_list = cert.san  # Returns a list
                    for san in san_list:
                        if san and isinstance(san, str):
                            target = f"{san}:443"
                            if target not in scan_targets:
                                scan_targets.append(target)
            
            # Collect from domains
            for domain in unique_domains:
                if domain and isinstance(domain, str):
                    target = f"{domain}:443"
                    if target not in scan_targets:
                        scan_targets.append(target)
            
            if scan_targets:
                st.markdown(f"**Scan Targets:** {len(scan_targets)} target(s) found")
                col1, col2 = st.columns([3, 1])
                with col1:
                    with st.expander("View Scan Targets", expanded=False):
                        st.text("\n".join(sorted(scan_targets)))
                with col2:
                    if st.button("🔍 Scan Everything", type="primary", use_container_width=True, key=f"scan_all_{application.id}"):
                        st.session_state.scan_targets = sorted(scan_targets)
                        st.session_state.current_view = "Scanner"
                        st.rerun()
            else:
                st.info("No scan targets available. Add hosts, certificates, or domains to enable scanning.")
            
            with st.expander("✏️ Edit Application"):
                with st.form("edit_application"):
                    st.text_input("Name", value=application.name, key="new_name")
                    st.selectbox("Type", options=APP_TYPES, index=APP_TYPES.index(application.app_type) if application.app_type in APP_TYPES else 0, key="new_type")
                    st.text_input("Description", value=application.description or '', key="new_description")
                    st.text_input("Owner", value=application.owner or '', key="new_owner")
                    if st.form_submit_button("Update Application", type="primary"):
                        handle_update_form()
        with tab2:
            st.markdown("### Certificates Bound to This Application")
            
            if unique_certs:
                for cert_id, cert_data in unique_certs.items():
                    cert = cert_data['certificate']
                    bindings = cert_data['bindings']
                    
                    with st.expander(f"🔐 {cert.common_name} ({len(bindings)} binding{'s' if len(bindings) != 1 else ''})", expanded=False):
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown(f"**Serial Number:** `{cert.serial_number}`")
                            st.markdown(f"**Valid Until:** {cert.valid_until.strftime('%Y-%m-%d')}")
                            is_valid = cert.valid_until > datetime.now()
                            status = "✅ Valid" if is_valid else "❌ Expired"
                            st.markdown(f"**Status:** {status}")
                            if cert.issuer:
                                issuer_cn = cert.issuer.get('commonName') or cert.issuer.get('CN') or 'Not specified'
                                st.markdown(f"**Issuer:** {issuer_cn}")
                            
                            # Show binding details
                            if bindings:
                                st.markdown("**Used in bindings:**")
                                for b in bindings:
                                    binding_info = []
                                    if b.host and b.host.name:
                                        binding_info.append(f"Host: {b.host.name}")
                                    if b.host_ip and b.host_ip.ip_address:
                                        binding_info.append(f"IP: {b.host_ip.ip_address}")
                                    if b.port:
                                        binding_info.append(f"Port: {b.port}")
                                    if b.platform:
                                        binding_info.append(f"Platform: {b.platform}")
                                    binding_info.append(f"Type: {BINDING_TYPE_DISPLAY.get(b.binding_type, 'Unknown')}")
                                    st.caption(" • ".join(binding_info))
                        
                        with col2:
                            if st.button("🔗 View Details", key=f"view_cert_{cert_id}", use_container_width=True):
                                st.session_state.selected_cert_id = cert_id
                                st.session_state.current_view = "Certificates"
                                st.rerun()
                            
                            # Remove certificate from application (remove all bindings)
                            dialog_key = f"remove_cert_{cert_id}"
                            if st.button("🗑️ Remove", key=f"remove_cert_{cert_id}", use_container_width=True, type="secondary"):
                                st.session_state[dialog_key] = True
                            
                            if st.session_state.get(dialog_key, False):
                                def on_remove_cert(_):
                                    with SessionManager(engine) as session:
                                        # Remove all bindings for this certificate
                                        removed = 0
                                        for b in bindings:
                                            try:
                                                session.delete(b)
                                                removed += 1
                                            except Exception as e:
                                                logger.exception(f"Error removing binding {b.id}: {str(e)}")
                                        session.commit()
                                        if removed > 0:
                                            notify(f"Removed {removed} binding(s) for this certificate", "success", page_key=APPLICATIONS_PAGE_KEY)
                                            st.session_state[dialog_key] = False
                                            st.rerun()
                                        else:
                                            notify("No bindings to remove", "info", page_key=APPLICATIONS_PAGE_KEY)
                                            st.session_state[dialog_key] = False
                                    return True
                                
                                render_danger_zone(
                                    title="Remove Certificate",
                                    entity_name=cert.common_name,
                                    entity_type="certificate",
                                    dependencies={
                                        "Bindings": [f"Binding {b.id}" for b in bindings]
                                    },
                                    on_delete=on_remove_cert,
                                    session=None,
                                    custom_warning=f"This will remove all {len(bindings)} binding(s) for certificate '{cert.common_name}'."
                                )
            else:
                st.info("No certificates are currently bound to this application.")
            
            # Scan Certificates Section
            st.markdown("---")
            st.markdown("### 🔍 Scan Certificates")
            
            # Collect all SANs from certificates
            cert_scan_targets = []
            for cert_id, cert_data in unique_certs.items():
                cert = cert_data['certificate']
                if hasattr(cert, 'san') and cert.san:
                    san_list = cert.san  # Returns a list
                    for san in san_list:
                        if san and isinstance(san, str):
                            target = f"{san}:443"
                            if target not in cert_scan_targets:
                                cert_scan_targets.append(target)
            
            if cert_scan_targets:
                st.markdown(f"**Scan Targets:** {len(cert_scan_targets)} target(s) from certificate SANs")
                col1, col2 = st.columns([3, 1])
                with col1:
                    with st.expander("View Scan Targets", expanded=False):
                        st.text("\n".join(sorted(cert_scan_targets)))
                with col2:
                    if st.button("🔍 Scan Certificates", type="primary", use_container_width=True, key=f"scan_certs_{application.id}"):
                        st.session_state.scan_targets = sorted(cert_scan_targets)
                        st.session_state.current_view = "Scanner"
                        st.rerun()
            else:
                st.info("No certificate SANs available for scanning.")
            
            st.markdown("---")
            st.markdown("### Add Certificate Bindings")
            
            with st.form(f"add_binding_form_{application.id}"):
                # Get available certificates
                available_certs = []
                try:
                    result = ApplicationService.get_available_certificates(engine, application.id)
                    if result['success']:
                        available_certs = result['data']
                except Exception as e:
                    logger.exception(f"Error loading certificates: {str(e)}")
                
                if not available_certs:
                    st.info("No available certificates found to bind.")
                else:
                    cert_options = {
                        f"{cert.common_name} (Valid until: {cert.valid_until.strftime('%Y-%m-%d')})": cert.id
                        for cert in available_certs
                    }
                    
                    # Binding method selection
                    binding_method = st.radio(
                        "Binding Method",
                        options=["By Certificate Only", "By Certificate + Host", "By Certificate + Domain"],
                        help="Choose how you want to bind certificates to this application",
                        horizontal=True,
                        key=f"binding_method_{application.id}"
                    )
                    
                    # Certificate selection - use multiselect for multiple certificates
                    st.markdown('<div class="certificate-multiselect-wrapper">', unsafe_allow_html=True)
                    selected_certs = st.multiselect(
                        "Select Certificates",
                        options=list(cert_options.keys()),
                        help="Select one or more certificates to bind (optional). Applications can have multiple certificates.",
                        key=f"selected_certs_{application.id}"
                    )
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        binding_type = st.selectbox(
                            "Binding Type",
                            options=["IP-Based", "JWT-Based", "Client Certificate"],
                            help="How will this certificate be used?",
                            key=f"binding_type_{application.id}"
                        )
                    with col2:
                        platform = st.selectbox(
                            "Platform",
                            options=["F5", "IIS", "Akamai", "Cloudflare", "Connection"],
                            help="Platform where this certificate is deployed",
                            key=f"platform_{application.id}"
                        )
                    
                    # Binding method specific fields
                    selected_host_id = None
                    selected_ip_id = None
                    hostname = None
                    ip_address = None
                    port = None
                    
                    if binding_method == "By Certificate + Host":
                        st.markdown("**Host Configuration**")
                        # Get available hosts
                        hosts_result = ApplicationService.get_available_hosts(engine)
                        if hosts_result['success']:
                            hosts = hosts_result['data']
                            host_options = {f"{h.name}": h.id for h in hosts}
                            if host_options:
                                selected_host = st.selectbox(
                                    "Select Host",
                                    options=list(host_options.keys()),
                                    help="Select a host",
                                    key=f"host_{application.id}"
                                )
                                selected_host_id = host_options[selected_host]
                                
                                # Get IPs for selected host
                                with SessionManager(engine) as session:
                                    host_obj = session.get(Host, selected_host_id)
                                    if host_obj and host_obj.ip_addresses:
                                        # Create IP options with hostname context
                                        ip_options = {}
                                        ip_display_options = ["None"]
                                        for ip in host_obj.ip_addresses:
                                            # Build display text with context
                                            display_parts = [ip.ip_address]
                                            if host_obj.name:
                                                display_parts.append(f"({host_obj.name})")
                                            if hasattr(ip, 'last_seen') and ip.last_seen:
                                                display_parts.append(f"Last seen: {ip.last_seen.strftime('%Y-%m-%d')}")
                                            
                                            display_text = " - ".join(display_parts)
                                            ip_options[display_text] = ip.id
                                            ip_display_options.append(display_text)
                                        
                                        ipcol1, ipcol2 = st.columns(2)
                                        with ipcol1:
                                            selected_ip = st.selectbox(
                                                "Select IP Address (Optional)",
                                                options=ip_display_options,
                                                help="IP addresses are shown with their associated hostname for easy identification",
                                                key=f"ip_{application.id}"
                                            )
                                            selected_ip_id = ip_options.get(selected_ip) if selected_ip != "None" else None
                                        with ipcol2:
                                            if binding_type == "IP-Based":
                                                port = st.number_input("Port", min_value=1, max_value=65535, value=443, key=f"port_{application.id}")
                                            else:
                                                port = None
                                    else:
                                        selected_ip_id = None
                                        st.info("No IP addresses found for this host")
                                        if binding_type == "IP-Based":
                                            port = st.number_input("Port", min_value=1, max_value=65535, value=443, key=f"port_{application.id}")
                                        else:
                                            port = None
                            else:
                                st.info("No hosts available. Please add hosts first.")
                        else:
                            st.error(f"Error loading hosts: {hosts_result.get('error', 'Unknown error')}")
                    
                    elif binding_method == "By Certificate + Domain":
                        st.markdown("**Domain Configuration**")
                        domaincol1, domaincol2 = st.columns(2)
                        with domaincol1:
                            hostname = st.text_input(
                                "Hostname/Domain",
                                help="Enter the hostname or domain name",
                                key=f"hostname_{application.id}"
                            )
                        with domaincol2:
                            ip_address = st.text_input(
                                "IP Address (Optional)",
                                help="Enter the IP address if known",
                                key=f"ip_address_{application.id}"
                            )
                        if binding_type == "IP-Based":
                            port = st.number_input("Port", min_value=1, max_value=65535, value=443, key=f"port_{application.id}")
                        else:
                            port = None
                    
                submitted = st.form_submit_button("Add Binding(s)", type="primary")
                if submitted:
                    if not selected_certs:
                        notify("Please select at least one certificate", "error", page_key=APPLICATIONS_PAGE_KEY)
                    else:
                        try:
                            cert_ids = [cert_options[cert_name] for cert_name in selected_certs]
                            binding_type_map = {
                                "IP-Based": "IP",
                                "JWT-Based": "JWT",
                                "Client Certificate": "CLIENT"
                            }
                            binding_type_code = binding_type_map[binding_type]
                            
                            bindings_added = 0
                            errors = []
                            
                            if binding_method == "By Certificate + Host":
                                if selected_host_id:
                                    for cert_id in cert_ids:
                                        result = ApplicationService.bind_certificate_with_host(
                                            engine, application.id, cert_id, selected_host_id,
                                            selected_ip_id, port if binding_type_code == "IP" else None,
                                            platform, binding_type_code
                                        )
                                        if result.get('success'):
                                            bindings_added += 1
                                        else:
                                            errors.append(result.get('error', 'Unknown error'))
                                else:
                                    notify("Please select a host", "error", page_key=APPLICATIONS_PAGE_KEY)
                            elif binding_method == "By Certificate + Domain":
                                if hostname:
                                    for cert_id in cert_ids:
                                        result = ApplicationService.bind_certificate_with_domain(
                                            engine, application.id, cert_id, hostname,
                                            ip_address if ip_address else None,
                                            port if binding_type_code == "IP" else None,
                                            platform, binding_type_code
                                        )
                                        if result.get('success'):
                                            bindings_added += 1
                                        else:
                                            errors.append(result.get('error', 'Unknown error'))
                                else:
                                    notify("Please enter a hostname/domain", "error", page_key=APPLICATIONS_PAGE_KEY)
                            else:
                                # Certificate only - bind all at once
                                result = ApplicationService.bind_certificates(
                                    engine, application.id, cert_ids, binding_type_code
                                )
                                if result.get('success'):
                                    bindings_added = result.get('count', 0)
                                else:
                                    errors.append(result.get('error', 'Unknown error'))
                            
                            if bindings_added > 0:
                                notify(f"{bindings_added} binding(s) added successfully!", "success", page_key=APPLICATIONS_PAGE_KEY)
                                st.rerun()
                            elif errors:
                                notify(f"Failed to add bindings: {errors[0]}", "error", page_key=APPLICATIONS_PAGE_KEY)
                        except Exception as e:
                            logger.exception(f"Error adding binding: {str(e)}")
                            notify(f"Error adding binding: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
            
        with tab3:
            st.markdown("### Hosts Associated with This Application")
            
            if unique_hosts:
                # Summary metrics
                total_hosts = len(unique_hosts)
                total_ips = sum(len(host_data['host'].ip_addresses) for host_data in unique_hosts.values())
                total_bindings = sum(len(host_data['bindings']) for host_data in unique_hosts.values())
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Hosts", total_hosts)
                with col2:
                    st.metric("Total IP Addresses", total_ips)
                with col3:
                    st.metric("Total Bindings", total_bindings)
                
                st.markdown("---")
                
                for host_id, host_data in unique_hosts.items():
                    host = host_data['host']
                    bindings = host_data['bindings']
                    
                    with st.expander(f"💻 {host.name} ({len(bindings)} binding{'s' if len(bindings) != 1 else ''})", expanded=False):
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown("#### Host Information")
                            info_col1, info_col2 = st.columns(2)
                            with info_col1:
                                st.markdown(f"**Host Type:** {host.host_type}")
                                st.markdown(f"**Environment:** {host.environment}")
                                if hasattr(host, 'last_seen') and host.last_seen:
                                    st.markdown(f"**Last Seen:** {host.last_seen.strftime('%Y-%m-%d %H:%M')}")
                            with info_col2:
                                if hasattr(host, 'created_at') and host.created_at:
                                    st.markdown(f"**Created:** {host.created_at.strftime('%Y-%m-%d')}")
                                if host.description:
                                    st.markdown(f"**Description:** {host.description}")
                            
                            # IP Addresses section
                            st.markdown("#### IP Addresses")
                            if host.ip_addresses:
                                ip_data = []
                                for ip in host.ip_addresses:
                                    ip_info = f"`{ip.ip_address}`"
                                    if hasattr(ip, 'last_seen') and ip.last_seen:
                                        ip_info += f" (Last seen: {ip.last_seen.strftime('%Y-%m-%d %H:%M')})"
                                    ip_data.append(ip_info)
                                st.markdown(" • ".join(ip_data) if ip_data else "No IP addresses")
                            else:
                                st.markdown("*No IP addresses recorded*")
                        
                        with col2:
                            st.markdown("#### Actions")
                            if st.button("🔗 View Details", key=f"view_host_{host_id}", use_container_width=True):
                                st.session_state.selected_host_id = host_id
                                st.session_state.current_view = "Hosts"
                                st.rerun()
                            
                            # Show summary metrics
                            st.markdown("#### Summary")
                            st.metric("Bindings", len(bindings))
                            if host.ip_addresses:
                                st.metric("IP Addresses", len(host.ip_addresses))
            
            # Scan Hosts Section
            st.markdown("---")
            st.markdown("### 🔍 Scan Hosts")
            
            # Collect all host and IP scan targets
            host_scan_targets = []
            if unique_hosts:
                for host_id, host_data in unique_hosts.items():
                    host = host_data['host']
                    if host.name:
                        # Add hostname with default port 443
                        host_scan_targets.append(f"{host.name}:443")
                    # Add IPs from bindings
                    for binding in host_data['bindings']:
                        if binding.host_ip and binding.host_ip.ip_address:
                            port = binding.port if binding.port else 443
                            target = f"{binding.host_ip.ip_address}:{port}"
                            if target not in host_scan_targets:
                                host_scan_targets.append(target)
                        elif binding.port and host.name:
                            target = f"{host.name}:{binding.port}"
                            if target not in host_scan_targets:
                                host_scan_targets.append(target)
            
            if host_scan_targets:
                st.markdown(f"**Scan Targets:** {len(host_scan_targets)} target(s) from hosts and IPs")
                col1, col2 = st.columns([3, 1])
                with col1:
                    with st.expander("View Scan Targets", expanded=False):
                        st.text("\n".join(sorted(host_scan_targets)))
                with col2:
                    if st.button("🔍 Scan Hosts", type="primary", use_container_width=True, key=f"scan_hosts_{application.id}"):
                        st.session_state.scan_targets = sorted(host_scan_targets)
                        st.session_state.current_view = "Scanner"
                        st.rerun()
            else:
                st.info("No hosts or IPs available for scanning.")
            
            if not unique_hosts:
                st.info("No hosts are currently associated with this application.")
            
            st.markdown("---")
            st.markdown("### Add Host to Application")
            
            with st.form(f"add_host_binding_form_{application.id}"):
                
                # Get available hosts
                hosts_result = ApplicationService.get_available_hosts(engine)
                selected_host_ids = []
                selected_ip_id = None
                port = None
                selected_certs = []
                cert_options = {}
                host_options = {}
                binding_type = "IP-Based"
                platform = "F5"
                
                if hosts_result['success']:
                    hosts = hosts_result['data']
                    if hosts:
                        # Create descriptive host options with context
                        host_options = {}
                        host_display_options = []
                        import re
                        
                        # Access IP addresses within a session to avoid detached instance errors
                        with SessionManager(engine) as session:
                            for h in hosts:
                                # Refresh host in current session with relationships loaded
                                host_obj = session.query(Host).options(
                                    joinedload(Host.ip_addresses),
                                    joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate)
                                ).filter(Host.id == h.id).first()
                                
                                if not host_obj:
                                    continue
                                
                                # Build display text with context
                                display_parts = []
                                
                                # Check if name is an IP address
                                is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_obj.name) if host_obj.name else False
                                
                                if is_ip:
                                    # If name is an IP, find associated hostnames from certificates
                                    hostnames = set()
                                    if host_obj.certificate_bindings:
                                        for binding in host_obj.certificate_bindings:
                                            if binding.certificate:
                                                cert = binding.certificate
                                                # Add common name
                                                if cert.common_name and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cert.common_name):
                                                    hostnames.add(cert.common_name)
                                                # Add SANs (if available)
                                                if hasattr(cert, 'san') and cert.san:
                                                    if isinstance(cert.san, list):
                                                        for san in cert.san:
                                                            if san and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', san):
                                                                hostnames.add(san)
                                    
                                    # Build display: IP with associated hostnames
                                    if hostnames:
                                        # Show IP and hostnames
                                        hostname_list = sorted(list(hostnames))[:3]  # Limit to 3 hostnames
                                        hostname_str = ', '.join(hostname_list)
                                        if len(hostnames) > 3:
                                            hostname_str += f" (+{len(hostnames) - 3} more)"
                                        display_parts.append(f"IP: {host_obj.name} → {hostname_str}")
                                    else:
                                        # Just show the IP if no hostnames found
                                        display_parts.append(f"IP: {host_obj.name}")
                                else:
                                    # Show hostname with associated IPs
                                    display_parts.append(host_obj.name or "Unnamed Host")
                                    ip_list = []
                                    if host_obj.ip_addresses:
                                        ip_list = [ip.ip_address for ip in host_obj.ip_addresses if ip.ip_address]
                                    if ip_list:
                                        display_parts.append(f"({', '.join(ip_list)})")
                                
                                display_text = " - ".join(display_parts)
                                host_options[display_text] = host_obj.id
                                host_display_options.append(display_text)
                        
                        st.markdown('<div class="certificate-multiselect-wrapper">', unsafe_allow_html=True)
                        selected_hosts = st.multiselect(
                            "Select Host(s)",
                            options=host_display_options,
                            help="Select one or more hosts to associate with this application. Hosts are shown with their type, environment, and IP count for easy identification.",
                            key=f"add_host_select_{application.id}"
                        )
                        st.markdown('</div>', unsafe_allow_html=True)
                        
                        if selected_hosts:
                            # Map display text back to host IDs
                            selected_host_ids = [host_options[display_text] for display_text in selected_hosts]
                            
                        if selected_host_ids:
                            # Get available certificates
                            cert_result = ApplicationService.get_available_certificates(engine, application.id)
                            if cert_result['success'] and cert_result['data']:
                                cert_options = {
                                    f"{cert.common_name} (Valid until: {cert.valid_until.strftime('%Y-%m-%d')})": cert.id
                                    for cert in cert_result['data']
                                }
                                
                                st.markdown('<div class="certificate-multiselect-wrapper">', unsafe_allow_html=True)
                                selected_certs = st.multiselect(
                                    "Select Certificates to Bind",
                                    options=list(cert_options.keys()),
                                    help="Select certificates to bind with these hosts",
                                    key=f"add_host_certs_{application.id}"
                                )
                                st.markdown('</div>', unsafe_allow_html=True)
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    binding_type = st.selectbox(
                                        "Binding Type",
                                        options=["IP-Based", "JWT-Based", "Client Certificate"],
                                        key=f"add_host_binding_type_{application.id}"
                                    )
                                with col2:
                                    platform = st.selectbox(
                                        "Platform",
                                        options=["F5", "IIS", "Akamai", "Cloudflare", "Connection"],
                                        key=f"add_host_platform_{application.id}"
                                    )
                                
                                # For multiple hosts, we'll use the first host's IPs or allow per-host configuration
                                # For simplicity, we'll use a single IP/port configuration that applies to all hosts
                                if len(selected_host_ids) == 1:
                                    # Single host - show IP selection
                                    with SessionManager(engine) as session:
                                        host_obj = session.get(Host, selected_host_ids[0])
                                        if host_obj and host_obj.ip_addresses:
                                            # Create IP options with hostname context
                                            ip_options = {}
                                            ip_display_options = ["None"]
                                            for ip in host_obj.ip_addresses:
                                                # Build display text with context
                                                display_parts = [ip.ip_address]
                                                if host_obj.name:
                                                    display_parts.append(f"({host_obj.name})")
                                                if hasattr(ip, 'last_seen') and ip.last_seen:
                                                    display_parts.append(f"Last seen: {ip.last_seen.strftime('%Y-%m-%d')}")
                                                
                                                display_text = " - ".join(display_parts)
                                                ip_options[display_text] = ip.id
                                                ip_display_options.append(display_text)
                                            
                                            ipcol1, ipcol2 = st.columns(2)
                                            with ipcol1:
                                                selected_ip = st.selectbox(
                                                    "Select IP Address (Optional)",
                                                    options=ip_display_options,
                                                    key=f"add_host_ip_{application.id}",
                                                    help="IP addresses are shown with their associated hostname for easy identification"
                                                )
                                                selected_ip_id = ip_options.get(selected_ip) if selected_ip != "None" else None
                                            with ipcol2:
                                                if binding_type == "IP-Based":
                                                    port = st.number_input("Port", min_value=1, max_value=65535, value=443, key=f"add_host_port_{application.id}")
                                        elif host_obj:
                                            if binding_type == "IP-Based":
                                                port = st.number_input("Port", min_value=1, max_value=65535, value=443, key=f"add_host_port_{application.id}")
                                else:
                                    # Multiple hosts - show port only (IP will be determined per host)
                                    if binding_type == "IP-Based":
                                        port = st.number_input("Port (applies to all hosts)", min_value=1, max_value=65535, value=443, key=f"add_host_port_{application.id}")
                                    st.info("💡 For multiple hosts, IP addresses will be determined automatically from each host's available IPs.")
                            else:
                                st.info("No available certificates to bind. All certificates are already bound to this application.")
                    else:
                        st.info("No hosts available. Please add hosts first in the Hosts page.")
                else:
                    st.error(f"Error loading hosts: {hosts_result.get('error', 'Unknown error')}")
                
                # Submit button must always be present in the form
                submitted = st.form_submit_button("Add Host Binding(s)", type="primary", use_container_width=True)
                if submitted:
                    if not selected_host_ids:
                        notify("Please select at least one host", "error", page_key=APPLICATIONS_PAGE_KEY)
                    elif not selected_certs:
                        notify("Please select at least one certificate", "error", page_key=APPLICATIONS_PAGE_KEY)
                    else:
                        try:
                            cert_ids = [cert_options[cert_name] for cert_name in selected_certs]
                            binding_type_map = {
                                "IP-Based": "IP",
                                "JWT-Based": "JWT",
                                "Client Certificate": "CLIENT"
                            }
                            binding_type_code = binding_type_map[binding_type]
                            
                            bindings_added = 0
                            errors = []
                            
                            # For each selected host and certificate combination
                            for host_id in selected_host_ids:
                                # If multiple hosts, get IP from each host
                                current_ip_id = selected_ip_id
                                if len(selected_host_ids) > 1:
                                    # For multiple hosts, use the first available IP or None
                                    with SessionManager(engine) as session:
                                        host_obj = session.get(Host, host_id)
                                        if host_obj and host_obj.ip_addresses:
                                            # Use first IP if available
                                            current_ip_id = host_obj.ip_addresses[0].id
                                
                                for cert_id in cert_ids:
                                    result = ApplicationService.bind_certificate_with_host(
                                        engine, application.id, cert_id, host_id,
                                        current_ip_id, port if binding_type_code == "IP" else None,
                                        platform, binding_type_code
                                    )
                                    if result.get('success'):
                                        bindings_added += 1
                                    else:
                                        errors.append(result.get('error', 'Unknown error'))
                            
                            if bindings_added > 0:
                                notify(f"{bindings_added} binding(s) added successfully!", "success", page_key=APPLICATIONS_PAGE_KEY)
                                st.rerun()
                            elif errors:
                                notify(f"Failed to add bindings: {errors[0]}", "error", page_key=APPLICATIONS_PAGE_KEY)
                        except Exception as e:
                            logger.exception(f"Error adding host binding: {str(e)}")
                            notify(f"Error adding host binding: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
        
        with tab4:
            st.markdown("### Domains Associated with This Application")
            
            # Display domains
            if unique_domains:
                st.markdown(f"**Total Domains:** {len(unique_domains)}")
                
                # Show domains in a list
                domain_list = sorted(list(unique_domains))
                for domain in domain_list:
                    with st.container():
                        col1, col2 = st.columns([4, 1])
                        with col1:
                            st.markdown(f"🌐 **{domain}**")
                            # Show which bindings use this domain
                            domain_bindings = []
                            for binding in application.certificate_bindings:
                                if (binding.host and binding.host.name == domain) or \
                                   (binding.host_ip and binding.host_ip.ip_address == domain):
                                    if binding.certificate:
                                        domain_bindings.append(binding.certificate.common_name)
                            if domain_bindings:
                                st.caption(f"Used by certificates: {', '.join(set(domain_bindings))}")
                        with col2:
                            # Note: Domain removal would require removing bindings, which is handled in other tabs
                            st.caption("Remove via bindings")
                        st.divider()
            else:
                st.info("No domains are currently associated with this application.")
            
            # Add Domain Section
            st.markdown("---")
            st.markdown("### Add Domain to Application")
            
            with st.form(f"add_domain_form_{application.id}"):
                domain_name = st.text_input(
                    "Domain/Hostname",
                    help="Enter a domain or hostname to associate with this application",
                    key=f"add_domain_name_{application.id}"
                )
                
                # Get available certificates
                cert_result = ApplicationService.get_available_certificates(engine, application.id)
                if cert_result['success'] and cert_result['data']:
                    cert_options = {
                        f"{cert.common_name} (Valid until: {cert.valid_until.strftime('%Y-%m-%d')})": cert.id
                        for cert in cert_result['data']
                    }
                    
                    st.markdown('<div class="certificate-multiselect-wrapper">', unsafe_allow_html=True)
                    selected_certs = st.multiselect(
                        "Select Certificates to Bind",
                        options=list(cert_options.keys()),
                        help="Select certificates to bind with this domain",
                        key=f"add_domain_certs_{application.id}"
                    )
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    if selected_certs:
                        col1, col2 = st.columns(2)
                        with col1:
                            binding_type = st.selectbox(
                                "Binding Type",
                                options=["IP-Based", "JWT-Based", "Client Certificate"],
                                key=f"add_domain_binding_type_{application.id}"
                            )
                        with col2:
                            platform = st.selectbox(
                                "Platform",
                                options=["F5", "IIS", "Akamai", "Cloudflare", "Connection"],
                                key=f"add_domain_platform_{application.id}"
                            )
                        
                        ip_address = st.text_input(
                            "IP Address (Optional)",
                            help="Enter the IP address if known",
                            key=f"add_domain_ip_{application.id}"
                        )
                        
                        if binding_type == "IP-Based":
                            port = st.number_input("Port", min_value=1, max_value=65535, value=443, key=f"add_domain_port_{application.id}")
                        else:
                            port = None
                
                submitted = st.form_submit_button("Add Domain Binding(s)", type="primary", use_container_width=True)
                if submitted:
                    if not domain_name:
                        notify("Please enter a domain/hostname", "error", page_key=APPLICATIONS_PAGE_KEY)
                    elif not selected_certs:
                        notify("Please select at least one certificate", "error", page_key=APPLICATIONS_PAGE_KEY)
                    else:
                        try:
                            cert_ids = [cert_options[cert_name] for cert_name in selected_certs]
                            binding_type_map = {
                                "IP-Based": "IP",
                                "JWT-Based": "JWT",
                                "Client Certificate": "CLIENT"
                            }
                            binding_type_code = binding_type_map[binding_type]
                            
                            bindings_added = 0
                            errors = []
                            
                            for cert_id in cert_ids:
                                result = ApplicationService.bind_certificate_with_domain(
                                    engine, application.id, cert_id, domain_name,
                                    ip_address if ip_address else None,
                                    port if binding_type_code == "IP" else None,
                                    platform, binding_type_code
                                )
                                if result.get('success'):
                                    bindings_added += 1
                                else:
                                    errors.append(result.get('error', 'Unknown error'))
                            
                            if bindings_added > 0:
                                notify(f"{bindings_added} binding(s) added successfully!", "success", page_key=APPLICATIONS_PAGE_KEY)
                                st.rerun()
                            elif errors:
                                notify(f"Failed to add bindings: {errors[0]}", "error", page_key=APPLICATIONS_PAGE_KEY)
                        except Exception as e:
                            logger.exception(f"Error adding domain binding: {str(e)}")
                            notify(f"Error adding domain binding: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
                elif not cert_result['success'] or not cert_result['data']:
                    st.info("No available certificates to bind. All certificates are already bound to this application.")
            
            # Scan Domains Section
            st.markdown("---")
            st.markdown("### 🔍 Scan Domains")
            
            # Collect all domain scan targets
            domain_scan_targets = []
            for domain in unique_domains:
                if domain and isinstance(domain, str):
                    target = f"{domain}:443"
                    if target not in domain_scan_targets:
                        domain_scan_targets.append(target)
            
            if domain_scan_targets:
                st.markdown(f"**Scan Targets:** {len(domain_scan_targets)} target(s) from domains")
                col1, col2 = st.columns([3, 1])
                with col1:
                    with st.expander("View Scan Targets", expanded=False):
                        st.text("\n".join(sorted(domain_scan_targets)))
                with col2:
                    if st.button("🔍 Scan Domains", type="primary", use_container_width=True, key=f"scan_domains_{application.id}"):
                        st.session_state.scan_targets = sorted(domain_scan_targets)
                        st.session_state.current_view = "Scanner"
                        st.rerun()
            else:
                st.info("No domains available for scanning.")
        
        with tab5:
            st.markdown("### ⚠️ Danger Zone")
            engine = st.session_state.get('engine')
            if engine:
                dependencies = {
                    "Certificate Bindings": [
                        f"{b.certificate.common_name} ({b.host.name if b.host else 'No Host'})"
                        for b in application.certificate_bindings
                    ] if application.certificate_bindings else []
                }
                def delete_app(_):
                    result = ApplicationService.delete_application(engine, application.id)
                    if result['success']:
                        st.session_state.current_app = None
                        return True
                    else:
                        logger.exception(f"Error deleting application: {result['error']}")
                        return False
                render_danger_zone(
                    title="Delete Application",
                    entity_name=application.name,
                    entity_type="application",
                    dependencies=dependencies,
                    on_delete=delete_app,
                    session=None,
                    custom_warning=f"This will permanently delete the application '{application.name}' and remove all certificate bindings."
                )
            else:
                notify("Unable to delete application: Engine not available", "error", page_key=APPLICATIONS_PAGE_KEY) 