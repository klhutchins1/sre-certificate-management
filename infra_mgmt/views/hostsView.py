"""
Host Management View Module

This module provides a comprehensive interface for managing hosts and their certificate
bindings in the certificate management system. It offers multiple views and management
capabilities for hosts, their IP addresses, and associated certificates.

Key Features:
- Host management (add, edit, delete)
- IP address management
- Certificate binding tracking
- Multiple view options (by hostname or IP address)
- Real-time certificate status monitoring
- Platform management
- Detailed host and binding information
- Certificate history tracking

The module uses Streamlit for the UI and AG Grid for interactive data display,
providing a rich and user-friendly interface for host management operations.
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
from ..models import Host, HostIP, CertificateBinding, Application, Certificate
from ..constants import platform_options, APP_TYPES, HOST_TYPES, ENVIRONMENTS, app_types
from ..static.styles import load_warning_suppression, load_css
from ..components.deletion_dialog import render_deletion_dialog, render_danger_zone
import logging
from ..services.HostService import HostService
from ..services.ViewDataService import ViewDataService
from infra_mgmt.utils.SessionManager import SessionManager

logger = logging.getLogger(__name__)

def render_hosts_view(engine) -> None:
    """
    Render the main host management interface.

    This function creates an interactive interface for managing hosts and their
    certificate bindings, providing multiple views and management capabilities:
    - Host creation and management
    - IP address management
    - Certificate binding tracking
    - Platform configuration
    - Host metrics and statistics

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Add new hosts with multiple IP addresses
        - View hosts by hostname or IP address
        - Track certificate bindings and their status
        - Monitor certificate expiration
        - Configure platform settings
        - View detailed host information
        - Real-time status updates
        - Interactive data grid with sorting and filtering
        - Automatic data refresh

    The view maintains state using Streamlit's session state for form visibility
    and success messages, and provides comprehensive error handling for all operations.
    """
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Create a row for title and button
    st.markdown('<div class="title-row">', unsafe_allow_html=True)
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Hosts")
    with col2:
        if st.button("➕ Add Host" if not st.session_state.get('show_add_host_form', False) else "❌ Cancel", 
                    type="primary" if not st.session_state.get('show_add_host_form', False) else "secondary", 
                    use_container_width=True):
            # Toggle the form visibility
            st.session_state['show_add_host_form'] = not st.session_state.get('show_add_host_form', False)
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Show any pending success messages
    if 'success_message' in st.session_state:
        st.success(st.session_state.success_message)
        del st.session_state.success_message
    
    # Show Add Host form if button was clicked
    if st.session_state.get('show_add_host_form', False):
        st.markdown('<div class="form-container">', unsafe_allow_html=True)
        with st.form("add_host_form"):
            st.subheader("Add New Host")
            
            # Basic host details
            col1, col2 = st.columns(2)
            with col1:
                hostname = st.text_input("Hostname", 
                    help="The name of the host (e.g., server1.example.com)")
                host_type = st.selectbox("Host Type",
                    options=HOST_TYPES,
                    help="The type of host")
            
            with col2:
                environment = st.selectbox("Environment",
                    options=ENVIRONMENTS,
                    help="The environment where this host is located")
                description = st.text_input("Description",
                    help="Optional description of the host")
            
            # IP Addresses
            st.markdown("### IP Addresses")
            st.markdown("Enter one IP address per line")
            ip_addresses = st.text_area("IP Addresses",
                help="Enter multiple IP addresses, one per line")
            
            col3, col4, col5 = st.columns([1,1,1])
            with col4:
                submitted = st.form_submit_button("Add Host", type="primary", use_container_width=True)
            
            if submitted:
                try:
                    with Session(engine) as session:
                        ip_list = [ip.strip() for ip in ip_addresses.strip().split('\n') if ip.strip()]
                        result = HostService.add_host_with_ips(session, hostname, host_type, environment, description, ip_list)
                        if result['success']:
                            st.success("✅ Host added successfully!")
                            st.session_state['show_add_host_form'] = False
                            st.rerun()
                        else:
                            st.error(f"Error adding host: {result['error']}")
                except Exception as e:
                    st.error(f"Error adding host: {str(e)}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Use ViewDataService for metrics and table data
    view_data_service = ViewDataService()
    result = view_data_service.get_host_list_view_data(engine)
    if not result['success']:
        st.error(result['error'])
        return
    metrics = result['data']['metrics']
    df = result['data']['df']
    column_config = result['data']['column_config']

    # Create metrics columns with minimal spacing
    st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Hosts", metrics["total_hosts"])
    col2.metric("Total IPs", metrics["total_ips"])
    col3.metric("Total Certificates", metrics["total_certs"])
    st.markdown('</div>', unsafe_allow_html=True)
    st.divider()

    if df.empty:
        st.warning("No host data available")
        return

    # Configure AG Grid to match certificatesView style
    gb = GridOptionsBuilder.from_dataframe(df)
    gb.configure_default_column(
        resizable=True,
        sortable=True,
        filter=True,
        editable=False
    )
    # Example explicit column configuration (adjust as needed for your df columns)
    if "Hostname" in df.columns:
        gb.configure_column("Hostname", minWidth=200, flex=2)
    if "Type" in df.columns:
        gb.configure_column("Type", minWidth=120, flex=1)
    if "Environment" in df.columns:
        gb.configure_column("Environment", minWidth=120, flex=1)
    if "Last Seen" in df.columns:
        gb.configure_column(
            "Last Seen",
            type=["dateColumnFilter"],
            minWidth=150,
            valueFormatter="value ? new Date(value).toLocaleString() : ''"
        )
    if "Certificates" in df.columns:
        gb.configure_column("Certificates", type=["numericColumn"], minWidth=100)
    if "Status" in df.columns:
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
    # Hide _id column if present
    if "_id" in df.columns:
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
        key="host_grid",
        reload_data=False,
        height=600
    )
    # Handle selection: show all details for the selected host
    try:
        selected_rows = grid_response['selected_rows']
        selected_host_id = None
        if isinstance(selected_rows, pd.DataFrame) and not selected_rows.empty:
            selected_row = selected_rows.iloc[0].to_dict()
            selected_host_id = selected_row.get('_id')
        elif isinstance(selected_rows, list) and selected_rows:
            selected_row = selected_rows[0]
            selected_host_id = selected_row.get('_id')
        if selected_host_id is not None:
            with SessionManager(engine) as session:
                host_obj = session.query(Host).get(selected_host_id)
                if host_obj:
                    render_details(host_obj)
    except Exception as e:
        st.error(f"Error handling selection: {str(e)}")

def render_details(selected_host: Host, binding: CertificateBinding = None) -> None:
    """
    Unified details view for both host and binding details.
    
    Args:
        selected_host: Host model instance
        binding: Optional CertificateBinding instance for binding-specific view
    """
    # Create header with title
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader(f"💻 {selected_host.name}")
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Certificates", "IP Addresses", "Danger Zone"])
    
    with tab1:
        # Overview tab
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Host Type:** {selected_host.host_type}")
            st.markdown(f"**Environment:** {selected_host.environment}")
            if selected_host.description:
                st.markdown(f"**Description:** {selected_host.description}")
            st.markdown(f"**Last Seen:** {selected_host.last_seen.strftime('%Y-%m-%d %H:%M')}")
        
        # If we're showing a specific binding, show its details
        if binding:
            with col2:
                st.markdown("### Current Certificate")
                st.markdown(f"**Certificate:** {binding.certificate.common_name}")
                is_valid = binding.certificate.valid_until > datetime.now()
                status_class = "cert-valid" if is_valid else "cert-expired"
                st.markdown(f"**Status:** <span class='cert-status {status_class}'>{'Valid' if is_valid else 'Expired'}</span>", unsafe_allow_html=True)
                st.markdown(f"**Valid Until:** {binding.certificate.valid_until.strftime('%Y-%m-%d')}")
                st.markdown(f"**Port:** {binding.port if binding.port else 'N/A'}")
                st.markdown(f"**Platform:** {binding.platform or 'Not Set'}")
    
    with tab2:
        # Certificates tab
        if binding:
            # Show detailed certificate information for the specific binding
            cert = binding.certificate
            st.markdown("### Certificate Details")
            st.markdown(f"**Serial Number:** {cert.serial_number}")
            st.markdown(f"**Thumbprint:** {cert.thumbprint}")
            st.markdown(f"**Type:** {binding.binding_type}")
            if binding.site_name:
                st.markdown(f"**Site:** {binding.site_name}")
            
            # Show scan history if available
            if cert.scans:
                st.markdown("### Scan History")
                scan_data = []
                for scan in cert.scans:
                    scan_data.append({
                        "Date": scan.scan_date,
                        "Status": scan.status,
                        "Port": scan.port
                    })
                
                if scan_data:
                    df = pd.DataFrame(scan_data)
                    st.dataframe(
                        df,
                        column_config={
                            "Date": st.column_config.DatetimeColumn(
                                "Date",
                                format="DD/MM/YYYY HH:mm"
                            ),
                            "Status": st.column_config.TextColumn(
                                "Status",
                                width="small"
                            ),
                            "Port": st.column_config.NumberColumn(
                                "Port",
                                width="small"
                            )
                        },
                        hide_index=True,
                        use_container_width=True
                    )
        else:
            # Show all certificates bound to this host
            bindings = selected_host.certificate_bindings
            if bindings:
                for b in bindings:
                    cert = b.certificate
                    if cert:
                        with st.expander(f"🔐 {cert.common_name}", expanded=True):
                            st.markdown(f"**Port:** {b.port if b.port else 'N/A'}")
                            st.markdown(f"**Platform:** {b.platform if b.platform else 'Not Set'}")
                            st.markdown(f"**Type:** {b.binding_type}")
                            st.markdown(f"**Valid Until:** {cert.valid_until.strftime('%Y-%m-%d')}")
                            if b.site_name:
                                st.markdown(f"**Site:** {b.site_name}")
                            
                            # Add remove binding button
                            if st.button("Remove Binding", key=f"remove_{b.id}", type="secondary"):
                                try:
                                    result = HostService.delete_binding(selected_host.id, b.id)
                                    if result['success']:
                                        st.success("Binding removed successfully!")
                                        st.rerun()
                                    else:
                                        st.error(f"Error removing binding: {result['error']}")
                                except Exception as e:
                                    st.error(f"Error removing binding: {str(e)}")
            else:
                st.info("No certificates bound to this host")
    
    with tab3:
        # IP Addresses tab
        if binding and binding.host_ip:
            st.markdown(f"**Current IP:** {binding.host_ip.ip_address}")
            st.markdown(f"**Last Seen:** {binding.host_ip.last_seen.strftime('%Y-%m-%d %H:%M')}")
        else:
            if selected_host.ip_addresses:
                for ip in selected_host.ip_addresses:
                    st.markdown(f"**{ip.ip_address}** - Last seen: {ip.last_seen.strftime('%Y-%m-%d %H:%M')}")
            else:
                st.info("No IP addresses recorded for this host")
    
    with tab4:
        st.markdown("### ⚠️ Danger Zone")
        # Gather dependencies
        dependencies = {
            "IP Addresses": [ip.ip_address for ip in selected_host.ip_addresses],
            "Certificate Bindings": [
                f"{b.certificate.common_name} ({b.port})" if b.port else b.certificate.common_name
                for b in selected_host.certificate_bindings if b.certificate
            ],
            "Scan Records": [
                f"Scan on {s.scan_date.strftime('%Y-%m-%d %H:%M')}"
                for s in selected_host.scans
            ]
        }
        def delete_host():
            result = HostService.delete_host_by_id(selected_host.id)
            if result['success']:
                if 'selected_host_id' in st.session_state:
                    del st.session_state.selected_host_id
                return True
            else:
                return False
        render_danger_zone(
            title="Delete Host",
            entity_name=selected_host.name,
            entity_type="host",
            dependencies=dependencies,
            on_delete=delete_host,
            session=None
        )
