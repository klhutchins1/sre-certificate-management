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
from ..db import SessionManager
from ..components.deletion_dialog import render_deletion_dialog, render_danger_zone
import logging
from ..services.HostService import HostService

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
    
    # Create metrics columns with standardized styling
    st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    
    with SessionManager(engine) as session:
        if not session:
            st.error("Database connection failed")
            return
        
        # Calculate metrics
        total_hosts = session.query(Host).count()
        total_ips = session.query(HostIP).count()
        total_certs = session.query(Certificate).count()
        
        # Display metrics
        col1.metric("Total Hosts", total_hosts)
        col2.metric("Total IPs", total_ips)
        col3.metric("Total Certificates", total_certs)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Handle platform updates from AG Grid
    if 'platform_update' in st.session_state:
        update_data = st.session_state.platform_update
        try:
            with Session(engine) as session:
                result = HostService.update_binding_platform(session, update_data['binding_id'], update_data['platform'])
                if result['success']:
                    st.session_state.success_message = f"Platform updated successfully for {update_data['binding_id']}"
                    del st.session_state.platform_update
                    st.rerun()
                else:
                    st.error(f"Error updating platform: {result['error']}")
        except Exception as e:
            st.error(f"Error updating platform: {str(e)}")
    
    # Add warning suppression script at the very beginning
    st.markdown("""
        <script>
            // Immediately executing warning suppression
            (function() {
                // Store original console methods
                const originalConsole = {
                    warn: window.console.warn.bind(console),
                    error: window.console.error.bind(console),
                    log: window.console.log.bind(console)
                };

                // Create a no-op function
                const noop = () => {};

                // Override console methods with filtered versions
                window.console.warn = function() {
                    const msg = arguments[0] || '';
                    if (typeof msg === 'string' && (
                        msg.includes('Feature Policy') ||
                        msg.includes('iframe') ||
                        msg.includes('AgGrid') ||
                        msg.includes('allow_unsafe_jscode') ||
                        msg.includes('grid return event') ||
                        msg.includes('selectionChanged')
                    )) {
                        return;
                    }
                    return originalConsole.warn.apply(this, arguments);
                };

                window.console.error = function() {
                    const msg = arguments[0] || '';
                    if (typeof msg === 'string' && (
                        msg.includes('Feature Policy') ||
                        msg.includes('iframe') ||
                        msg.includes('sandbox')
                    )) {
                        return;
                    }
                    return originalConsole.error.apply(this, arguments);
                };
            })();
        </script>
    """, unsafe_allow_html=True)
    
    with Session(engine) as session:
        # Store session in session state for use in binding details
        st.session_state['session'] = session
        
        # Get all hosts with their bindings and related data
        hosts = session.query(Host).options(
            joinedload(Host.ip_addresses),
            joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate)
        ).all()
        
        if not hosts:
            st.warning("No hosts found in database")
            return
        
        # View type selector
        view_type = st.radio(
            "View By",
            ["Hostname", "IP Address"],
            horizontal=True
        )
        
        # Convert to DataFrame for display
        binding_data = []
        for host in hosts:
            if view_type == "Hostname":
                # For hostname view, show all certificates regardless of IP
                if host.certificate_bindings:  # If host has any certificates
                    for binding in host.certificate_bindings:
                        binding_data.append({
                            'Hostname': host.name,
                            'IP Address': binding.host_ip.ip_address if binding.host_ip else 'No IP',
                            'Port': binding.port,
                            'Certificate': binding.certificate.common_name,
                            'Platform': binding.platform or 'Unknown',
                            'Status': 'Valid' if binding.certificate.valid_until > datetime.now() else 'Expired',
                            'Expires': binding.certificate.valid_until,
                            'Last Seen': binding.last_seen,
                            '_id': binding.id,
                            'Source': '🔒 Manual' if binding.manually_added else '🔍 Scanned'
                        })
                else:  # No certificates for this host
                    binding_data.append({
                        'Hostname': host.name,
                        'IP Address': host.ip_addresses[0].ip_address if host.ip_addresses else 'No IP',
                        'Port': None,
                        'Certificate': 'No Certificate',
                        'Platform': 'Unknown',
                        'Status': 'No Certificate',
                        'Expires': None,
                        'Last Seen': None,
                        '_id': None,
                        'Source': ''
                    })
            else:  # IP Address view
                if host.ip_addresses:  # If host has IP addresses
                    for ip in host.ip_addresses:
                        # Get all bindings for this host/IP combination
                        host_bindings = [b for b in host.certificate_bindings if b.host_ip_id == ip.id]
                        
                        if host_bindings:  # If there are any bindings (manual or scanned)
                            for binding in host_bindings:
                                binding_data.append({
                                    'Hostname': host.name,
                                    'IP Address': ip.ip_address,
                                    'Port': binding.port,
                                    'Certificate': binding.certificate.common_name,
                                    'Platform': binding.platform or 'Unknown',
                                    'Status': 'Valid' if binding.certificate.valid_until > datetime.now() else 'Expired',
                                    'Expires': binding.certificate.valid_until,
                                    'Last Seen': binding.last_seen,
                                    '_id': binding.id,
                                    'Source': '🔒 Manual' if binding.manually_added else '🔍 Scanned'
                                })
                        else:  # No certificates for this IP
                            binding_data.append({
                                'Hostname': host.name,
                                'IP Address': ip.ip_address,
                                'Port': None,
                                'Certificate': 'No Certificate',
                                'Platform': 'Unknown',
                                'Status': 'No Certificate',
                                'Expires': None,
                                'Last Seen': None,
                                '_id': None,
                                'Source': ''
                            })
                else:  # Host without IP addresses
                    binding_data.append({
                        'Hostname': host.name,
                        'IP Address': 'No IP',
                        'Port': None,
                        'Certificate': 'No Certificate',
                        'Platform': 'Unknown',
                        'Status': 'No Certificate',
                        'Expires': None,
                        'Last Seen': None,
                        '_id': None,
                        'Source': ''
                    })
        
        if binding_data:
            df = pd.DataFrame(binding_data)
            
            # Configure AG Grid
            gb = GridOptionsBuilder.from_dataframe(df)
            
            # Configure default settings
            gb.configure_default_column(
                resizable=True,
                sortable=True,
                filter=True,
                editable=False
            )
            
            # Configure specific columns based on view type
            if view_type == "Hostname":
                gb.configure_column(
                    "Hostname",
                    minWidth=200,
                    flex=2,
                    rowGroup=True
                )
                gb.configure_column(
                    "IP Address",
                    minWidth=150,
                    flex=1
                )
            else:  # IP Address view
                gb.configure_column(
                    "IP Address",
                    minWidth=150,
                    flex=1,
                    sort="asc"
                )
                gb.configure_column(
                    "Hostname",
                    minWidth=200,
                    flex=2
                )
            
            # Configure source column
            gb.configure_column(
                "Source",
                minWidth=100,
                flex=1
            )
            
            gb.configure_column(
                "Port",
                type=["numericColumn"],
                minWidth=100
            )
            
            gb.configure_column(
                "Certificate",
                minWidth=200,
                flex=2,
                cellClass=JsCode("""
                function(params) {
                    if (!params.data) return [];
                    if (params.data.Status === 'No Certificate') {
                        return ['ag-cert-cell-none'];
                    }
                    return [];
                }
                """)
            )
            
            # Configure platform column
            gb.configure_column(
                "Platform",
                minWidth=120,
                editable=True,
                cellEditor='agSelectCellEditor',
                cellEditorParams={
                    'values': [''] + list(platform_options.keys())
                },
                valueFormatter="value === '' ? 'Unknown' : value",
                cellClass=JsCode("""
                function(params) {
                    if (!params.value) return ['ag-platform-cell-unknown'];
                    return [];
                }
                """)
            )
            
            # Configure status column
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
            
            # Configure date columns
            gb.configure_column(
                "Expires",
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
                "Last Seen",
                type=["dateColumnFilter"],
                minWidth=150,
                valueFormatter="value ? new Date(value).toLocaleString() : ''",
                cellClass='ag-date-cell'
            )
            
            # Hide ID column
            gb.configure_column("_id", hide=True)
            
            # Configure selection
            gb.configure_selection(
                selection_mode="single",
                use_checkbox=False,
                pre_selected_rows=[]
            )
            
            # Configure grid options based on view type
            grid_options = {
                'animateRows': True,
                'enableRangeSelection': True,
                'suppressAggFuncInHeader': True,
                'suppressMovableColumns': True,
                'rowHeight': 35,
                'headerHeight': 40
            }
            
            if view_type == "Hostname":
                grid_options.update({
                    'groupDefaultExpanded': 1,
                    'groupDisplayType': 'groupRows',
                    'groupTotalRow': True,
                    'groupSelectsChildren': True,
                    'suppressGroupClickSelection': True
                })
            
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
                key=f"host_grid_{view_type}",
                height=600
            )
            
            # Handle selection
            try:
                selected_rows = grid_response.get('selected_rows', [])
                
                # Convert DataFrame to list of dicts if needed
                if isinstance(selected_rows, pd.DataFrame):
                    selected_rows = selected_rows.to_dict('records')
                
                # Handle selection for both views
                if selected_rows and len(selected_rows) > 0:
                    selected_row = selected_rows[0]
                    
                    # Skip group rows in hostname view (rows without hostname)
                    if view_type == "Hostname" and not selected_row.get('Hostname'):
                        return
                    
                    # Get the host with all relationships
                    selected_host = session.query(Host).options(
                        joinedload(Host.ip_addresses),
                        joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate),
                        joinedload(Host.scans)
                    ).filter_by(name=selected_row['Hostname']).first()
                    
                    if selected_host:
                        st.divider()
                        if selected_row.get('_id'):
                            # If there's a binding ID, show binding details
                            binding = session.query(CertificateBinding).options(
                                joinedload(CertificateBinding.host),
                                joinedload(CertificateBinding.host_ip),
                                joinedload(CertificateBinding.certificate)
                            ).get(selected_row['_id'])
                            if binding:
                                render_details(selected_host, binding, session)
                        else:
                            # If no binding, show host details
                            render_details(selected_host, None, session)
            except Exception as e:  # Only Exception is possible here due to UI/DB/unknown errors
                st.error(f"Error handling selection: {str(e)}")
                logger.exception(f"Selection error: {str(e)}")  # Add detailed logging
                
            # Add spacing after grid
            st.markdown("<div class='mb-5'></div>", unsafe_allow_html=True)
        else:
            st.warning("No host data available")

def render_details(selected_host: Host, binding: CertificateBinding = None, session: Session = None) -> None:
    """
    Unified details view for both host and binding details.
    
    Args:
        selected_host: Host model instance
        binding: Optional CertificateBinding instance for binding-specific view
        session: SQLAlchemy session for database operations
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
            bindings = session.query(CertificateBinding).filter_by(host_id=selected_host.id).all()
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
                                    result = HostService.delete_binding(session, b.id)
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
        
        def delete_host(session):
            try:
                # Delete the host and all related records
                session.delete(selected_host)
                session.commit()
                # Clear the selection and rerun to refresh the view
                if 'selected_host_id' in st.session_state:
                    del st.session_state.selected_host_id
                return True
            except Exception as e:
                session.rollback()
                return False
        
        render_danger_zone(
            title="Delete Host",
            entity_name=selected_host.name,
            entity_type="host",
            dependencies=dependencies,
            on_delete=delete_host,
            session=session
        )
