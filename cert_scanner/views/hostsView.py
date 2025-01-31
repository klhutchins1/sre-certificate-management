import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
from ..models import Host, HostIP, CertificateBinding, Application, Certificate
from ..constants import platform_options, APP_TYPES, HOST_TYPES, ENVIRONMENTS, app_types

def render_hosts_view(engine):
    """Render the hosts view"""
    # Create a row for title and button
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
    
    # Show any pending success messages
    if 'success_message' in st.session_state:
        st.success(st.session_state.success_message)
        del st.session_state.success_message
    
    # Show Add Host form if button was clicked
    if st.session_state.get('show_add_host_form', False):
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
                        # Create new host
                        new_host = Host(
                            name=hostname,
                            host_type=host_type,
                            environment=environment,
                            description=description,
                            last_seen=datetime.now()
                        )
                        session.add(new_host)
                        session.flush()  # Get the new host ID
                        
                        # Add IP addresses
                        if ip_addresses.strip():
                            for ip in ip_addresses.strip().split('\n'):
                                ip = ip.strip()
                                if ip:  # Skip empty lines
                                    new_ip = HostIP(
                                        host_id=new_host.id,
                                        ip_address=ip,
                                        is_active=True,
                                        last_seen=datetime.now()
                                    )
                                    session.add(new_ip)
                        
                        session.commit()
                        st.success("✅ Host added successfully!")
                        st.session_state['show_add_host_form'] = False  # Hide the form
                        st.rerun()  # Refresh the page
                except Exception as e:
                    st.error(f"Error adding host: {str(e)}")
    
    st.divider()
    
    # Handle platform updates from AG Grid
    if 'platform_update' in st.session_state:
        update_data = st.session_state.platform_update
        try:
            with Session(engine) as session:
                binding = session.query(CertificateBinding).get(update_data['binding_id'])
                if binding:
                    binding.platform = update_data['platform']
                    session.commit()
                    # Store success message in session state
                    st.session_state.success_message = f"Platform updated successfully for {binding.host.name}"
                    # Clear the update data
                    del st.session_state.platform_update
                    st.rerun()
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
    
    # Add custom CSS for AG Grid
    st.markdown("""
        <style>
        .ag-root-wrapper {
            border: none !important;
        }
        .ag-row-selected {
            background-color: #e6f3ff !important;
            border-left: 3px solid #1e88e5 !important;
        }
        .ag-row-hover {
            background-color: #f5f5f5 !important;
        }
        .ag-row {
            cursor: pointer;
            transition: all 0.2s ease;
        }
        [data-testid="stAgGrid"] {
            min-height: 300px;
            max-height: 500px;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Create metrics columns
    col1, col2, col3 = st.columns(3)
    
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
        
        # Calculate metrics
        all_bindings = []
        for host in hosts:
            all_bindings.extend(host.certificate_bindings)
        
        unique_ips = len(set(
            ip.ip_address 
            for host in hosts 
            for ip in host.ip_addresses
        ))
        unique_hosts = len(hosts)
        total_certs = len(set(
            binding.certificate_id 
            for binding in all_bindings
        ))
        
        # Display metrics
        col1.metric("Total Hosts", unique_hosts)
        col2.metric("Total IPs", unique_ips)
        col3.metric("Total Certificates", total_certs)
        
        st.divider()
        
        # Add view selector
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
                cellStyle=JsCode("""
                function(params) {
                    if (!params.data) return null;
                    if (params.data.Status === 'Expired') {
                        return {
                            'color': '#dc3545',
                            'font-weight': '500'
                        };
                    }
                    if (params.data.Status === 'No Certificate') {
                        return {
                            'color': '#6c757d',
                            'font-style': 'italic'
                        };
                    }
                    return {
                        'color': '#198754',
                        'font-weight': '500'
                    };
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
                valueFormatter="value === '' ? 'Unknown' : value"
            )
            
            # Configure status column
            gb.configure_column(
                "Status",
                minWidth=100,
                cellStyle=JsCode("""
                function(params) {
                    if (!params.data) return null;
                    if (params.value === 'No Certificate') {
                        return {
                            'background-color': '#6c757d',
                            'color': 'white',
                            'font-weight': '500',
                            'border-radius': '20px',
                            'padding': '2px 8px',
                            'display': 'flex',
                            'justify-content': 'center',
                            'align-items': 'center'
                        };
                    }
                    return {
                        'background-color': params.value === 'Expired' ? '#dc3545' : '#198754',
                        'color': 'white',
                        'font-weight': '500',
                        'border-radius': '20px',
                        'padding': '2px 8px',
                        'display': 'flex',
                        'justify-content': 'center',
                        'align-items': 'center'
                    };
                }
                """)
            )
            
            # Configure date columns
            gb.configure_column(
                "Expires",
                type=["dateColumnFilter"],
                minWidth=120,
                valueFormatter="value ? new Date(value).toLocaleDateString() : ''",
                cellStyle=JsCode("""
                function(params) {
                    if (!params.data) return null;
                    return params.data.Status === 'Expired' ? {
                        'color': '#dc3545',
                        'font-weight': '500'
                    } : null;
                }
                """)
            )
            gb.configure_column(
                "Last Seen",
                type=["dateColumnFilter"],
                minWidth=150,
                valueFormatter="value ? new Date(value).toLocaleString() : ''"
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
                    
                    # Get the host based on the hostname
                    selected_host = next(
                        (h for h in hosts if h.name == selected_row['Hostname']),
                        None
                    )
                    
                    if selected_host:
                        st.divider()
                        if selected_row.get('_id'):
                            # If there's a binding ID, show binding details
                            selected_binding = next(
                                (b for b in all_bindings if b.id == selected_row['_id']), 
                                None
                            )
                            if selected_binding:
                                render_binding_details(selected_binding)
                        else:
                            # If no binding, show host details
                            render_host_details(selected_host)
            except Exception as e:
                st.error(f"Error handling selection: {str(e)}")
                
            # Add spacing after grid
            st.markdown("<div style='margin-bottom: 2rem;'></div>", unsafe_allow_html=True)
        else:
            st.warning("No host data available")

def render_binding_details(binding):
    """Render detailed view of a binding"""
    st.subheader(f"🔗 {binding.host.name}")
    
    # Create tabs for different sections
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Certificate Details", "Manage Certificates", "Applications"])
    
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
                **IP Address:** {binding.host_ip.ip_address if binding.host_ip else 'N/A'}  
                **Port:** {binding.port}  
                **Site Name:** {binding.site_name or 'Default'}  
                **Site ID:** {binding.site_id or 'N/A'}
            """)
            
            # Add platform selection
            current_platform = binding.platform or ''
            new_platform = st.selectbox(
                "Platform",
                options=[''] + list(platform_options.keys()),
                format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                key=f"platform_select_{binding.id}",
                index=list([''] + list(platform_options.keys())).index(current_platform)
            )
            
            if new_platform != current_platform:
                binding.platform = new_platform
                st.session_state.get('session').commit()
                st.success("Platform saved", icon="✅")
                st.rerun()
            
            # Add application selection
            session = st.session_state.get('session')
            applications = session.query(Application).all()
            app_options = [('', 'No Application')] + [(str(app.id), f"{app.name} ({app_types.get(app.app_type, app.app_type)})") for app in applications]
            
            current_app_id = str(binding.application_id) if binding.application_id else ''
            new_app_id = st.selectbox(
                "Application",
                options=[id for id, _ in app_options],
                format_func=lambda x: dict(app_options).get(x, 'No Application'),
                key=f"app_select_{binding.id}",
                index=[id for id, _ in app_options].index(current_app_id) if current_app_id in [id for id, _ in app_options] else 0
            )
            
            if new_app_id != current_app_id:
                binding.application_id = int(new_app_id) if new_app_id else None
                session.commit()
                st.success("Application saved", icon="✅")
                st.rerun()
            
            st.markdown(f"**Last Seen:** {binding.last_seen.strftime('%Y-%m-%d %H:%M')}")
        
        with col2:
            # Get all certificates for this host
            host_bindings = (
                st.session_state.get('session')
                .query(CertificateBinding)
                .filter(CertificateBinding.host_id == binding.host_id)
                .all()
            )
            
            # Display current certificate
            is_valid = binding.certificate.valid_until > datetime.now()
            status_color = "#198754" if is_valid else "#dc3545"
            status_text = "Valid" if is_valid else "Expired"
            st.markdown(f"""
                **Current Certificate:** <span style="color: {status_color}; font-weight: 500">{binding.certificate.common_name}</span>  
                **Status:** <span style="background-color: {status_color}; color: white; font-weight: 500; padding: 2px 8px; border-radius: 20px">{status_text}</span>  
                **Valid Until:** <span style="color: {status_color if not is_valid else 'inherit'}">{binding.certificate.valid_until.strftime('%Y-%m-%d')}</span>
            """, unsafe_allow_html=True)
            
            # Show other certificates if any
            other_bindings = [b for b in host_bindings if b.id != binding.id]
            if other_bindings:
                st.markdown("### Other Certificates")
                for b in other_bindings:
                    is_valid = b.certificate.valid_until > datetime.now()
                    status_color = "#198754" if is_valid else "#dc3545"
                    status_text = "Valid" if is_valid else "Expired"
                    source = "🔒 Manual" if b.manually_added else "🔍 Scanned"
                    with st.expander(f"{b.certificate.common_name} ({source})", expanded=False):
                        st.markdown(f"""
                            **Port:** {b.port or 'N/A'}  
                            **Platform:** {b.platform or 'Not Set'}  
                            **Status:** <span style="background-color: {status_color}; color: white; font-weight: 500; padding: 2px 8px; border-radius: 20px">{status_text}</span>  
                            **Valid Until:** {b.certificate.valid_until.strftime('%Y-%m-%d')}  
                            **Last Seen:** {b.last_seen.strftime('%Y-%m-%d %H:%M')}
                        """, unsafe_allow_html=True)
    
    with tab2:
        cert = binding.certificate
        st.json({
            "Common Name": cert.common_name,
            "Serial Number": cert.serial_number,
            "Thumbprint": cert.thumbprint,
            "Valid From": cert.valid_from.strftime('%Y-%m-%d'),
            "Valid Until": cert.valid_until.strftime('%Y-%m-%d'),
            "Issuer": cert.issuer,
            "Subject": cert.subject,
            "Key Usage": cert.key_usage,
            "Signature Algorithm": cert.signature_algorithm
        })
    
    with tab3:
        st.subheader("Add Manual Certificate")
        with st.form("add_manual_certificate"):
            # Basic certificate details
            common_name = st.text_input("Common Name (CN)", 
                help="The domain name or identifier for the certificate")
            serial_number = st.text_input("Serial Number", 
                help="The certificate's serial number")
            thumbprint = st.text_input("Thumbprint/Fingerprint", 
                help="SHA-1 or SHA-256 fingerprint of the certificate")
            
            # Validity dates
            col1, col2 = st.columns(2)
            with col1:
                valid_from = st.date_input("Valid From", 
                    help="Certificate validity start date")
            with col2:
                valid_until = st.date_input("Valid Until", 
                    help="Certificate expiration date")
            
            # Additional details
            issuer = st.text_input("Issuer", 
                help="The certificate issuer's distinguished name")
            subject = st.text_input("Subject", 
                help="The certificate subject's distinguished name")
            
            # Certificate type and usage
            col3, col4 = st.columns(2)
            with col3:
                cert_type = st.selectbox("Certificate Type", 
                    options=["Server", "Client", "Code Signing", "Other"],
                    help="The type of certificate")
            with col4:
                key_usage = st.text_input("Key Usage", 
                    help="Certificate key usage (e.g., Digital Signature, Key Encipherment)")
            
            signature_algorithm = st.text_input("Signature Algorithm", 
                help="The algorithm used to sign the certificate (e.g., sha256RSA)")
            
            # Binding details
            col5, col6 = st.columns(2)
            with col5:
                port = st.number_input("Port", min_value=1, max_value=65535, 
                    help="The port number where this certificate is used (optional)")
            with col6:
                platform = st.selectbox("Platform",
                    options=[''] + list(platform_options.keys()),
                    format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                    help="The platform where this certificate is used")
            
            notes = st.text_area("Notes", 
                help="Additional notes about this certificate (optional)")
            
            submitted = st.form_submit_button("Add Certificate", type="primary")
            
            if submitted:
                try:
                    with Session(st.session_state.get('engine')) as session:
                        # Create new certificate
                        new_cert = Certificate(
                            common_name=common_name,
                            serial_number=serial_number,
                            thumbprint=thumbprint,
                            valid_from=datetime.combine(valid_from, datetime.min.time()),
                            valid_until=datetime.combine(valid_until, datetime.max.time()),
                            issuer=issuer,
                            subject=subject,
                            key_usage=key_usage,
                            signature_algorithm=signature_algorithm,
                            notes=notes,
                            manually_added=True
                        )
                        session.add(new_cert)
                        session.flush()  # Get the new certificate ID
                        
                        # Create new binding
                        new_binding = CertificateBinding(
                            host_id=binding.host_id,
                            certificate_id=new_cert.id,
                            port=port if port > 0 else None,
                            platform=platform if platform else None,
                            manually_added=True,
                            last_seen=datetime.now()
                        )
                        session.add(new_binding)
                        session.commit()
                        
                        st.success("✅ Certificate added successfully!")
                        st.rerun()  # Refresh the page to show the new certificate
                except Exception as e:
                    st.error(f"Error adding certificate: {str(e)}")
        
        # Show existing manual certificates
        st.divider()
        st.subheader("Manual Certificates")
        
        manual_bindings = (
            st.session_state.get('session')
            .query(CertificateBinding)
            .join(Certificate)
            .filter(
                CertificateBinding.host_id == binding.host_id,
                CertificateBinding.manually_added == True
            )
            .all()
        )
        
        if manual_bindings:
            for mb in manual_bindings:
                with st.expander(f"{mb.certificate.common_name} ({mb.port or 'No Port'})"):
                    col1, col2, col3 = st.columns([2,1,1])
                    with col1:
                        st.markdown(f"**Serial:** {mb.certificate.serial_number}")
                        st.markdown(f"**Thumbprint:** {mb.certificate.thumbprint}")
                    with col2:
                        st.markdown(f"**Valid From:** {mb.certificate.valid_from.strftime('%Y-%m-%d')}")
                        st.markdown(f"**Valid Until:** {mb.certificate.valid_until.strftime('%Y-%m-%d')}")
                    with col3:
                        st.markdown(f"**Platform:** {mb.platform or 'Not Set'}")
                        if st.button("Delete", key=f"delete_{mb.id}", type="secondary"):
                            try:
                                session = st.session_state.get('session')
                                session.delete(mb)
                                session.commit()
                                st.success("Certificate binding deleted successfully!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error deleting certificate: {str(e)}")
        else:
            st.info("No manually added certificates found for this host.")

    with tab4:
        st.subheader("Applications")
        
        session = st.session_state.get('session')
        applications = session.query(Application).all()
        
        if not applications:
            st.info("No applications available. Create applications in the Applications page.")
            return
        
        # Show current application assignment
        st.markdown("### Current Assignment")
        if binding.application:
            st.markdown(f"""
                **Application:** {binding.application.name}  
                **Type:** {app_types.get(binding.application.app_type, binding.application.app_type)}  
                **Suite:** {binding.application.suite.name}  
                **Description:** {binding.application.description or 'No description'}
            """)
        else:
            st.info("No application assigned to this binding.")
        
        # Application assignment
        st.markdown("### Assign Application")
        app_options = [('', 'No Application')] + [(str(app.id), f"{app.name} ({app_types.get(app.app_type, app.app_type)}) - {app.suite.name}") for app in applications]
        
        current_app_id = str(binding.application_id) if binding.application_id else ''
        new_app_id = st.selectbox(
            "Select Application",
            options=[id for id, _ in app_options],
            format_func=lambda x: dict(app_options).get(x, 'No Application'),
            help="Select an application to assign to this binding"
        )
        
        if new_app_id != current_app_id:
            if st.button("Update Assignment", type="primary"):
                try:
                    binding.application_id = int(new_app_id) if new_app_id else None
                    session.commit()
                    st.success("✅ Application assignment updated successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error updating application assignment: {str(e)}")

def render_host_details(host):
    """Render detailed view of a host without certificates"""
    st.subheader(f"🖥️ {host.name}")
    
    # Create tabs for different sections
    tab1, tab2 = st.tabs(["Overview", "Add Certificate"])
    
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            # Show host details
            st.markdown(f"""
                **Host Type:** {host.host_type}  
                **Environment:** {host.environment}  
                **Description:** {host.description or 'No description'}
            """)
            
            # Show IP addresses
            if host.ip_addresses:
                st.markdown("### IP Addresses")
                for ip in host.ip_addresses:
                    st.markdown(f"- {ip.ip_address}")
            else:
                st.info("No IP addresses configured")
            
            st.markdown(f"**Last Seen:** {host.last_seen.strftime('%Y-%m-%d %H:%M')}")
    
    with tab2:
        st.subheader("Add Manual Certificate")
        with st.form("add_manual_certificate"):
            # Basic certificate details
            common_name = st.text_input("Common Name (CN)", 
                help="The domain name or identifier for the certificate")
            serial_number = st.text_input("Serial Number", 
                help="The certificate's serial number")
            thumbprint = st.text_input("Thumbprint/Fingerprint", 
                help="SHA-1 or SHA-256 fingerprint of the certificate")
            
            # Validity dates
            col1, col2 = st.columns(2)
            with col1:
                valid_from = st.date_input("Valid From", 
                    help="Certificate validity start date")
            with col2:
                valid_until = st.date_input("Valid Until", 
                    help="Certificate expiration date")
            
            # Additional details
            issuer = st.text_input("Issuer", 
                help="The certificate issuer's distinguished name")
            subject = st.text_input("Subject", 
                help="The certificate subject's distinguished name")
            
            # Certificate type and usage
            col3, col4 = st.columns(2)
            with col3:
                cert_type = st.selectbox("Certificate Type", 
                    options=["Server", "Client", "Code Signing", "Other"],
                    help="The type of certificate")
            with col4:
                key_usage = st.text_input("Key Usage", 
                    help="Certificate key usage (e.g., Digital Signature, Key Encipherment)")
            
            signature_algorithm = st.text_input("Signature Algorithm", 
                help="The algorithm used to sign the certificate (e.g., sha256RSA)")
            
            # Binding details
            col5, col6 = st.columns(2)
            with col5:
                port = st.number_input("Port", min_value=1, max_value=65535, 
                    help="The port number where this certificate is used (optional)")
            with col6:
                platform = st.selectbox("Platform",
                    options=[''] + list(platform_options.keys()),
                    format_func=lambda x: platform_options.get(x, 'Not Set') if x else 'Select Platform',
                    help="The platform where this certificate is used")
            
            notes = st.text_area("Notes", 
                help="Additional notes about this certificate (optional)")
            
            submitted = st.form_submit_button("Add Certificate", type="primary")
            
            if submitted:
                try:
                    with Session(st.session_state.get('engine')) as session:
                        # Create new certificate
                        new_cert = Certificate(
                            common_name=common_name,
                            serial_number=serial_number,
                            thumbprint=thumbprint,
                            valid_from=datetime.combine(valid_from, datetime.min.time()),
                            valid_until=datetime.combine(valid_until, datetime.max.time()),
                            issuer=issuer,
                            subject=subject,
                            key_usage=key_usage,
                            signature_algorithm=signature_algorithm,
                            notes=notes,
                            manually_added=True
                        )
                        session.add(new_cert)
                        session.flush()  # Get the new certificate ID
                        
                        # Create new binding
                        new_binding = CertificateBinding(
                            host_id=host.id,
                            port=port if port > 0 else None,
                            platform=platform if platform else None,
                            certificate_id=new_cert.id,
                            manually_added=True,
                            last_seen=datetime.now()
                        )
                        session.add(new_binding)
                        session.commit()
                        
                        st.success("✅ Certificate added successfully!")
                        st.rerun()  # Refresh the page to show the new certificate
                except Exception as e:
                    st.error(f"Error adding certificate: {str(e)}")
