import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode
from ..models import Host, HostIP, CertificateBinding
from ..constants import platform_options

def render_hosts_view(engine):
    """Render the hosts view"""
    st.title("Hosts")
    
    # Show any pending success messages
    if 'success_message' in st.session_state:
        st.success(st.session_state.success_message)
        del st.session_state.success_message
    
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
    
    # Create two columns for metrics
    col1, col2 = st.columns(2)
    
    with Session(engine) as session:
        # Store session in session state for use in binding details
        st.session_state['session'] = session
        
        # Get all bindings
        bindings = session.query(CertificateBinding).all()
        
        if not bindings:
            st.warning("No certificate bindings found in database")
            return
        
        # Display total count
        unique_ips = len(set(b.host_ip.ip_address for b in bindings if b.host_ip))
        unique_hosts = len(set(b.host_id for b in bindings))
        
        col1.metric("Total IPs", unique_ips)
        col2.metric("Total Hosts", unique_hosts)
        
        st.divider()
        
        # Convert to DataFrame for display
        binding_data = []
        for binding in bindings:
            if binding.host_ip:  # IP-based certificates
                binding_data.append({
                    'IP Address': binding.host_ip.ip_address,
                    'Port': binding.port,
                    'Hostname': binding.host.name,
                    'Certificate': binding.certificate.common_name,
                    'Platform': binding.platform or 'Unknown',
                    'Expires': binding.certificate.valid_until,
                    'Last Seen': binding.last_seen,
                    'Status': 'Valid' if binding.certificate.valid_until > datetime.now() else 'Expired',
                    '_id': binding.id
                })
        
        if binding_data:
            df = pd.DataFrame(binding_data)
            
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
                "IP Address",
                minWidth=150,
                flex=1
            )
            gb.configure_column(
                "Port",
                type=["numericColumn"],
                minWidth=100
            )
            gb.configure_column(
                "Hostname",
                minWidth=200,
                flex=2
            )
            gb.configure_column(
                "Certificate",
                minWidth=200,
                flex=2,
                cellStyle={"styleConditions": [
                    {
                        "condition": "params.data.Status == 'Expired'",
                        "style": {
                            "background-color": "#dc3545",
                            "color": "white",
                            "font-weight": "500",
                            "border-radius": "20px",
                            "padding": "2px 8px",
                            "display": "flex",
                            "justify-content": "center",
                            "align-items": "center"
                        }
                    },
                    {
                        "condition": "params.data.Status == 'Valid'",
                        "style": {
                            "background-color": "#198754",
                            "color": "white",
                            "font-weight": "500",
                            "border-radius": "20px",
                            "padding": "2px 8px",
                            "display": "flex",
                            "justify-content": "center",
                            "align-items": "center"
                        }
                    }
                ]}
            )
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
            gb.configure_column(
                "Status",
                minWidth=100,
                cellStyle={"styleConditions": [
                    {
                        "condition": "params.value == 'Expired'",
                        "style": {
                            "background-color": "#dc3545",
                            "color": "white",
                            "font-weight": "500",
                            "border-radius": "20px",
                            "padding": "2px 8px",
                            "display": "flex",
                            "justify-content": "center",
                            "align-items": "center"
                        }
                    },
                    {
                        "condition": "params.value == 'Valid'",
                        "style": {
                            "background-color": "#198754",
                            "color": "white",
                            "font-weight": "500",
                            "border-radius": "20px",
                            "padding": "2px 8px",
                            "display": "flex",
                            "justify-content": "center",
                            "align-items": "center"
                        }
                    }
                ]}
            )
            gb.configure_column(
                "Expires",
                type=["dateColumnFilter"],
                minWidth=120,
                cellStyle={"styleConditions": [
                    {
                        "condition": "params.data.Status == 'Expired'",
                        "style": {
                            "background-color": "#dc3545",
                            "color": "white",
                            "font-weight": "500",
                            "border-radius": "20px",
                            "padding": "2px 8px",
                            "display": "flex",
                            "justify-content": "center",
                            "align-items": "center"
                        }
                    }
                ]}
            )
            gb.configure_column(
                "Last Seen",
                type=["dateColumnFilter"],
                minWidth=150
            )
            gb.configure_column("_id", hide=True)
            
            # Configure selection
            gb.configure_selection(
                selection_mode="single",
                use_checkbox=False,
                pre_selected_rows=[]
            )
            
            # Configure grid options
            gb.configure_grid_options(
                onCellValueChanged="""
                function(params) {
                    if (params.colDef.field === 'Platform') {
                        const args = {
                            'binding_id': params.data._id,
                            'platform': params.newValue
                        };
                        window.parent.postMessage({
                            type: 'streamlit:setComponentValue',
                            value: args,
                            dataType: 'json',
                            key: 'platform_update'
                        }, '*');
                    }
                }
                """,
                suppressBrowserResizeObserver=True,
                suppressPropertyNamesCheck=True,
                suppressRowDeselection=True,
                suppressCellSelection=True,
                suppressColumnVirtualisation=True,
                suppressRowVirtualisation=True,
                suppressDragLeaveHidesColumns=True,
                suppressMakeColumnVisibleAfterUnGroup=True,
                suppressAggFuncInHeader=True,
                suppressLoadingOverlay=True,
                suppressNoRowsOverlay=True,
                suppressFieldDotNotation=True,
                suppressScrollOnNewData=True,
                suppressMovableColumns=True,
                suppressColumnMoveAnimation=True,
                suppressAnimationFrame=True,
                suppressCopyRowsToClipboard=True,
                suppressClipboardApi=True,
                suppressFocusAfterRefresh=True,
                enableRangeSelection=False,
                domLayout='normal',
                rowHeight=35,
                headerHeight=40,
                rowSelection="single",
                onFirstDataRendered="""
                function(params) {
                    params.api.sizeColumnsToFit();
                }
                """,
                onGridReady="""
                function(params) {
                    params.api.sizeColumnsToFit();
                }
                """
            )
            
            gridOptions = gb.build()
            
            # Display the AG Grid with update mode for cell changes
            grid_response = AgGrid(
                df,
                gridOptions=gridOptions,
                update_mode=GridUpdateMode.MODEL_CHANGED,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                fit_columns_on_grid_load=True,
                theme="streamlit",
                allow_unsafe_jscode=True,
                key="host_grid",
                enable_enterprise_modules=False,
                height=400,
                custom_css={
                    ".ag-root-wrapper": {
                        "border": "none !important",
                        "box-shadow": "none !important"
                    },
                    ".ag-header": {
                        "border-bottom": "2px solid #e0e0e0 !important"
                    }
                }
            )
            
            # Handle platform updates
            if grid_response['data'] is not None:
                updated_rows = grid_response['data'].to_dict('records')
                original_rows = df.to_dict('records')
                
                for updated_row in updated_rows:
                    original_row = next((r for r in original_rows if r['_id'] == updated_row['_id']), None)
                    if original_row and original_row['Platform'] != updated_row['Platform']:
                        try:
                            binding = session.query(CertificateBinding).get(updated_row['_id'])
                            if binding:
                                binding.platform = updated_row['Platform'] if updated_row['Platform'] != 'Unknown' else None
                                session.commit()
                                st.success(f"✅ Platform updated for {binding.host.name}")
                        except Exception as e:
                            st.error(f"Error updating platform: {str(e)}")
            
            # Handle selection
            try:
                selected_rows = grid_response['selected_rows']
                
                if isinstance(selected_rows, pd.DataFrame):
                    if not selected_rows.empty:
                        selected_row = selected_rows.iloc[0].to_dict()
                        selected_binding_id = int(selected_row['_id'])
                        selected_binding = next((b for b in bindings if b.id == selected_binding_id), None)
                        if selected_binding:
                            st.divider()
                            render_binding_details(selected_binding)
                elif isinstance(selected_rows, list) and selected_rows:
                    selected_row = selected_rows[0]
                    if isinstance(selected_row, dict) and '_id' in selected_row:
                        selected_binding_id = int(selected_row['_id'])
                        selected_binding = next((b for b in bindings if b.id == selected_binding_id), None)
                        if selected_binding:
                            st.divider()
                            render_binding_details(selected_binding)
            except Exception as e:
                st.error(f"Error handling selection: {str(e)}")
        else:
            st.warning("No host data available")

def render_binding_details(binding):
    """Render detailed view of a binding"""
    st.subheader(f"🔗 {binding.host.name}")
    
    # Create tabs for different sections
    tab1, tab2 = st.tabs(["Overview", "Certificate Details"])
    
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
                **IP Address:** {binding.host_ip.ip_address if binding.host_ip else 'N/A'}  
                **Port:** {binding.port}
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
                if st.button("Update Platform", key=f"update_platform_{binding.id}", type="primary"):
                    binding.platform = new_platform
                    st.session_state.get('session').commit()
                    st.success("✅ Platform updated successfully!")
            
            st.markdown(f"**Last Seen:** {binding.last_seen.strftime('%Y-%m-%d %H:%M')}")
            
        with col2:
            is_valid = binding.certificate.valid_until > datetime.now()
            status_color = "#198754" if is_valid else "#dc3545"
            status_text = "Valid" if is_valid else "Expired"
            st.markdown(f"""
                **Certificate:** <span style="color: {status_color}; font-weight: 500">{binding.certificate.common_name}</span>  
                **Status:** <span style="background-color: {status_color}; color: white; font-weight: 500; padding: 2px 8px; border-radius: 20px">{status_text}</span>  
                **Valid Until:** <span style="color: {status_color if not is_valid else 'inherit'}">{binding.certificate.valid_until.strftime('%Y-%m-%d')}</span>
            """, unsafe_allow_html=True)
    
    with tab2:
        cert = binding.certificate
        is_valid = cert.valid_until > datetime.now()
        status_color = "#198754" if is_valid else "#dc3545"
        status_text = "Valid" if is_valid else "Expired"
        st.markdown(f"""
            <div style="margin-bottom: 20px;">
                <span style="color: {status_color}; font-size: 1.1em; font-weight: 500;">
                    {cert.common_name}
                </span>
                <span style="background-color: {status_color}; color: white; font-weight: 500; padding: 2px 8px; border-radius: 20px; margin-left: 10px;">
                    {status_text}
                </span>
            </div>
        """, unsafe_allow_html=True)
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
