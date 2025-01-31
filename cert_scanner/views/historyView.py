import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
from ..models import Certificate, CertificateScan, Host, HostIP, CertificateBinding, CertificateTracking
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css


def render_history_view(engine):
    """Render the certificate scan history view"""
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
    st.title("Certificate History")
    
    # Create tabs for different history views
    cn_tab, scan_tab, host_tab = st.tabs(["Common Name History", "Scan History", "Host Certificate History"])
    
    with cn_tab:
        render_cn_history(engine)
    
    with scan_tab:
        render_scan_history(engine)
        
    with host_tab:
        render_host_certificate_history(engine)

def render_host_certificate_history(engine):
    """Render certificate history by host"""
    with SessionManager(engine) as session:
        # Get all hosts with their bindings and certificates
        hosts = session.query(Host).options(
            joinedload(Host.ip_addresses),
            joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate)
        ).all()
        
        if not hosts:
            st.warning("No host data found")
            return
        
        # Create host selection options
        host_options = {}
        for host in hosts:
            for ip in host.ip_addresses:
                key = f"{host.name} ({ip.ip_address})"
                host_options[key] = (host.id, ip.id)
        
        # Host selection
        selected_host = st.selectbox(
            "Select Host",
            options=list(host_options.keys()),
            index=None,
            placeholder="Choose a host to view certificate history..."
        )
        
        if selected_host:
            host_id, ip_id = host_options[selected_host]
            
            # Get certificate history for this host/IP
            bindings = session.query(CertificateBinding).filter(
                CertificateBinding.host_id == host_id,
                CertificateBinding.host_ip_id == ip_id
            ).join(
                Certificate
            ).order_by(
                CertificateBinding.last_seen.desc()
            ).all()
            
            if bindings:
                # Convert to DataFrame for display
                cert_history = []
                for binding in bindings:
                    cert = binding.certificate
                    cert_history.append({
                        "Certificate": cert.common_name,
                        "Serial Number": cert.serial_number,
                        "Valid From": cert.valid_from,
                        "Valid Until": cert.valid_until,
                        "Last Seen": binding.last_seen,
                        "Port": binding.port,
                        "Platform": binding.platform or "Unknown",
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired"
                    })
                
                df = pd.DataFrame(cert_history)
                
                # Display timeline of certificates
                st.subheader("Certificate Timeline")
                timeline_chart = {
                    "Certificate": df["Certificate"].tolist(),
                    "Start": df["Valid From"].tolist(),
                    "End": df["Valid Until"].tolist()
                }
                st.plotly_chart(create_timeline_chart(timeline_chart))
                
                # Display detailed history
                st.subheader("Detailed History")
                st.dataframe(
                    df,
                    column_config={
                        "Certificate": st.column_config.TextColumn(
                            "Certificate",
                            width="medium"
                        ),
                        "Serial Number": st.column_config.TextColumn(
                            "Serial Number",
                            width="medium"
                        ),
                        "Valid From": st.column_config.DatetimeColumn(
                            "Valid From",
                            format="DD/MM/YYYY"
                        ),
                        "Valid Until": st.column_config.DatetimeColumn(
                            "Valid Until",
                            format="DD/MM/YYYY"
                        ),
                        "Last Seen": st.column_config.DatetimeColumn(
                            "Last Seen",
                            format="DD/MM/YYYY HH:mm"
                        ),
                        "Port": st.column_config.NumberColumn(
                            "Port",
                            width="small"
                        ),
                        "Platform": st.column_config.TextColumn(
                            "Platform",
                            width="small"
                        ),
                        "Status": st.column_config.TextColumn(
                            "Status",
                            width="small"
                        )
                    },
                    hide_index=True,
                    use_container_width=True
                )
            else:
                st.info("No certificate history found for this host")

def create_timeline_chart(data):
    """Create a timeline chart using plotly"""
    import plotly.figure_factory as ff
    import plotly.express as px
    
    # Create timeline data
    df_timeline = []
    for i, (cert, start, end) in enumerate(zip(data["Certificate"], data["Start"], data["End"])):
        df_timeline.append(dict(
            Task=cert,
            Start=start,
            Finish=end,
            Resource="Certificate"
        ))
    
    # Create the figure
    fig = ff.create_gantt(
        df_timeline,
        index_col='Resource',
        show_colorbar=True,
        group_tasks=True,
        showgrid_x=True,
        showgrid_y=True
    )
    
    # Update layout
    fig.update_layout(
        title="Certificate Timeline",
        height=200 + (len(data["Certificate"]) * 30),
        xaxis_title="Date",
        showlegend=False
    )
    
    return fig

def render_scan_history(engine):
    """Render the scan history view"""
    with SessionManager(engine) as session:
        # Get all scans with certificate and host info
        scans = session.query(CertificateScan)\
            .outerjoin(Certificate)\
            .outerjoin(Host)\
            .options(
                joinedload(CertificateScan.certificate),
                joinedload(CertificateScan.host).joinedload(Host.ip_addresses)
            )\
            .order_by(desc(CertificateScan.scan_date))\
            .all()
        
        if not scans:
            st.warning("No scan history found")
            return
        
        # Convert to DataFrame for easier manipulation
        scan_data = []
        for scan in scans:
            # Get host information
            if scan.host:
                host_display = scan.host.name
                # Get IP addresses for the host
                if scan.host.ip_addresses:
                    ip_addresses = [ip.ip_address for ip in scan.host.ip_addresses]
                    if ip_addresses:
                        host_display = f"{host_display} ({', '.join(ip_addresses)})"
            else:
                host_display = "Unknown Host"  # Fallback if no host information
            
            data = {
                "Scan Date": scan.scan_date,
                "Status": scan.status,
                "Port": scan.port,
                "Host": host_display,
            }
            
            # Add certificate info if available
            if scan.certificate:
                data.update({
                    "Certificate": scan.certificate.common_name,
                    "Serial Number": scan.certificate.serial_number,
                    "Valid Until": scan.certificate.valid_until,
                })
            else:
                data.update({
                    "Certificate": "N/A",
                    "Serial Number": "N/A",
                    "Valid Until": None,
                })
            
            scan_data.append(data)
        
        df = pd.DataFrame(scan_data)
        
        # Add filtering options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Date range filter
            date_range = st.selectbox(
                "Time Period",
                ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
                index=2  # Default to Last 30 Days
            )
            
            if date_range != "All Time":
                days = {
                    "Last 24 Hours": 1,
                    "Last 7 Days": 7,
                    "Last 30 Days": 30
                }[date_range]
                cutoff_date = datetime.now() - timedelta(days=days)
                df = df[df["Scan Date"] >= cutoff_date]
        
        with col2:
            # Status filter
            statuses = ["All"] + sorted(df["Status"].unique().tolist())
            status_filter = st.selectbox("Status", statuses)
            if status_filter != "All":
                df = df[df["Status"] == status_filter]
        
        with col3:
            # Host filter
            hosts = ["All"] + sorted(df["Host"].unique().tolist())
            host_filter = st.selectbox("Host", hosts)
            if host_filter != "All":
                df = df[df["Host"] == host_filter]
        
        # Display metrics
        st.divider()
        metric_col1, metric_col2, metric_col3 = st.columns(3)
        with metric_col1:
            st.metric("Total Scans", len(df))
        with metric_col2:
            success_rate = (df["Status"] == "Valid").mean() * 100
            st.metric("Success Rate", f"{success_rate:.1f}%")
        with metric_col3:
            unique_hosts = len(df["Host"].unique())
            st.metric("Unique Hosts", unique_hosts)
        st.divider()
        
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
            "Host",
            minWidth=200,
            flex=2
        )
        gb.configure_column(
            "Port",
            type=["numericColumn"],
            minWidth=100
        )
        gb.configure_column(
            "Status",
            minWidth=120,
            cellClass=JsCode("""
            function(params) {
                if (!params.data) return [];
                if (params.value === 'Valid') return ['ag-status-valid'];
                if (params.value === 'Failed') return ['ag-status-expired'];
                if (params.value === 'Warning') return ['ag-status-warning'];
                return [];
            }
            """)
        )
        gb.configure_column(
            "Scan Date",
            type=["dateColumnFilter"],
            minWidth=150,
            valueFormatter="value ? new Date(value).toLocaleString() : ''"
        )
        gb.configure_column(
            "Certificate",
            minWidth=200,
            flex=2
        )
        gb.configure_column(
            "Valid Until",
            type=["dateColumnFilter"],
            minWidth=150,
            valueFormatter="value ? new Date(value).toLocaleDateString() : ''",
            cellClass=JsCode("""
            function(params) {
                if (!params.data || !params.value) return ['ag-date-cell'];
                const today = new Date();
                const validUntil = new Date(params.value);
                if (validUntil < today) return ['ag-date-cell', 'ag-date-cell-expired'];
                return ['ag-date-cell'];
            }
            """)
        )
        gb.configure_column(
            "Serial Number",
            minWidth=150,
            flex=1
        )
        
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
            'headerHeight': 40
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
            key="scan_history_grid",
            height=600
        )

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
                "Updated": entry.updated_at,
                "_id": entry.id  # Add ID for selection handling
            })
        
        df = pd.DataFrame(tracking_data)
        
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
            "Change Number",
            minWidth=150,
            flex=1
        )
        gb.configure_column(
            "Planned Date",
            type=["dateColumnFilter"],
            minWidth=120,
            valueFormatter="value ? new Date(value).toLocaleDateString() : ''",
            cellClass=JsCode("""
            function(params) {
                if (!params.data) return ['ag-date-cell'];
                const today = new Date();
                const planned = new Date(params.value);
                if (planned < today) return ['ag-date-cell', 'ag-date-cell-expired'];
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
                if (params.value === 'Completed') return ['ag-status-valid'];
                if (params.value === 'Cancelled') return ['ag-status-expired'];
                if (params.value === 'Pending') return ['ag-status-warning'];
                return [];
            }
            """)
        )
        gb.configure_column(
            "Notes",
            minWidth=200,
            flex=2
        )
        gb.configure_column(
            "Created",
            type=["dateColumnFilter"],
            minWidth=150,
            valueFormatter="value ? new Date(value).toLocaleString() : ''"
        )
        gb.configure_column(
            "Updated",
            type=["dateColumnFilter"],
            minWidth=150,
            valueFormatter="value ? new Date(value).toLocaleString() : ''"
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
            'headerHeight': 40
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
            key=f"tracking_grid_{cert.id}",
            height=400
        )
    else:
        st.info("No change entries found for this certificate")
        
def render_cn_history(engine):
    """Render certificate history by Common Name"""
    with SessionManager(engine) as session:
        # Get all unique common names
        common_names = session.query(Certificate.common_name)\
            .distinct()\
            .order_by(Certificate.common_name)\
            .all()
        
        if not common_names:
            st.warning("No certificate data found")
            return
        
        # Create CN selection options
        cn_options = [cn[0] for cn in common_names if cn[0]]  # Filter out None values
        
        # CN selection
        selected_cn = st.selectbox(
            "Select Common Name",
            options=cn_options,
            index=None,
            placeholder="Choose a common name to view certificate history..."
        )
        
        if selected_cn:
            # Get all certificates with this CN
            certificates = session.query(Certificate)\
                .filter(Certificate.common_name == selected_cn)\
                .order_by(Certificate.valid_from.desc())\
                .all()
            
            if certificates:
                # Convert to DataFrame for display
                cert_history = []
                for cert in certificates:
                    # Get all bindings for this certificate
                    bindings = []
                    first_seen = None
                    last_seen = None
                    
                    for binding in cert.certificate_bindings:
                        host_name = binding.host.name if binding.host else "Unknown Host"
                        host_ip = binding.host_ip.ip_address if binding.host_ip else "No IP"
                        bindings.append(f"{host_name} ({host_ip})")
                        
                        # Track first and last seen
                        if binding.last_seen:
                            if first_seen is None or binding.last_seen < first_seen:
                                first_seen = binding.last_seen
                            if last_seen is None or binding.last_seen > last_seen:
                                last_seen = binding.last_seen
                    
                    cert_history.append({
                        "Serial Number": cert.serial_number,
                        "Valid From": cert.valid_from,
                        "Valid Until": cert.valid_until,
                        "First Seen": first_seen or "Never",
                        "Last Seen": last_seen or "Never",
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                        "Hosts": ", ".join(bindings) if bindings else "No Bindings",
                        "Thumbprint": cert.thumbprint,
                        "_id": cert.id
                    })
                
                df = pd.DataFrame(cert_history)
                
                # Display timeline of certificates
                st.subheader("Certificate Timeline")
                timeline_chart = {
                    "Certificate": [f"Cert {i+1}" for i in range(len(df))],
                    "Start": df["Valid From"].tolist(),
                    "End": df["Valid Until"].tolist()
                }
                st.plotly_chart(create_timeline_chart(timeline_chart))
                
                # Display metrics
                st.divider()
                metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)
                with metric_col1:
                    st.metric("Total Certificates", len(df))
                with metric_col2:
                    valid_certs = (df["Status"] == "Valid").sum()
                    st.metric("Valid Certificates", valid_certs)
                with metric_col3:
                    unique_hosts = len(set([host for hosts in df["Hosts"].str.split(", ") for host in hosts if host != "No Bindings"]))
                    st.metric("Unique Hosts", unique_hosts)
                with metric_col4:
                    active_certs = df["Last Seen"].apply(lambda x: x != "Never" and (isinstance(x, datetime) and (datetime.now() - x).days < 30)).sum()
                    st.metric("Active Certificates", active_certs, help="Certificates seen in the last 30 days")
                st.divider()
                
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
                        if (!params.data || !params.value) return ['ag-date-cell'];
                        const today = new Date();
                        const validUntil = new Date(params.value);
                        if (validUntil < today) return ['ag-date-cell', 'ag-date-cell-expired'];
                        return ['ag-date-cell'];
                    }
                    """)
                )
                gb.configure_column(
                    "First Seen",
                    type=["dateColumnFilter"],
                    minWidth=150,
                    valueFormatter=JsCode("""
                    function(params) {
                        if (!params.value || params.value === 'Never') return 'Never';
                        return new Date(params.value).toLocaleString();
                    }
                    """)
                )
                gb.configure_column(
                    "Last Seen",
                    type=["dateColumnFilter"],
                    minWidth=150,
                    valueFormatter=JsCode("""
                    function(params) {
                        if (!params.value || params.value === 'Never') return 'Never';
                        return new Date(params.value).toLocaleString();
                    }
                    """),
                    cellClass=JsCode("""
                    function(params) {
                        if (!params.value || params.value === 'Never') return ['ag-date-cell'];
                        const today = new Date();
                        const lastSeen = new Date(params.value);
                        const daysSince = Math.floor((today - lastSeen) / (1000 * 60 * 60 * 24));
                        if (daysSince > 30) return ['ag-date-cell', 'ag-date-cell-expired'];
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
                        if (params.value === 'Valid') return ['ag-status-valid'];
                        if (params.value === 'Expired') return ['ag-status-expired'];
                        return [];
                    }
                    """)
                )
                gb.configure_column(
                    "Hosts",
                    minWidth=300,
                    flex=2
                )
                gb.configure_column(
                    "Thumbprint",
                    minWidth=200,
                    flex=1
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
                    'headerHeight': 40
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
                    key="cn_history_grid",
                    height=400
                )
                
                # Handle selection to show certificate details
                if grid_response['selected_rows']:
                    selected = grid_response['selected_rows'][0]
                    cert_id = selected['_id']
                    selected_cert = next((c for c in certificates if c.id == cert_id), None)
                    
                    if selected_cert:
                        st.divider()
                        st.subheader("Certificate Details")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.json({
                                "Issuer": selected_cert.issuer,
                                "Subject": selected_cert.subject,
                                "Key Usage": selected_cert.key_usage,
                                "Signature Algorithm": selected_cert.signature_algorithm
                            })
                        with col2:
                            if selected_cert.san:
                                st.subheader("Subject Alternative Names")
                                try:
                                    san_list = selected_cert.san
                                    if isinstance(san_list, str):
                                        san_list = san_list.replace("'", "").replace("[", "").replace("]", "").split(",")
                                    san_list = [domain.strip(" '\"[]") for domain in san_list if domain and domain.strip()]
                                    for san in sorted(set(san_list)):
                                        st.text(san)
                                except Exception as e:
                                    st.error(f"Error parsing SANs: {str(e)}")
            else:
                st.info("No certificates found with this common name")

        