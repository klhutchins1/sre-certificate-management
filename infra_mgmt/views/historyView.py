"""
Certificate History View Module

This module provides a comprehensive interface for viewing and analyzing certificate history
in the certificate management system. It offers multiple perspectives on certificate history:

Views:
1. Common Name History - Track certificates by their common names over time
2. Scan History - View the history of certificate scans and their results
3. Host Certificate History - Monitor certificate changes on specific hosts

Key Features:
- Interactive timeline visualizations
- Detailed certificate history tracking
- Scan result analysis
- Host-based certificate monitoring
- Certificate change tracking
- Comprehensive filtering and sorting capabilities
- Real-time certificate status monitoring

The module uses Streamlit for the UI and Plotly for timeline visualizations,
providing an interactive and user-friendly interface for certificate history analysis.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
from ..models import Certificate, CertificateScan, Host, HostIP, CertificateBinding, CertificateTracking
from infra_mgmt.utils.SessionManager import SessionManager
from ..static.styles import load_warning_suppression, load_css
from ..services.HistoryService import HistoryService


def render_history_view(engine) -> None:
    """
    Render the main certificate history interface with multiple view options.

    This function creates a tabbed interface that provides different perspectives
    on certificate history:
    1. Common Name History - Track certificates by their common names
    2. Scan History - View certificate scan results
    3. Host Certificate History - Monitor certificates on specific hosts

    Args:
        engine: SQLAlchemy engine instance for database connections

    The view uses tabs to organize different aspects of certificate history,
    allowing users to switch between different views while maintaining a clean
    and organized interface.
    """
    # Initialize UI components and styles
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

def render_host_certificate_history(engine) -> None:
    """
    Render the certificate history view for specific hosts.

    This function provides a detailed view of certificate history for individual hosts,
    including:
    - Timeline visualization of certificates
    - Detailed certificate information
    - Certificate validity tracking
    - Port and platform information
    - Last seen timestamps

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Host selection with IP address information
        - Interactive timeline visualization
        - Detailed certificate history in tabular format
        - Real-time certificate status monitoring
        - Certificate validity period tracking
    """
    result = HistoryService.get_host_certificate_history(engine)
    if not result['success']:
        st.warning(result['error'])
        return
    hosts = result['data']['hosts']
    host_options = result['data']['host_options']
    selected_host = st.selectbox(
        "Select Host",
        options=list(host_options.keys()),
        index=None,
        placeholder="Choose a host to view certificate history..."
    )
    if selected_host:
        host_id, ip_id = host_options[selected_host]
        bindings = HistoryService.get_bindings_for_host(engine, host_id, ip_id)
        if bindings:
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
            st.subheader("Certificate Timeline")
            timeline_chart = {
                "Certificate": df["Certificate"].tolist(),
                "Start": df["Valid From"].tolist(),
                "End": df["Valid Until"].tolist()
            }
            st.plotly_chart(create_timeline_chart(timeline_chart))
            st.subheader("Detailed History")
            st.dataframe(
                df,
                column_config={
                    "Certificate": st.column_config.TextColumn("Certificate", width="medium"),
                    "Serial Number": st.column_config.TextColumn("Serial Number", width="medium"),
                    "Valid From": st.column_config.DatetimeColumn("Valid From", format="DD/MM/YYYY"),
                    "Valid Until": st.column_config.DatetimeColumn("Valid Until", format="DD/MM/YYYY"),
                    "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="DD/MM/YYYY HH:mm"),
                    "Port": st.column_config.NumberColumn("Port", width="small"),
                    "Platform": st.column_config.TextColumn("Platform", width="small"),
                    "Status": st.column_config.TextColumn("Status", width="small")
                },
                hide_index=True,
                use_container_width=True
            )
        else:
            st.info("No certificate history found for this host")

def create_timeline_chart(data: dict) -> "plotly.graph_objs._figure.Figure":
    """
    Create an interactive timeline visualization using Plotly.

    This function generates a Gantt chart showing certificate validity periods,
    allowing users to visualize certificate lifespans and overlaps.

    Args:
        data: Dictionary containing timeline data with the following keys:
            - Certificate: List of certificate names/identifiers
            - Start: List of validity start dates
            - End: List of validity end dates

    Returns:
        plotly.Figure: A Plotly figure object containing the timeline visualization

    Features:
        - Interactive timeline with zoom and pan capabilities
        - Color-coded certificate periods
        - Automatic height adjustment based on number of certificates
        - Grid lines for better date reference
        - Grouped certificates for better organization
    """
    import plotly.figure_factory as ff
    import plotly.express as px
    
    # Prepare timeline data structure
    df_timeline = []
    for i, (cert, start, end) in enumerate(zip(data["Certificate"], data["Start"], data["End"])):
        df_timeline.append(dict(
            Task=cert,
            Start=start,
            Finish=end,
            Resource="Certificate"
        ))
    
    # Create the Gantt chart
    fig = ff.create_gantt(
        df_timeline,
        index_col='Resource',
        show_colorbar=True,
        group_tasks=True,
        showgrid_x=True,
        showgrid_y=True
    )
    
    # Configure chart layout
    fig.update_layout(
        title="Certificate Timeline",
        height=200 + (len(data["Certificate"]) * 30),
        xaxis_title="Date",
        showlegend=False
    )
    
    return fig

def render_scan_history(engine) -> None:
    """
    Render the certificate scan history interface.

    This function provides a comprehensive view of certificate scan results,
    including filtering capabilities, metrics, and detailed scan information.

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Time period filtering (24h, 7d, 30d, All time)
        - Status-based filtering
        - Host-based filtering
        - Key metrics display:
            - Total scans
            - Success rate
            - Unique hosts
        - Interactive data grid with:
            - Sorting capabilities
            - Column filtering
            - Status highlighting
            - Date formatting
            - Certificate validity indicators

    The view provides a detailed analysis of scan results, helping users
    track certificate scanning activities and identify potential issues.
    """
    with SessionManager(engine) as session:
        scans = HistoryService.get_scan_history(session)
        if not scans:
            st.warning("No scan history found")
            return
        scan_data = []
        for scan in scans:
            if scan.host:
                host_display = scan.host.name
                if scan.host.ip_addresses:
                    ip_addresses = [ip.ip_address for ip in scan.host.ip_addresses]
                    if ip_addresses:
                        host_display = f"{host_display} ({', '.join(ip_addresses)})"
            else:
                host_display = "Unknown Host"
            data = {
                "Scan Date": scan.scan_date,
                "Status": scan.status,
                "Port": scan.port,
                "Host": host_display,
            }
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
        
        # Filtering interface
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Time period filter
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
        
        # Display key metrics
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
        
        # Configure and display data grid
        gb = GridOptionsBuilder.from_dataframe(df)
        
        # Configure default column settings
        gb.configure_default_column(
            resizable=True,
            sortable=True,
            filter=True,
            editable=False
        )
        
        # Configure individual columns
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

def render_certificate_tracking(cert: Certificate, session: Session) -> None:
    """
    Render the certificate tracking interface for change management.

    This function provides an interface for tracking and managing changes
    related to a specific certificate, including planned changes, updates,
    and historical tracking entries.

    Args:
        cert: Certificate model instance to display tracking information for
        session: SQLAlchemy session for database operations

    Features:
        - Add new change/tracking entries
        - Track change numbers/tickets
        - Manage planned change dates
        - Monitor change status (Pending/Completed/Cancelled)
        - Add detailed change notes
        - View change history in an interactive grid
        - Real-time status indicators
        - Automatic timestamp tracking

    The interface helps maintain a complete audit trail of certificate-related
    changes and planned activities.
    """
    # Header section with add button
    col1, col2 = st.columns([0.7, 0.3])
    
    with col1:
        st.subheader("Change History")
    with col2:
        if st.button("➕ Add Change Entry", type="primary", use_container_width=True):
            st.session_state.show_tracking_entry = True
            st.session_state.editing_cert_id = cert.id
    
    # Change entry form
    if st.session_state.get('show_tracking_entry', False) and st.session_state.get('editing_cert_id') == cert.id:
        with st.form("tracking_entry_form"):
            st.subheader("Add Change Entry")
            
            # Form input fields
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
            
            # Form submission handling
            submitted = st.form_submit_button("Save Entry")
            if submitted:
                result = HistoryService.add_certificate_tracking_entry(
                    session,
                    cert.id,
                    change_number,
                    planned_date,
                    status,
                    notes
                )
                if result['success']:
                    st.success("Change entry added!")
                    st.session_state.show_tracking_entry = False
                    st.rerun()
                else:
                    st.error(f"Error saving change entry: {result['error']}")
    
    # Display existing tracking entries
    if cert.tracking_entries:
        # Prepare tracking data for display
        tracking_data = []
        for entry in cert.tracking_entries:
            tracking_data.append({
                "Change Number": entry.change_number,
                "Planned Date": entry.planned_change_date,
                "Status": entry.status,
                "Notes": entry.notes,
                "Created": entry.created_at,
                "Updated": entry.updated_at,
                "_id": entry.id
            })
        
        df = pd.DataFrame(tracking_data)
        
        # Configure data grid
        gb = GridOptionsBuilder.from_dataframe(df)
        
        # Configure default column settings
        gb.configure_default_column(
            resizable=True,
            sortable=True,
            filter=True,
            editable=False
        )
        
        # Configure individual columns
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
        
        # Configure grid selection
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
        
        # Display the tracking history grid
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
        
def render_cn_history(engine) -> None:
    """
    Render the certificate history view organized by Common Name (CN).

    This function provides a comprehensive view of certificate history for each
    unique Common Name in the system, including:
    - Timeline visualization of certificate validity periods
    - Detailed certificate information and metrics
    - Host binding information
    - Certificate status tracking
    - Detailed certificate properties

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Common Name selection interface
        - Interactive timeline visualization
        - Key metrics display:
            - Total certificates
            - Valid certificates
            - Unique hosts
            - Active certificates
        - Detailed certificate information:
            - Serial numbers
            - Validity periods
            - Host bindings
            - Certificate status
        - Certificate details view:
            - Issuer information
            - Subject details
            - Key usage
            - Signature algorithm
            - Subject Alternative Names (SANs)
    """
    with SessionManager(engine) as session:
        cn_options = HistoryService.get_cn_history(session)
        if not cn_options:
            st.warning("No certificate data found")
            return
        selected_cn = st.selectbox(
            "Select Common Name",
            options=cn_options,
            index=None,
            placeholder="Choose a common name to view certificate history..."
        )
        if selected_cn:
            certificates = HistoryService.get_certificates_by_cn(session, selected_cn)
            if certificates:
                # Prepare certificate history data
                cert_history = []
                for cert in certificates:
                    # Process certificate bindings
                    bindings = []
                    first_seen = None
                    last_seen = None
                    
                    for binding in cert.certificate_bindings:
                        host_name = binding.host.name if binding.host else "Unknown Host"
                        host_ip = binding.host_ip.ip_address if binding.host_ip else "No IP"
                        bindings.append(f"{host_name} ({host_ip})")
                        
                        # Track first and last seen dates
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
                
                # Display certificate timeline
                st.subheader("Certificate Timeline")
                timeline_chart = {
                    "Certificate": [f"Cert {i+1}" for i in range(len(df))],
                    "Start": df["Valid From"].tolist(),
                    "End": df["Valid Until"].tolist()
                }
                st.plotly_chart(create_timeline_chart(timeline_chart))
                
                # Display key metrics
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
                
                # Configure and display certificate history grid
                gb = GridOptionsBuilder.from_dataframe(df)
                
                # Configure default column settings
                gb.configure_default_column(
                    resizable=True,
                    sortable=True,
                    filter=True,
                    editable=False
                )
                
                # Configure individual columns
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
                
                # Configure grid selection
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
                
                # Display the certificate history grid
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
                
                # Handle certificate selection for detailed view
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

        