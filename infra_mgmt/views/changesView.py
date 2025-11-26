"""
Changes View Module

This module provides a centralized interface for tracking infrastructure changes
related to certificates. It builds on the existing per-certificate tracking
(`CertificateTracking`) and adds:

- Global list of change entries across all certificates
- Visibility into affected domains, IP addresses, platforms, and host types
- Time-bounded scan actions that navigate to the Scanner view with
  pre-populated targets (similar to SAN scanning from the Certificates view)

The goal is to allow users to:
- Register a change (via certificate views or this page)
- See all bindings (domains/IPs) affected by that change
- Run scans around the time of the change to validate before/after state
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Set

import pandas as pd
import streamlit as st
from sqlalchemy.orm import joinedload

from ..models import CertificateTracking, Certificate, CertificateBinding, Host, HostIP, CertificateScan
from infra_mgmt.utils.SessionManager import SessionManager
from ..static.styles import load_warning_suppression, load_css
from infra_mgmt.components.page_header import render_page_header
from ..notifications import (
    initialize_page_notifications,
    show_notifications,
    notify,
)
from ..services.HistoryService import HistoryService
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode

CHANGES_PAGE_KEY = "changes"  # Define page key

# How far from the planned change date scans are allowed (in days)
CHANGE_SCAN_WINDOW_DAYS = 30


def _build_change_dataframe(entries: List[CertificateTracking]) -> pd.DataFrame:
    """Build a flat dataframe for the changes list grid."""
    rows: List[Dict[str, Any]] = []

    for entry in entries:
        cert: Certificate = entry.certificate
        
        # Aggregate simple summary info for bindings (only if certificate exists)
        hostnames: Set[str] = set()
        ip_addrs: Set[str] = set()
        platforms: Set[str] = set()
        host_types: Set[str] = set()

        if cert:
            for binding in cert.certificate_bindings:
                host: Host = binding.host
                host_ip: HostIP = binding.host_ip

                if host and host.name:
                    hostnames.add(host.name)
                    if getattr(host, "host_type", None):
                        host_types.add(host.host_type)
                if host_ip and host_ip.ip_address:
                    ip_addrs.add(host_ip.ip_address)

                if binding.platform:
                    platforms.add(binding.platform)

        planned = entry.planned_change_date
        rows.append(
            {
                "Change Number": entry.change_number or "",
                "Certificate": cert.common_name if cert else "(No certificate assigned)",
                "Planned Date": planned,
                "Status": entry.status or "",
                "Hosts": ", ".join(sorted(hostnames)) if hostnames else "",
                "IPs": ", ".join(sorted(ip_addrs)) if ip_addrs else "",
                "Platforms": ", ".join(sorted(platforms)) if platforms else "",
                "Host Types": ", ".join(sorted(host_types)) if host_types else "",
                "Created": entry.created_at,
                "Updated": entry.updated_at,
                "_id": entry.id,
            }
        )

    if not rows:
        return pd.DataFrame(
            columns=[
                "Change Number",
                "Certificate",
                "Planned Date",
                "Status",
                "Hosts",
                "IPs",
                "Platforms",
                "Host Types",
                "Created",
                "Updated",
                "_id",
            ]
        )

    return pd.DataFrame(rows)


def _build_scan_targets(cert: Certificate) -> List[str]:
    """
    Build scan targets for a certificate based on its bindings.

    Targets are in the form 'hostname:port' or 'ip:port' and mirror the patterns used
    by the Hosts and Applications views when sending users to the Scanner page.
    Prefers hostname over IP when both are available, but includes both if they differ.
    """
    targets: List[str] = []
    seen: Set[str] = set()

    for binding in cert.certificate_bindings:
        host: Host = binding.host
        host_ip: HostIP = binding.host_ip
        port = binding.port or 443

        # Prefer hostname over IP (matches CertificateService pattern)
        # Include both hostname and IP if both are available and different
        if host and host.name:
            hostname_target = f"{host.name}:{port}"
            if hostname_target not in seen:
                seen.add(hostname_target)
                targets.append(hostname_target)
        
        # Also include IP if available and different from hostname
        if host_ip and host_ip.ip_address:
            ip_target = f"{host_ip.ip_address}:{port}"
            if ip_target not in seen:
                seen.add(ip_target)
                targets.append(ip_target)

    # Fallback: use SANs as generic domain targets if no bindings exist
    if not targets and getattr(cert, "san", None):
        for san in cert.san:
            if san and isinstance(san, str):
                target = f"{san}:443"
                if target not in seen:
                    seen.add(target)
                    targets.append(target)

    return targets


def _is_within_scan_window(entry: CertificateTracking) -> bool:
    """Check whether the current time is within the allowed scan window."""
    if not entry.planned_change_date:
        # If no planned date is set, allow scans (cannot enforce proximity)
        return True

    now = datetime.now()
    delta = abs((now - entry.planned_change_date).days)
    return delta <= CHANGE_SCAN_WINDOW_DAYS


def render_changes_view(engine) -> None:
    """
    Render the global Changes view.

    This view surfaces all `CertificateTracking` entries and provides:
    - A grid of changes across all certificates
    - Detail view for the selected change with domains/IPs, platforms, host types
    - A scan action that navigates to the Scanner page with pre-populated
      targets, restricted to a configurable window around the planned change date.
    """
    load_warning_suppression()
    load_css()
    initialize_page_notifications(CHANGES_PAGE_KEY)

    notification_placeholder = st.empty()

    with notification_placeholder.container():
        show_notifications(CHANGES_PAGE_KEY)

    # Toggle for add form
    def toggle_add_change_form():
        st.session_state['show_add_change_form'] = not st.session_state.get('show_add_change_form', False)

    render_page_header(
        title="Changes",
        button_label="➕ Add Change" if not st.session_state.get('show_add_change_form', False) else "❌ Cancel",
        button_callback=toggle_add_change_form,
        button_type="primary" if not st.session_state.get('show_add_change_form', False) else "secondary"
    )

    # Show add change form if button was clicked
    if st.session_state.get('show_add_change_form', False):
        _render_add_change_form(engine)
        return  # Prevent rendering the rest of the page when the form is shown

    # Load all tracking entries with related certificate/binding/host info
    with SessionManager(engine) as session:
        entries: List[CertificateTracking] = (
            session.query(CertificateTracking)
            .options(
                joinedload(CertificateTracking.certificate)
                .joinedload(Certificate.certificate_bindings)
                .joinedload(CertificateBinding.host)
                .joinedload(Host.ip_addresses),
                joinedload(CertificateTracking.certificate)
                .joinedload(Certificate.certificate_bindings)
                .joinedload(CertificateBinding.host_ip),
            )
            .order_by(
                CertificateTracking.planned_change_date.desc().nullslast(),
                CertificateTracking.created_at.desc(),
            )
            .all()
        )

    df = _build_change_dataframe(entries)

    if df.empty:
        notify("No change entries found. Add changes from the Certificates page.", "info", page_key=CHANGES_PAGE_KEY)
        return

    # Optional filters
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.selectbox(
            "Status",
            options=["All", "Pending", "Completed", "Cancelled"],
            index=0,
        )
    with col2:
        time_filter = st.selectbox(
            "Time Window",
            options=[
                "All",
                "Within Scan Window",
                "Last 7 Days",
                "Last 30 Days",
            ],
            index=1,
            help="Use 'Within Scan Window' to see changes that are currently eligible for scanning.",
        )
    with col3:
        cert_filter = st.text_input(
            "Filter by Certificate/Common Name",
            placeholder="Contains text...",
        )

    filtered_df = df.copy()

    if status_filter != "All":
        filtered_df = filtered_df[filtered_df["Status"] == status_filter]

    now = datetime.now()
    if time_filter == "Within Scan Window":
        ids_in_window: Set[int] = set()
        for entry in entries:
            if _is_within_scan_window(entry):
                ids_in_window.add(entry.id)
        filtered_df = filtered_df[filtered_df["_id"].isin(ids_in_window)]
    elif time_filter in {"Last 7 Days", "Last 30 Days"}:
        days = 7 if time_filter == "Last 7 Days" else 30
        cutoff = now - timedelta(days=days)
        filtered_df = filtered_df[
            (filtered_df["Planned Date"].notnull())
            & (filtered_df["Planned Date"] >= cutoff)
        ]

    if cert_filter:
        mask = filtered_df["Certificate"].str.contains(cert_filter, case=False, na=False)
        filtered_df = filtered_df[mask]

    if filtered_df.empty:
        notify("No changes match the selected filters.", "info", page_key=CHANGES_PAGE_KEY)
        return

    # Configure grid
    gb = GridOptionsBuilder.from_dataframe(filtered_df)
    gb.configure_default_column(
        resizable=True,
        sortable=True,
        filter=True,
        editable=False,
    )
    gb.configure_column("Change Number", minWidth=150, flex=1)
    gb.configure_column("Certificate", minWidth=200, flex=2)
    gb.configure_column(
        "Planned Date",
        type=["dateColumnFilter"],
        minWidth=150,
        valueFormatter="value ? new Date(value).toLocaleString() : ''",
        cellClass=JsCode(
            """
            function(params) {
                if (!params.data || !params.value) return ['ag-date-cell'];
                const today = new Date();
                const planned = new Date(params.value);
                if (planned < today) return ['ag-date-cell', 'ag-date-cell-expired'];
                return ['ag-date-cell'];
            }
            """
        ),
    )
    gb.configure_column("Status", minWidth=120)
    gb.configure_column("Hosts", minWidth=200, flex=2)
    gb.configure_column("IPs", minWidth=200, flex=2)
    gb.configure_column("Platforms", minWidth=150, flex=1)
    gb.configure_column("Host Types", minWidth=150, flex=1)
    gb.configure_column(
        "Created",
        type=["dateColumnFilter"],
        minWidth=150,
        valueFormatter="value ? new Date(value).toLocaleString() : ''",
    )
    gb.configure_column(
        "Updated",
        type=["dateColumnFilter"],
        minWidth=150,
        valueFormatter="value ? new Date(value).toLocaleString() : ''",
    )
    gb.configure_column("_id", hide=True)

    gb.configure_selection(
        selection_mode="single",
        use_checkbox=False,
        pre_selected_rows=[],
    )

    grid_options = {
        "animateRows": True,
        "enableRangeSelection": True,
        "suppressAggFuncInHeader": True,
        "suppressMovableColumns": True,
        "rowHeight": 35,
        "headerHeight": 40,
        "domLayout": "normal",
        "pagination": True,
        "paginationPageSize": 15,
        "paginationAutoPageSize": False,
    }
    gb.configure_grid_options(**grid_options)
    gridOptions = gb.build()

    grid_response = AgGrid(
        filtered_df,
        gridOptions=gridOptions,
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
        fit_columns_on_grid_load=True,
        theme="streamlit",
        allow_unsafe_jscode=True,
        key="changes_grid",
        height=500,
    )

    # Selection handling
    selected_rows = grid_response.get("selected_rows", [])
    selected_id = None
    if isinstance(selected_rows, pd.DataFrame):
        if not selected_rows.empty:
            row = selected_rows.iloc[0].to_dict()
            selected_id = row.get("_id")
    elif isinstance(selected_rows, list) and selected_rows:
        row = selected_rows[0]
        if isinstance(row, dict):
            selected_id = row.get("_id")

    if not selected_id:
        return

    # Find the underlying tracking entry
    entry = next((e for e in entries if e.id == selected_id), None)
    if not entry:
        return

    cert = entry.certificate
    st.divider()
    st.subheader(f"Change Details – {entry.change_number or '(unnamed change)'}")

    # Edit button for pending changes
    is_pending = entry.status == 'Pending'
    if is_pending:
        edit_key = f"edit_change_{entry.id}"
        if st.session_state.get(edit_key, False):
            _render_edit_change_form(entry, engine)
            return
        else:
            if st.button("✏️ Edit Change", key=edit_key, type="secondary", use_container_width=False):
                st.session_state[edit_key] = True
                st.rerun()

    col1, col2 = st.columns(2)
    with col1:
        if cert:
            st.markdown(f"**Certificate:** {cert.common_name or 'N/A'}")
            st.markdown(f"**Serial Number:** `{cert.serial_number}`")
        else:
            st.markdown("**Certificate:** *Not assigned yet*")
            st.info("💡 This change doesn't have a certificate assigned. You can assign one by editing this change (if status is Pending).")
        st.markdown(
            f"**Planned Date:** {entry.planned_change_date.strftime('%Y-%m-%d %H:%M') if entry.planned_change_date else 'Not set'}"
        )
        st.markdown(f"**Status:** {entry.status or 'N/A'}")
    with col2:
        st.markdown(
            f"**Created:** {entry.created_at.strftime('%Y-%m-%d %H:%M') if entry.created_at else 'N/A'}"
        )
        st.markdown(
            f"**Updated:** {entry.updated_at.strftime('%Y-%m-%d %H:%M') if entry.updated_at else 'N/A'}"
        )
        if entry.notes:
            st.markdown("**Notes:**")
            st.write(entry.notes)

    # Only show bindings and scan if certificate exists
    if cert:
        # Detailed bindings section
        st.markdown("### Affected Bindings")
        binding_rows: List[Dict[str, Any]] = []
        for binding in cert.certificate_bindings:
            host: Host = binding.host
            host_ip: HostIP = binding.host_ip

            environments: List[str] = []
            host_type = getattr(host, "host_type", None) if host else None
            if host and getattr(host, "environment", None):
                environments.append(host.environment)

            binding_rows.append(
                {
                    "Hostname": host.name if host and host.name else "",
                    "IP Address": host_ip.ip_address if host_ip and host_ip.ip_address else "",
                    "Port": str(binding.port) if binding.port else "",
                    "Platform": binding.platform or "",
                    "Host Type": host_type or "",
                    "Environment": ", ".join(sorted(set(environments))) if environments else "",
                }
            )

        if binding_rows:
            bindings_df = pd.DataFrame(binding_rows)
            st.dataframe(
                bindings_df,
                hide_index=True,
                use_container_width=True,
            )
        else:
            st.info("No bindings found for this certificate. Scan targets will be derived from SANs if available.")

        # Scan controls
        st.markdown("### Scan This Change")

        in_window = _is_within_scan_window(entry)
        if not in_window and entry.planned_change_date:
            notify(
                f"Scans for this change are restricted to ±{CHANGE_SCAN_WINDOW_DAYS} days "
                f"around the planned date. Planned date: {entry.planned_change_date.strftime('%Y-%m-%d')}",
                "warning",
                page_key=CHANGES_PAGE_KEY,
            )

        scan_targets = _build_scan_targets(cert)
        if scan_targets:
            with st.expander("View Scan Targets", expanded=False):
                st.text("\n".join(sorted(scan_targets)))

            col_left, col_mid, col_right = st.columns([2, 1, 1])
            with col_left:
                st.caption(
                    f"Scans are allowed within ±{CHANGE_SCAN_WINDOW_DAYS} days of the planned change date "
                    "(or anytime if no planned date is set)."
                )
            with col_mid:
                if st.button("📊 Scan Before", type="primary", disabled=not in_window, key=f"scan_before_{entry.id}"):
                    if not in_window and entry.planned_change_date:
                        notify(
                            "This change is outside the allowed scan window and cannot be scanned anymore.",
                            "error",
                            page_key=CHANGES_PAGE_KEY,
                        )
                    else:
                        # Send targets to Scanner view with change context
                        st.session_state.scan_targets = sorted(scan_targets)
                        st.session_state.scan_change_id = entry.id
                        st.session_state.scan_type = "before"
                        st.session_state.current_view = "Scanner"
                        st.rerun()
            with col_right:
                if st.button("📊 Scan After", type="primary", disabled=not in_window, key=f"scan_after_{entry.id}"):
                    if not in_window and entry.planned_change_date:
                        notify(
                            "This change is outside the allowed scan window and cannot be scanned anymore.",
                            "error",
                            page_key=CHANGES_PAGE_KEY,
                        )
                    else:
                        # Send targets to Scanner view with change context
                        st.session_state.scan_targets = sorted(scan_targets)
                        st.session_state.scan_change_id = entry.id
                        st.session_state.scan_type = "after"
                        st.session_state.current_view = "Scanner"
                        st.rerun()
        else:
            st.info("No scan targets could be derived from bindings or SANs.")
    
    # Show before/after scan results (works even without certificate)
    _render_change_scan_results(entry, engine)


def _render_add_change_form(engine) -> None:
    """
    Render the form to add a new change entry.
    
    This form allows users to:
    - Optionally select a certificate (can be None if certificate doesn't exist yet)
    - Enter change number, planned date, status, and notes
    - Create a new tracking entry
    """
    st.subheader("Add New Change Entry")
    
    # Load certificates outside the form for the selectbox
    with SessionManager(engine) as session:
        certificates = session.query(Certificate).order_by(Certificate.common_name).all()
        
        # Create certificate options with descriptive labels
        cert_options = {"None (Certificate not created yet)": None}
        for cert in certificates:
            status = "Valid" if cert.valid_until > datetime.now() else "Expired"
            label = f"{cert.common_name} (Serial: {cert.serial_number[:20]}..., {status})"
            cert_options[label] = cert.id
    
    with st.form("add_change_form"):
        # Form fields
        selected_cert_label = st.selectbox(
            "Certificate (Optional)",
            options=list(cert_options.keys()),
            help="Select the certificate this change relates to, or 'None' if the certificate doesn't exist yet"
        )
        
        cert_id = cert_options[selected_cert_label]
        
        col1, col2 = st.columns(2)
        with col1:
            change_number = st.text_input(
                "Change/Ticket Number",
                placeholder="e.g., CHG0012345",
                help="The change management ticket or change number"
            )
            planned_date = st.date_input(
                "Planned Change Date",
                help="When this change is planned to occur"
            )
        with col2:
            status = st.selectbox(
                "Change Status",
                options=["Pending", "Completed", "Cancelled"],
                index=0,
                help="Current status of this change"
            )
        
        notes = st.text_area(
            "Change Notes",
            placeholder="Enter any additional notes about this change...",
            help="Optional notes describing the change, affected systems, or other relevant information"
        )
        
        submitted = st.form_submit_button("Save Change Entry", type="primary")
        
        if submitted:
            # Validation
            if not change_number or not change_number.strip():
                notify("Change number is required", "error", page_key=CHANGES_PAGE_KEY)
                return
            
            # Create the tracking entry with a new session for the submission
            with SessionManager(engine) as session:
                result = HistoryService.add_certificate_tracking_entry(
                    session,
                    cert_id,
                    change_number.strip(),
                    planned_date,
                    status,
                    notes.strip() if notes else None
                )
                
                if result['success']:
                    notify("Change entry added successfully!", "success", page_key=CHANGES_PAGE_KEY)
                    st.session_state['show_add_change_form'] = False
                    st.rerun()
                else:
                    notify(f"Error saving change entry: {result.get('error', 'Unknown error')}", "error", page_key=CHANGES_PAGE_KEY)


def _render_edit_change_form(entry: CertificateTracking, engine) -> None:
    """
    Render the form to edit a change entry (only for Pending status).
    
    This form allows users to:
    - Change the certificate (if status is Pending)
    - Update change number, planned date, status, and notes
    """
    st.subheader(f"Edit Change Entry – {entry.change_number or '(unnamed change)'}")
    
    # Load certificates outside the form for the selectbox
    with SessionManager(engine) as session:
        certificates = session.query(Certificate).order_by(Certificate.common_name).all()
        
        # Create certificate options with descriptive labels
        cert_options = {"None (Certificate not created yet)": None}
        for cert in certificates:
            status = "Valid" if cert.valid_until > datetime.now() else "Expired"
            label = f"{cert.common_name} (Serial: {cert.serial_number[:20]}..., {status})"
            cert_options[label] = cert.id
        
        # Find current certificate label
        current_cert_label = "None (Certificate not created yet)"
        if entry.certificate_id:
            for label, cert_id in cert_options.items():
                if cert_id == entry.certificate_id:
                    current_cert_label = label
                    break
    
    with st.form("edit_change_form"):
        # Form fields
        selected_cert_label = st.selectbox(
            "Certificate",
            options=list(cert_options.keys()),
            index=list(cert_options.keys()).index(current_cert_label) if current_cert_label in cert_options else 0,
            help="Select the certificate this change relates to. Can be changed since status is Pending."
        )
        
        cert_id = cert_options[selected_cert_label]
        
        col1, col2 = st.columns(2)
        with col1:
            change_number = st.text_input(
                "Change/Ticket Number",
                value=entry.change_number or "",
                placeholder="e.g., CHG0012345",
                help="The change management ticket or change number"
            )
            planned_date = st.date_input(
                "Planned Change Date",
                value=entry.planned_change_date.date() if entry.planned_change_date else None,
                help="When this change is planned to occur"
            )
        with col2:
            status = st.selectbox(
                "Change Status",
                options=["Pending", "Completed", "Cancelled"],
                index=["Pending", "Completed", "Cancelled"].index(entry.status) if entry.status in ["Pending", "Completed", "Cancelled"] else 0,
                help="Current status of this change"
            )
        
        notes = st.text_area(
            "Change Notes",
            value=entry.notes or "",
            placeholder="Enter any additional notes about this change...",
            help="Optional notes describing the change, affected systems, or other relevant information"
        )
        
        col_submit, col_cancel = st.columns([1, 1])
        with col_submit:
            submitted = st.form_submit_button("💾 Save Changes", type="primary")
        with col_cancel:
            cancelled = st.form_submit_button("❌ Cancel", type="secondary")
        
        if cancelled:
            edit_key = f"edit_change_{entry.id}"
            st.session_state[edit_key] = False
            st.rerun()
        
        if submitted:
            # Validation
            if not change_number or not change_number.strip():
                notify("Change number is required", "error", page_key=CHANGES_PAGE_KEY)
                return
            
            # Update the tracking entry
            with SessionManager(engine) as session:
                result = HistoryService.update_tracking_entry(
                    session,
                    entry.id,
                    cert_id,
                    change_number.strip(),
                    planned_date,
                    status,
                    notes.strip() if notes else None
                )
                
                if result['success']:
                    notify("Change entry updated successfully!", "success", page_key=CHANGES_PAGE_KEY)
                    edit_key = f"edit_change_{entry.id}"
                    st.session_state[edit_key] = False
                    st.rerun()
                else:
                    notify(f"Error updating change entry: {result.get('error', 'Unknown error')}", "error", page_key=CHANGES_PAGE_KEY)


def _render_change_scan_results(entry: CertificateTracking, engine) -> None:
    """
    Render before/after scan results for a change entry.
    
    Shows scans that were performed before and after the change was implemented,
    allowing users to compare the state before and after.
    """
    st.markdown("### 📊 Scan Results")
    
    with SessionManager(engine) as session:
        # Load scans associated with this change
        before_scans = session.query(CertificateScan).filter(
            CertificateScan.change_id == entry.id,
            CertificateScan.scan_type == 'before'
        ).order_by(CertificateScan.scan_date.desc()).all()
        
        after_scans = session.query(CertificateScan).filter(
            CertificateScan.change_id == entry.id,
            CertificateScan.scan_type == 'after'
        ).order_by(CertificateScan.scan_date.desc()).all()
        
        if not before_scans and not after_scans:
            st.info("No scans have been performed for this change yet. Use the 'Scan Before' and 'Scan After' buttons above to record scans.")
            return
        
        # Display before scans
        if before_scans:
            st.markdown("#### 🔵 Before Change Scans")
            before_data = []
            for scan in before_scans:
                host_display = scan.host.name if scan.host else "Unknown"
                cert_display = scan.certificate.common_name if scan.certificate else "N/A"
                before_data.append({
                    "Scan Date": scan.scan_date.strftime('%Y-%m-%d %H:%M') if scan.scan_date else 'N/A',
                    "Host": host_display,
                    "Port": str(scan.port) if scan.port else 'N/A',
                    "Certificate": cert_display,
                    "Status": scan.status or 'N/A'
                })
            
            if before_data:
                before_df = pd.DataFrame(before_data)
                st.dataframe(before_df, hide_index=True, use_container_width=True)
        
        # Display after scans
        if after_scans:
            st.markdown("#### 🟢 After Change Scans")
            after_data = []
            for scan in after_scans:
                host_display = scan.host.name if scan.host else "Unknown"
                cert_display = scan.certificate.common_name if scan.certificate else "N/A"
                after_data.append({
                    "Scan Date": scan.scan_date.strftime('%Y-%m-%d %H:%M') if scan.scan_date else 'N/A',
                    "Host": host_display,
                    "Port": str(scan.port) if scan.port else 'N/A',
                    "Certificate": cert_display,
                    "Status": scan.status or 'N/A'
                })
            
            if after_data:
                after_df = pd.DataFrame(after_data)
                st.dataframe(after_df, hide_index=True, use_container_width=True)
        
        # Show comparison if both exist
        if before_scans and after_scans:
            st.markdown("#### 📈 Comparison")
            st.info(f"**Before scans:** {len(before_scans)} | **After scans:** {len(after_scans)}")
            
            # Simple comparison: show certificates found in before vs after
            before_certs = {scan.certificate.serial_number for scan in before_scans if scan.certificate}
            after_certs = {scan.certificate.serial_number for scan in after_scans if scan.certificate}
            
            if before_certs or after_certs:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**Certificates Before:**")
                    if before_certs:
                        for serial in sorted(before_certs):
                            cert = next((s.certificate for s in before_scans if s.certificate and s.certificate.serial_number == serial), None)
                            if cert:
                                st.markdown(f"- {cert.common_name} ({serial[:20]}...)")
                    else:
                        st.markdown("*None*")
                
                with col2:
                    st.markdown("**Certificates After:**")
                    if after_certs:
                        for serial in sorted(after_certs):
                            cert = next((s.certificate for s in after_scans if s.certificate and s.certificate.serial_number == serial), None)
                            if cert:
                                st.markdown(f"- {cert.common_name} ({serial[:20]}...)")
                    else:
                        st.markdown("*None*")
                
                # Show what changed
                added = after_certs - before_certs
                removed = before_certs - after_certs
                
                if added or removed:
                    st.markdown("**Changes Detected:**")
                    if added:
                        st.success(f"✅ {len(added)} new certificate(s) found after change")
                    if removed:
                        st.warning(f"⚠️ {len(removed)} certificate(s) no longer found after change")


