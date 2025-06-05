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
                st.session_state.show_add_app_form = False
                notify("✅ Application added successfully!", "success", page_key=APPLICATIONS_PAGE_KEY)
            else:
                notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
    except Exception as e:
        logger.exception(f"Error adding application: {str(e)}")
        notify(f"Error adding application: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)

def toggle_add_form():
    """Toggle the add application form visibility."""
    st.session_state.show_add_app_form = not st.session_state.show_add_app_form
    st.rerun()

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
                if st.form_submit_button("Add Application", type="primary", on_click=handle_add_form):
                    pass

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
            # Only include columns with data
            display_columns = [col for col in df.columns if not df[col].isnull().all() and col != '_id']
            df_display = df[display_columns]
            gb = GridOptionsBuilder.from_dataframe(df_display)
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
                use_checkbox=False
            )
            for col in display_columns:
                gb.configure_column(col, minWidth=120, flex=1)
            gb.configure_grid_options(
                domLayout='normal',
                enableRangeSelection=True,
                pagination=True,
                paginationPageSize=10,
                paginationAutoPageSize=False,
                suppressRowClickSelection=False,
                rowSelection='single'
            )
            grid_options = gb.build()
            grid_response = AgGrid(
                df_display,
                gridOptions=grid_options,
                height=400,
                data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                update_mode=GridUpdateMode.SELECTION_CHANGED | GridUpdateMode.VALUE_CHANGED,
                fit_columns_on_grid_load=True,
                allow_unsafe_jscode=False,
                theme='streamlit',
                key=f"applications_grid_{view_type}"
            )
            if grid_response:
                try:
                    selected_rows = grid_response.get('selected_rows', None)
                    if isinstance(selected_rows, pd.DataFrame) and not selected_rows.empty:
                        if '_id' not in selected_rows.columns:
                            return
                        row_dict = selected_rows.iloc[0].to_dict()
                        selected_app_id = row_dict.get('_id')
                        if selected_app_id:
                            with SessionManager(engine) as session:
                                selected_app = session.query(Application).get(selected_app_id)
                                if selected_app:
                                    st.divider()
                                    st.session_state['current_app'] = selected_app
                                    render_application_details(selected_app)
                                else:
                                    logger.warning(f"No application found for ID: {selected_app_id}")
                                    notify("Application not found", "error", page_key=APPLICATIONS_PAGE_KEY)
                except Exception as e:
                    logger.exception(f"Error handling grid selection: {str(e)}")
                    clear_page_notifications(APPLICATIONS_PAGE_KEY) # Clear existing before showing new error
                    notify("Error displaying application details. Please try again.", "error", page_key=APPLICATIONS_PAGE_KEY)
    except Exception as e:
        logger.exception(f"Error rendering applications view: {str(e)}")
        notify(f"Error rendering applications view: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
    # show_notifications(APPLICATIONS_PAGE_KEY) # Removed, will show via placeholder on rerun

def render_application_details(application: Application) -> None:
    """
    Render a detailed view for a specific application.

    This function creates a tabbed interface showing detailed information about
    an application, including:
    - Basic application information (name, type, description, owner)
    - Certificate metrics and status
    - Certificate expiration visualization
    - Certificate binding management

    Args:
        application: Application model instance to display details for
    """
    if not application:
        return
    st.session_state.current_app = application
    # clear_page_notifications(APPLICATIONS_PAGE_KEY) # Clear if switching detail view, or on action
    details_container = st.container()
    with details_container:
        st.subheader(f"📱 {application.name}")
        tab1, tab2, tab3 = st.tabs(["Overview", "Certificate Bindings", "⚠️ Danger Zone"])
        with tab1:
            st.markdown(f"""
                **Type:** {app_types.get(application.app_type, application.app_type)}  
                **Description:** {application.description or 'No description'}  
                **Owner:** {application.owner or 'Not specified'}  
                **Created:** {application.created_at.strftime('%Y-%m-%d')}
            """)
            with st.expander("Edit Application"):
                with st.form("edit_application"):
                    st.text_input("Name", value=application.name, key="new_name")
                    st.selectbox("Type", options=APP_TYPES, index=APP_TYPES.index(application.app_type), key="new_type")
                    st.text_input("Description", value=application.description or '', key="new_description")
                    st.text_input("Owner", value=application.owner or '', key="new_owner")
                    if st.form_submit_button("Update Application", type="primary", on_click=handle_update_form):
                        pass
        with tab2:
            st.markdown("### Current Certificate Bindings")
            if application.certificate_bindings:
                for binding in application.certificate_bindings:
                    with st.container():
                        cols = st.columns([4, 1])
                        with cols[0]:
                            st.write(f"**Certificate:** {binding.certificate.common_name}")
                            st.write(f"**Valid Until:** {binding.certificate.valid_until.strftime('%Y-%m-%d')}")
                            if binding.host and binding.host.name:
                                st.write(f"**Host:** {binding.host.name}")
                            if binding.host_ip and binding.host_ip.ip_address:
                                st.write(f"**IP:** {binding.host_ip.ip_address}")
                            if binding.port:
                                st.write(f"**Port:** {binding.port}")
                            if binding.platform:
                                st.write(f"**Platform:** {binding.platform}")
                            st.write(f"**Usage:** {BINDING_TYPE_DISPLAY.get(binding.binding_type, 'Unknown Type')}")
                        with cols[1]:
                            # Use a unique key for each dialog state
                            dialog_key = f"show_delete_binding_dialog_{binding.id}"
                            if st.button("🗑️", key=f"delete_{binding.id}", help="Remove this binding"):
                                st.session_state[dialog_key] = True
                            if st.session_state.get(dialog_key, False):
                                def on_delete_binding(_):
                                    engine = st.session_state.get('engine')
                                    if engine:
                                        result = ApplicationService.remove_binding(engine, binding.id)
                                        if result['success']:
                                            notify("Certificate binding removed", "success", page_key=APPLICATIONS_PAGE_KEY)
                                            st.session_state[dialog_key] = False
                                            st.rerun()
                                        else:
                                            notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
                                            st.session_state[dialog_key] = False
                                    else:
                                        notify("Engine not available", "error", page_key=APPLICATIONS_PAGE_KEY)
                                        st.session_state[dialog_key] = False
                                    return True
                                render_danger_zone(
                                    title="Delete Certificate Binding",
                                    entity_name=binding.certificate.common_name,
                                    entity_type="certificate binding",
                                    dependencies={},
                                    on_delete=on_delete_binding,
                                    session=None,
                                    custom_warning=f"This will remove the binding for certificate '{binding.certificate.common_name}'."
                                )
                        st.divider()
            else:
                notify("No certificate bindings found for this application.", "info", page_key=APPLICATIONS_PAGE_KEY)
            st.markdown("### Add Certificate Bindings")
            available_certs = []
            try:
                # Fetch available certificates for binding
                engine = st.session_state.get('engine')
                if engine:
                    result = ApplicationService.get_available_certificates(engine, application.id)
                    if result['success']:
                        available_certs = result['data']
                    else:
                        notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
                if available_certs:
                    cert_options = {
                        f"{cert.common_name} (Valid until: {cert.valid_until.strftime('%Y-%m-%d')})": cert.id
                        for cert in available_certs
                    }
                    binding_type = st.selectbox(
                        "Binding Type",
                        options=["IP-Based", "JWT-Based", "Client Certificate"],
                        help="How will this certificate be used?"
                    )
                    binding_type_map = {
                        "IP-Based": "IP",
                        "JWT-Based": "JWT",
                        "Client Certificate": "CLIENT"
                    }
                    selected_certs = st.multiselect(
                        "Select Certificates to Bind",
                        options=list(cert_options.keys()),
                        help="Select one or more certificates to bind to this application"
                    )
                    if selected_certs:
                        if st.button("Bind Selected Certificates", type="primary"):
                            try:
                                cert_ids = [cert_options[cert_name] for cert_name in selected_certs]
                                result = ApplicationService.bind_certificates(
                                    engine,
                                    application.id,
                                    cert_ids,
                                    binding_type_map[binding_type]
                                )
                                if result['success']:
                                    notify(f"{result['count']} certificate(s) bound successfully!", "success", page_key=APPLICATIONS_PAGE_KEY)
                                else:
                                    notify(result['error'], "error", page_key=APPLICATIONS_PAGE_KEY)
                            except Exception as e:
                                logger.exception(f"Error binding certificates: {str(e)}")
                                notify(f"Error binding certificates: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
                else:
                    notify("No available certificates found to bind.", "info", page_key=APPLICATIONS_PAGE_KEY)
            except Exception as e:
                logger.exception(f"Error loading available certificates: {str(e)}")
                notify(f"Error loading available certificates: {str(e)}", "error", page_key=APPLICATIONS_PAGE_KEY)
        with tab3:
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