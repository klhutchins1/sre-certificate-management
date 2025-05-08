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
from ..db import SessionManager
from ..components.deletion_dialog import render_deletion_dialog, render_danger_zone
from infra_mgmt.notifications import initialize_notifications, show_notifications, notify, clear_notifications
import altair as alt
from ..services.ApplicationService import ApplicationService

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

def handle_add_form():
    """Handle the add application form submission."""
    if not st.session_state.app_name:
        notify("Application Name is required", "error")
        return
    
    if len(st.session_state.app_name) > 255:
        notify("Application Name must be 255 characters or less", "error")
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
                notify("✅ Application added successfully!", "success")
                st.rerun()
            else:
                notify(result['error'], "error")
    except Exception as e:
        logger.exception(f"Error adding application: {str(e)}")
        notify(f"Error adding application: {str(e)}", "error")

def toggle_add_form():
    """Toggle the add application form visibility."""
    st.session_state.show_add_app_form = not st.session_state.show_add_app_form

def delete_application(application, session):
    """Handle application deletion."""
    try:
        session.delete(application)
        session.commit()
        notify("Application deleted successfully!", "success")
        st.session_state.deleted_app_id = application.id
        return True
    except Exception as e:  # Only Exception is possible here due to DB errors
        session.rollback()
        logger.exception(f"Error deleting application: {str(e)}")
        notify(f"Error deleting application: {str(e)}", "error")
        return False

def handle_update_form():
    """Handle the update application form submission."""
    try:
        # Use the selection_session instead of regular session
        session = st.session_state.get('selection_session')
        application = st.session_state.get('current_app')
        if session and application:
            result = ApplicationService.update_application(
                session,
                application,
                st.session_state.new_name,
                st.session_state.new_type,
                st.session_state.new_description,
                st.session_state.new_owner
            )
            if result['success']:
                notify("Application updated successfully!", "success")
                st.rerun()
            else:
                notify(result['error'], "error")
        else:
            notify("Unable to update application: Session not available", "error")
    except Exception as e:
        logger.exception(f"Error updating application: {str(e)}")
        notify(f"Error updating application: {str(e)}", "error")

def handle_delete_app():
    """Handle application deletion."""
    try:
        session = st.session_state.get('session')
        application = st.session_state.get('current_app')
        if session and application:
            result = ApplicationService.delete_application(session, application)
            if result['success']:
                st.session_state.current_app = None
                notify("Application deleted successfully!", "success")
                st.rerun()
            else:
                notify(result['error'], "error")
    except Exception as e:
        session.rollback()
        logger.exception(f"Error deleting application: {str(e)}")
        notify(f"Error deleting application: {str(e)}", "error")

def render_applications_view(engine) -> None:
    """Render the main applications management interface."""
    try:
        # Initialize UI components and styles
        load_warning_suppression()
        load_css()
        
        # Add custom CSS
        st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
        
        # Initialize notifications
        initialize_notifications()
        clear_notifications()
        
        # Store engine in session state
        st.session_state.engine = engine
        
        # Initialize session state
        if 'show_add_app_form' not in st.session_state:
            st.session_state.show_add_app_form = False
        
        # Show notifications at the top
        show_notifications()
        
        # Header section with title and add button
        st.markdown('<div class="title-row">', unsafe_allow_html=True)
        col1, col2 = st.columns([3, 1])
        with col1:
            st.title("Applications")
        with col2:
            st.button(
                "❌ Cancel" if st.session_state.show_add_app_form else "➕ Add Application",
                type="secondary" if st.session_state.show_add_app_form else "primary",
                on_click=toggle_add_form,
                use_container_width=True
            )
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Application creation form
        if st.session_state.show_add_app_form:
            with st.form("add_application_form"):
                st.subheader("Add New Application")
                st.markdown('<div class="form-content">', unsafe_allow_html=True)
                
                # Form input fields
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
                    pass  # The actual handling is done in the callback

        st.divider()
        
        # Create metrics columns with standardized styling
        st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        
        with SessionManager(engine) as session:
            if not session:
                notify("Database connection failed", "error")
                show_notifications()
                return
            
            # Calculate metrics
            total_apps = session.query(Application).count()
            total_bindings = session.query(CertificateBinding).filter(CertificateBinding.application_id.isnot(None)).count()
            valid_certs = session.query(CertificateBinding).join(CertificateBinding.certificate).filter(
                CertificateBinding.application_id.isnot(None),
                Certificate.valid_until > datetime.now()
            ).count()
            
            # Display metrics
            col1.metric("Total Applications", total_apps)
            col2.metric("Certificate Bindings", total_bindings)
            col3.metric("Valid Certificates", valid_certs)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.divider()
        
        # Database query and data preparation
        with Session(engine) as session:
            st.session_state['session'] = session
            
            applications = (
                session.query(Application)
                .options(
                    joinedload(Application.certificate_bindings)
                )
                .all()
            )
            
            if not applications:
                notify("No applications found. Use the 'Add Application' button above to create one. \n", "info")
                return

            # View type selector
            view_type = st.radio(
                "View By",
                ["Group by Type", "All Applications"],
                horizontal=True,
                help="Group applications by their type or view all applications"
            )
            
            # Data grid preparation and configuration
            app_data = []
            for app in applications:
                cert_count = len(app.certificate_bindings)
                valid_certs = sum(1 for binding in app.certificate_bindings 
                                if binding.certificate.valid_until > datetime.now())
                
                app_data.append({
                    'Application': app.name,
                    'Type': app_types.get(app.app_type, app.app_type),
                    'Description': app.description or '',
                    'Owner': app.owner,
                    'Certificates': cert_count,
                    'Valid Certificates': valid_certs,
                    'Expired Certificates': cert_count - valid_certs,
                    'Created': app.created_at,
                    '_id': app.id
                })
            
            if app_data:
                df = pd.DataFrame(app_data)
                
                # AG Grid configuration
                gb = GridOptionsBuilder.from_dataframe(df)
                
                # Configure default column settings
                gb.configure_default_column(
                    resizable=True,
                    sortable=True,
                    filter=True,
                    editable=False
                )
                
                # Configure selection
                gb.configure_selection(
                    selection_mode='single',
                    use_checkbox=False
                )
                
                # Configure specific columns
                gb.configure_column(
                    "Application",
                    minWidth=200,
                    flex=2
                )
                
                gb.configure_column(
                    "Type",
                    minWidth=150,
                    flex=1,
                    rowGroup=True if view_type == "Group by Type" else False,
                    hide=True if view_type == "Group by Type" else False
                )
                
                gb.configure_column(
                    "Description",
                    minWidth=200,
                    flex=2
                )
                
                gb.configure_column(
                    "Owner",
                    minWidth=150,
                    flex=1
                )
                
                gb.configure_column(
                    "Certificates",
                    type=["numericColumn"],
                    minWidth=120
                )
                
                gb.configure_column(
                    "Valid Certificates",
                    type=["numericColumn"],
                    minWidth=120
                )
                
                gb.configure_column(
                    "Expired Certificates",
                    type=["numericColumn"],
                    minWidth=120
                )
                
                gb.configure_column(
                    "Created",
                    type=["dateTimeColumn"],
                    minWidth=120,
                    valueFormatter="value ? new Date(value).toLocaleDateString() : ''"
                )
                
                gb.configure_column(
                    "_id",
                    hide=True
                )
                
                # Configure grid options
                gb.configure_grid_options(
                    domLayout='normal',
                    enableRangeSelection=True,
                    pagination=True,
                    paginationPageSize=10,
                    paginationAutoPageSize=False,
                    suppressRowClickSelection=False,
                    rowSelection='single'
                )
                
                # Build grid options
                grid_options = gb.build()
                
                # Render the grid
                grid_response = AgGrid(
                    df,
                    gridOptions=grid_options,
                    height=400,
                    data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                    update_mode=GridUpdateMode.SELECTION_CHANGED | GridUpdateMode.VALUE_CHANGED,
                    fit_columns_on_grid_load=True,
                    allow_unsafe_jscode=False,
                    theme='streamlit',
                    key=f"applications_grid_{view_type}"
                )
                
                # Handle grid selection for application details
                if grid_response:
                    try:
                        selected_rows = grid_response.get('selected_rows', None)
                        
                        # Handle DataFrame response format
                        if isinstance(selected_rows, pd.DataFrame) and not selected_rows.empty:
                            # Check if this is a group row (has no _id)
                            if '_id' not in selected_rows.columns:
                                return
                            
                            # Convert first selected row to dictionary
                            row_dict = selected_rows.iloc[0].to_dict()
                            selected_app_id = row_dict.get('_id')
                            
                            if selected_app_id:
                                # Create a new session for handling the selection
                                with Session(engine) as selection_session:
                                    try:
                                        # Explicitly load all relationships with outer joins
                                        selected_app = (
                                            selection_session.query(Application)
                                            .options(
                                                joinedload(Application.certificate_bindings)
                                                .joinedload(CertificateBinding.certificate),
                                                joinedload(Application.certificate_bindings)
                                                .joinedload(CertificateBinding.host, innerjoin=False),
                                                joinedload(Application.certificate_bindings)
                                                .joinedload(CertificateBinding.host_ip, innerjoin=False)
                                            )
                                            .filter(Application.id == selected_app_id)
                                            .first()
                                        )
                                        if selected_app:
                                            st.divider()
                                            # Store the session in session_state for use in application details
                                            st.session_state['selection_session'] = selection_session
                                            render_application_details(selected_app)
                                        else:
                                            logger.warning(f"No application found for ID: {selected_app_id}")
                                            notify("Application not found", "error")
                                    except Exception as e:
                                        logger.exception(f"Error loading application details: {str(e)}")
                                        notify("Error loading application details. Please try again.", "error")
                    
                    except Exception as e:
                        logger.exception(f"Error handling grid selection: {str(e)}")
                        clear_notifications()  # Clear any existing notifications before showing error
                        notify("Error displaying application details. Please try again.", "error")
    except Exception as e:
        logger.exception(f"Error rendering applications view: {str(e)}")
        notify(f"Error rendering applications view: {str(e)}", "error")

    # Show notifications at the end using the placeholder
    show_notifications()

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
        
    # Store current application in session state
    st.session_state.current_app = application
    
    # Clear any existing notifications before showing application details
    clear_notifications()
    
    # Create container for application details
    details_container = st.container()
    
    with details_container:
        st.subheader(f"📱 {application.name}")
        
        # Create tabs for different sections
        tab1, tab2, tab3 = st.tabs(["Overview", "Certificate Bindings", "⚠️ Danger Zone"])
        
        with tab1:
            # Display application information and metrics
            st.markdown(f"""
                **Type:** {app_types.get(application.app_type, application.app_type)}  
                **Description:** {application.description or 'No description'}  
                **Owner:** {application.owner or 'Not specified'}  
                **Created:** {application.created_at.strftime('%Y-%m-%d')}
            """)
            
            # Application editing interface
            with st.expander("Edit Application"):
                with st.form("edit_application"):
                    st.text_input("Name", value=application.name, key="new_name")
                    st.selectbox("Type", 
                        options=APP_TYPES,
                        index=APP_TYPES.index(application.app_type),
                        key="new_type")
                    st.text_input("Description", 
                        value=application.description or '',
                        key="new_description")
                    st.text_input("Owner",
                        value=application.owner or '',
                        key="new_owner")
                    
                    if st.form_submit_button("Update Application", type="primary", on_click=handle_update_form):
                        pass  # Handling is done in the callback

        with tab2:
            # Certificate bindings management interface
            st.markdown("### Current Certificate Bindings")
            
            if application.certificate_bindings:
                # Create a clean table-like display for bindings
                for binding in application.certificate_bindings:
                    with st.container():
                        cols = st.columns([4, 1])
                        
                        # Column 1: Certificate Info
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
                        
                        # Column 2: Remove button
                        with cols[1]:
                            if st.button("🗑️", key=f"delete_{binding.id}", help="Remove this binding"):
                                session = st.session_state.get('selection_session')
                                if session:
                                    result = ApplicationService.remove_binding(session, binding)
                                    if result['success']:
                                        notify("Certificate binding removed", "success")
                                        st.rerun()
                                    else:
                                        notify(result['error'], "error")
                        
                        st.divider()  # Add visual separation between bindings
            else:
                notify("No certificate bindings found for this application.", "info")
            
            # Add new bindings section
            st.markdown("### Add Certificate Bindings")
            
            try:
                session = st.session_state.get('selection_session')
                if session:
                    # Query available certificates (not bound to this application)
                    available_certs = (
                        session.query(Certificate)
                        .join(CertificateBinding, isouter=True)
                        .filter(
                            (CertificateBinding.application_id.is_(None)) |
                            (CertificateBinding.application_id != application.id)
                        )
                        .all()
                    )
                    
                    if available_certs:
                        # Create options for multiselect
                        cert_options = {
                            f"{cert.common_name} (Valid until: {cert.valid_until.strftime('%Y-%m-%d')})": cert.id
                            for cert in available_certs
                        }
                        
                        # Select binding type first
                        binding_type = st.selectbox(
                            "Binding Type",
                            options=["IP-Based", "JWT-Based", "Client Certificate"],
                            help="How will this certificate be used?"
                        )
                        
                        # Map friendly names to actual binding types
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
                                        session,
                                        application.id,
                                        cert_ids,
                                        binding_type_map[binding_type]
                                    )
                                    if result['success']:
                                        notify(f"{result['count']} certificate(s) bound successfully!", "success")
                                        st.rerun()
                                    else:
                                        notify(result['error'], "error")
                                except Exception as e:
                                    logger.exception(f"Error binding certificates: {str(e)}")
                                    notify(f"Error binding certificates: {str(e)}", "error")
                    else:
                        notify("No available certificates found to bind.", "info")
            except Exception as e:
                logger.exception(f"Error loading available certificates: {str(e)}")
                notify(f"Error loading available certificates: {str(e)}", "error")
        
        with tab3:
            # Get the session from session state
            current_session = st.session_state.get('selection_session')
            
            if current_session:
                # Gather dependencies
                dependencies = {
                    "Certificate Bindings": [
                        f"{b.certificate.common_name} ({b.host.name if b.host else 'No Host'})" 
                        for b in application.certificate_bindings
                    ] if application.certificate_bindings else []
                }
                
                def delete_app(delete_session):
                    result = ApplicationService.delete_application(delete_session, application)
                    if result['success']:
                        st.session_state.current_app = None
                        st.rerun()
                        return True
                    else:
                        logger.exception(f"Error deleting application: {result['error']}")
                        return False
                
                # Use render_danger_zone without additional wrappers
                render_danger_zone(
                    title="Delete Application",
                    entity_name=application.name,
                    entity_type="application",
                    dependencies=dependencies,
                    on_delete=delete_app,
                    session=current_session,
                    custom_warning=f"This will permanently delete the application '{application.name}' and remove all certificate bindings."
                )
            else:
                notify("Unable to delete application: Session not available", "error") 