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
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
import logging
from ..models import Application, CertificateBinding, Certificate
from ..constants import APP_TYPES, app_types
from ..static.styles import load_warning_suppression, load_css
from ..db import SessionManager
from ..components.deletion_dialog import render_deletion_dialog, render_danger_zone
from cert_scanner.notifications import initialize_notifications, show_notifications, notify, clear_notifications

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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
            # Check if application name already exists
            existing_app = session.query(Application).filter(
                Application.name == st.session_state.app_name
            ).first()
            
            if existing_app:
                notify(f"An application with the name '{st.session_state.app_name}' already exists", "error")
                return
            
            # Create new application
            new_app = Application(
                name=st.session_state.app_name,
                app_type=st.session_state.app_type,
                description=st.session_state.app_description,
                owner=st.session_state.app_owner,
                created_at=datetime.now()
            )
            session.add(new_app)
            session.commit()
            st.session_state.show_add_app_form = False
            notify("✅ Application added successfully!", "success")
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            notify(f"An application with the name '{st.session_state.app_name}' already exists", "error")
        else:
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
    except Exception as e:
        notify(f"Error deleting application: {str(e)}", "error")
        return False

def handle_update_form():
    """Handle the update application form submission."""
    try:
        # Use the selection_session instead of regular session
        session = st.session_state.get('selection_session')
        application = st.session_state.get('current_app')
        if session and application:
            # Refresh the application from the database
            application = session.merge(application)
            application.name = st.session_state.new_name
            application.app_type = st.session_state.new_type
            application.description = st.session_state.new_description
            application.owner = st.session_state.new_owner
            session.commit()
            notify("Application updated successfully!", "success")
            # Force a page refresh to show updated data
            st.rerun()
        else:
            notify("Unable to update application: Session not available", "error")
    except Exception as e:
        notify(f"Error updating application: {str(e)}", "error")

def handle_delete_app():
    """Handle application deletion."""
    try:
        session = st.session_state.get('session')
        application = st.session_state.get('current_app')
        if session and application:
            session.delete(application)
            session.commit()
            notify("Application deleted successfully!", "success")
            st.session_state.current_app = None
    except Exception as e:
        notify(f"Error deleting application: {str(e)}", "error")

def render_applications_view(engine) -> None:
    """Render the main applications management interface."""
    try:
        # Initialize UI components and styles
        load_warning_suppression()
        load_css()
        
        # Initialize notifications
        initialize_notifications()
        clear_notifications()  # Clear any existing notifications
        show_notifications()
        
        # Store engine in session state
        st.session_state.engine = engine
        
        # Initialize session state
        if 'show_add_app_form' not in st.session_state:
            st.session_state.show_add_app_form = False
        
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
                ["Application Type", "All Applications"],
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
                
                # Enable row selection first
                gb.configure_selection(
                    selection_mode='single',
                    use_checkbox=False,
                    pre_selected_rows=[]
                )
                
                # View-specific column configuration
                if view_type == "Application Type":
                    gb.configure_column(
                        "Type",
                        minWidth=150,
                        flex=1,
                        rowGroup=True
                    )
                
                # Individual column configurations
                gb.configure_column(
                    "Application",
                    minWidth=200,
                    flex=2
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
                
                # Certificate-related column configurations
                gb.configure_column(
                    "Certificates",
                    type=["numericColumn"],
                    minWidth=120
                )
                
                gb.configure_column(
                    "Valid Certificates",
                    type=["numericColumn"],
                    minWidth=120,
                    cellClass=JsCode("""
                    function(params) {
                        if (!params.data) return ['ag-numeric-cell'];
                        return ['ag-numeric-cell', 'ag-numeric-cell-positive'];
                    }
                    """)
                )
                
                gb.configure_column(
                    "Expired Certificates",
                    type=["numericColumn"],
                    minWidth=120,
                    cellClass=JsCode("""
                    function(params) {
                        if (!params.data) return ['ag-numeric-cell'];
                        return params.value > 0 ? ['ag-numeric-cell', 'ag-numeric-cell-negative'] : ['ag-numeric-cell'];
                    }
                    """)
                )
                
                # Configure column for Created date
                gb.configure_column(
                    "Created",
                    type=["dateColumn"],
                    minWidth=120
                )
                
                # Configure hidden ID column
                gb.configure_column(
                    "_id",
                    hide=True
                )
                
                # Build grid options once with all configurations
                grid_options = gb.build()
                
                # Add additional grid options
                grid_options['enableBrowserTooltips'] = True
                
                # Render the grid
                grid_response = AgGrid(
                    df,
                    gridOptions=grid_options,
                    height=400,
                    data_return_mode=DataReturnMode.FILTERED_AND_SORTED,
                    update_mode=GridUpdateMode.SELECTION_CHANGED | GridUpdateMode.VALUE_CHANGED,
                    fit_columns_on_grid_load=True,
                    allow_unsafe_jscode=True
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
                                            .get(selected_app_id)
                                        )
                                        if selected_app:
                                            st.divider()
                                            # Store the session in session_state for use in application details
                                            st.session_state['selection_session'] = selection_session
                                            render_application_details(selected_app)
                                        else:
                                            logger.warning(f"No application found for ID: {selected_app_id}")
                                    except Exception as e:
                                        logger.error(f"Error loading application details: {str(e)}")
                                        notify("Error loading application details. Please try again.", "error")
                    
                    except Exception as e:
                        logger.error(f"Error handling grid selection: {str(e)}")
                        clear_notifications()  # Clear any existing notifications before showing error
                        notify("Error displaying application details. Please try again.", "error")
    except Exception as e:
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
            col1, col2 = st.columns(2)
            with col1:
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
            
            with col2:
                # Certificate metrics and visualization
                valid_certs = sum(1 for binding in application.certificate_bindings 
                                if binding.certificate.valid_until > datetime.now())
                total_certs = len(application.certificate_bindings)
                
                st.markdown("### Certificate Status")
                col3, col4 = st.columns(2)
                col3.metric("Valid Certificates", valid_certs)
                col4.metric("Total Certificates", total_certs)
                
                if total_certs > 0:
                    # Certificate expiration visualization
                    st.markdown("### Certificate Expiration")
                    expiration_data = []
                    for binding in application.certificate_bindings:
                        days_until = (binding.certificate.valid_until - datetime.now()).days
                        status = "Valid" if days_until > 0 else "Expired"
                        expiration_data.append({
                            "Certificate": binding.certificate.common_name,
                            "Days Until Expiration": max(days_until, 0),
                            "Status": status
                        })
                    
                    df_exp = pd.DataFrame(expiration_data)
                    if not df_exp.empty:
                        st.bar_chart(
                            df_exp.set_index("Certificate")["Days Until Expiration"],
                            use_container_width=True
                        )
        
        with tab2:
            # Certificate bindings management interface
            st.markdown("### Current Certificate Bindings")
            
            if application.certificate_bindings:
                # Create a table for certificate bindings
                bindings_data = []
                for binding in application.certificate_bindings:
                    is_valid = binding.certificate.valid_until > datetime.now()
                    days_until = (binding.certificate.valid_until - datetime.now()).days
                    
                    # Handle missing relationships gracefully
                    host_name = binding.host.name if binding.host else "Not Set"
                    ip_address = binding.host_ip.ip_address if binding.host_ip else "Not Set"
                    
                    bindings_data.append({
                        "Certificate": binding.certificate.common_name,
                        "Host": host_name,
                        "IP Address": ip_address,
                        "Port": binding.port or "Not Set",
                        "Platform": binding.platform or "Not Set",
                        "Status": "Valid" if is_valid else "Expired",
                        "Days Until Expiration": max(days_until, 0),
                        "Last Seen": binding.last_seen.strftime('%Y-%m-%d %H:%M'),
                        "_binding_id": binding.id
                    })
                
                if bindings_data:
                    df_bindings = pd.DataFrame(bindings_data)
                    
                    # Configure grid for bindings
                    gb_bindings = GridOptionsBuilder.from_dataframe(df_bindings)
                    gb_bindings.configure_default_column(
                        resizable=True,
                        sortable=True,
                        filter=True
                    )
                    
                    # Enable row selection
                    gb_bindings.configure_selection(
                        selection_mode='multiple',
                        use_checkbox=True
                    )
                    
                    # Configure specific columns
                    gb_bindings.configure_column("Status", 
                        cellStyle=JsCode("""
                        function(params) {
                            if (params.value === 'Valid') {
                                return {'color': 'green'};
                            }
                            return {'color': 'red'};
                        }
                        """)
                    )
                    
                    gb_bindings.configure_column("Days Until Expiration",
                        type=["numericColumn"],
                        cellStyle=JsCode("""
                        function(params) {
                            if (params.value > 30) {
                                return {'color': 'green'};
                            } else if (params.value > 7) {
                                return {'color': 'orange'};
                            }
                            return {'color': 'red'};
                        }
                        """)
                    )
                    
                    # Hide binding ID column
                    gb_bindings.configure_column("_binding_id", hide=True)
                    
                    # Build and render bindings grid
                    grid_options_bindings = gb_bindings.build()
                    
                    bindings_grid = AgGrid(
                        df_bindings,
                        gridOptions=grid_options_bindings,
                        height=300,
                        fit_columns_on_grid_load=True,
                        allow_unsafe_jscode=True
                    )
                    
                    # Add remove binding button
                    if st.button("Remove Selected Bindings", type="secondary"):
                        selected_rows = bindings_grid.get('selected_rows', [])
                        if isinstance(selected_rows, pd.DataFrame) and not selected_rows.empty:
                            try:
                                session = st.session_state.get('selection_session')
                                if session:
                                    success_count = 0
                                    for _, row in selected_rows.iterrows():
                                        binding_id = row.get('_binding_id')
                                        if binding_id:
                                            binding = session.query(CertificateBinding).get(binding_id)
                                            if binding:
                                                binding.application_id = None
                                                success_count += 1
                                    
                                    if success_count > 0:
                                        session.commit()
                                        notify(f"{success_count} binding(s) removed successfully!", "success")
                                        # Use new rerun API
                                        st.rerun()
                            except Exception as e:
                                notify(f"Error removing bindings: {str(e)}", "error")
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
                        
                        selected_certs = st.multiselect(
                            "Select Certificates to Bind",
                            options=list(cert_options.keys()),
                            help="Select one or more certificates to bind to this application"
                        )
                        
                        if selected_certs:
                            if st.button("Bind Selected Certificates", type="primary"):
                                try:
                                    success_count = 0
                                    for cert_name in selected_certs:
                                        cert_id = cert_options[cert_name]
                                        # Create new binding with default values
                                        new_binding = CertificateBinding(
                                            certificate_id=cert_id,
                                            application_id=application.id,
                                            last_seen=datetime.now(),
                                            port=None,
                                            platform=None
                                        )
                                        session.add(new_binding)
                                        success_count += 1
                                    
                                    if success_count > 0:
                                        session.commit()
                                        notify(f"{success_count} certificate(s) bound successfully!", "success")
                                        # Ensure session is committed before rerun
                                        session.flush()
                                        # Use new rerun API
                                        st.rerun()
                                except Exception as e:
                                    notify(f"Error binding certificates: {str(e)}", "error")
                    else:
                        notify("No available certificates found to bind.", "info")
            except Exception as e:
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
                    try:
                        # Use the session passed to the callback
                        delete_session.delete(application)
                        delete_session.commit()
                        st.session_state.current_app = None
                        # Force a page refresh after deletion
                        st.rerun()
                        return True
                    except Exception as e:
                        delete_session.rollback()
                        logger.error(f"Error deleting application: {str(e)}")
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