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
from ..models import Application, CertificateBinding, Certificate
from ..constants import APP_TYPES, app_types
from ..static.styles import load_warning_suppression, load_css
from ..db import SessionManager
from cert_scanner.notifications import notifications, show_notifications, clear_notifications, initialize_notifications


def handle_add_form():
    """Handle the add application form submission."""
    if not st.session_state.app_name:
        st.error("Application Name is required")
        return
    
    if len(st.session_state.app_name) > 255:
        st.error("Application Name must be 255 characters or less")
        return
    
    try:
        with Session(st.session_state.engine) as session:
            # Check if application name already exists
            existing_app = session.query(Application).filter(
                Application.name == st.session_state.app_name
            ).first()
            
            if existing_app:
                st.error(f"An application with the name '{st.session_state.app_name}' already exists")
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
            st.success("✅ Application added successfully!")
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            st.error(f"An application with the name '{st.session_state.app_name}' already exists")
        else:
            st.error(f"Error adding application: {str(e)}")

def toggle_add_form():
    """Toggle the add application form visibility."""
    st.session_state.show_add_app_form = not st.session_state.show_add_app_form

def delete_application(application, session):
    """Handle application deletion."""
    try:
        session.delete(application)
        session.commit()
        notifications.add("Application deleted successfully!", "success")
        st.session_state.deleted_app_id = application.id
        return True
    except Exception as e:
        notifications.add(f"Error deleting application: {str(e)}", "error")
        return False

def handle_update_form():
    """Handle the update application form submission."""
    try:
        session = st.session_state.get('session')
        application = st.session_state.get('current_app')
        if session and application:
            application.name = st.session_state.new_name
            application.app_type = st.session_state.new_type
            application.description = st.session_state.new_description
            application.owner = st.session_state.new_owner
            session.commit()
            st.success("✅ Application updated successfully!")
    except Exception as e:
        st.error(f"Error updating application: {str(e)}")

def handle_delete_app():
    """Handle application deletion."""
    try:
        session = st.session_state.get('session')
        application = st.session_state.get('current_app')
        if session and application:
            session.delete(application)
            session.commit()
            st.success("Application deleted successfully!")
            st.session_state.current_app = None
    except Exception as e:
        st.error(f"Error deleting application: {str(e)}")

def render_applications_view(engine) -> None:
    """Render the main applications management interface."""
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Initialize notifications
    initialize_notifications()
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
            notifications.add("Database connection failed", "error")
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
            notifications.add("No applications found. Use the 'Add Application' button above to create one.", "info")
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
            
            # Configure grid options
            grid_options = gb.build()
            
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
            selected_rows = grid_response['selected_rows']
            if selected_rows:
                selected_app_id = selected_rows[0]['_id']
                selected_app = session.query(Application).get(selected_app_id)
                if selected_app:
                    render_application_details(selected_app)
        else:
            notifications.add("No application data available", "warning")
            return

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

    Features:
        - Two-tab interface (Overview and Certificate Bindings)
        - Real-time certificate status monitoring
        - Interactive certificate binding management
        - Application editing and deletion capabilities
    """
    # Store current application in session state
    st.session_state.current_app = application
    
    st.subheader(f"📱 {application.name}")
    
    # Create tabs for different sections
    tab1, tab2 = st.tabs(["Overview", "Certificate Bindings"])
    
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
            
            # Application deletion interface
            with st.expander("Delete Application", expanded=False):
                st.warning("⚠️ This action cannot be undone!")
                if st.button("Delete Application", key=f"delete_app_{application.id}", type="secondary", on_click=handle_delete_app):
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
        if application.certificate_bindings:
            st.markdown("### Certificate Bindings")
            for binding in application.certificate_bindings:
                is_valid = binding.certificate.valid_until > datetime.now()
                status_class = "cert-valid" if is_valid else "cert-expired"
                
                with st.expander(f"{binding.certificate.common_name} ({binding.host.name})", expanded=False):
                    st.markdown(f"""
                        **Host:** {binding.host.name}  
                        **IP Address:** {binding.host_ip.ip_address if binding.host_ip else 'N/A'}  
                        **Port:** {binding.port or 'N/A'}  
                        **Platform:** {binding.platform or 'Not Set'}  
                        **Status:** <span class='cert-status {status_class}'>{"Valid" if is_valid else "Expired"}</span>  
                        **Valid Until:** {binding.certificate.valid_until.strftime('%Y-%m-%d')}  
                        **Last Seen:** {binding.last_seen.strftime('%Y-%m-%d %H:%M')}
                    """, unsafe_allow_html=True)
                    
                    if st.button("Remove Binding", key=f"remove_{binding.id}", type="secondary"):
                        try:
                            session = st.session_state.get('session')
                            binding.application_id = None
                            session.commit()
                            notifications.add("Binding removed successfully!", "success")
                        except Exception as e:
                            notifications.add(f"Error removing binding: {str(e)}", "error")
        else:
            notifications.add("No certificate bindings found for this application.", "info") 