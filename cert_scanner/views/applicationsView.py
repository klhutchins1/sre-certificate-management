import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode, DataReturnMode, JsCode
from ..models import Application, CertificateBinding
from ..constants import APP_TYPES, app_types
from ..static.styles import load_warning_suppression, load_css


def render_applications_view(engine):
    """Render the applications view"""
    # Load warning suppression script and CSS
    load_warning_suppression()
    load_css()
    
    # Create a row for title and button
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Applications")
    with col2:
        if st.button("➕ Add Application" if not st.session_state.get('show_add_app_form', False) else "❌ Cancel", 
                    type="primary" if not st.session_state.get('show_add_app_form', False) else "secondary",
                    use_container_width=True):
            st.session_state['show_add_app_form'] = not st.session_state.get('show_add_app_form', False)
            st.rerun()
    
    # Show any pending success messages
    if 'success_message' in st.session_state:
        st.success(st.session_state.success_message)
        del st.session_state.success_message
    
    # Show Add Application form if button was clicked
    if st.session_state.get('show_add_app_form', False):
        with st.form("add_application_form"):
            st.subheader("Add New Application")
            
            # Application details
            col1, col2 = st.columns(2)
            with col1:
                app_name = st.text_input("Application Name",
                    help="Name of the application or service (e.g., 'Payment Gateway', 'Customer Portal')")
                app_type = st.selectbox("Application Type",
                    options=APP_TYPES,
                    help="The type of application or service")
            
            with col2:
                app_description = st.text_input("Description",
                    help="Brief description of what this application does")
                app_owner = st.text_input("Owner",
                    help="Team or individual responsible for this application")
            
            submitted = st.form_submit_button("Add Application", type="primary")
            
            if submitted:
                try:
                    with Session(engine) as session:
                        # Validate required fields
                        if not app_name:
                            st.error("Application Name is required")
                            return
                        
                        # Create application
                        new_app = Application(
                            name=app_name,
                            app_type=app_type,
                            description=app_description,
                            owner=app_owner,
                            created_at=datetime.now()
                        )
                        session.add(new_app)
                        session.commit()
                        st.session_state['success_message'] = "✅ Application added successfully!"
                        st.session_state['show_add_app_form'] = False
                        st.rerun()
                except Exception as e:
                    st.error(f"Error adding application: {str(e)}")
    
    st.divider()
    
    # Query applications and their related data
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
            st.info("No applications found. Use the 'Add Application' button above to create one.")
            return

        # Add view selector
        view_type = st.radio(
            "View By",
            ["Application Type", "All Applications"],
            horizontal=True,
            help="Group applications by their type or view all applications"
        )
        
        # Calculate metrics
        total_apps = len(applications)
        total_bindings = sum(len(app.certificate_bindings) for app in applications)
        valid_certs = sum(1 for app in applications 
                         for binding in app.certificate_bindings 
                         if binding.certificate.valid_until > datetime.now())
        
        # Display metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Applications", total_apps)
        col2.metric("Certificate Bindings", total_bindings)
        col3.metric("Valid Certificates", valid_certs)
        
        st.divider()
        
        # Convert to DataFrame for display
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
            if view_type == "Application Type":
                gb.configure_column(
                    "Type",
                    minWidth=150,
                    flex=1,
                    rowGroup=True
                )
            
            gb.configure_column(
                "Application",
                minWidth=200,
                flex=2
            )
            
            # Configure other columns
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
            
            # Configure certificate columns
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
            
            # Configure date column
            gb.configure_column(
                "Created",
                type=["dateColumnFilter"],
                minWidth=120,
                valueFormatter="value ? new Date(value).toLocaleDateString() : ''"
            )
            
            # Hide ID column
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
            
            if view_type == "Application Type":
                grid_options.update({
                    'groupDefaultExpanded': 1,
                    'groupDisplayType': 'groupRows',
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
                key=f"app_grid_{view_type}",
                height=600
            )
            
            # Handle selection
            try:
                selected_rows = grid_response.get('selected_rows', [])
                
                if isinstance(selected_rows, pd.DataFrame):
                    selected_rows = selected_rows.to_dict('records')
                
                if selected_rows and len(selected_rows) > 0:
                    selected_row = selected_rows[0]
                    
                    # Skip group rows in Application Type view
                    if view_type == "Application Type" and not selected_row.get('Application'):
                        return
                    
                    # Get the application based on the ID
                    selected_app = next(
                        (app for app in applications if app.id == selected_row['_id']),
                        None
                    )
                    
                    if selected_app:
                        st.divider()
                        render_application_details(selected_app)
            except Exception as e:
                st.error(f"Error handling selection: {str(e)}")
            
            # Add spacing after grid
            st.markdown("<div class='mb-5'></div>", unsafe_allow_html=True)
        else:
            st.warning("No application data available")

def render_application_details(application):
    """Render detailed view of an application"""
    st.subheader(f"📱 {application.name}")
    
    # Create tabs for different sections
    tab1, tab2 = st.tabs(["Overview", "Certificate Bindings"])
    
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
                **Type:** {app_types.get(application.app_type, application.app_type)}  
                **Description:** {application.description or 'No description'}  
                **Owner:** {application.owner or 'Not specified'}  
                **Created:** {application.created_at.strftime('%Y-%m-%d')}
            """)
            
            # Add edit functionality
            with st.expander("Edit Application"):
                with st.form("edit_application"):
                    new_name = st.text_input("Name", value=application.name)
                    new_type = st.selectbox("Type", 
                        options=APP_TYPES,
                        index=APP_TYPES.index(application.app_type))
                    new_description = st.text_input("Description", 
                        value=application.description or '')
                    new_owner = st.text_input("Owner",
                        value=application.owner or '')
                    
                    if st.form_submit_button("Update Application", type="primary"):
                        try:
                            session = st.session_state.get('session')
                            application.name = new_name
                            application.app_type = new_type
                            application.description = new_description
                            application.owner = new_owner
                            session.commit()
                            st.success("✅ Application updated successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error updating application: {str(e)}")
            
            # Add delete functionality
            with st.expander("Delete Application", expanded=False):
                st.warning("⚠️ This action cannot be undone!")
                if st.button("Delete Application", type="secondary"):
                    try:
                        session = st.session_state.get('session')
                        session.delete(application)
                        session.commit()
                        st.success("Application deleted successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error deleting application: {str(e)}")
        
        with col2:
            # Display certificate metrics
            valid_certs = sum(1 for binding in application.certificate_bindings 
                            if binding.certificate.valid_until > datetime.now())
            total_certs = len(application.certificate_bindings)
            
            st.markdown("### Certificate Status")
            col3, col4 = st.columns(2)
            col3.metric("Valid Certificates", valid_certs)
            col4.metric("Total Certificates", total_certs)
            
            if total_certs > 0:
                # Display certificate expiration chart
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
                            st.success("Binding removed successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error removing binding: {str(e)}")
        else:
            st.info("No certificate bindings found for this application.") 