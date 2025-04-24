import pytest
from datetime import datetime, timedelta
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from infra_mgmt.models import Base, Application, CertificateBinding, Certificate, Host, HostIP
from infra_mgmt.views.applicationsView import render_applications_view, render_application_details, APP_TYPES, app_types
from infra_mgmt.constants import HOST_TYPE_SERVER, ENV_PRODUCTION

@pytest.fixture(scope="function")
def engine():
    """Create in-memory database for testing"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture(scope="function")
def session(engine):
    """Create database session"""
    Session = scoped_session(sessionmaker(bind=engine))
    session = Session()
    yield session
    session.close()
    Session.remove()

@pytest.fixture
def mock_streamlit():
    """Mock streamlit functionality"""
    with patch('infra_mgmt.views.applicationsView.st') as mock_st:
        # Create column mocks with metrics
        def create_column_mock():
            col = MagicMock()
            col.metric = MagicMock()
            col.__enter__ = MagicMock(return_value=col)
            col.__exit__ = MagicMock(return_value=None)
            return col
        
        # Create a fixed set of columns for metrics
        metric_cols = [create_column_mock() for _ in range(3)]
        
        # Mock columns to return the correct mocks based on input
        def mock_columns(spec):
            if isinstance(spec, (list, tuple)):
                if spec == [3, 1]:
                    return [create_column_mock(), create_column_mock()]
                elif spec == 2:
                    return [create_column_mock(), create_column_mock()]
                else:
                    return metric_cols
            else:
                return metric_cols[:spec]
        
        mock_st.columns = MagicMock(side_effect=mock_columns)
        
        # Store metric columns for test access
        mock_st._metric_cols = metric_cols
        
        # Mock tabs
        tab1, tab2, tab3 = [create_column_mock() for _ in range(3)]
        mock_st.tabs.return_value = [tab1, tab2, tab3]
        
        # Mock form
        form_mock = MagicMock()
        form_mock.__enter__ = MagicMock(return_value=form_mock)
        form_mock.__exit__ = MagicMock(return_value=None)
        form_mock.form_submit_button = MagicMock(return_value=False)
        mock_st.form.return_value = form_mock
        
        # Mock session state
        class SessionState(dict):
            def __getattr__(self, name):
                return self.get(name)
            
            def __setattr__(self, name, value):
                self[name] = value
            
            def __delattr__(self, name):
                del self[name]
        
        session_state = SessionState()
        mock_st.session_state = session_state
        
        # Mock other commonly used methods
        mock_st.title = MagicMock()
        mock_st.subheader = MagicMock()
        mock_st.success = MagicMock()
        mock_st.error = MagicMock()
        mock_st.info = MagicMock()
        mock_st.warning = MagicMock()
        mock_st.markdown = MagicMock()
        mock_st.radio = MagicMock(return_value="All Applications")
        mock_st.button = MagicMock(return_value=False)
        mock_st.text_input = MagicMock(return_value="")
        mock_st.selectbox = MagicMock(return_value=None)
        mock_st.expander = MagicMock()
        mock_st.divider = MagicMock()
        
        # Mock toggle_add_form function
        def toggle_add_form():
            mock_st.session_state['show_add_app_form'] = not mock_st.session_state.get('show_add_app_form', False)
        
        mock_st.session_state['toggle_add_form'] = toggle_add_form
        
        yield mock_st

@pytest.fixture
def mock_aggrid():
    """Mock ag-grid functionality"""
    with patch('infra_mgmt.views.applicationsView.AgGrid') as mock_aggrid, \
         patch('infra_mgmt.views.applicationsView.GridOptionsBuilder') as mock_gb, \
         patch('infra_mgmt.views.applicationsView.JsCode') as mock_jscode:
        
        # Create a mock GridOptionsBuilder that supports all required methods
        class MockGridOptionsBuilder:
            def __init__(self):
                self.grid_options = {
                    'defaultColDef': {},
                    'columnDefs': [],
                    'rowData': [],
                    'animateRows': True,
                    'enableRangeSelection': True,
                    'suppressAggFuncInHeader': True,
                    'suppressMovableColumns': True,
                    'rowHeight': 35,
                    'headerHeight': 40
                }
            
            def configure_default_column(self, **kwargs):
                self.grid_options['defaultColDef'].update(kwargs)
                return self
                
            def configure_column(self, field, **kwargs):
                col_def = {"field": field, **kwargs}
                self.grid_options['columnDefs'].append(col_def)
                return self
                
            def configure_selection(self, **kwargs):
                self.grid_options.update({
                    'rowSelection': kwargs.get('selection_mode', 'single'),
                    'suppressRowClickSelection': kwargs.get('suppress_row_click_selection', False)
                })
                return self
                
            def configure_grid_options(self, **kwargs):
                self.grid_options.update(kwargs)
                return self
                
            def build(self):
                return self.grid_options
            
            @classmethod
            def from_dataframe(cls, df):
                instance = cls()
                return instance
        
        # Create a mock builder instance
        mock_builder = MockGridOptionsBuilder()
        
        # Configure GridOptionsBuilder mock
        mock_gb.from_dataframe = MagicMock(return_value=mock_builder)
        mock_gb.return_value = mock_builder
        
        # Configure mock JsCode to return the input string
        mock_jscode.side_effect = lambda x: x
        
        # Configure AgGrid mock
        def mock_aggrid_func(*args, **kwargs):
            return {
                'data': args[0] if args else pd.DataFrame(),
                'selected_rows': [],
                'grid_options': kwargs.get('gridOptions', {})
            }
        mock_aggrid.side_effect = mock_aggrid_func
        
        yield mock_gb

@pytest.fixture
def sample_application():
    """Create a sample application for testing"""
    return Application(
        name="Test App",
        app_type=APP_TYPES[0],  # Use first app type from the list
        description="Test Description",
        owner="Test Team",
        created_at=datetime.now()
    )

@pytest.fixture
def sample_host():
    return Host(
        name="test.example.com",
        host_type=HOST_TYPE_SERVER,
        environment=ENV_PRODUCTION,
        description="Test Host",
        last_seen=datetime.now()
    )

@pytest.fixture
def sample_host_ip(sample_host):
    return HostIP(
        host=sample_host,
        ip_address="192.168.1.1",
        is_active=True,
        last_seen=datetime.now()
    )

def test_render_applications_view_empty(mock_streamlit, engine):
    """Test rendering applications view when no applications exist"""
    # Mock notification system
    with patch('infra_mgmt.views.applicationsView.notify') as mock_notify:
        render_applications_view(engine)
        
        # Verify title was set
        mock_streamlit.title.assert_called_with("Applications")
        
        # Verify empty state message
        mock_notify.assert_called_with(
            "No applications found. Use the 'Add Application' button above to create one. \n",
            "info"
        )

def test_render_applications_view_with_data(mock_streamlit, mock_aggrid, engine, sample_application, session):
    """Test rendering applications view with sample data"""
    # Add application to session
    session.add(sample_application)
    session.commit()
    
    # Mock radio button for view selection
    mock_streamlit.radio.return_value = "All Applications"
    
    # Mock session state
    mock_streamlit.session_state['session'] = session
    
    render_applications_view(engine)
    
    # Verify title was set
    mock_streamlit.title.assert_called_with("Applications")
    
    # Verify metrics were displayed using the stored metric columns
    mock_streamlit._metric_cols[0].metric.assert_called_with("Total Applications", 1)
    mock_streamlit._metric_cols[1].metric.assert_called_with("Certificate Bindings", 0)
    mock_streamlit._metric_cols[2].metric.assert_called_with("Valid Certificates", 0)

def handle_add_form():
    """Handle application form submission"""
    try:
        session = st.session_state.get('session')
        if not session:
            notify("Database connection failed", "error")
            return
            
        # Get form values
        name = st.session_state.get('app_name')
        app_type = st.session_state.get('app_type')
        description = st.session_state.get('app_description')
        owner = st.session_state.get('app_owner')
        
        # Validate required fields
        if not name:
            notify("Application Name is required", "error")
            return
            
        # Create new application
        app = Application(
            name=name,
            app_type=app_type,
            description=description,
            owner=owner,
            created_at=datetime.now()
        )
        
        session.add(app)
        session.commit()
        
        # Reset form state
        st.session_state.show_add_app_form = False
        notify("Application added successfully!", "success")
        
    except Exception as e:
        notify(f"Error adding application: {str(e)}", "error")

def test_add_application_form(mock_streamlit, engine):
    """Test adding a new application through the form"""
    # Mock session state to show form
    mock_streamlit.session_state['show_add_app_form'] = True
    mock_streamlit.session_state['engine'] = engine
    
    # Configure form input values
    mock_streamlit.text_input.side_effect = [
        "New Test App",  # Application Name
        "Test Description",  # Description
        "Test Team"  # Owner
    ]
    mock_streamlit.selectbox.return_value = APP_TYPES[0]  # Application Type
    
    # Mock form submission
    form_mock = MagicMock()
    form_mock.form_submit_button.return_value = True
    mock_streamlit.form.return_value = form_mock
    
    # Mock the form handler
    with patch('infra_mgmt.views.applicationsView.handle_add_form') as mock_handler:
        render_applications_view(engine)
        
        # Verify form was created
        mock_streamlit.form.assert_called_with("add_application_form")
        
        # Verify form submission triggered handler
        form_mock.form_submit_button.assert_called_with("Add Application", type="primary", on_click=handle_add_form)
        
        # Verify application was added
        with Session(engine) as session:
            app = session.query(Application).filter_by(name="New Test App").first()
            assert app is not None
            assert app.app_type == APP_TYPES[0]
            assert app.description == "Test Description"
            assert app.owner == "Test Team"

def test_add_application_form_validation(mock_streamlit, engine):
    """Test form validation when adding a new application"""
    # Mock session state to show form
    mock_streamlit.session_state['show_add_app_form'] = True
    mock_streamlit.session_state['engine'] = engine
    
    # Configure form input values (empty application name)
    mock_streamlit.text_input.side_effect = [
        "",  # Empty Application Name
        "Test Description",
        "Test Team"
    ]
    mock_streamlit.selectbox.return_value = APP_TYPES[0]
    
    # Mock form submission
    form_mock = MagicMock()
    form_mock.form_submit_button.return_value = True
    mock_streamlit.form.return_value = form_mock
    
    # Mock notification system
    with patch('infra_mgmt.views.applicationsView.notify') as mock_notify:
        render_applications_view(engine)
        
        # Verify error message was shown
        mock_notify.assert_called_with("Application Name is required", "error")
        
        # Verify no application was added
        with Session(engine) as session:
            app_count = session.query(Application).count()
            assert app_count == 0

def test_view_type_switching(mock_streamlit, mock_aggrid, engine, sample_application, session):
    """Test switching between different view types"""
    # Add application to session
    session.add(sample_application)
    session.commit()
    
    # Test "Application Type" view
    mock_streamlit.radio.return_value = "Application Type"
    mock_streamlit.session_state['session'] = session
    render_applications_view(engine)
    
    # Verify grid builder was configured for grouped view
    builder = mock_aggrid.from_dataframe.return_value
    type_column = next(col for col in builder.grid_options['columnDefs'] if col['field'] == 'Type')
    assert type_column['rowGroup'] is True
    
    # Test "All Applications" view
    mock_streamlit.radio.return_value = "All Applications"
    render_applications_view(engine)
    
    # Verify grid builder was configured for flat view
    builder = mock_aggrid.from_dataframe.return_value
    type_column = next(col for col in builder.grid_options['columnDefs'] if col['field'] == 'Type')
    assert 'rowGroup' not in type_column

def test_application_metrics(mock_streamlit, mock_aggrid, engine, session):
    """Test application metrics calculation and display"""
    # Create test data with certificates
    app = Application(
        name="Test App",
        app_type=APP_TYPES[0],
        description="Test Description",
        owner="Test Team",
        created_at=datetime.now()
    )
    
    # Add some certificate bindings
    valid_cert = Certificate(
        serial_number="valid123",
        thumbprint="valid123",
        common_name="valid.test.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=30)
    )
    
    expired_cert = Certificate(
        serial_number="expired123",
        thumbprint="expired123",
        common_name="expired.test.com",
        valid_from=datetime.now() - timedelta(days=60),
        valid_until=datetime.now() - timedelta(days=30)
    )
    
    binding1 = CertificateBinding(
        certificate=valid_cert,
        port=443,
        last_seen=datetime.now()
    )
    
    binding2 = CertificateBinding(
        certificate=expired_cert,
        port=443,
        last_seen=datetime.now()
    )
    
    app.certificate_bindings.extend([binding1, binding2])
    session.add(app)
    session.commit()
    
    # Mock radio button
    mock_streamlit.radio.return_value = "All Applications"
    mock_streamlit.session_state['session'] = session
    
    render_applications_view(engine)
    
    # Verify metrics using stored metric columns
    mock_streamlit._metric_cols[0].metric.assert_called_with("Total Applications", 1)
    mock_streamlit._metric_cols[1].metric.assert_called_with("Certificate Bindings", 2)
    mock_streamlit._metric_cols[2].metric.assert_called_with("Valid Certificates", 1)

def test_error_handling(mock_streamlit, engine):
    """Test error handling during application operations"""
    # Mock session state to show form
    mock_streamlit.session_state['show_add_app_form'] = True
    
    # Configure form inputs to trigger database error
    mock_streamlit.text_input.side_effect = [
        "Test App" * 1000,  # Very long name to trigger SQLite error
        "Test Description",
        "Test Team"
    ]
    mock_streamlit.selectbox.return_value = APP_TYPES[0]
    mock_streamlit.form.return_value.form_submit_button.return_value = True
    
    render_applications_view(engine)
    
    # Verify error message was shown (the exact message depends on SQLite implementation)
    assert mock_streamlit.error.call_count > 0
    
    # Verify no application was added
    with Session(engine) as session:
        app_count = session.query(Application).count()
        assert app_count == 0

def test_render_application_details(mock_streamlit, sample_application, sample_host, sample_host_ip, session):
    """Test rendering application details"""
    # Add certificate bindings to the application
    valid_cert = Certificate(
        serial_number="valid123",
        thumbprint="valid123",
        common_name="valid.test.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=30)
    )
    
    binding = CertificateBinding(
        certificate=valid_cert,
        host=sample_host,
        host_ip=sample_host_ip,
        port=443,
        last_seen=datetime.now()
    )
    
    sample_application.certificate_bindings.append(binding)
    session.add_all([sample_application, sample_host, sample_host_ip])
    session.commit()
    
    # Mock session state
    mock_streamlit.session_state['session'] = session
    
    # Mock form context for edit form
    edit_form_mock = MagicMock()
    mock_streamlit.form.return_value.__enter__.return_value = edit_form_mock
    
    # Configure form inputs for edit form
    mock_streamlit.text_input.return_value = sample_application.name
    mock_streamlit.selectbox.return_value = sample_application.app_type
    
    render_application_details(sample_application)
    
    # Verify subheader was set
    mock_streamlit.subheader.assert_called_with(f"📱 {sample_application.name}")
    
    # Verify tabs were created with correct names
    mock_streamlit.tabs.assert_called_with(["Overview", "Certificate Bindings", "⚠️ Danger Zone"])
    
    # Get the tabs
    tabs = mock_streamlit.tabs.return_value
    assert len(tabs) == 3

def test_success_message_handling(mock_streamlit, engine):
    """Test success message handling after operations"""
    # Mock notification system
    with patch('infra_mgmt.views.applicationsView.notify') as mock_notify:
        # Set success message in session state
        message = "✅ Application added successfully!"
        mock_streamlit.session_state['success_message'] = message
        
        render_applications_view(engine)
        
        # Verify success message was displayed
        mock_notify.assert_called_with(message, "success")

def test_add_application_cancel(mock_streamlit, engine):
    """Test canceling application addition"""
    # Initial state: form not shown
    mock_streamlit.session_state['show_add_app_form'] = False
    
    # Mock the add/cancel button
    mock_streamlit.button.return_value = True
    
    render_applications_view(engine)
    
    # Verify button was shown with correct text
    mock_streamlit.button.assert_called_with(
        "➕ Add Application",
        type="primary",
        on_click=mock_streamlit.session_state.get('toggle_add_form'),
        use_container_width=True
    )

def test_application_grid_configuration(mock_streamlit, mock_aggrid, engine, sample_application, session):
    """Test AG Grid configuration for applications view"""
    # Add sample application
    session.add(sample_application)
    session.commit()
    
    # Mock radio button
    mock_streamlit.radio.return_value = "All Applications"
    mock_streamlit.session_state['session'] = session
    
    render_applications_view(engine)
    
    # Verify grid builder was created
    mock_aggrid.from_dataframe.assert_called()
    
    # Verify grid options were configured
    builder = mock_aggrid.from_dataframe.return_value
    assert builder.grid_options['defaultColDef']['resizable'] is True
    assert builder.grid_options['defaultColDef']['sortable'] is True
    assert builder.grid_options['defaultColDef']['filter'] is True
    assert builder.grid_options['defaultColDef']['editable'] is False 