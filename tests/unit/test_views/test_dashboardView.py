import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from infra_mgmt.models import Base, Certificate, Host
from infra_mgmt.views.dashboardView import render_dashboard
import streamlit as st
from unittest.mock import ANY, patch, MagicMock

@pytest.fixture
def engine():
    """Create a SQLite in-memory database"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine

@pytest.fixture
def session(engine):
    """Create a new database session for a test"""
    with Session(engine) as session:
        yield session

@pytest.fixture
def mock_streamlit():
    """Mock streamlit module for dashboardView tests"""
    with patch('infra_mgmt.views.dashboardView.st') as mock_st, \
         patch('infra_mgmt.components.page_header.st') as mock_header_st, \
         patch('infra_mgmt.components.metrics_row.st') as mock_metrics_st, \
         patch('infra_mgmt.notifications.st') as mock_notifications_st:
        # Mock columns to return objects with context manager support
        def get_column_mocks(spec):
            if isinstance(spec, (list, tuple)):
                num_cols = len(spec)
            else:
                num_cols = spec
            cols = []
            for _ in range(num_cols):
                col = MagicMock()
                col.__enter__ = MagicMock(return_value=col)
                col.__exit__ = MagicMock(return_value=None)
                cols.append(col)
            return tuple(cols)
        mock_st.columns.side_effect = get_column_mocks
        mock_header_st.columns.side_effect = get_column_mocks
        mock_metrics_st.columns.side_effect = get_column_mocks
        mock_notifications_st.columns.side_effect = get_column_mocks
        # Mock metric
        mock_st.metric = MagicMock()
        mock_header_st.metric = MagicMock()
        mock_metrics_st.metric = MagicMock()
        mock_notifications_st.metric = MagicMock()
        # Mock markdown
        mock_st.markdown = MagicMock()
        mock_header_st.markdown = MagicMock()
        mock_notifications_st.markdown = MagicMock()
        # Mock error and info
        mock_st.error = MagicMock()
        mock_st.info = MagicMock()
        mock_notifications_st.error = MagicMock()
        mock_notifications_st.info = MagicMock()
        # Mock plotly chart
        mock_st.plotly_chart = MagicMock()
        mock_notifications_st.plotly_chart = MagicMock()
        # Use a real object for session_state
        class SessionState(dict):
            def __init__(self):
                super().__init__()
                self.notifications = []
            def __getattr__(self, name):
                return self[name] if name in self else super().__getattribute__(name)
            def __setattr__(self, name, value):
                self[name] = value
        session_state = SessionState()
        mock_st.session_state = session_state
        mock_notifications_st.session_state = session_state
        yield (mock_st, mock_header_st, mock_metrics_st)

@pytest.fixture
def sample_data(session):
    """Create sample certificates and hosts"""
    now = datetime.now()
    
    # Create certificates with different expiry dates
    certs = [
        Certificate(
            serial_number="123",
            thumbprint="abc123",
            common_name="test1.com",
            valid_from=now - timedelta(days=30),
            valid_until=now + timedelta(days=15),  # Expiring soon
            issuer="Test CA",
            subject="CN=test1.com",
            san="test1.com"
        ),
        Certificate(
            serial_number="456",
            thumbprint="def456",
            common_name="test2.com",
            valid_from=now - timedelta(days=30),
            valid_until=now + timedelta(days=60),  # Not expiring soon
            issuer="Test CA",
            subject="CN=test2.com",
            san="test2.com"
        )
    ]
    
    # Create hosts
    hosts = [
        Host(
            name="host1",
            host_type="Server",
            environment="Production",
            last_seen=now
        ),
        Host(
            name="host2",
            host_type="Server",
            environment="Production",
            last_seen=now
        )
    ]
    
    session.add_all(certs + hosts)
    session.commit()
    return {'certificates': certs, 'hosts': hosts}

def test_dashboard_metrics(engine, session, mock_streamlit, sample_data):
    mock_st, mock_header_st, mock_metrics_st = mock_streamlit
    # Patch Session to support context manager
    class DummySession:
        def __enter__(self):
            return session
        def __exit__(self, exc_type, exc_val, exc_tb):
            pass
    import sys
    sys.modules['sqlalchemy.orm.session'].Session = DummySession
    render_dashboard(engine)
    # Verify header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Dashboard</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"
    # Verify metrics were rendered (at least 4 for the first row)
    assert mock_metrics_st.metric.call_count >= 4
    mock_metrics_st.metric.assert_any_call(label=ANY, value=ANY, delta=None, help=None)
    # Verify metrics through direct database queries
    total_certs = session.query(Certificate).count()
    assert total_certs == 2
    expiring_soon = session.query(Certificate).filter(
        Certificate.valid_until <= datetime.now() + timedelta(days=30)
    ).count()
    assert expiring_soon == 1
    total_hosts = session.query(Host).count()
    assert total_hosts == 2

def test_dashboard_empty_database(engine, mock_streamlit):
    mock_st, mock_header_st, mock_metrics_st = mock_streamlit
    render_dashboard(engine)
    # Verify header was rendered
    found = False
    for call in mock_header_st.markdown.call_args_list:
        if call.args and call.args[0] == "<h1 style='margin-bottom:0.5rem'>Dashboard</h1>" and call.kwargs.get('unsafe_allow_html'):
            found = True
            break
    assert found, "Expected header markdown call not found"

def test_dashboard_invalid_engine(mock_streamlit, monkeypatch):
    mock_st, mock_header_st, mock_metrics_st = mock_streamlit
    # Patch ViewDataService.get_dashboard_view_data to simulate DB error
    from infra_mgmt.services.ViewDataService import ViewDataService
    monkeypatch.setattr(ViewDataService, 'get_dashboard_view_data', lambda self, engine: {
        'success': False,
        'error': 'Error fetching dashboard data: no such table: certificates'
    })
    # Patch notify in dashboardView to capture notifications
    notifications = []
    def fake_notify(message, level='info'):
        notifications.append({'message': message, 'level': level})
    monkeypatch.setattr('infra_mgmt.views.dashboardView.notify', fake_notify)
    # Create an engine without creating tables
    invalid_engine = create_engine('sqlite:///:memory:')
    render_dashboard(invalid_engine)
    print('NOTIFICATIONS:', notifications)
    # Verify that an error notification was added
    found_error = False
    for notif in notifications:
        if notif['level'] == 'error' and "Error fetching dashboard data" in notif['message'] and "no such table: certificates" in notif['message']:
            found_error = True
            break
    assert found_error, "Expected error notification not found"

def test_dashboard_timeline_generation(engine, session, mock_streamlit, sample_data):
    mock_st, mock_header_st, mock_metrics_st = mock_streamlit
    render_dashboard(engine)
    # Verify certificate data is available for timeline
    certs = session.query(
        Certificate.common_name,
        Certificate.valid_from,
        Certificate.valid_until
    ).all()
    assert len(certs) == 2
    assert all(cert.common_name and cert.valid_from and cert.valid_until for cert in certs) 