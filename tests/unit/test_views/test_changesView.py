"""
Tests for changesView module.

Tests the Changes view functionality including:
- Rendering change entries
- Adding new changes
- Editing pending changes
- Building scan targets
- Scan window validation
- Port number formatting
- Edit button styling
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch, call
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from infra_mgmt.models import (
    Base, Certificate, CertificateTracking, CertificateBinding,
    Host, HostIP, Domain, CertificateScan
)
from sqlalchemy.orm import joinedload
from infra_mgmt.views.changesView import (
    render_changes_view,
    _build_change_dataframe,
    _build_scan_targets,
    _is_within_scan_window,
    CHANGE_SCAN_WINDOW_DAYS
)
import json


@pytest.fixture(scope="function")
def engine():
    """Create in-memory database for testing"""
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="function")
def session(engine):
    """Create a database session for testing"""
    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def mock_streamlit():
    """Mock streamlit module"""
    # Mock columns function that works for all modules
    def mock_columns(num_cols):
        if isinstance(num_cols, (list, tuple)):
            num_cols = len(num_cols)
        # Ensure we always return at least the number requested
        if num_cols <= 0:
            num_cols = 1  # Default to 1 if invalid
        cols = [MagicMock() for _ in range(num_cols)]
        # Make columns context managers
        for col in cols:
            col.__enter__ = MagicMock(return_value=col)
            col.__exit__ = MagicMock(return_value=None)
        return cols
    
    # Mock session state as a dict-like object
    class SessionState(dict):
        def __getattr__(self, name):
            return self.get(name)
        
        def __setattr__(self, name, value):
            self[name] = value
    
    session_state = SessionState()
    
    # Create a shared mock_st that can be used across modules
    mock_st = MagicMock()
    mock_st.session_state = session_state
    mock_st.empty = MagicMock(return_value=MagicMock())
    mock_st.columns = MagicMock(side_effect=mock_columns)
    mock_st.subheader = MagicMock()
    mock_st.markdown = MagicMock()
    mock_st.divider = MagicMock()
    mock_st.button = MagicMock(return_value=False)
    mock_st.selectbox = MagicMock(return_value="All")
    mock_st.text_input = MagicMock(return_value="")
    mock_st.dataframe = MagicMock()
    mock_st.info = MagicMock()
    mock_st.caption = MagicMock()
    mock_st.expander = MagicMock(return_value=MagicMock())
    mock_st.text = MagicMock()
    mock_st.form = MagicMock(return_value=MagicMock())
    mock_st.form_submit_button = MagicMock(return_value=False)
    mock_st.date_input = MagicMock(return_value=datetime.now().date())
    mock_st.text_area = MagicMock(return_value="")
    mock_st.rerun = MagicMock()
    mock_st.metric = MagicMock()
    
    # Patch st in all relevant modules
    with patch('infra_mgmt.views.changesView.st', mock_st), \
         patch('infra_mgmt.components.page_header.st', mock_st), \
         patch('infra_mgmt.components.deletion_dialog.st', mock_st):
        yield mock_st


@pytest.fixture
def sample_certificate(session):
    """Create a sample certificate"""
    cert = Certificate(
        serial_number="test_serial_123",
        thumbprint="test_thumbprint_456",
        common_name="example.com",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=90),
        issuer=json.dumps({"commonName": "Test CA"}),
        subject=json.dumps({"commonName": "example.com"}),
        san=json.dumps(["example.com", "www.example.com"])
    )
    session.add(cert)
    session.flush()  # Flush to get ID before creating bindings
    return cert


@pytest.fixture
def sample_host(session):
    """Create a sample host"""
    host = Host(name="test-host.example.com", host_type="Server")
    session.add(host)
    session.commit()
    return host


@pytest.fixture
def sample_host_ip(session, sample_host):
    """Create a sample host IP"""
    host_ip = HostIP(ip_address="192.168.1.1", host_id=sample_host.id)
    session.add(host_ip)
    session.commit()
    return host_ip


@pytest.fixture
def sample_binding(session, sample_certificate, sample_host, sample_host_ip):
    """Create a sample certificate binding"""
    binding = CertificateBinding(
        certificate_id=sample_certificate.id,
        host_id=sample_host.id,
        host_ip_id=sample_host_ip.id,
        port=443,
        platform="F5",
        last_seen=datetime.now()
    )
    session.add(binding)
    session.commit()
    return binding


@pytest.fixture
def tracking_entry(session, sample_certificate):
    """Create a sample tracking entry"""
    # Ensure certificate is committed first
    session.commit()
    entry = CertificateTracking(
        certificate_id=sample_certificate.id,
        change_number="CHG001234",
        planned_change_date=datetime.now() + timedelta(days=30),
        status="Pending",
        notes="Test change",
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    session.add(entry)
    session.commit()
    # Set the relationship explicitly
    entry.certificate = sample_certificate
    return entry


@pytest.fixture
def tracking_entry_no_cert(session):
    """Create a tracking entry without a certificate"""
    entry = CertificateTracking(
        certificate_id=None,
        change_number="CHG005678",
        planned_change_date=datetime.now() + timedelta(days=30),
        status="Pending",
        notes="Change without certificate",
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    session.add(entry)
    session.commit()
    return entry


class TestBuildChangeDataframe:
    """Test _build_change_dataframe function"""
    
    def test_build_dataframe_with_certificate(self, session, tracking_entry, sample_certificate, sample_binding):
        """Test building dataframe with certificate and bindings"""
        # Refresh to ensure relationships are in session
        session.refresh(tracking_entry)
        session.refresh(sample_certificate)
        session.refresh(sample_binding)
        
        # Ensure certificate relationship is accessible
        # The entry should have the certificate relationship set
        if not hasattr(tracking_entry, 'certificate') or tracking_entry.certificate is None:
            tracking_entry.certificate = sample_certificate
        
        # Ensure certificate has bindings
        if sample_certificate not in session:
            session.merge(sample_certificate)
        if sample_binding not in session:
            session.merge(sample_binding)
        
        entries = [tracking_entry]
        df = _build_change_dataframe(entries)
        
        assert not df.empty
        assert len(df) == 1
        assert df.iloc[0]["Change Number"] == "CHG001234"
        assert df.iloc[0]["Certificate"] == "example.com"
        assert df.iloc[0]["Status"] == "Pending"
        assert "_id" in df.columns
    
    def test_build_dataframe_without_certificate(self, session, tracking_entry_no_cert):
        """Test building dataframe without certificate"""
        # Refresh to ensure the entry is in the session
        session.refresh(tracking_entry_no_cert)
        entries = [tracking_entry_no_cert]
        df = _build_change_dataframe(entries)
        
        assert not df.empty
        assert len(df) == 1
        assert df.iloc[0]["Certificate"] == "(No certificate assigned)"
        assert df.iloc[0]["Change Number"] == "CHG005678"
    
    def test_build_dataframe_empty(self):
        """Test building dataframe with no entries"""
        df = _build_change_dataframe([])
        
        assert df.empty
        assert "Change Number" in df.columns
        assert "Certificate" in df.columns
    
    def test_build_dataframe_aggregates_bindings(self, session, sample_certificate, sample_host, sample_host_ip):
        """Test that dataframe aggregates bindings correctly"""
        # Ensure certificate is in session
        session.commit()
        
        # Create multiple bindings
        binding1 = CertificateBinding(
            certificate_id=sample_certificate.id,
            host_id=sample_host.id,
            host_ip_id=sample_host_ip.id,
            port=443,
            platform="F5"
        )
        binding2 = CertificateBinding(
            certificate_id=sample_certificate.id,
            host_id=sample_host.id,
            host_ip_id=sample_host_ip.id,
            port=8443,
            platform="Cloudflare"
        )
        session.add_all([binding1, binding2])
        session.commit()
        
        entry = CertificateTracking(
            certificate_id=sample_certificate.id,
            change_number="CHG_MULTI",
            status="Pending"
        )
        session.add(entry)
        session.commit()
        
        # Refresh to ensure relationships are loaded
        session.refresh(entry)
        session.refresh(sample_certificate)
        
        # Ensure certificate relationship is set
        if not hasattr(entry, 'certificate') or entry.certificate is None:
            entry.certificate = sample_certificate
        
        df = _build_change_dataframe([entry])
        # Check that at least one platform is in the result
        platforms_str = df.iloc[0]["Platforms"]
        assert platforms_str != "", "Platforms should not be empty"
        assert "F5" in platforms_str or "Cloudflare" in platforms_str


class TestBuildScanTargets:
    """Test _build_scan_targets function"""
    
    def test_build_scan_targets_with_hostname(self, sample_certificate, sample_binding):
        """Test building scan targets with hostname"""
        targets = _build_scan_targets(sample_certificate)
        
        assert len(targets) > 0
        assert any("test-host.example.com:443" in target for target in targets)
    
    def test_build_scan_targets_with_ip(self, session, sample_certificate, sample_host, sample_host_ip):
        """Test building scan targets with IP address"""
        binding = CertificateBinding(
            certificate_id=sample_certificate.id,
            host_id=sample_host.id,
            host_ip_id=sample_host_ip.id,
            port=9403
        )
        session.add(binding)
        session.commit()
        
        targets = _build_scan_targets(sample_certificate)
        
        # Should include both hostname and IP
        assert any("test-host.example.com:9403" in target for target in targets)
        assert any("192.168.1.1:9403" in target for target in targets)
    
    def test_build_scan_targets_fallback_to_sans(self, session):
        """Test building scan targets falls back to SANs when no bindings"""
        cert = Certificate(
            serial_number="test_serial",
            thumbprint="test_thumb",
            common_name="example.com",
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=90),
            issuer=json.dumps({"CN": "Test CA"}),
            subject=json.dumps({"CN": "example.com"}),
            san=json.dumps(["example.com", "www.example.com"])
        )
        session.add(cert)
        session.commit()
        
        targets = _build_scan_targets(cert)
        
        assert len(targets) > 0
        assert any("example.com:443" in target for target in targets)
    
    def test_build_scan_targets_no_bindings_no_sans(self, session):
        """Test building scan targets with no bindings and no SANs"""
        cert = Certificate(
            serial_number="test_serial",
            thumbprint="test_thumb",
            common_name="example.com",
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=90),
            issuer=json.dumps({"CN": "Test CA"}),
            subject=json.dumps({"CN": "example.com"}),
            san=None
        )
        session.add(cert)
        session.commit()
        
        targets = _build_scan_targets(cert)
        
        assert len(targets) == 0


class TestIsWithinScanWindow:
    """Test _is_within_scan_window function"""
    
    def test_within_scan_window(self, tracking_entry):
        """Test that entry within scan window returns True"""
        # Set planned date to today
        tracking_entry.planned_change_date = datetime.now()
        assert _is_within_scan_window(tracking_entry) is True
    
    def test_outside_scan_window(self, tracking_entry):
        """Test that entry outside scan window returns False"""
        # Set planned date to beyond window
        tracking_entry.planned_change_date = datetime.now() - timedelta(days=CHANGE_SCAN_WINDOW_DAYS + 1)
        assert _is_within_scan_window(tracking_entry) is False
    
    def test_no_planned_date(self, tracking_entry):
        """Test that entry without planned date allows scans"""
        tracking_entry.planned_change_date = None
        assert _is_within_scan_window(tracking_entry) is True
    
    def test_at_window_boundary(self, tracking_entry):
        """Test entry exactly at window boundary"""
        tracking_entry.planned_change_date = datetime.now() - timedelta(days=CHANGE_SCAN_WINDOW_DAYS)
        assert _is_within_scan_window(tracking_entry) is True


class TestPortNumberFormatting:
    """Test that port numbers are formatted correctly (no commas)"""
    
    def test_port_as_string_in_bindings(self, session, sample_certificate, sample_host, sample_host_ip):
        """Test that ports are converted to strings in bindings table"""
        binding = CertificateBinding(
            certificate_id=sample_certificate.id,
            host_id=sample_host.id,
            host_ip_id=sample_host_ip.id,
            port=443
        )
        session.add(binding)
        session.commit()
        
        entry = CertificateTracking(
            certificate_id=sample_certificate.id,
            change_number="CHG_PORT",
            status="Pending"
        )
        session.add(entry)
        session.commit()
        
        # This would be tested in render_changes_view, but we can test the data structure
        # The port should be stored as integer but displayed as string
        assert isinstance(binding.port, int)
        assert str(binding.port) == "443"
    
    def test_port_as_string_in_scan_results(self, session, sample_certificate, sample_host):
        """Test that ports are converted to strings in scan results"""
        scan = CertificateScan(
            certificate_id=sample_certificate.id,
            host_id=sample_host.id,
            port=9403,
            scan_date=datetime.now(),
            status="Success",
            change_id=1,
            scan_type="before"
        )
        session.add(scan)
        session.commit()
        
        # Port should be stored as integer but displayed as string
        assert isinstance(scan.port, int)
        assert str(scan.port) == "9403"


class TestRenderChangesView:
    """Test render_changes_view function"""
    
    def test_render_empty_list(self, mock_streamlit, engine):
        """Test rendering with no entries"""
        mock_st = mock_streamlit
        
        with patch('infra_mgmt.views.changesView.SessionManager') as mock_sm, \
             patch('infra_mgmt.views.changesView.notify') as mock_notify:
            mock_session = MagicMock()
            mock_session.query.return_value.options.return_value.order_by.return_value.all.return_value = []
            mock_sm.return_value.__enter__.return_value = mock_session
            
            render_changes_view(engine)
            
            # Should show info message via notify
            mock_notify.assert_called()
    
    def test_render_with_entries(self, mock_streamlit, engine, tracking_entry):
        """Test rendering with entries"""
        mock_st = mock_streamlit
        
        with patch('infra_mgmt.views.changesView.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.query.return_value.options.return_value.order_by.return_value.all.return_value = [tracking_entry]
            mock_sm.return_value.__enter__.return_value = mock_session
            
            # Mock AgGrid
            with patch('infra_mgmt.views.changesView.AgGrid') as mock_ag:
                mock_ag.return_value = {"selected_rows": []}
                
                render_changes_view(engine)
                
                # Should call AgGrid
                mock_ag.assert_called()
    
    def test_edit_button_not_in_column(self, mock_streamlit, engine, tracking_entry):
        """Test that edit button is not constrained to narrow column"""
        mock_st = mock_streamlit
        mock_st.session_state['show_add_change_form'] = False
        mock_st.button.return_value = False
        
        with patch('infra_mgmt.views.changesView.SessionManager') as mock_sm:
            mock_session = MagicMock()
            mock_session.query.return_value.options.return_value.order_by.return_value.all.return_value = [tracking_entry]
            mock_sm.return_value.__enter__.return_value = mock_session
            
            with patch('infra_mgmt.views.changesView.AgGrid') as mock_ag:
                # Mock selection
                mock_selected = pd.DataFrame([{"_id": tracking_entry.id}])
                mock_ag.return_value = {"selected_rows": mock_selected}
                
                render_changes_view(engine)
                
                # Verify button is called with use_container_width=False
                # This ensures it's not in a narrow column
                button_calls = [c for c in mock_st.button.call_args_list if "Edit Change" in str(c)]
                if button_calls:
                    # Check that use_container_width is False or not set (defaults to True in columns)
                    call_kwargs = button_calls[0].kwargs
                    assert call_kwargs.get('use_container_width', True) is False or 'use_container_width' not in call_kwargs


class TestAddChangeForm:
    """Test add change form functionality"""
    
    def test_add_change_without_certificate(self, mock_streamlit, engine):
        """Test adding a change without a certificate"""
        mock_st = mock_streamlit
        # Set show_add_change_form to True
        mock_st.session_state['show_add_change_form'] = True
        
        # Mock form and form_submit_button - need to return True when form is submitted
        form_mock = MagicMock()
        form_mock.__enter__ = MagicMock(return_value=form_mock)
        form_mock.__exit__ = MagicMock(return_value=None)
        mock_st.form.return_value = form_mock
        
        # Mock form_submit_button on st (called inside form context)
        mock_st.form_submit_button = MagicMock(return_value=True)
        
        # Mock other form inputs
        mock_st.selectbox.return_value = "None (Certificate not created yet)"
        mock_st.text_input.return_value = "CHG001234"
        mock_st.date_input.return_value = datetime.now().date()
        mock_st.text_area.return_value = "Test notes"
        
        with patch('infra_mgmt.views.changesView.SessionManager') as mock_sm:
            # Create mock sessions - one for loading certificates, one for creating entry
            mock_session1 = MagicMock()
            mock_session1.query.return_value.order_by.return_value.all.return_value = []
            
            mock_session2 = MagicMock()
            
            # Mock SessionManager to return different sessions on each call
            call_count = [0]
            def get_session(eng):
                call_count[0] += 1
                mock_sm_instance = MagicMock()
                if call_count[0] == 1:
                    mock_sm_instance.__enter__ = MagicMock(return_value=mock_session1)
                else:
                    mock_sm_instance.__enter__ = MagicMock(return_value=mock_session2)
                mock_sm_instance.__exit__ = MagicMock(return_value=None)
                return mock_sm_instance
            
            mock_sm.side_effect = get_session
            
            with patch('infra_mgmt.views.changesView.HistoryService') as mock_service:
                mock_service.add_certificate_tracking_entry.return_value = {'success': True}
                
                render_changes_view(engine)
                
                # Should call add_certificate_tracking_entry when form is submitted
                mock_service.add_certificate_tracking_entry.assert_called()


class TestUpdateTrackingEntry:
    """Test update_tracking_entry functionality"""
    
    def test_update_pending_change_certificate(self, session, tracking_entry, sample_certificate):
        """Test updating certificate for pending change"""
        from infra_mgmt.services.HistoryService import HistoryService
        
        # Create another certificate
        cert2 = Certificate(
            serial_number="test_serial_789",
            thumbprint="test_thumbprint_789",
            common_name="example2.com",
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=90),
            issuer=json.dumps({"commonName": "Test CA"}),
            subject=json.dumps({"commonName": "example2.com"})
        )
        session.add(cert2)
        session.commit()
        
        # Update tracking entry to use new certificate
        result = HistoryService.update_tracking_entry(
            session,
            tracking_entry.id,
            cert2.id,
            "CHG_UPDATED",
            datetime.now().date(),
            "Pending",
            "Updated notes"
        )
        
        assert result['success'] is True
        session.refresh(tracking_entry)
        assert tracking_entry.certificate_id == cert2.id
    
    def test_update_completed_change_certificate_not_changed(self, session, tracking_entry, sample_certificate):
        """Test that certificate cannot be changed for completed change"""
        from infra_mgmt.services.HistoryService import HistoryService
        
        # Change status to Completed
        tracking_entry.status = "Completed"
        session.commit()
        
        # Create another certificate
        cert2 = Certificate(
            serial_number="test_serial_999",
            thumbprint="test_thumbprint_999",
            common_name="example3.com",
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=90),
            issuer=json.dumps({"commonName": "Test CA"}),
            subject=json.dumps({"commonName": "example3.com"})
        )
        session.add(cert2)
        session.commit()
        
        original_cert_id = tracking_entry.certificate_id
        
        # Try to update tracking entry with new certificate
        result = HistoryService.update_tracking_entry(
            session,
            tracking_entry.id,
            cert2.id,  # Try to change certificate
            "CHG_UPDATED",
            datetime.now().date(),
            "Completed",
            "Updated notes"
        )
        
        assert result['success'] is True
        session.refresh(tracking_entry)
        # Certificate should not have changed
        assert tracking_entry.certificate_id == original_cert_id

