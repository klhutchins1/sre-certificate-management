import pytest
from datetime import datetime, timedelta, date
import streamlit as st
from unittest.mock import Mock, patch, MagicMock
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from cert_scanner.models import Base, Certificate, Host, HostIP, CertificateBinding, CertificateTracking
from cert_scanner.views.certificatesView import render_certificate_list, render_certificate_card
import json
from unittest import mock

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
    """Mock streamlit components"""
    with patch("cert_scanner.views.certificatesView.st") as mock_st:
        # Mock columns - support both 2-column and 5-column layouts
        def mock_columns(ratios):
            num_cols = len(ratios) if isinstance(ratios, list) else 2
            cols = [Mock() for _ in range(num_cols)]
            for col in cols:
                col.__enter__ = Mock(return_value=col)
                col.__exit__ = Mock(return_value=None)
            return cols
            
        mock_st.columns = Mock(side_effect=mock_columns)
        
        # Mock tabs with context managers
        tab1, tab2, tab3, tab4 = Mock(), Mock(), Mock(), Mock()
        for tab in [tab1, tab2, tab3, tab4]:
            tab.__enter__ = Mock(return_value=tab)
            tab.__exit__ = Mock(return_value=None)
        mock_st.tabs.return_value = [tab1, tab2, tab3, tab4]
        
        # Mock session state as a dict with attribute access
        class SessionState(dict):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.show_manual_entry = False
                
            def __getattr__(self, key):
                try:
                    return self[key]
                except KeyError:
                    return None
                    
            def __setattr__(self, key, value):
                self[key] = value
                
        mock_st.session_state = SessionState()
        
        # Mock dataframe
        mock_df = pd.DataFrame()
        mock_st.dataframe.return_value = mock_df
        
        # Mock form and expander
        mock_form = Mock()
        mock_form.__enter__ = Mock(return_value=mock_form)
        mock_form.__exit__ = Mock(return_value=None)
        mock_st.form = Mock(return_value=mock_form)
        
        mock_expander = Mock()
        mock_expander.__enter__ = Mock(return_value=mock_expander)
        mock_expander.__exit__ = Mock(return_value=None)
        mock_st.expander = Mock(return_value=mock_expander)
        
        yield mock_st

@pytest.fixture
def sample_certificate(session):
    """Create a sample certificate for testing"""
    cert = Certificate(
        common_name="test.com",
        serial_number="123456",
        valid_from=datetime.now(),
        valid_until=datetime.now() + timedelta(days=365),
        thumbprint="abc123",
        subject={"CN": "test.com"},
        issuer={"CN": "Test CA"},
        san=["test.com", "www.test.com"],
        key_usage=None,
        signature_algorithm=None,
        sans_scanned=False
    )
    session.add(cert)
    session.commit()
    session.refresh(cert)
    return cert

def test_render_certificate_list_empty(mock_streamlit, engine):
    """Test rendering certificate list when no certificates exist"""
    render_certificate_list(engine)
    
    # Verify title and add button are shown
    mock_streamlit.title.assert_called_with("Certificates")
    mock_streamlit.button.assert_called_with(
        "➕ Add Certificate", 
        type="primary",
        use_container_width=True
    )
    
    # Verify empty state warning
    mock_streamlit.warning.assert_called_with("No certificates found in database")

def test_render_certificate_list_with_data(mock_streamlit, engine, sample_certificate, session):
    """Test rendering certificate list with sample data"""
    # Mock selectbox to return None (no certificate selected)
    mock_streamlit.selectbox.return_value = None
    
    render_certificate_list(engine)
    
    # Verify dataframe was created with correct data
    mock_streamlit.dataframe.assert_called()
    
    # Get the styled dataframe that was passed to st.dataframe
    styled_df = mock_streamlit.dataframe.call_args[0][0]
    # Get the underlying dataframe
    df = styled_df.data
    
    # Convert df to dict for easier assertion
    data = df.to_dict('records')[0] if not df.empty else {}
    
    assert data.get("Common Name") == "test.com"
    assert data.get("Serial Number") == "123456"

def test_render_certificate_card(mock_streamlit, sample_certificate, session):
    """Test rendering certificate details card"""
    # Mock st.json to verify the data structure
    def mock_json(data):
        if isinstance(data, dict):
            # For issuer/subject details
            assert isinstance(data, dict)
        elif isinstance(data, list):
            # For SANs
            assert isinstance(data, list)
    mock_streamlit.json = Mock(side_effect=mock_json)
    
    # Mock tabs
    mock_tabs = [MagicMock() for _ in range(4)]
    for tab in mock_tabs:
        tab.__enter__ = MagicMock(return_value=None)
        tab.__exit__ = MagicMock(return_value=None)
    mock_streamlit.tabs.return_value = mock_tabs
    
    # Mock form inputs with actual values instead of MagicMock objects
    mock_streamlit.text_input.return_value = "CHG123"
    mock_streamlit.date_input.return_value = date(2024, 1, 1)
    mock_streamlit.selectbox.return_value = "Pending"
    mock_streamlit.text_area.return_value = "Test notes"
    mock_streamlit.form_submit_button.return_value = False  # Don't trigger form submission
    
    render_certificate_card(sample_certificate, session)
    
    # Verify tabs were created
    mock_streamlit.tabs.assert_called_once_with(["Overview", "Bindings", "Details", "Change Tracking"])

def test_add_certificate_button(mock_streamlit, engine):
    """Test add certificate button functionality"""
    render_certificate_list(engine)
    
    # Simulate button click
    mock_streamlit.button.return_value = True
    render_certificate_list(engine)
    
    # Verify manual entry form is shown
    assert mock_streamlit.session_state.get('show_manual_entry') == True

def test_certificate_selection(mock_streamlit, engine, sample_certificate, session):
    """Test certificate selection from dropdown"""
    # Mock selectbox to simulate selection
    mock_streamlit.selectbox.return_value = f"test.com (123456)"
    
    # Mock text_area to return a string
    mock_streamlit.text_area.return_value = "Test description"
    
    # Mock form_submit_button to return False (don't submit the form)
    mock_streamlit.form_submit_button.return_value = False
    
    # Mock st.json to verify the data structure
    def mock_json(data):
        if isinstance(data, dict):
            # For issuer/subject details
            assert isinstance(data, dict)
        elif isinstance(data, list):
            # For SANs
            assert isinstance(data, list)
    mock_streamlit.json = Mock(side_effect=mock_json)
    
    # Mock tabs
    mock_tabs = [MagicMock() for _ in range(4)]
    for tab in mock_tabs:
        tab.__enter__ = MagicMock(return_value=None)
        tab.__exit__ = MagicMock(return_value=None)
    mock_streamlit.tabs.return_value = mock_tabs
    
    render_certificate_list(engine)
    
    # Verify certificate details are shown - check that the call was made at some point
    assert any(
        call == mock.call("📜 test.com") 
        for call in mock_streamlit.subheader.call_args_list
    ), "Certificate title not found in subheader calls"

def test_expired_certificate_styling(mock_streamlit, engine, session):
    """Test styling of expired certificates"""
    # Create an expired certificate
    expired_cert = Certificate(
        common_name="expired.com",
        serial_number="654321",
        valid_from=datetime.now() - timedelta(days=730),  # 2 years ago
        valid_until=datetime.now() - timedelta(days=365),  # 1 year ago
        thumbprint="def456",
        subject={"CN": "expired.com"},
        issuer={"CN": "Test CA"},
        san=["expired.com"],
        key_usage=None,
        signature_algorithm=None,
        sans_scanned=False
    )
    session.add(expired_cert)
    session.commit()
    
    # Mock selectbox to return None (no certificate selected)
    mock_streamlit.selectbox.return_value = None
    
    render_certificate_list(engine)
    
    # Get the styled dataframe that was passed to st.dataframe
    styled_df = mock_streamlit.dataframe.call_args[0][0]
    # Get the underlying dataframe
    df = styled_df.data
    
    # Convert df to dict for easier assertion
    data = df.to_dict('records')[0] if not df.empty else {}
    assert data.get("Status") == "Expired" 