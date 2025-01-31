import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import logging
import threading
from .scanner import CertificateScanner, CertificateInfo
from .models import (
    Certificate, Host, HostIP, CertificateScan, CertificateBinding,
    HOST_TYPE_SERVER, HOST_TYPE_LOAD_BALANCER, HOST_TYPE_CDN, HOST_TYPE_VIRTUAL,
    ENV_PRODUCTION, ENV_STAGING, ENV_DEVELOPMENT, ENV_INTERNAL, ENV_EXTERNAL,
    BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION
)
from sqlalchemy.orm import Session
import plotly.express as px
from urllib.parse import urlparse
from .constants import platform_options
from .db import init_database, get_session
from .views.dashboardView import render_dashboard
from .views.certificatesView import render_certificate_list
from .views.hostsView import render_hosts_view
from .views.applicationsView import render_applications_view
from .views.certificateFlowView import render_certificate_flow_view
from .views.scannerView import render_scan_interface
from .views.historyView import render_history_view
from .views.searchView import render_search_view
from .views.settingsView import render_settings_view

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lock for thread-safe initialization
init_lock = threading.Lock()

def init_session_state():
    """Initialize session state variables"""
    with init_lock:
        if 'initialized' not in st.session_state:
            logger.info("Initializing session state...")
            st.session_state.scanner = CertificateScanner()
            st.session_state.selected_cert = None
            st.session_state.current_view = "Dashboard"
            logger.info("Initializing database engine...")
            st.session_state.engine = init_database()
            if st.session_state.engine:
                logger.info("Database engine initialized successfully")
            else:
                logger.error("Failed to initialize database engine")
            st.session_state.initialized = True

def render_sidebar():
    """Render the sidebar navigation"""
    with st.sidebar:
        st.title("Certificate Manager")
        st.markdown("---")
        
        # Map pages to their display names with icons
        page_mapping = {
            "Dashboard": "📊 Dashboard",
            "Certificates": "🔐 Certificates",
            "Hosts": "💻 Hosts",
            "Applications": "📦 Applications",
            "Certificate Flow": "🌐 Certificate Flow",
            "Scanner": "🔍 Scanner",
            "Search": "🔎 Search",
            "History": "📋 History",
            "Settings": "⚙️ Settings"
        }
        
        # Create reverse mapping for display names to pages
        reverse_mapping = {display: page for page, display in page_mapping.items()}
        
        # Get the current view's display name
        current_display = page_mapping.get(st.session_state.current_view, "📊 Dashboard")
        
        # Navigation list with icons
        selected = st.radio(
            "Navigation",
            options=list(page_mapping.values()),
            index=list(page_mapping.values()).index(current_display),
            key="nav_radio",
            label_visibility="collapsed"
        )
        
        # Update the current view based on selection
        new_view = reverse_mapping[selected]
        if new_view != st.session_state.current_view:
            st.session_state.current_view = new_view
            st.rerun()
        
        st.markdown("---")
        st.caption("v1.0.0")
        
        return st.session_state.current_view

def main():
    """Main application entry point"""
    # Initialize session state
    init_session_state()
    
    # Get current view from sidebar
    current_view = render_sidebar()
    
    # Render the selected view
    if current_view == "Dashboard":
        render_dashboard(st.session_state.engine)
    elif current_view == "Certificates":
        render_certificate_list(st.session_state.engine)
    elif current_view == "Hosts":
        render_hosts_view(st.session_state.engine)
    elif current_view == "Applications":
        render_applications_view(st.session_state.engine)
    elif current_view == "Certificate Flow":
        render_certificate_flow_view(st.session_state.engine)
    elif current_view == "Scanner":
        render_scan_interface(st.session_state.engine)
    elif current_view == "Search":
        render_search_view(st.session_state.engine)
    elif current_view == "History":
        render_history_view(st.session_state.engine)
    elif current_view == "Settings":
        render_settings_view(st.session_state.engine)

if __name__ == "__main__":
    main() 