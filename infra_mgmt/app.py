"""
Main application module for the Infrastructure Management System (IMS).

This module serves as the entry point for the Streamlit-based web application that manages
SSL/TLS certificates, hosts, and domains across different environments and platforms. It provides functionality
for scanning, monitoring, and managing digital certificates, hosts, domains, and their relationships.

The application features multiple views including:
- Dashboard: Overview of certificate status and metrics
- Certificates: Detailed certificate management
- Hosts: Host management and certificate bindings
- Applications: Application-level certificate usage
- Scanner: Certificate scanning interface
- Search: Global search functionality
- History: Historical certificate data
- Settings: Application configuration
"""

# Standard library imports
import threading
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import Optional, Dict, List

# Third-party imports
import streamlit as st
import pandas as pd
import plotly.express as px
from sqlalchemy.orm import Session

# Local application imports
from .settings import settings
from .scanner.certificate_scanner import CertificateScanner, CertificateInfo
from .scanner import ScanManager
from .models import (
    Certificate, Host, HostIP, CertificateScan, CertificateBinding,
    # Host type constants
    HOST_TYPE_SERVER, HOST_TYPE_LOAD_BALANCER, HOST_TYPE_CDN, HOST_TYPE_VIRTUAL,
    # Environment constants
    ENV_PRODUCTION, ENV_CERT, ENV_DEVELOPMENT, ENV_INTERNAL, ENV_EXTERNAL,
    # Binding type constants
    BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    # Platform constants
    PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION,
    Domain
)
from .constants import platform_options
from .db import init_database
# View imports
from .views.dashboardView import render_dashboard
from .views.certificatesView import render_certificate_list
from .views.hostsView import render_hosts_view
from .views.applicationsView import render_applications_view
from .views.scannerView import render_scan_interface
from .views.historyView import render_history_view
from .views.searchView import render_search_view
from .views.settingsView import render_settings_view
from .views.domainsView import render_domain_list
from .static.styles import load_css

# Configure logging for the application
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Thread-safe initialization lock to prevent race conditions
init_lock = threading.Lock()

def init_session_state():
    """
    Initialize the Streamlit session state with required variables and objects.

    Ensures that all necessary components are initialized only once per session, including:
    - Certificate scanner instance
    - Database engine
    - UI state variables

    Side Effects:
        - Modifies st.session_state to add scanner, engine, and UI state variables.
        - Logs initialization steps.

    Edge Cases:
        - If already initialized, does nothing.
        - If database initialization fails, logs an error.
    """
    with init_lock:
        if 'initialized' not in st.session_state:
            logger.info("Initializing session state...")
            # Initialize the certificate scanner
            st.session_state.scanner = CertificateScanner()
            # Initialize UI state variables
            st.session_state.selected_cert = None
            st.session_state.current_view = "Dashboard"
            # Initialize database connection
            logger.info("Initializing database engine...")
            st.session_state.engine = init_database()
            if st.session_state.engine:
                logger.info("Database engine initialized successfully")
            else:
                logger.error("Failed to initialize database engine")
            st.session_state.initialized = True

def render_sidebar():
    """
    Render the application's sidebar navigation menu.

    Creates a sidebar with:
    - Application title
    - Navigation options with icons
    - Version information

    Returns:
        str: The currently selected view name

    Side Effects:
        - Modifies st.session_state['current_view'] based on user selection.
        - Calls st.rerun() to trigger a rerun on navigation change.
        - Renders sidebar UI elements.

    Edge Cases:
        - If the current view is not in the mapping, defaults to Dashboard.
    """
    with st.sidebar:
        st.title("SRO Infra Manager")
        st.markdown("---")
        
        # Define mapping of page names to their display versions with icons
        page_mapping = {
            "Dashboard": "📊 Dashboard",
            "Certificates": "🔐 Certificates",
            "Domains": "🌐 Domains",
            "Hosts": "💻 Hosts",
            "Applications": "📦 Applications",
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
    """
    Main application entry point and routing function.

    This function:
    1. Initializes the session state
    2. Loads CSS styles
    3. Renders the sidebar navigation
    4. Routes to the appropriate view based on user selection

    Side Effects:
        - Calls init_session_state() to initialize session state.
        - Calls load_css() to load UI styles.
        - Renders the selected view.

    Edge Cases:
        - If an unknown view is selected, nothing is rendered.
    """
    # Initialize session state
    init_session_state()
    
    # Load CSS styles
    load_css()
    
    # Get current view from sidebar
    current_view = render_sidebar()
    
    # Route to the appropriate view based on selection
    if current_view == "Dashboard":
        render_dashboard(st.session_state.engine)
    elif current_view == "Certificates":
        render_certificate_list(st.session_state.engine)
    elif current_view == "Domains":
        render_domain_list(st.session_state.engine)
    elif current_view == "Hosts":
        render_hosts_view(st.session_state.engine)
    elif current_view == "Applications":
        render_applications_view(st.session_state.engine)
    elif current_view == "Scanner":
        render_scan_interface(st.session_state.engine)
    elif current_view == "Search":
        render_search_view(st.session_state.engine)
    elif current_view == "History":
        render_history_view(st.session_state.engine)
    elif current_view == "Settings":
        render_settings_view(st.session_state.engine)

# Make main function available for import
__all__ = ['main']

# Only run main directly if this is the entry point
if __name__ == "__main__":
    main() 