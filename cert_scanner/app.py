import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import logging
import threading
from cert_scanner.scanner import CertificateScanner, CertificateInfo
from cert_scanner.models import (
    Certificate, Host, HostIP, CertificateScan, CertificateBinding,
    HOST_TYPE_SERVER, HOST_TYPE_LOAD_BALANCER, HOST_TYPE_CDN, HOST_TYPE_VIRTUAL,
    ENV_PRODUCTION, ENV_STAGING, ENV_DEVELOPMENT, ENV_INTERNAL, ENV_EXTERNAL,
    BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION
)
from sqlalchemy.orm import Session
import plotly.express as px
from urllib.parse import urlparse
from cert_scanner.constants import platform_options
from cert_scanner.db import init_database, get_session
from cert_scanner.views.dashboardView import render_dashboard
from cert_scanner.views.certificatesView import render_certificate_list
from cert_scanner.views.hostsView import render_hosts_view
from cert_scanner.views.scannerView import render_scan_interface
from cert_scanner.views.historyView import render_history_view
from cert_scanner.views.searchView import render_search_view
from cert_scanner.views.settingsView import render_settings_view

__all__ = ['main']  # Explicitly declare what should be exported

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lock for thread-safe initialization
init_lock = threading.Lock()

# Page configuration
st.set_page_config(
    page_title="Certificate Manager",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Global styling for full width and navigation
st.markdown("""
    <style>
        .block-container {
            padding-top: 1rem;
            padding-right: 1rem;
            padding-left: 1rem;
            padding-bottom: 1rem;
            max-width: 100%;
        }
        .stDataFrame {
            width: 100%;
        }
        .element-container {
            width: 100%;
        }
        /* Make all containers full width */
        .stTabs [data-baseweb="tab-panel"] {
            padding-top: 1rem;
            width: 100%;
        }
        section[data-testid="stSidebar"] {
            width: 250px !important;
        }
        /* Main content area */
        .main .block-container {
            padding: 2rem 1rem;
            max-width: none;
        }
        /* Tables and dataframes */
        .stTable, div[data-testid="stTable"] {
            width: 100%;
        }
        /* Forms and inputs */
        .stForm {
            width: 100%;
        }
        /* Metrics and cards */
        [data-testid="stMetricValue"] {
            width: 100%;
        }
        /* Expanders */
        .streamlit-expanderContent {
            width: 100%;
        }
        /* Sidebar styling */
        div[data-testid="stSidebarNav"] {
            padding-top: 2rem;
        }
        div.row-widget.stRadio > div {
            font-size: 1rem;
            line-height: 2.5;
        }
        div.row-widget.stRadio > div[role="radiogroup"] > label {
            padding: 0.5rem 1rem;
            width: 100%;
            cursor: pointer;
        }
        div.row-widget.stRadio > div[role="radiogroup"] > label:hover {
            background-color: rgba(151, 166, 195, 0.15);
        }
    </style>
""", unsafe_allow_html=True)

def init_session_state():
    """Initialize session state variables"""
    with init_lock:
        if 'initialized' not in st.session_state:
            logger.info("Initializing session state...")
            st.session_state.scanner = CertificateScanner()
            st.session_state.selected_cert = None
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
        
        # Navigation list with icons
        selected = st.radio(
            "Navigation",
            options=[
                "📊 Dashboard",
                "🔐 Certificates",
                "💻 Hosts",
                "🔍 Scan",
                "📜 History",
                "🔎 Search",
                "⚙️ Settings"
            ],
            label_visibility="collapsed",
            horizontal=False
        )
        
        # Strip icons for page logic
        current_page = selected.split(" ")[1]
        
        st.markdown("---")
        st.caption("v1.0.0")
        return current_page

def main():
    logger.info("Starting application...")
    init_session_state()
    
    if not st.session_state.engine:
        st.error("Failed to initialize database. Please check your configuration.")
        return
    
    logger.info("Rendering main interface...")
    # Render sidebar and get current page
    current_page = render_sidebar()
    
    # Render the selected page
    if current_page == "Dashboard":
        render_dashboard(st.session_state.engine)
    elif current_page == "Certificates":
        render_certificate_list(st.session_state.engine)
    elif current_page == "Hosts":
        render_hosts_view(st.session_state.engine)
    elif current_page == "Scan":
        render_scan_interface(st.session_state.engine)
    elif current_page == "History":
        render_history_view(st.session_state.engine)
    elif current_page == "Search":
        render_search_view(st.session_state.engine)
    elif current_page == "Settings":
        render_settings_view()

if __name__ == "__main__":
    main() 