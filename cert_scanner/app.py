import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from cert_scanner.scanner import CertificateScanner, CertificateInfo
from cert_scanner.models import (
    Certificate, Host, HostIP, CertificateScan, CertificateBinding,
    HOST_TYPE_SERVER, HOST_TYPE_LOAD_BALANCER, HOST_TYPE_CDN, HOST_TYPE_VIRTUAL,
    ENV_PRODUCTION, ENV_STAGING, ENV_DEVELOPMENT, ENV_INTERNAL, ENV_EXTERNAL,
    BINDING_TYPE_IP, BINDING_TYPE_JWT, BINDING_TYPE_CLIENT,
    PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION
)
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
import plotly.express as px
from urllib.parse import urlparse
from cert_scanner.constants import platform_options
from cert_scanner.views.dashboardView import render_dashboard
from cert_scanner.views.certificatesView import render_certificate_list
from cert_scanner.views.hostsView import render_hosts_view
from cert_scanner.views.scannerView import render_scan_interface
from cert_scanner.views.historyView import render_history_view
from cert_scanner.views.searchView import render_search_view

# Initialize database connection
engine = create_engine('sqlite:///certificates.db')

# Page configuration
st.set_page_config(
    page_title="Certificate Manager",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Global styling for full width
st.markdown("""
    <style>
        .block-container {
            padding-top: 1rem;
            padding-right: 1rem;
            padding-left: 1rem;
            padding-bottom: 1rem;
        }
        .stDataFrame {
            width: 100%;
        }
        .element-container {
            width: 100%;
        }
    </style>
""", unsafe_allow_html=True)

def init_session_state():
    """Initialize session state variables"""
    if 'scanner' not in st.session_state:
        st.session_state.scanner = CertificateScanner()
    if 'selected_cert' not in st.session_state:
        st.session_state.selected_cert = None

def render_sidebar():
    """Render the sidebar navigation"""
    st.sidebar.title("Certificate Manager")
    
    return st.sidebar.radio(
        "Navigation",
        ["Dashboard", "Certificates", "Hosts", "Scan", "History", "Search"]
    )

def main():
    init_session_state()
    
    # Render sidebar and get current page
    current_page = render_sidebar()
    
    # Render the selected page
    if current_page == "Dashboard":
        render_dashboard(engine)
    elif current_page == "Certificates":
        render_certificate_list(engine)
    elif current_page == "Hosts":
        render_hosts_view(engine)
    elif current_page == "Scan":
        render_scan_interface(engine)
    elif current_page == "History":
        render_history_view(engine)
    elif current_page == "Search":
        render_search_view(engine)

if __name__ == "__main__":
    main() 