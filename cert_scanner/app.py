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

# Force wide mode programmatically
st.markdown("""
    <script>
        // Force wide mode in local storage
        localStorage.setItem('stWideModeEnabled', 'true');
        
        // Force wide mode through UI
        const observer = new MutationObserver(function(mutations) {
            // Force wide mode in local storage again
            localStorage.setItem('stWideModeEnabled', 'true');
            
            // Find and click the wide mode button if needed
            const layoutButton = document.querySelector('button[data-testid="baseButton-header-layoutButton"]');
            const wideModeCheckbox = document.querySelector('input[name="wideMode"]');
            
            if (layoutButton && !layoutButton.classList.contains('wide')) {
                layoutButton.click();
            }
            
            if (wideModeCheckbox && !wideModeCheckbox.checked) {
                wideModeCheckbox.checked = true;
                wideModeCheckbox.dispatchEvent(new Event('change', { bubbles: true }));
            }
        });
        
        observer.observe(document.body, { childList: true, subtree: true });
        
        // Prevent wide mode from being disabled
        document.addEventListener('change', function(e) {
            if (e.target.name === 'wideMode' && !e.target.checked) {
                e.preventDefault();
                e.target.checked = true;
                localStorage.setItem('stWideModeEnabled', 'true');
            }
        }, true);
    </script>
""", unsafe_allow_html=True)

# Hide all Streamlit UI elements 
st.markdown("""
    <style>
        
        /* Force wide mode */
        .stApp > header + div {
            max-width: none !important;
            padding-left: 1rem !important;
            padding-right: 1rem !important;
        }
        
        /* Force wide mode for all containers */
        .element-container, .stBlock {
            width: 100% !important;
            max-width: none !important;
            padding-left: 0 !important;
            padding-right: 0 !important;
        }
        
        /* Force wide mode for dataframes */
        .stDataFrame {
            width: 100% !important;
            max-width: none !important;
        }
        
        /* Hide layout toggle button */
        button[data-testid="baseButton-header-layoutButton"] {
            display: none !important;
        }
        
        .stApp > div[data-testid="stDecoration"] {
            display: none !important;
        }
        
        /* Hide main menu button */
        #MainMenu {display: none !important;}
        
        /* Hide header */
        header {display: none !important;}
        
        /* Hide footer */
        footer {display: none !important;}
        
        /* Hide hamburger menu */
        [data-testid="collapsedControl"] {display: none !important;}
        
        /* Hide toolbar */
        div[data-testid="stToolbar"] {display: none !important;}
        div[data-testid="stDecoration"] {display: none !important;}
        div[data-testid="stStatusWidget"] {display: none !important;}
        
        /* Hide deploy button */
        button[title="Deploy"] {display: none !important;}
        
        /* Remove top padding from sidebar */
        section[data-testid="stSidebarUserContent"] {padding-top: 0rem;}
        
        /* Remove extra padding from main content */
        .main > div {padding-top: 1rem;}
        .reportview-container {margin-top: -2em;}
        
        /* Hide all Streamlit branding elements */
        .stDeployButton {display: none !important;}
        .stToolbar {display: none !important;}
        .stApp > header {display: none !important;}
        .stApp > footer {display: none !important;}
        
        
        /* Ensure wide mode for all blocks */
        div[data-testid="stBlock"] {
            max-width: none !important;
            width: 100% !important;
        }
    </style>
""", unsafe_allow_html=True)

__all__ = ['main']  # Explicitly declare what should be exported

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lock for thread-safe initialization
init_lock = threading.Lock()



# Add CSS for consistent layout

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
            "Scan": "🔍 Scan",
            "History": "📜 History",
            "Search": "🔎 Search",
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
    try:
        # Initialize session state
        init_session_state()
        
        # Get current view from sidebar
        current_view = render_sidebar()
        
        # Render the appropriate view
        if current_view == "Dashboard":
            render_dashboard(st.session_state.engine)
        elif current_view == "Certificates":
            render_certificate_list(st.session_state.engine)
        elif current_view == "Hosts":
            render_hosts_view(st.session_state.engine)
        elif current_view == "Scan":
            render_scan_interface(st.session_state.engine)
        elif current_view == "History":
            render_history_view(st.session_state.engine)
        elif current_view == "Search":
            render_search_view(st.session_state.engine)
        elif current_view == "Settings":
            render_settings_view(st.session_state.engine)
    except Exception as e:
        st.error(f"Error rendering view: {str(e)}")

if __name__ == "__main__":
    main() 