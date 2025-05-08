"""
Certificate Search View Module

This module provides a comprehensive search interface for the certificate management system,
allowing users to search across certificates, hosts, and IP addresses. It offers multiple
search filters and views to help users quickly find relevant certificate information.

Key Features:
- Unified search across multiple entities:
  - Certificates (by CN, serial number, subject, SAN)
  - Hosts (by hostname)
  - IP Addresses
- Advanced filtering capabilities:
  - Entity type filtering (Certificates/Hosts/IP Addresses)
  - Certificate status filtering (Valid/Expired)
  - Platform filtering (F5/Akamai/Cloudflare/IIS/Connection)
- Interactive results display:
  - Certificate section with validity status
  - Host section with binding information
  - Real-time filtering and sorting
  - Detailed certificate properties
- Comprehensive result information:
  - Certificate details (CN, serial number, validity)
  - Host information (hostname, IP, platform)
  - Binding details (ports, last seen)
  - Status indicators and metrics

The module uses Streamlit for the UI and provides real-time search results
as users type, making it easy to find and analyze certificate information.
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, and_, String

from infra_mgmt.notifications import notify
from ..models import Certificate, Host, HostIP, CertificateBinding
from infra_mgmt.utils.SessionManager import SessionManager
from ..static.styles import load_warning_suppression, load_css
import logging
from infra_mgmt.services.ViewDataService import ViewDataService

# Add logger setup at the top
logger = logging.getLogger(__name__)

def render_search_view(engine) -> None:
    """
    Render the main certificate search interface.

    This function creates an interactive search interface that allows users to
    search across certificates, hosts, and IP addresses with advanced filtering
    capabilities. It provides real-time results and detailed information about
    found certificates and their relationships.

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Search input field with placeholder text
        - Multiple search filters:
            - Entity type selection (All/Certificates/Hosts/IP Addresses)
            - Certificate status filter (All/Valid/Expired)
            - Platform filter (All/F5/Akamai/Cloudflare/IIS/Connection)
        - Results display:
            - Certificate section with validity information
            - Host section with binding details
            - Interactive data grids with sorting/filtering
        - Status indicators:
            - Valid/Expired status highlighting
            - Last seen timestamps
            - Platform information

    The view maintains a clean and organized interface while providing
    comprehensive search capabilities across all certificate-related entities.
    """
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Create header layout
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("Search")
    with col2:
        st.write("")  # Empty space for layout consistency
    
    # Main search input field
    search_query = st.text_input(
        "Search certificates, hosts, or IP addresses",
        placeholder="Enter hostname, IP, common name, serial number..."
    ).strip()
    
    # Search filter controls
    col1, col2, col3 = st.columns(3)
    with col1:
        search_type = st.selectbox(
            "Search In",
            ["All", "Certificates", "Hosts", "IP Addresses"]
        )
    with col2:
        status_filter = st.selectbox(
            "Certificate Status",
            ["All", "Valid", "Expired"]
        )
    with col3:
        platform_filter = st.selectbox(
            "Platform",
            ["All", "F5", "Akamai", "Cloudflare", "IIS", "Connection"]
        )
    
    # Process search and display results
    if search_query:
        try:
            # Fetch data for search results
            result = ViewDataService().get_search_view_data(engine, search_query, search_type, status_filter, platform_filter)
            if not result['success']:
                notify(result['error'], "error")
                return
            df = result['data']['df']
            column_config = result['data']['column_config']
            # Use df and column_config for display
            if df.empty:
                st.info("No results found")
            else:
                st.dataframe(
                    df,
                    column_config=column_config,
                    hide_index=True,
                    use_container_width=True
                )
        except Exception as e:
            logger.exception(f"Error in search view: {str(e)}")
            notify(f"Error in search view: {str(e)}", "error")
