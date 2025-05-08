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
from ..db import SessionManager
from ..static.styles import load_warning_suppression, load_css
import logging
from ..services.ViewDataService import ViewDataService

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
            view_data_service = ViewDataService()
            result = view_data_service.get_search_view_data(engine, search_query, search_type, status_filter, platform_filter)
            if not result['success']:
                notify(result['error'], "error")
                return
            results = result['data']
            if not results or (
                ('certificates' not in results or not results['certificates']) and 
                ('hosts' not in results or not results['hosts'])
            ):
                st.info("No results found")
                return
            if 'certificates' in results and (search_type in ['All', 'Certificates']):
                st.subheader("Certificates")
                cert_data = []
                for cert in results['certificates']:
                    cert_data.append({
                        "Common Name": cert.common_name,
                        "Serial Number": cert.serial_number,
                        "Valid Until": cert.valid_until,
                        "Status": "Valid" if cert.valid_until > datetime.now() else "Expired",
                        "Bindings": len(cert.certificate_bindings)
                    })
                if cert_data:
                    df = pd.DataFrame(cert_data)
                    st.dataframe(
                        df,
                        column_config={
                            "Common Name": st.column_config.TextColumn("Common Name", width="large"),
                            "Serial Number": st.column_config.TextColumn("Serial Number", width="medium"),
                            "Valid Until": st.column_config.DatetimeColumn("Valid Until", format="DD/MM/YYYY"),
                            "Status": st.column_config.TextColumn("Status", width="small"),
                            "Bindings": st.column_config.NumberColumn("Bindings", width="small")
                        },
                        hide_index=True,
                        use_container_width=True
                    )
            if 'hosts' in results and (search_type in ['All', 'Hosts', 'IP Addresses']):
                st.subheader("Hosts")
                host_data = []
                for host in results['hosts']:
                    for ip in host.ip_addresses:
                        for binding in host.certificate_bindings:
                            if binding.host_ip_id == ip.id and (
                                platform_filter == "All" or 
                                binding.platform == platform_filter
                            ):
                                is_valid = binding.certificate.valid_until > datetime.now()
                                if status_filter == "All" or (
                                    (status_filter == "Valid") == is_valid
                                ):
                                    host_data.append({
                                        "Hostname": host.name,
                                        "IP Address": ip.ip_address,
                                        "Port": binding.port,
                                        "Certificate": binding.certificate.common_name,
                                        "Platform": binding.platform or "Unknown",
                                        "Last Seen": binding.last_seen
                                    })
                if host_data:
                    df = pd.DataFrame(host_data)
                    st.dataframe(
                        df,
                        column_config={
                            "Hostname": st.column_config.TextColumn("Hostname", width="large"),
                            "IP Address": st.column_config.TextColumn("IP Address", width="medium"),
                            "Port": st.column_config.NumberColumn("Port", width="small"),
                            "Certificate": st.column_config.TextColumn("Certificate", width="large"),
                            "Platform": st.column_config.TextColumn("Platform", width="small"),
                            "Last Seen": st.column_config.DatetimeColumn("Last Seen", format="DD/MM/YYYY HH:mm")
                        },
                        hide_index=True,
                        use_container_width=True
                    )
        except Exception as e:
            logger.exception(f"Error in search view: {str(e)}")
            notify(f"Error in search view: {str(e)}", "error")
