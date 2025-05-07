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
            with SessionManager(engine) as session:
                results = perform_search(session, search_query, search_type, status_filter, platform_filter)
                
                # Handle no results case
                if not results or (
                    ('certificates' not in results or not results['certificates']) and 
                    ('hosts' not in results or not results['hosts'])
                ):
                    st.info("No results found")
                    return
                
                # Display certificate results
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
                
                # Display host and binding results
                if 'hosts' in results and (search_type in ['All', 'Hosts', 'IP Addresses']):
                    st.subheader("Hosts")
                    host_data = []
                    for host in results['hosts']:
                        for ip in host.ip_addresses:
                            for binding in host.certificate_bindings:
                                # Filter by platform if specified
                                if binding.host_ip_id == ip.id and (
                                    platform_filter == "All" or 
                                    binding.platform == platform_filter
                                ):
                                    # Apply certificate status filter
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
        except Exception as e:  # Only Exception is possible here due to DB/UI/unknown errors
            logger.exception(f"Error in search view: {str(e)}")
            notify(f"Error in search view: {str(e)}", "error")

def perform_search(session: Session, query: str, search_type: str, status_filter: str, platform_filter: str) -> dict:
    """
    Perform a comprehensive search across the database based on user criteria.

    This function executes a search across certificates, hosts, and IP addresses
    based on the provided search criteria. It handles multiple entity types and
    applies filters for certificate status and platform.

    Args:
        session: SQLAlchemy session for database operations
        query: Search string to match against various fields
        search_type: Type of entities to search (All/Certificates/Hosts/IP Addresses)
        status_filter: Certificate validity filter (All/Valid/Expired)
        platform_filter: Platform filter for certificate bindings

    Returns:
        dict: Dictionary containing search results with keys:
            - 'certificates': List of matching Certificate objects
            - 'hosts': List of matching Host objects

    Features:
        - Certificate search across:
            - Common Name
            - Serial Number
            - Subject
            - Subject Alternative Names (SAN)
        - Host search across:
            - Hostname
            - IP Addresses
        - Advanced filtering:
            - Certificate validity status
            - Platform-specific bindings
            - Date-based filtering
        - Relationship handling:
            - Certificate-Host relationships
            - IP address bindings
            - Platform configurations

    The function uses SQLAlchemy's query builder to construct efficient
    database queries with appropriate joins and filters.
    """
    results = {}
    now = datetime.now()
    
    # Build base certificate query with relationships
    cert_query = session.query(Certificate).options(
        joinedload(Certificate.certificate_bindings)
        .joinedload(CertificateBinding.host)
        .joinedload(Host.ip_addresses)
    )
    
    # Apply certificate status filter
    if status_filter != "All":
        is_valid = status_filter == "Valid"
        cert_query = cert_query.filter(
            Certificate.valid_until > now if is_valid else Certificate.valid_until <= now
        )
    
    # Apply platform filter to certificate bindings
    if platform_filter != "All":
        cert_query = cert_query.join(CertificateBinding).filter(
            CertificateBinding.platform == platform_filter
        )
    
    # Search certificates if requested
    if search_type in ['All', 'Certificates']:
        results['certificates'] = cert_query.filter(
            or_(
                Certificate.common_name.ilike(f"%{query}%"),
                Certificate.serial_number.ilike(f"%{query}%"),
                Certificate._subject.ilike(f"%{query}%"),
                Certificate._san.ilike(f"%{query}%")
            )
        ).all()
    
    # Search hosts and IPs if requested
    if search_type in ['All', 'Hosts', 'IP Addresses']:
        # Build base host query with relationships
        host_query = session.query(Host).options(
            joinedload(Host.ip_addresses),
            joinedload(Host.certificate_bindings)
            .joinedload(CertificateBinding.certificate)
        )
        
        # Apply platform filter if specified
        if platform_filter != "All":
            host_query = host_query.join(
                CertificateBinding,
                Host.certificate_bindings
            ).filter(
                CertificateBinding.platform == platform_filter
            )
        
        # Apply certificate status filter
        if status_filter != "All":
            is_valid = status_filter == "Valid"
            host_query = host_query.join(
                CertificateBinding,
                Host.certificate_bindings
            ).join(
                Certificate,
                CertificateBinding.certificate
            ).filter(
                Certificate.valid_until > now if is_valid else Certificate.valid_until <= now
            )
        
        # Execute host search query
        results['hosts'] = host_query.filter(
            or_(
                Host.name.ilike(f"%{query}%"),
                Host.ip_addresses.any(HostIP.ip_address.ilike(f"%{query}%"))
            )
        ).all()
    
    return results
