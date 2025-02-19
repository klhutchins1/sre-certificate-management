"""
Certificate Scanner View Module

This module provides the interface for scanning and discovering SSL/TLS certificates
across hosts and networks. It offers a user-friendly interface for initiating scans,
monitoring progress, and viewing results in real-time.

Key Features:
- Multiple input formats for scan targets
- Batch scanning capabilities
- Real-time scan progress monitoring
- Detailed scan results display
- Automatic certificate discovery
- Error handling and reporting
- Recent scan history tracking
- Database integration for results storage

The module handles various input formats, validates targets, manages scan operations,
and provides immediate feedback on scan progress and results. It integrates with
the database to store discovered certificates and their relationships with hosts.
"""

import streamlit as st
from datetime import datetime
from sqlalchemy.orm import Session
from urllib.parse import urlparse
from ..models import (
    Certificate, Host, HostIP, CertificateScan, CertificateBinding,
    HOST_TYPE_SERVER, ENV_PRODUCTION
)
from ..static.styles import load_warning_suppression, load_css
import json
from typing import Tuple


def validate_port(port_str: str, entry: str) -> Tuple[bool, int]:
    """
    Validate a port number string.
    
    Args:
        port_str: The port number as a string
        entry: The full entry string for error messages
        
    Returns:
        Tuple[bool, int]: (is_valid, port_number)
    """
    print(f"DEBUG: Validating port: {port_str} from entry: {entry}")  # Debug log
    try:
        port = int(port_str)
        print(f"DEBUG: Converted port to integer: {port}")  # Debug log
        if port < 0:
            print(f"DEBUG: Port is negative: {port}")  # Debug log
            st.error(f"Invalid port number in {entry}: Port cannot be negative")
            return False, 0
        if port > 65535:
            print(f"DEBUG: Port is too large: {port}")  # Debug log
            st.error(f"Invalid port number in {entry}: Port must be between 1 and 65535")
            return False, 0
        print(f"DEBUG: Port is valid: {port}")  # Debug log
        return True, port
    except ValueError as e:
        print(f"DEBUG: ValueError converting port: {str(e)}")  # Debug log
        st.error(f"Invalid port number in {entry}: '{port_str}' is not a valid number")
        return False, 0

def render_scan_interface(engine) -> None:
    """
    Render the main certificate scanning interface.

    This function provides a comprehensive interface for scanning SSL/TLS certificates,
    including input validation, progress tracking, and results display. It handles:
    - Multiple input formats for scan targets
    - Real-time scan progress monitoring
    - Result storage and display
    - Error handling and reporting

    Args:
        engine: SQLAlchemy engine instance for database connections

    Features:
        - Flexible input formats:
            - Standard hostnames
            - Custom ports
            - URLs with protocols
            - IP addresses
        - Input validation:
            - Port range checking
            - Hostname validation
            - Format verification
        - Progress tracking:
            - Real-time progress bar
            - Status updates
            - Error reporting
        - Results management:
            - Success/failure tracking
            - Database storage
            - Recent scan history
        - Error handling:
            - Connection errors
            - Certificate retrieval failures
            - Database errors

    The interface maintains state using Streamlit's session state for scan results
    and provides comprehensive error handling for all operations.
    """
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Clear transitioning flag if set
    if st.session_state.get('transitioning', False):
        st.session_state.transitioning = False
        
    st.title("Scan Certificates")
    
    # Initialize scan results state
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = {
            "success": [],
            "error": [],
            "warning": []
        }
    
    # Create main layout columns
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Handle pre-populated scan targets
        default_scan_targets = st.session_state.get('scan_targets', [])
        if default_scan_targets:
            # Ensure we have a list of strings
            if isinstance(default_scan_targets, str):
                default_scan_targets = [default_scan_targets]
            # Clean up the targets
            default_scan_targets = [s.strip() for s in default_scan_targets if s.strip()]
            default_text = "\n".join(default_scan_targets)
        else:
            default_text = ""
        
        # Scan input interface
        scan_input = st.text_area(
            "Enter hostnames to scan (one per line)",
            value=default_text,
            height=150,
            placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
        )
        
        # Input format help section
        with st.expander("ℹ️ Input Format Help"):
            st.markdown("""
            Enter one host per line in any of these formats:
            ```
            example.com                    # Standard HTTPS (port 443)
            example.com:8443              # Custom port
            https://example.com           # URLs are automatically parsed
            http://internal.local:8080    # Any protocol and port
            10.0.0.1                      # IP addresses
            10.0.0.1:444                  # IP with custom port
            ```
            The scanner will:
            - Strip any protocol (http://, https://, etc.)
            - Use port 443 if not specified
            - Handle both hostnames and IP addresses
            
            **Port Numbers:**
            - Must be between 1 and 65535
            - Common ports:
              - 443: HTTPS (default)
              - 8443: Alternative HTTPS
              - 4443: Alternative HTTPS
              - 8080: Alternative HTTP
            """)
        
        # Scan initiation button
        scan_button_clicked = st.button("Start Scan")
        
        # Handle scan initiation
        if scan_button_clicked:
            # Reset scan results
            st.session_state.scan_results = {
                "success": [],
                "error": [],
                "warning": []
            }
            
            # Validate input
            if not scan_input.strip():
                st.error("Please enter at least one hostname to scan")
                return
            
            # Parse and validate scan targets
            entries = [h.strip() for h in scan_input.split('\n') if h.strip()]
            scan_targets = []
            validation_errors = False
            
            # Process each target
            for entry in entries:
                try:
                    # First check if input contains a scheme
                    has_scheme = entry.startswith(('http://', 'https://'))
                    
                    if has_scheme:
                        # Parse as URL
                        parsed = urlparse(entry)
                        print(f"DEBUG: URL parse result: {parsed}")  # Debug log
                        
                        # Get hostname from netloc
                        hostname = parsed.netloc
                        print(f"DEBUG: Using netloc as hostname: {hostname}")  # Debug log
                        
                        # Check if port is in netloc
                        if ':' in hostname:
                            hostname, port_str = hostname.rsplit(':', 1)
                            print(f"DEBUG: Split hostname and port from netloc: {hostname}, {port_str}")  # Debug log
                            is_valid, port = validate_port(port_str, entry)
                            if not is_valid:
                                validation_errors = True
                                continue
                        elif parsed.port:
                            is_valid, port = validate_port(str(parsed.port), entry)
                            if not is_valid:
                                validation_errors = True
                                continue
                        else:
                            port = 443  # Default port for URLs
                    else:
                        # Handle hostname:port format
                        if ':' in entry:
                            hostname, port_str = entry.rsplit(':', 1)
                            print(f"DEBUG: Split hostname and port from entry: {hostname}, {port_str}")  # Debug log
                            
                            # Validate port number
                            is_valid, port = validate_port(port_str, entry)
                            if not is_valid:
                                validation_errors = True
                                continue
                        else:
                            hostname = entry
                            port = 443  # Default port
                    
                    # Validate hostname
                    hostname = hostname.strip('/')
                    if not hostname:
                        st.error(f"Invalid entry: {entry} - Hostname cannot be empty")
                        validation_errors = True
                        continue
                    
                    print(f"DEBUG: Final hostname and port: {hostname}, {port}")  # Debug log
                    
                    scan_targets.append((hostname, port))
                except Exception as e:
                    st.error(f"Error parsing {entry}: Please check the format")
                    validation_errors = True
                    continue
            
            # Handle validation errors
            if validation_errors:
                st.error("Please enter at least one valid hostname to scan")
                return
            
            # Execute scans
            if scan_targets:
                # Create progress tracking containers
                progress_container = st.empty()
                status_container = st.empty()
                
                with progress_container:
                    st.markdown("""
                        <style>
                        .stProgress > div > div > div > div {
                            background-color: #0066ff;
                        }
                        </style>
                        """, unsafe_allow_html=True)
                    progress = st.progress(0)
                
                # Execute scans with progress tracking
                with status_container:
                    with st.spinner('Scanning certificates...'):
                        for i, (hostname, port) in enumerate(scan_targets):
                            status_container.text(f'Scanning {hostname}:{port}...')
                            try:
                                # Perform certificate scan
                                cert_info = st.session_state.scanner.scan_certificate(hostname, port)
                                if cert_info:
                                    st.session_state.scan_results["success"].append(f"{hostname}:{port}")
                                    # Save scan results to database
                                    with Session(engine) as session:
                                        try:
                                            # Process certificate information
                                            cert = session.query(Certificate).filter_by(
                                                serial_number=cert_info.serial_number
                                            ).first()
                                            
                                            if not cert:
                                                cert = Certificate(
                                                    serial_number=cert_info.serial_number,
                                                    thumbprint=cert_info.thumbprint,
                                                    common_name=cert_info.common_name,
                                                    valid_from=cert_info.valid_from,
                                                    valid_until=cert_info.expiration_date,
                                                    _issuer=json.dumps(cert_info.issuer),
                                                    _subject=json.dumps(cert_info.subject),
                                                    _san=json.dumps(cert_info.san),
                                                    key_usage=cert_info.key_usage,
                                                    signature_algorithm=cert_info.signature_algorithm,
                                                    chain_valid=cert_info.chain_valid,
                                                    sans_scanned=False
                                                )
                                                session.add(cert)
                                            else:
                                                # Update existing certificate
                                                cert.thumbprint = cert_info.thumbprint
                                                cert.common_name = cert_info.common_name
                                                cert.valid_from = cert_info.valid_from
                                                cert.valid_until = cert_info.expiration_date
                                                cert._issuer = json.dumps(cert_info.issuer)
                                                cert._subject = json.dumps(cert_info.subject)
                                                cert._san = json.dumps(cert_info.san)
                                                cert.key_usage = cert_info.key_usage
                                                cert.signature_algorithm = cert_info.signature_algorithm
                                                cert.chain_valid = cert_info.chain_valid
                                                cert.sans_scanned = False
                                                cert.updated_at = datetime.now()
                                            
                                            # Process host information
                                            host = session.query(Host).filter_by(
                                                name=cert_info.hostname
                                            ).first()
                                            
                                            if not host:
                                                host = Host(
                                                    name=cert_info.hostname,
                                                    host_type=HOST_TYPE_SERVER,
                                                    environment=ENV_PRODUCTION,
                                                    last_seen=datetime.now()
                                                )
                                                session.add(host)
                                            else:
                                                host.last_seen = datetime.now()
                                            
                                            # Process IP addresses and bindings
                                            for ip in cert_info.ip_addresses:
                                                host_ip = session.query(HostIP).filter_by(
                                                    host_id=host.id,
                                                    ip_address=ip
                                                ).first()
                                                
                                                if not host_ip:
                                                    host_ip = HostIP(
                                                        host_id=host.id,
                                                        ip_address=ip,
                                                        last_seen=datetime.now()
                                                    )
                                                    session.add(host_ip)
                                                else:
                                                    host_ip.last_seen = datetime.now()
                                                
                                                # Update certificate bindings
                                                binding = session.query(CertificateBinding).filter_by(
                                                    host_id=host.id,
                                                    host_ip_id=host_ip.id,
                                                    port=cert_info.port
                                                ).first()
                                                
                                                if binding:
                                                    binding.certificate_id = cert.id
                                                    binding.last_seen = datetime.now()
                                                else:
                                                    binding = CertificateBinding(
                                                        host_id=host.id,
                                                        host_ip_id=host_ip.id,
                                                        certificate_id=cert.id,
                                                        port=cert_info.port,
                                                        binding_type='IP',
                                                        last_seen=datetime.now()
                                                    )
                                                    session.add(binding)
                                            
                                            # Record successful scan
                                            scan = CertificateScan(
                                                certificate=cert,
                                                scan_date=datetime.now(),
                                                status='Valid',
                                                port=cert_info.port
                                            )
                                            session.add(scan)
                                            
                                            session.commit()
                                            
                                            # Update sans_scanned flag if this was a SAN scan
                                            if st.session_state.get('scan_targets') and isinstance(st.session_state.scan_targets, list):
                                                # Set sans_scanned to True since we've attempted the scan
                                                cert.sans_scanned = True
                                                session.commit()
                                            
                                        except Exception as e:
                                            st.session_state.scan_results["error"].append(f"{hostname}:{port} - Database error: {str(e)}")
                                            session.rollback()
                                else:
                                    # Handle failed certificate retrieval
                                    st.session_state.scan_results["error"].append(f"{hostname}:{port} - Failed to retrieve certificate")
                                    with Session(engine) as session:
                                        try:
                                            # Record failed scan
                                            host = session.query(Host).filter_by(name=hostname).first()
                                            if not host:
                                                host = Host(
                                                    name=hostname,
                                                    host_type=HOST_TYPE_SERVER,
                                                    environment=ENV_PRODUCTION,
                                                    last_seen=datetime.now()
                                                )
                                                session.add(host)
                                                session.flush()

                                            scan = CertificateScan(
                                                scan_date=datetime.now(),
                                                status='Failed',
                                                port=port,
                                                host_id=host.id
                                            )
                                            session.add(scan)
                                            session.commit()
                                        except Exception as e:
                                            logger.error(f"Failed to record failed scan: {str(e)}")
                                            session.rollback()
                            except Exception as e:
                                # Handle other errors
                                error_msg = f"Error scanning {hostname}:{port} - {str(e)}"
                                st.error(error_msg)
                                st.session_state.scan_results["error"].append(error_msg)
                                with Session(engine) as session:
                                    try:
                                        # Record failed scan
                                        host = session.query(Host).filter_by(name=hostname).first()
                                        if not host:
                                            host = Host(
                                                name=hostname,
                                                host_type=HOST_TYPE_SERVER,
                                                environment=ENV_PRODUCTION,
                                                last_seen=datetime.now()
                                            )
                                            session.add(host)
                                            session.flush()

                                        scan = CertificateScan(
                                            scan_date=datetime.now(),
                                            status='Failed',
                                            port=port,
                                            host_id=host.id
                                        )
                                        session.add(scan)
                                        session.commit()
                                    except Exception as e:
                                        logger.error(f"Failed to record failed scan: {str(e)}")
                                        session.rollback()
                            
                            # Update progress
                            progress.progress((i + 1) / len(scan_targets))
                
                # Clear status after completion
                status_container.empty()
                
                # Clear scan targets after successful scan
                if 'scan_targets' in st.session_state:
                    del st.session_state.scan_targets
            else:
                st.error("Please enter at least one valid hostname to scan")
    
    # Recent scans sidebar
    with col2:
        st.subheader("Recent Scans")
        with Session(engine) as session:
            recent_scans = session.query(CertificateScan)\
                .outerjoin(Certificate)\
                .order_by(CertificateScan.scan_date.desc())\
                .limit(5)\
                .all()
            
            if recent_scans:
                st.markdown("<div class='text-small'>", unsafe_allow_html=True)
                for scan in recent_scans:
                    scan_time = scan.scan_date.strftime("%Y-%m-%d %H:%M")
                    if scan.certificate:
                        cert_name = scan.certificate.common_name
                        status_class = "text-success" if scan.status == 'Valid' else "text-danger"
                        st.markdown(
                            f"**{cert_name}** "
                            f"<span class='text-muted'>"
                            f"(🕒 {scan_time} • <span class='{status_class}'>{scan.status}</span>)</span>",
                            unsafe_allow_html=True
                        )
                    else:
                        # Get host information for failed scan
                        host = session.query(Host).filter_by(id=scan.host_id).first()
                        host_info = f"{host.name}:{scan.port}" if host else "Unknown Host"
                        st.markdown(
                            f"**{host_info}** "
                            f"<span class='text-muted'>"
                            f"(🕒 {scan_time} • <span class='text-danger'>Failed</span>)</span>",
                            unsafe_allow_html=True
                        )
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.info("No recent scans")
    
    # Display scan results summary
    if any(st.session_state.scan_results.values()):
        st.divider()
        st.subheader("Current Scan Results")
        
        if st.session_state.scan_results["success"]:
            st.markdown("#### ✅ Successfully Scanned")
            for host in st.session_state.scan_results["success"]:
                st.markdown(f"- {host}")
        
        if st.session_state.scan_results["error"]:
            st.markdown("#### ❌ Failed to Scan")
            for host in st.session_state.scan_results["error"]:
                st.markdown(f"- {host}")
        
        if st.session_state.scan_results["warning"]:
            st.markdown("#### ⚠️ Warnings")
            for host in st.session_state.scan_results["warning"]:
                st.markdown(f"- {host}")
        
        st.success(f"Scan completed! Found {len(st.session_state.scan_results['success'])} certificates.")

def render_scan_results() -> None:
    """
    Render the scan results section showing success, failures, and warnings.

    This function displays a comprehensive summary of certificate scan results,
    organized into three categories:
    - Successful scans
    - Failed scans
    - Warning messages

    Features:
        - Categorized results display:
            - Success section with valid certificates
            - Error section with failed scans
            - Warning section for potential issues
        - Detailed information for each result:
            - Hostname and port
            - Scan timestamp
            - Status indicators
        - Visual status indicators:
            - Success: Green checkmark
            - Error: Red X
            - Warning: Yellow triangle
        - Formatted timestamps
        - Monospace formatting for technical details

    The function handles both string-based messages and scan result objects,
    providing consistent formatting and visual indicators for each type.
    Results are stored in Streamlit's session state for persistence between
    reruns.
    """
    # Display successful scans
    if st.session_state.scan_results["success"]:
        st.markdown("### ✅ Successful Scans")
        for scan in st.session_state.scan_results["success"]:
            if isinstance(scan, str):
                st.markdown(scan)
            else:
                scan_time = scan.scan_date.strftime("%Y-%m-%d %H:%M")
                chain_status = "🔒 Valid Chain" if scan.certificate and scan.certificate.chain_valid else "⚠️ Unverified Chain"
                st.markdown(
                    f"<span class='text-monospace d-block'>{scan.hostname}:{scan.port} "
                    f"(🕒 {scan_time} • <span class='text-success'>Valid</span> • {chain_status})</span>",
                    unsafe_allow_html=True
                )
    
    # Display failed scans
    if st.session_state.scan_results["error"]:
        st.markdown("### ❌ Failed Scans")
        for scan in st.session_state.scan_results["error"]:
            if isinstance(scan, str):
                st.markdown(scan)
            else:
                scan_time = scan.scan_date.strftime("%Y-%m-%d %H:%M")
                st.markdown(
                    f"<span class='text-monospace d-block'>{scan.hostname}:{scan.port} "
                    f"(🕒 {scan_time} • <span class='text-danger'>Failed</span>)</span>",
                    unsafe_allow_html=True
                )
    
    # Display warning messages
    if st.session_state.scan_results["warning"]:
        st.markdown("### ⚠️ Warnings")
        for scan in st.session_state.scan_results["warning"]:
            if isinstance(scan, str):
                st.markdown(scan)
            else:
                scan_time = scan.scan_date.strftime("%Y-%m-%d %H:%M")
                st.markdown(
                    f"<span class='text-monospace d-block'>{scan.hostname}:{scan.port} "
                    f"(🕒 {scan_time} • <span class='text-warning'>Warning</span>)</span>",
                    unsafe_allow_html=True
                )
