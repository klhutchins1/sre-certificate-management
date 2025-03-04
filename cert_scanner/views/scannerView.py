"""
Domain and Certificate Scanner View Module

This module provides a comprehensive interface for scanning and discovering:
- SSL/TLS certificates
- Domain information and registration details
- DNS records
- Host relationships
- Certificate-domain associations

The scanner automatically creates and updates domain records while scanning
certificates, providing a complete view of the domain's security infrastructure.
"""

import streamlit as st
from datetime import datetime
from sqlalchemy.orm import Session
from urllib.parse import urlparse
import socket
import logging
from ..models import (
    Certificate, Host, HostIP, CertificateScan, CertificateBinding,
    Domain, DomainDNSRecord,
    HOST_TYPE_SERVER, ENV_PRODUCTION
)
from ..static.styles import load_warning_suppression, load_css
from ..domain_scanner import DomainScanner, DomainInfo
from ..scanner import CertificateScanner, CertificateInfo, ScanResult
from cert_scanner.notifications import initialize_notifications, show_notifications, notify
import json
from typing import Tuple, Dict, List, Optional
import pandas as pd
from ..subdomain_scanner import SubdomainScanner

# Configure logging
logger = logging.getLogger(__name__)

# Create console handler if it doesn't exist
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    # Set UTF-8 encoding for the handler
    console_handler.stream.reconfigure(encoding='utf-8')
    logger.addHandler(console_handler)

def validate_port(port_str: str, entry: str) -> Tuple[bool, int]:
    """
    Validate a port number string.
    
    Args:
        port_str: The port number as a string
        entry: The full entry string for error messages
        
    Returns:
        Tuple[bool, int]: (is_valid, port_number)
    """
    try:
        port = int(port_str)
        if port < 0:
            notify("Invalid port number in {}: Port cannot be negative", "error", entry)
            return False, 0
        if port > 65535:
            notify("Invalid port number in {}: Port must be between 1 and 65535", "error", entry)
            return False, 0
        return True, port
    except ValueError as e:
        notify("Invalid port number in {}: '{}' is not a valid number", "error", entry, port_str)
        return False, 0

def render_scan_interface(engine) -> None:
    """Render the main domain and certificate scanning interface."""
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Initialize notifications at the very beginning
    initialize_notifications()
    
    # Create a placeholder for notifications at the top
    notification_placeholder = st.empty()
    
    # Initialize scanners
    if 'domain_scanner' not in st.session_state:
        st.session_state.domain_scanner = DomainScanner()
    if 'scanner' not in st.session_state:
        st.session_state.scanner = CertificateScanner()
    if 'subdomain_scanner' not in st.session_state:
        st.session_state.subdomain_scanner = SubdomainScanner()
    
    # Initialize session state for tracking scanned domains
    if 'scanned_domains' not in st.session_state:
        st.session_state.scanned_domains = set()
    
    # Clear transitioning flag if set
    if st.session_state.get('transitioning', False):
        st.session_state.transitioning = False
    
    st.title("Domain & Certificate Scanner")
    st.markdown("""
    This scanner performs comprehensive domain analysis including:
    - SSL/TLS certificates
    - Domain registration information
    - DNS records
    - Host relationships
    """)
    
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
        # Create two columns for input and options
        input_col, options_col = st.columns([3, 2])
        
        with input_col:
            # Handle pre-populated scan targets
            default_scan_targets = st.session_state.get('scan_targets', [])
            if default_scan_targets:
                if isinstance(default_scan_targets, str):
                    default_scan_targets = [default_scan_targets]
                default_scan_targets = [s.strip() for s in default_scan_targets if s.strip()]
                default_text = "\n".join(default_scan_targets)
            else:
                default_text = ""
            
            # Scan input interface
            scan_input = st.text_area(
                "Enter domains to scan (one per line)",
                value=default_text,
                height=150,
                placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
            )
        
        with options_col:
            st.markdown("### Scan Options")
            check_dns = st.checkbox("Scan DNS Records", value=True)
            check_whois = st.checkbox("Get WHOIS Info", value=True)
            check_subdomains = st.checkbox("Include Subdomains", value=True)
            check_related = st.checkbox("Find Related Domains", value=True)
        
        # Scan initiation button below both columns
        scan_button_clicked = st.button("Start Scan", type="primary")
        
        # Input format help section
        with st.expander("ℹ️ Input Format Help"):
            st.markdown("""
            Enter one domain per line in any of these formats:
            ```
            example.com                    # Standard HTTPS (port 443)
            example.com:8443              # Custom port
            https://example.com           # URLs are automatically parsed
            http://internal.local:8080    # Any protocol and port
            ```
            
            The scanner will:
            1. Gather domain information:
               - Registration details
               - DNS records
               - Expiration dates
            2. Check SSL/TLS certificates:
               - All specified ports
               - Certificate validity
               - Chain verification
            3. Create relationships:
               - Domain-certificate associations
               - Parent-child domain relationships
               - Host mappings
            """)
        
        # Handle scan initiation
        if scan_button_clicked:
            logger.info("[SCAN] Starting new scan session")
            # Reset scan results but keep scanned domains history
            st.session_state.scan_results = {
                "success": [],
                "error": [],
                "warning": []
            }
            
            # Validate input
            if not scan_input.strip():
                notify("Please enter at least one domain to scan", "error")
                show_notifications()
                return
            
            # Parse and validate scan targets
            entries = [h.strip() for h in scan_input.split('\n') if h.strip()]
            scan_targets = []
            validation_errors = False
            
            # Process each target
            for entry in entries:
                try:
                    # Parse entry (existing parsing code)
                    has_scheme = entry.startswith(('http://', 'https://'))
                    
                    if has_scheme:
                        parsed = urlparse(entry)
                        hostname = parsed.netloc
                        if ':' in hostname:
                            hostname, port_str = hostname.rsplit(':', 1)
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
                            port = 443
                    else:
                        if ':' in entry:
                            hostname, port_str = entry.rsplit(':', 1)
                            is_valid, port = validate_port(port_str, entry)
                            if not is_valid:
                                validation_errors = True
                                continue
                        else:
                            hostname = entry
                            port = 443
                    
                    hostname = hostname.strip('/')
                    if not hostname:
                        notify("Invalid entry: {} - Hostname cannot be empty", "error", entry)
                        validation_errors = True
                        continue
                    
                    # Add validated target if not already scanned in this session
                    if hostname not in st.session_state.scanned_domains:
                        scan_targets.append((hostname, port))
                        st.session_state.scanned_domains.add(hostname)
                    else:
                        logger.info(f"[SCAN] Skipping {hostname} - Already scanned in this session")
                        notify("{hostname} - Skipped (already scanned in this session)", "warning")
                        continue
                except Exception as e:
                    notify("Error parsing {}: Please check the format", "error", entry)
                    validation_errors = True
                    continue
                    
            # Show notifications at the end using the placeholder
            with notification_placeholder:
                show_notifications()
            
            # Handle validation errors
            if validation_errors:
                notify("Please correct the errors above", "error")
                show_notifications()
                return
            
            # Execute scans
            if scan_targets:
                logger.info(f"[SCAN] Processing {len(scan_targets)} scan targets")
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
                    with st.spinner('Scanning domains and certificates...'):
                        # Expand scan targets with subdomains if enabled
                        expanded_targets = []
                        total_domains = len(scan_targets)
                        current_domain = 0
                        
                        for hostname, port in scan_targets:
                            current_domain += 1
                            expanded_targets.append((hostname, port))
                            
                            if check_subdomains:
                                try:
                                    logger.info(f"[SCAN] Searching for subdomains of {hostname}")
                                    status_container.text(f'Searching for subdomains of {hostname}...')
                                    
                                    # Update progress for subdomain search
                                    progress.progress(current_domain / (total_domains * 2))
                                    
                                    # Get subdomains using all available methods
                                    subdomains = st.session_state.subdomain_scanner.scan_subdomains(
                                        hostname,
                                        methods=['cert', 'ct'] if check_ct_logs else ['cert']
                                    )
                                    
                                    if subdomains:
                                        valid_subdomains = []
                                        for subdomain in subdomains:
                                            # Only add subdomains we haven't scanned yet
                                            if (subdomain not in st.session_state.scanned_domains and 
                                                not any(target[0] == subdomain for target in expanded_targets)):
                                                valid_subdomains.append(subdomain)
                                                expanded_targets.append((subdomain, port))
                                                st.session_state.scanned_domains.add(subdomain)
                                                logger.info(f"[SCAN] Added new subdomain to scan targets: {subdomain}")
                                        
                                        if valid_subdomains:
                                            st.write(f"Found {len(valid_subdomains)} new subdomains for {hostname}:")
                                            # Show first 10 subdomains
                                            for subdomain in valid_subdomains[:10]:
                                                st.write(f"- {subdomain}")
                                            if len(valid_subdomains) > 10:
                                                st.write(f"- ... and {len(valid_subdomains) - 10} more")
                                        else:
                                            logger.info(f"[SCAN] No new subdomains found for {hostname}")
                                    
                                except Exception as e:
                                    logger.error(f"[SCAN] Error searching subdomains for {hostname}: {str(e)}")
                                    notify("Error searching subdomains for {}: {}", "warning", hostname, str(e))
                                    show_notifications()
                        
                        # Update scan targets with expanded list
                        scan_targets = expanded_targets
                        logger.info(f"[SCAN] Total unique targets to scan: {len(scan_targets)}")
                        
                        # Calculate total steps for progress bar
                        steps_per_domain = 1  # Base step for domain creation
                        if check_whois:
                            steps_per_domain += 1
                        if check_dns:
                            steps_per_domain += 1
                        if True:  # Certificate scan is always performed
                            steps_per_domain += 1
                        
                        total_steps = len(scan_targets) * steps_per_domain
                        current_step = 0
                        
                        for hostname, port in scan_targets:
                            try:
                                with Session(engine) as session:
                                    logger.info(f"[SCAN] Processing target: {hostname}:{port}")
                                    # Get or create domain
                                    domain = session.query(Domain).filter_by(domain_name=hostname).first()
                                    if not domain:
                                        domain = Domain(
                                            domain_name=hostname,
                                            created_at=datetime.now(),
                                            updated_at=datetime.now()
                                        )
                                        session.add(domain)
                                    else:
                                        domain.updated_at = datetime.now()
                                    
                                    # Increment step for domain creation/update
                                    current_step += 1
                                    progress.progress(min(current_step / total_steps, 1.0))
                                    
                                    # Get domain information first, independent of certificate scanning
                                    if check_whois or check_dns:
                                        try:
                                            logger.info(f"[SCAN] Domain info gathering for {hostname} - WHOIS: {'enabled' if check_whois else 'disabled'}, DNS: {'enabled' if check_dns else 'disabled'}")
                                            status_container.text(f'Getting domain information for {hostname}...')
                                            domain_info = st.session_state.domain_scanner.scan_domain(
                                                hostname,
                                                get_whois=check_whois,
                                                get_dns=check_dns
                                            )
                                            if domain_info:
                                                if check_whois:
                                                    logger.info(f"[SCAN] Updating WHOIS information for {hostname}")
                                                    if domain_info.registrar:
                                                        domain.registrar = domain_info.registrar
                                                    if domain_info.registration_date:
                                                        domain.registration_date = domain_info.registration_date
                                                    if domain_info.expiration_date:
                                                        domain.expiration_date = domain_info.expiration_date
                                                    if domain_info.registrant:
                                                        domain.owner = domain_info.registrant
                                                
                                                if check_dns and domain_info.dns_records:
                                                    logger.info(f"[SCAN] Updating DNS records for {hostname}")
                                                    # Clear existing DNS records
                                                    session.query(DomainDNSRecord).filter_by(domain_id=domain.id).delete()
                                                    session.flush()
                                                    
                                                    # Add new DNS records
                                                    seen_records = set()
                                                    for record in domain_info.dns_records:
                                                        record_key = (record['type'], record['name'])
                                                        if record_key in seen_records:
                                                            continue
                                                        seen_records.add(record_key)
                                                        
                                                        dns_record = DomainDNSRecord(
                                                            domain=domain,
                                                            record_type=record['type'],
                                                            name=record['name'],
                                                            value=record['value'],
                                                            ttl=record['ttl'],
                                                            priority=record.get('priority'),
                                                            created_at=datetime.now(),
                                                            updated_at=datetime.now()
                                                        )
                                                        session.add(dns_record)
                                                        logger.debug(f"Added DNS record: {record['type']} {record['name']}")
                                                
                                                # Commit domain info changes immediately
                                                session.commit()
                                                logger.info(f"[SCAN] Domain information updated for {hostname}")
                                            
                                            # Increment step for WHOIS/DNS scan
                                            if check_whois:
                                                current_step += 1
                                                progress.progress(min(current_step / total_steps, 1.0))
                                            if check_dns:
                                                current_step += 1
                                                progress.progress(min(current_step / total_steps, 1.0))
                                            
                                        except Exception as domain_error:
                                            logger.error(f"[SCAN] Error gathering domain info for {hostname}: {str(domain_error)}")
                                            st.session_state.scan_results["warning"].append(f"{hostname} - Domain info error: {str(domain_error)}")
                                            # Still increment steps even if there's an error
                                            if check_whois:
                                                current_step += 1
                                            if check_dns:
                                                current_step += 1
                                            progress.progress(min(current_step / total_steps, 1.0))
                                    
                                    # Now try certificate scanning
                                    logger.info(f"[SCAN] Starting certificate scan for {hostname}:{port}")
                                    status_container.text(f'Scanning certificate for {hostname}:{port}...')
                                    scan_result = st.session_state.scanner.scan_certificate(hostname, port)
                                    
                                    # Process certificate information
                                    if isinstance(scan_result, CertificateInfo):
                                        # Handle old-style result
                                        cert_info = scan_result
                                        st.session_state.scan_results["success"].append(f"{hostname}:{port}")
                                        scan_status = "Success"
                                    elif scan_result and scan_result.certificate_info:
                                        cert_info = scan_result.certificate_info
                                        st.session_state.scan_results["success"].append(f"{hostname}:{port}")
                                        scan_status = "Success"
                                    elif scan_result and scan_result.error:
                                        st.session_state.scan_results["error"].append(f"{hostname}:{port} - {scan_result.error}")
                                        scan_status = f"Error: {scan_result.error}"
                                        # Increment certificate scan step on error
                                        current_step += 1
                                        progress.progress(min(current_step / total_steps, 1.0))
                                        continue
                                    else:
                                        st.session_state.scan_results["error"].append(f"{hostname}:{port} - No certificate found")
                                        scan_status = "No certificate found"
                                        # Increment certificate scan step when no cert found
                                        current_step += 1
                                        progress.progress(min(current_step / total_steps, 1.0))
                                        continue
                                    
                                    # Process the certificate info
                                    try:
                                        with session.begin_nested():
                                            # First create or update the host record
                                            host = session.query(Host).filter_by(name=hostname).first()
                                            if not host:
                                                host = Host(
                                                    name=hostname,
                                                    host_type=HOST_TYPE_SERVER,  # Default to server type
                                                    environment=ENV_PRODUCTION,   # Default to production
                                                    last_seen=datetime.now()
                                                )
                                                session.add(host)
                                            else:
                                                host.last_seen = datetime.now()
                                            
                                            # Create or update IP addresses
                                            if cert_info.ip_addresses:
                                                # Get existing IPs to avoid duplicates
                                                existing_ips = {ip.ip_address for ip in host.ip_addresses}
                                                for ip_addr in cert_info.ip_addresses:
                                                    if ip_addr not in existing_ips:
                                                        host_ip = HostIP(
                                                            host=host,
                                                            ip_address=ip_addr,
                                                            is_active=True,
                                                            last_seen=datetime.now()
                                                        )
                                                        session.add(host_ip)
                                                    else:
                                                        # Update last_seen for existing IP
                                                        for ip in host.ip_addresses:
                                                            if ip.ip_address == ip_addr:
                                                                ip.last_seen = datetime.now()
                                                                ip.is_active = True
                                            
                                            # Process certificate
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
                                                    sans_scanned=True,
                                                    created_at=datetime.now(),
                                                    updated_at=datetime.now()
                                                )
                                                session.add(cert)
                                            else:
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
                                                cert.sans_scanned = True
                                                cert.updated_at = datetime.now()
                                            
                                            # Associate certificate with domain
                                            if cert not in domain.certificates:
                                                domain.certificates.append(cert)
                                            
                                            # Create certificate binding
                                            # Find the IP that matches the scanned port
                                            host_ip = None
                                            if cert_info.ip_addresses:
                                                for ip in host.ip_addresses:
                                                    if ip.ip_address in cert_info.ip_addresses:
                                                        host_ip = ip
                                                        break
                                            
                                            # Create or update binding
                                            binding = session.query(CertificateBinding).filter_by(
                                                host=host,
                                                host_ip=host_ip,
                                                port=port
                                            ).first()
                                            
                                            if not binding:
                                                binding = CertificateBinding(
                                                    host=host,
                                                    host_ip=host_ip,
                                                    certificate=cert,
                                                    port=port,
                                                    binding_type='IP',  # Default to IP binding
                                                    last_seen=datetime.now(),
                                                    manually_added=False
                                                )
                                                session.add(binding)
                                            else:
                                                binding.certificate = cert
                                                binding.last_seen = datetime.now()
                                            
                                            # Create scan history record
                                            scan_record = CertificateScan(
                                                certificate=cert,
                                                host=host,
                                                scan_date=datetime.now(),
                                                status=scan_status,
                                                port=port
                                            )
                                            session.add(scan_record)
                                            
                                            session.flush()
                                    except Exception as cert_error:
                                        st.session_state.scan_results["error"].append(f"{hostname}:{port} - Error processing certificate: {str(cert_error)}")
                                        session.rollback()
                                
                                current_step += 1
                                progress.progress(min(current_step / total_steps, 1.0))
                                
                                # Commit changes for this domain
                                try:
                                    session.commit()
                                except Exception as commit_error:
                                    st.session_state.scan_results["error"].append(f"{hostname} - Error saving changes: {str(commit_error)}")
                                    session.rollback()
                                
                            except Exception as e:
                                st.session_state.scan_results["error"].append(f"{hostname} - Error: {str(e)}")
                                current_step = min(current_step + steps_per_domain, total_steps)
                                progress.progress(min(current_step / total_steps, 1.0))
                                continue
                
                # Clear status after completion
                status_container.empty()
                
                # Show success message and results
                if st.session_state.scan_results["success"]:
                    notify("Scan completed! Found {} certificates.", "success", len(st.session_state.scan_results['success']))
                
                if st.session_state.scan_results["error"]:
                    notify("Some scans failed:")
                    for error in st.session_state.scan_results["error"]:
                        # Clean up error message for display
                        if isinstance(error, str):
                            # Remove the port number from the display if it's the default 443
                            error = error.replace(":443", "")
                            # Remove any raw error codes
                            if "[Errno" in error:
                                error = error.split(" - ", 1)[0] + " - " + error.split("] ")[-1]
                        notify("- {}")
                
                # Show notifications
                with notification_placeholder:
                    show_notifications()
                
                # Show results summary
                st.divider()
                st.subheader("Scan Results")
                
                # Display results in tabs
                tab_domains, tab_certs, tab_dns = st.tabs([
                    "🌐 Domains",
                    "🔐 Certificates",
                    "📝 DNS Records"
                ])
                
                with tab_domains:
                    with Session(engine) as session:
                        for hostname, _ in scan_targets:
                            domain = session.query(Domain).filter_by(domain_name=hostname).first()
                            if domain:
                                st.markdown(f"### {domain.domain_name}")
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.write("**Registrar:**", domain.registrar or "N/A")
                                    st.write("**Registration Date:**", domain.registration_date.strftime("%Y-%m-%d") if domain.registration_date else "N/A")
                                    st.write("**Owner:**", domain.owner or "N/A")
                                with col2:
                                    st.write("**Expiration Date:**", domain.expiration_date.strftime("%Y-%m-%d") if domain.expiration_date else "N/A")
                                    st.write("**Certificates:**", len(domain.certificates))
                                    st.write("**DNS Records:**", len(domain.dns_records))
                
                with tab_certs:
                    with Session(engine) as session:
                        for hostname, _ in scan_targets:
                            domain = session.query(Domain).filter_by(domain_name=hostname).first()
                            if domain and domain.certificates:
                                st.markdown(f"### {domain.domain_name}")
                                for cert in domain.certificates:
                                    with st.expander(f"Certificate: {cert.common_name}"):
                                        col1, col2 = st.columns(2)
                                        with col1:
                                            st.write("**Common Name:**", cert.common_name)
                                            st.write("**Valid From:**", cert.valid_from.strftime("%Y-%m-%d"))
                                            st.write("**Valid Until:**", cert.valid_until.strftime("%Y-%m-%d"))
                                            st.write("**Serial Number:**", cert.serial_number)
                                        with col2:
                                            st.write("**Issuer:**", cert.issuer.get('CN', 'Unknown'))
                                            st.write("**Chain Valid:**", "✅" if cert.chain_valid else "❌")
                                            st.write("**SANs:**", ", ".join(cert.san))
                                            st.write("**Signature Algorithm:**", cert.signature_algorithm)
                
                with tab_dns:
                    with Session(engine) as session:
                        for hostname, _ in scan_targets:
                            domain = session.query(Domain).filter_by(domain_name=hostname).first()
                            if domain and domain.dns_records:
                                st.markdown(f"### {domain.domain_name}")
                                records_df = []
                                for record in domain.dns_records:
                                    # Convert Priority to string to avoid type mixing
                                    priority = str(record.priority) if record.priority is not None else 'N/A'
                                    records_df.append({
                                        'Type': record.record_type,
                                        'Name': record.name,
                                        'Value': record.value,
                                        'TTL': int(record.ttl),  # Ensure TTL is integer
                                        'Priority': priority  # Priority as string
                                    })
                                if records_df:
                                    df = pd.DataFrame(records_df)
                                    # Configure column types explicitly
                                    st.dataframe(
                                        df,
                                        column_config={
                                            'Type': st.column_config.TextColumn('Type'),
                                            'Name': st.column_config.TextColumn('Name'),
                                            'Value': st.column_config.TextColumn('Value'),
                                            'TTL': st.column_config.NumberColumn('TTL', format='%d'),
                                            'Priority': st.column_config.TextColumn('Priority')
                                        },
                                        hide_index=True,
                                        use_container_width=True
                                    )
                
                # Clear scan targets after successful scan
                if 'scan_targets' in st.session_state:
                    del st.session_state.scan_targets
                else:
                    notify("Please enter at least one valid domain to scan", "error")
                    show_notifications()
    
    # Recent scans sidebar
    with col2:
        st.subheader("Recent Scans")
        with Session(engine) as session:
            recent_domains = session.query(Domain)\
                .order_by(Domain.updated_at.desc())\
                .limit(5)\
                .all()
            
            if recent_domains:
                st.markdown("<div class='text-small'>", unsafe_allow_html=True)
                for domain in recent_domains:
                    scan_time = domain.updated_at.strftime("%Y-%m-%d %H:%M")
                    cert_count = len(domain.certificates)
                    cert_status = "✅" if any(c.chain_valid for c in domain.certificates) else "❌"
                    st.markdown(
                        f"**{domain.domain_name}** "
                        f"<span class='text-muted'>"
                        f"(🕒 {scan_time} • {cert_status} {cert_count} certs)</span>",
                        unsafe_allow_html=True
                    )
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                notify("No recent scans", "info")
                show_notifications()
