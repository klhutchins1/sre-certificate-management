"""
Scanner view module for the Certificate Management System.

This module provides the UI components and view logic for the scanner interface,
including:
- Scan target input and validation
- Progress tracking and display
- Result visualization
- Error handling and user feedback
"""

import streamlit as st
from datetime import datetime
from sqlalchemy.orm import Session
import logging
from typing import Tuple
from ..models import Domain, Certificate, DomainDNSRecord
from ..static.styles import load_warning_suppression, load_css
from ..scanner import ScanManager
import pandas as pd
from ..notifications import initialize_notifications, show_notifications, notify, clear_notifications
import time
import json

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

class StreamlitProgressContainer:
    """Wrapper for Streamlit progress functionality."""
    
    def __init__(self, progress_bar, status_text):
        self.progress_bar = progress_bar
        self.status_text = status_text
    
    def progress(self, value: float):
        """Update progress bar."""
        self.progress_bar.progress(value)
    
    def text(self, message: str):
        """Update status text."""
        self.status_text.text(message)

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
            notify(f"Invalid port number in {entry}: Port cannot be negative", "error")
            return False, 0
        if port > 65535:
            notify(f"Invalid port number in {entry}: Port must be between 1 and 65535", "error")
            return False, 0
        return True, port
    except ValueError as e:
        notify(f"Invalid port number in {entry}: '{port_str}' is not a valid number", "error")
        return False, 0

def get_scanners():
    """Get scanner instances with shared tracking."""
    # Create scanner instances
    domain_scanner = DomainScanner()
    cert_scanner = CertificateScanner()
    subdomain_scanner = SubdomainScanner()
    
    # Share the tracking system between scanners
    subdomain_scanner.tracker = cert_scanner.tracker
    
    return domain_scanner, cert_scanner, subdomain_scanner

def process_scan_target(session, domain: str, port: int, check_whois: bool, check_dns: bool, check_subdomains: bool, 
                       check_sans: bool = False,  # New parameter to control SAN scanning
                       progress_container=None, status_container=None, current_step=None, total_steps=None,
                       cert_scanner=None, domain_scanner=None, subdomain_scanner=None,
                       scan_queue=None) -> None:
    """Process a single scan target."""
    logger.info(f"[SCAN] Processing target: {domain}:{port}")
    
    # Use provided scanner instances or get new ones
    if not all([cert_scanner, domain_scanner, subdomain_scanner]):
        domain_scanner, cert_scanner, subdomain_scanner = get_scanners()
    
    # Print current scanner status
    cert_scanner.tracker.print_status()
    
    # Skip if already scanned in this scan session
    if cert_scanner.tracker.is_endpoint_scanned(domain, port):
        logger.info(f"[SCAN] Skipping {domain}:{port} - Already scanned in this scan")
        if status_container:
            status_container.text(f'Skipping {domain}:{port} (already scanned in this scan)')
        return
    
    # Get or create domain
    domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
    if not domain_obj:
        if status_container:
            status_container.text(f'Creating new domain record for {domain}...')
        domain_obj = Domain(
            domain_name=domain,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        session.add(domain_obj)
    else:
        if status_container:
            status_container.text(f'Updating existing domain record for {domain}...')
        domain_obj.updated_at = datetime.now()
    
    # Track success/error states
    has_errors = False
    error_messages = []
    
    # Get domain information first
    if check_whois or check_dns:
        try:
            if status_container:
                status_container.text(f'Gathering domain information for {domain}...')
            
            logger.info(f"[SCAN] Domain info gathering for {domain} - WHOIS: {'enabled' if check_whois else 'disabled'}, DNS: {'enabled' if check_dns else 'disabled'}")
            
            # Let the domain scanner handle all domain-related work
            domain_info = domain_scanner.scan_domain(
                domain,
                get_whois=check_whois,
                get_dns=check_dns
            )
            
            if domain_info:
                if check_whois:
                    if status_container:
                        status_container.text(f'Updating WHOIS information for {domain}...')
                    logger.info(f"[SCAN] Updating WHOIS information for {domain}")
                    if domain_info.registrar:
                        domain_obj.registrar = domain_info.registrar
                    if domain_info.registration_date:
                        domain_obj.registration_date = domain_info.registration_date
                    if domain_info.expiration_date:
                        domain_obj.expiration_date = domain_info.expiration_date
                    if domain_info.registrant:
                        domain_obj.owner = domain_info.registrant
                
                # Process related domains if found
                if domain_info.related_domains and scan_queue is not None:
                    related_count = 0
                    for related_domain in domain_info.related_domains:
                        if not cert_scanner.tracker.is_endpoint_scanned(related_domain, port):
                            scan_queue.add((related_domain, port))
                            related_count += 1
                            logger.info(f"[SCAN] Added related domain to scan queue: {related_domain}:{port}")
                    
                    # Update total steps count for related domains
                    if related_count > 0 and total_steps is not None:
                        total_steps += related_count
                        if progress_container and current_step is not None:
                            with progress_container:
                                progress = st.progress(min(current_step / total_steps, 1.0))
                
                # Process DNS records if available
                if check_dns and domain_info.dns_records:
                    if status_container:
                        status_container.text(f'Processing DNS records for {domain}...')
                    
                    # Create processor if needed
                    if not hasattr(st.session_state.scan_manager, 'processor'):
                        st.session_state.scan_manager.processor = ScanProcessor(session, status_container)
                    else:
                        st.session_state.scan_manager.processor.session = session
                        st.session_state.scan_manager.processor.status_container = status_container
                    
                    st.session_state.scan_manager.processor.process_dns_records(
                        domain_obj,
                        domain_info.dns_records,
                        scan_queue,
                        port
                    )
                
                # Commit domain information changes
                session.commit()
                logger.info(f"[SCAN] Domain information updated for {domain}")
                
                if domain_info.error:
                    has_errors = True
                    error_messages.append(domain_info.error)
        
        except Exception as domain_error:
            logger.error(f"[SCAN] Error gathering domain info for {domain}: {str(domain_error)}")
            session.rollback()
            has_errors = True
            error_messages.append(f"Error gathering domain info: {str(domain_error)}")
    
    # Now scan for certificates
    if status_container:
        status_container.text(f'Scanning certificates for {domain}:{port}...')
    logger.info(f"[SCAN] Starting certificate scan for {domain}:{port}")
    scan_result = cert_scanner.scan_certificate(domain, port)
    
    if scan_result and scan_result.certificate_info:
        cert_info = scan_result.certificate_info
        try:
            # Get or create certificate
            cert = session.query(Certificate).filter_by(
                serial_number=cert_info.serial_number
            ).first()
            
            if not cert:
                if status_container:
                    status_container.text(f'Found new certificate for {domain}...')
                cert = Certificate(
                    serial_number=cert_info.serial_number,
                    thumbprint=cert_info.thumbprint,
                    common_name=cert_info.common_name,
                    valid_from=cert_info.valid_from,
                    valid_until=cert_info.expiration_date,
                    _issuer=json.dumps(cert_info.issuer),
                    _subject=json.dumps(cert_info.subject),
                    _san=json.dumps(cert_info.san),
                    key_usage=json.dumps(cert_info.key_usage) if cert_info.key_usage else None,
                    signature_algorithm=cert_info.signature_algorithm,
                    chain_valid=cert_info.chain_valid,
                    sans_scanned=True,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                session.add(cert)
            else:
                if status_container:
                    status_container.text(f'Updating existing certificate for {domain}...')
                cert.thumbprint = cert_info.thumbprint
                cert.common_name = cert_info.common_name
                cert.valid_from = cert_info.valid_from
                cert.valid_until = cert_info.expiration_date
                cert._issuer = json.dumps(cert_info.issuer)
                cert._subject = json.dumps(cert_info.subject)
                cert._san = json.dumps(cert_info.san)
                cert.key_usage = json.dumps(cert_info.key_usage) if cert_info.key_usage else None
                cert.signature_algorithm = cert_info.signature_algorithm
                cert.chain_valid = cert_info.chain_valid
                cert.sans_scanned = True
                cert.updated_at = datetime.now()
            
            # Associate certificate with domain
            if cert not in domain_obj.certificates:
                domain_obj.certificates.append(cert)
            
            # Create host record
            host = session.query(Host).filter_by(name=domain).first()
            if not host:
                if status_container:
                    status_container.text(f'Creating host record for {domain}...')
                host = Host(
                    name=domain,
                    host_type=HOST_TYPE_SERVER,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                session.add(host)
            else:
                host.last_seen = datetime.now()
            
            # Create or update IP addresses
            if cert_info.ip_addresses:
                if status_container:
                    status_container.text(f'Updating IP addresses for {domain}...')
                cert_scanner.tracker.add_discovered_ips(domain, cert_info.ip_addresses)
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
            
            # Create certificate binding
            host_ip = None
            if cert_info.ip_addresses:
                for ip in host.ip_addresses:
                    if ip.ip_address in cert_info.ip_addresses:
                        host_ip = ip
                        break
            
            binding = session.query(CertificateBinding).filter_by(
                host=host,
                host_ip=host_ip,
                port=port
            ).first()
            
            if not binding:
                if status_container:
                    status_container.text(f'Creating certificate binding for {domain}:{port}...')
                binding = CertificateBinding(
                    host=host,
                    host_ip=host_ip,
                    certificate=cert,
                    port=port,
                    binding_type='IP',
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
                status="Success",
                port=port
            )
            session.add(scan_record)
            
            # Commit all changes
            session.commit()
            logger.info(f"[SCAN] Successfully processed certificate for {domain}:{port}")
            
            # Update success state
            if not has_errors:
                st.session_state.scan_results["success"].append(f"{domain}:{port}")
            
        except Exception as cert_error:
            logger.error(f"[SCAN] Error processing certificate for {domain}:{port}: {str(cert_error)}")
            session.rollback()
            has_errors = True
            error_messages.append(f"Error processing certificate: {str(cert_error)}")
    else:
        logger.error(f"[SCAN] No certificate found or error for {domain}:{port}")
        has_errors = True
        if scan_result and scan_result.error:
            error_messages.append(scan_result.error)
        else:
            error_messages.append("No certificate found")
    
    # Process subdomains if requested
    if check_subdomains:
        try:
            # Update status to show subdomain discovery
            if status_container:
                status_container.text(f'Discovering subdomains for {domain}...')
                # Set status container for subdomain scanner
                subdomain_scanner.set_status_container(status_container)
            
            # Use the comprehensive subdomain scanning from SubdomainScanner
            subdomain_results = subdomain_scanner.scan_and_process_subdomains(
                domain=domain,
                port=port,
                check_whois=check_whois,
                check_dns=check_dns,
                scanned_domains=cert_scanner.tracker.scanned_domains
            )
            
            if subdomain_results and scan_queue is not None:
                if status_container:
                    status_container.text(f'Found {len(subdomain_results)} subdomains for {domain}...')
                logger.info(f"[SCAN] Found {len(subdomain_results)} subdomains for {domain}")
                
                # Add discovered subdomains to scan queue and update total steps
                new_subdomains = 0
                for result in subdomain_results:
                    subdomain = result['domain']
                    if not cert_scanner.tracker.is_endpoint_scanned(subdomain, port):
                        scan_queue.add((subdomain, port))
                        new_subdomains += 1
                        logger.info(f"[SCAN] Added new subdomain to scan queue: {subdomain}:{port}")
                
                # Update total steps count for new subdomains
                if new_subdomains > 0 and total_steps is not None:
                    total_steps += new_subdomains
                    if progress_container and current_step is not None:
                        with progress_container:
                            progress = st.progress(min(current_step / total_steps, 1.0))
            
            # Print updated scanner status after subdomain discovery
            cert_scanner.tracker.print_status()
            
            # Clear status container from subdomain scanner
            subdomain_scanner.set_status_container(None)
            
        except Exception as subdomain_error:
            logger.error(f"[SCAN] Error in subdomain scanning for {domain}: {str(subdomain_error)}")
            has_errors = True
            error_messages.append(f"Error in subdomain scanning: {str(subdomain_error)}")
            # Clear status container from subdomain scanner in case of error
            subdomain_scanner.set_status_container(None)
    
    # Update final status
    if has_errors:
        error_msg = f"{domain}:{port} - " + "; ".join(error_messages)
        if error_msg not in st.session_state.scan_results["error"]:
            st.session_state.scan_results["error"].append(error_msg)
    
    # Print final scanner status for this target
    cert_scanner.tracker.print_status()

def render_scan_interface(engine) -> None:
    """Render the main domain and certificate scanning interface."""
    # Initialize UI components and styles
    load_warning_suppression()
    load_css()
    
    # Initialize notifications at the very beginning
    initialize_notifications()
    clear_notifications()  # Clear any existing notifications
    
    # Create a placeholder for notifications at the top
    notification_placeholder = st.empty()
    
    # Initialize session state
    if 'scan_in_progress' not in st.session_state:
        st.session_state.scan_in_progress = False
    if 'current_operation' not in st.session_state:
        st.session_state.current_operation = None
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = {
            "success": [],
            "error": [],
            "warning": []
        }
    if 'scan_input' not in st.session_state:
        st.session_state.scan_input = ""
    
    # Initialize scan manager if not exists
    if 'scan_manager' not in st.session_state:
        st.session_state.scan_manager = ScanManager()
    
    st.title("Domain & Certificate Scanner")
    st.markdown("""
    This scanner performs comprehensive domain analysis including:
    - SSL/TLS certificates
    - Domain registration information
    - DNS records
    - Host relationships
    """)
    
    # Create main layout columns
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Create two columns for input and options
        input_col, options_col = st.columns([3, 2])
        
        with input_col:
            # Check if we have scan targets from certificate view
            if 'scan_targets' in st.session_state:
                st.session_state.scan_input = "\n".join(st.session_state.scan_targets)
                # Clear the scan targets to avoid reusing them
                del st.session_state.scan_targets
            
            # Scan input interface
            scan_input = st.text_area(
                "Enter domains to scan (one per line)",
                value=st.session_state.scan_input,
                height=150,
                placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
            )
            
            # Update session state with current input
            st.session_state.scan_input = scan_input
        
        with options_col:
            st.markdown("### Scan Options")
            check_whois = st.checkbox("Get WHOIS Info", value=True)
            check_dns = st.checkbox("Get DNS Records", value=True)
            check_subdomains = st.checkbox("Include Subdomains", value=True)
            check_sans = st.checkbox("Scan SANs", value=True)  # New checkbox for SAN scanning
        
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
            """)
        
        # Handle scan initiation
        if scan_button_clicked and not st.session_state.scan_in_progress:
            logger.info("[SCAN] Starting new scan session")
            st.session_state.scan_in_progress = True
            
            # Reset scan results for new scan
            st.session_state.scan_manager.reset_scan_state()
            
            # Validate input
            if not st.session_state.scan_input.strip():
                notify("Please enter at least one domain to scan", "error")
                show_notifications()
                st.session_state.scan_in_progress = False
                return
            
            # Process each target
            validation_errors = False
            entries = [h.strip() for h in scan_input.split('\n') if h.strip()]
            
            for entry in entries:
                is_valid, hostname, port, error = st.session_state.scan_manager.process_scan_target(entry)
                if not is_valid:
                    notify(f"Invalid entry {entry}: {error}", "error")
                    validation_errors = True
                    continue
                
                # Add validated target to queue
                st.session_state.scan_manager.add_to_queue(hostname, port)
            
            # Show notifications
            with notification_placeholder:
                show_notifications()
            
            # Handle validation errors
            if validation_errors:
                notify("Please correct the errors above", "error")
                show_notifications()
                st.session_state.scan_in_progress = False
                return
            
            # Execute scans if we have targets
            if st.session_state.scan_manager.has_pending_targets():
                progress_bar = st.empty()
                status_container = st.empty()
                queue_status = st.empty()
                
                with progress_bar:
                    st.markdown("""
                        <style>
                        .stProgress > div > div > div > div {
                            background-color: #0066ff;
                        }
                        </style>
                        """, unsafe_allow_html=True)
                    progress = st.progress(0)
                
                # Create progress container
                progress_container = StreamlitProgressContainer(progress, queue_status)
                
                # Process targets in a single session
                with Session(engine) as session:
                    current_step = 0
                    total_steps = st.session_state.scan_manager.cert_scanner.get_queue_size()
                    
                    while st.session_state.scan_manager.has_pending_targets():
                        # Get next target from queue
                        target = st.session_state.scan_manager.get_next_target()
                        if not target:
                            break
                            
                        hostname, port = target
                        target_key = f"{hostname}:{port}"
                        
                        try:
                            # Skip if this operation is already in progress
                            if st.session_state.current_operation == target_key:
                                continue
                            st.session_state.current_operation = target_key
                            
                            # Update progress
                            current_step += 1
                            
                            # Process the scan target
                            st.session_state.scan_manager.scan_target(
                                session=session,
                                domain=hostname,
                                port=port,
                                check_whois=check_whois,
                                check_dns=check_dns,
                                check_subdomains=check_subdomains,
                                check_sans=check_sans,
                                status_container=status_container,
                                progress_container=progress_container,
                                current_step=current_step,
                                total_steps=total_steps
                            )
                            
                            # Update total steps based on queue size
                            total_steps = max(total_steps, current_step + st.session_state.scan_manager.cert_scanner.get_queue_size())
                            
                        except Exception as e:
                            logger.error(f"[SCAN] Error processing {target_key}: {str(e)}")
                            st.session_state.scan_manager.scan_results["error"].append(f"{target_key} - {str(e)}")
                        finally:
                            # Clear current operation
                            if st.session_state.current_operation == target_key:
                                st.session_state.current_operation = None
                        
                        # Small delay to allow UI updates
                        time.sleep(0.1)
                
                # Clear status after completion
                status_container.empty()
                queue_status.empty()
                st.session_state.scan_in_progress = False
                
                # Get final scan stats
                stats = st.session_state.scan_manager.get_scan_stats()
                
                # Show success message and results
                if st.session_state.scan_manager.scan_results["success"]:
                    notify(f"Scan completed! Processed {stats['total_scanned']} targets.", "success")
                
                if st.session_state.scan_manager.scan_results["error"]:
                    notify("Some scans failed:", "error")
                    for error in st.session_state.scan_manager.scan_results["error"]:
                        notify(f"- {error}", "error")
                
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
                        # Get all scanned domains from tracker
                        for domain in st.session_state.scan_manager.cert_scanner.tracker.scanned_domains:
                            domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
                            if domain_obj:
                                st.markdown(f"### {domain_obj.domain_name}")
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.write("**Registrar:**", domain_obj.registrar or "N/A")
                                    st.write("**Registration Date:**", domain_obj.registration_date.strftime("%Y-%m-%d") if domain_obj.registration_date else "N/A")
                                    st.write("**Owner:**", domain_obj.owner or "N/A")
                                with col2:
                                    st.write("**Expiration Date:**", domain_obj.expiration_date.strftime("%Y-%m-%d") if domain_obj.expiration_date else "N/A")
                                    st.write("**Certificates:**", len(domain_obj.certificates))
                                    st.write("**DNS Records:**", len(domain_obj.dns_records))
                
                with tab_certs:
                    with Session(engine) as session:
                        # Get all scanned domains from tracker
                        for domain in st.session_state.scan_manager.cert_scanner.tracker.scanned_domains:
                            domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
                            if domain_obj and domain_obj.certificates:
                                st.markdown(f"### {domain_obj.domain_name}")
                                for cert in domain_obj.certificates:
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
                        # Get all scanned domains from tracker
                        scanned_domains = st.session_state.scan_manager.cert_scanner.tracker.scanned_domains
                        logger.info(f"[DNS] Processing DNS records for {len(scanned_domains)} domains")
                        
                        for domain in scanned_domains:
                            domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
                            if domain_obj:
                                dns_records = domain_obj.dns_records
                                logger.info(f"[DNS] Found {len(dns_records)} DNS records for {domain}")
                                
                                if dns_records:
                                    st.markdown(f"### {domain_obj.domain_name}")
                                    records_df = []
                                    
                                    for record in dns_records:
                                        # Convert priority to string 'N/A' if None, otherwise keep as int
                                        priority = record.priority if record.priority is not None else 'N/A'
                                        
                                        record_data = {
                                            'Type': record.record_type,
                                            'Name': record.name,
                                            'Value': record.value,
                                            'TTL': int(record.ttl),
                                            'Priority': priority
                                        }
                                        records_df.append(record_data)
                                        logger.debug(f"[DNS] Processing record: {record_data}")
                                    
                                    if records_df:
                                        df = pd.DataFrame(records_df)
                                        
                                        # Convert Priority column to string type to handle mixed data
                                        df['Priority'] = df['Priority'].astype(str)
                                        
                                        st.dataframe(
                                            df,
                                            column_config={
                                                'Type': st.column_config.TextColumn('Type', width='small'),
                                                'Name': st.column_config.TextColumn('Name', width='medium'),
                                                'Value': st.column_config.TextColumn('Value', width='large'),
                                                'TTL': st.column_config.NumberColumn('TTL', width='small'),
                                                'Priority': st.column_config.TextColumn('Priority', width='small')
                                            },
                                            hide_index=True,
                                            use_container_width=True
                                        )
                                    else:
                                        st.info(f"No DNS records found for {domain}")
                                else:
                                    st.info(f"No DNS records found for {domain}")
                            else:
                                logger.warning(f"[DNS] Domain object not found for {domain}")
    
    # Recent scans section in the right column
    with col2:
        st.markdown("### Recent Scans")
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
