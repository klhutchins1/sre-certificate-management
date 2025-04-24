"""
Scanner view module for the Certificate Management System.

This module provides the UI components and view logic for the scanner interface,
including:
- Scan target input and validation
- Progress tracking and display
- Result visualization
- Error handling and user feedback
- Certificate SAN processing
"""

import streamlit as st
from datetime import datetime
from sqlalchemy.orm import Session
import logging
from typing import Tuple, List, Set
from ..models import Domain, Certificate, DomainDNSRecord, Host, HostIP, CertificateBinding, CertificateScan, HOST_TYPE_SERVER, ENV_PRODUCTION
from ..static.styles import load_warning_suppression, load_css
from ..scanner import ScanManager, ScanProcessor
from ..domain_scanner import DomainScanner
from ..certificate_scanner import CertificateScanner, CertificateInfo, ScanResult
from ..subdomain_scanner import SubdomainScanner
import pandas as pd
from ..notifications import initialize_notifications, show_notifications, notify, clear_notifications
import time
import json

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Only add console handler if no handlers exist
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
        try:
            # Clamp value between 0.0 and 1.0
            clamped_value = max(0.0, min(1.0, value))
            self.progress_bar.progress(clamped_value)
        except Exception:
            # Silently handle any errors
            pass
    
    def text(self, message: str):
        """Update status text."""
        try:
            self.status_text.text(message)
        except Exception:
            # Silently handle any errors
            pass

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
    infra_mgmt = CertificateScanner()
    subdomain_scanner = SubdomainScanner()
    
    # Share the tracking system between scanners
    subdomain_scanner.tracker = infra_mgmt.tracker
    
    return domain_scanner, infra_mgmt, subdomain_scanner

def process_scan_target(session, domain: str, port: int, check_whois: bool, check_dns: bool, check_subdomains: bool, 
                       check_sans: bool = False, detect_platform: bool = True, validate_chain: bool = True,
                       progress_container=None, status_container=None, current_step=None, total_steps=None,
                       infra_mgmt=None, domain_scanner=None, subdomain_scanner=None,
                       scan_queue=None) -> None:
    """Process a single scan target."""
    logger.info(f"[SCAN] Processing target: {domain}:{port}")
    
    # Use provided scanner instances or get new ones
    if not all([infra_mgmt, domain_scanner, subdomain_scanner]):
        domain_scanner, infra_mgmt, subdomain_scanner = get_scanners()
    
    # Print current scanner status
    infra_mgmt.tracker.print_status()
    
    # Skip if already scanned in this scan session
    if infra_mgmt.tracker.is_endpoint_scanned(domain, port):
        logger.info(f"[SCAN] Skipping {domain}:{port} - Already scanned in this scan")
        if status_container:
            status_container.text(f'Skipping {domain}:{port} (already scanned in this scan)')
        return
    
    # Calculate total sub-steps
    total_sub_steps = 1
    if check_whois or check_dns:
        total_sub_steps += 1  # Domain info gathering
        if check_dns:
            total_sub_steps += 1  # DNS processing
    total_sub_steps += 2  # Certificate scanning and processing
    if check_subdomains:
        total_sub_steps += 1  # Subdomain processing
    if check_sans:
        total_sub_steps += 1  # SAN processing
    
    current_sub_step = 0
    
    def update_progress(sub_step: int):
        """Update progress bar and queue status."""
        if progress_container and current_step is not None and total_steps is not None:
            progress = min((current_step - 1 + sub_step/total_sub_steps) / total_steps, 1.0)
            progress_container.progress(progress)
            progress_container.text(f"Remaining targets in queue: {infra_mgmt.tracker.queue_size()}")
    
    # Track success/error states
    has_errors = False
    error_messages = []
    
    try:
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
        
        current_sub_step += 1
        update_progress(current_sub_step)
        
        # Get domain information first
        if check_whois or check_dns:
            try:
                if status_container:
                    status_container.text(f'Gathering domain information for {domain}...')
                
                logger.info(f"[SCAN] Domain info gathering for {domain} - WHOIS: {'enabled' if check_whois else 'disabled'}, DNS: {'enabled' if check_dns else 'disabled'}")
                
                domain_info = domain_scanner.scan_domain(
                    domain,
                    get_whois=check_whois,
                    get_dns=check_dns
                )
                
                if domain_info:
                    # Process domain information
                    if check_whois and domain_info.registrar:
                        if status_container:
                            status_container.text(f'Updating WHOIS information for {domain}...')
                        domain_obj.registrar = domain_info.registrar
                        domain_obj.registration_date = domain_info.registration_date
                        domain_obj.expiration_date = domain_info.expiration_date
                        domain_obj.owner = domain_info.registrant
                    
                    # Process DNS records
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
                    
                    # Process related domains
                    if domain_info.related_domains and scan_queue is not None:
                        for related_domain in domain_info.related_domains:
                            if not infra_mgmt.tracker.is_endpoint_scanned(related_domain, port):
                                scan_queue.add((related_domain, port))
                                logger.info(f"[SCAN] Added related domain to queue: {related_domain}:{port}")
                
                current_sub_step += 1
                update_progress(current_sub_step)
                
                session.commit()
                logger.info(f"[SCAN] Domain information updated for {domain}")
                
            except Exception as e:
                logger.error(f"[SCAN] Error gathering domain info for {domain}: {str(e)}")
                has_errors = True
                error_messages.append(f"Error gathering domain info: {str(e)}")
                st.session_state.scan_results["error"].append(f"{domain}:{port} - Error gathering domain info: {str(e)}")
        
        # Scan for certificates
        if status_container:
            status_container.text(f'Scanning certificates for {domain}:{port}...')
        
        scan_result = infra_mgmt.scan_certificate(domain, port)
        current_sub_step += 1
        update_progress(current_sub_step)
        
        if scan_result and scan_result.certificate_info:
            cert_info = scan_result.certificate_info
            try:
                # Process certificate
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
                        chain_valid=validate_chain and cert_info.chain_valid,
                        sans_scanned=check_sans,
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
                    cert.chain_valid = validate_chain and cert_info.chain_valid
                    cert.sans_scanned = check_sans
                    cert.updated_at = datetime.now()
                
                # Associate certificate with domain
                if cert not in domain_obj.certificates:
                    domain_obj.certificates.append(cert)
                
                # Create or update host record
                host = session.query(Host).filter_by(name=domain).first()
                if not host:
                    if status_container:
                        status_container.text(f'Creating host record for {domain}...')
                    host = Host(
                        name=domain,
                        host_type=HOST_TYPE_SERVER,  # Will be updated if platform detection is enabled
                        environment=ENV_PRODUCTION,
                        last_seen=datetime.now()
                    )
                    session.add(host)
                else:
                    host.last_seen = datetime.now()
                
                # Update host type based on platform if enabled
                if detect_platform and cert_info.platform:
                    host.host_type = cert_info.platform
                
                # Process IP addresses
                if cert_info.ip_addresses:
                    if status_container:
                        status_container.text(f'Updating IP addresses for {domain}...')
                    infra_mgmt.tracker.add_discovered_ips(domain, cert_info.ip_addresses)
                    
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
                
                # Create or update certificate binding
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
                        platform=cert_info.platform if detect_platform else None,
                        last_seen=datetime.now(),
                        manually_added=False
                    )
                    session.add(binding)
                else:
                    binding.certificate = cert
                    binding.last_seen = datetime.now()
                    if detect_platform:
                        binding.platform = cert_info.platform
                
                # Create scan history record
                scan_record = CertificateScan(
                    certificate=cert,
                    host=host,
                    scan_date=datetime.now(),
                    status="Success",
                    port=port
                )
                session.add(scan_record)
                
                session.commit()
                logger.info(f"[SCAN] Successfully processed certificate for {domain}:{port}")
                
                # Update success state
                st.session_state.scan_results["success"].append(f"{domain}:{port}")
                
            except Exception as cert_error:
                logger.error(f"[SCAN] Error processing certificate for {domain}:{port}: {str(cert_error)}")
                has_errors = True
                error_messages.append(f"Error processing certificate: {str(cert_error)}")
                st.session_state.scan_results["error"].append(f"{domain}:{port} - Error processing certificate: {str(cert_error)}")
        else:
            logger.error(f"[SCAN] No certificate found or error for {domain}:{port}")
            has_errors = True
            if scan_result and scan_result.error:
                error_messages.append(scan_result.error)
                st.session_state.scan_results["error"].append(f"{domain}:{port} - {scan_result.error}")
            else:
                error_messages.append("No certificate found")
                st.session_state.scan_results["no_cert"].append(f"{domain}:{port}")
        
        # Process subdomains if requested
        if check_subdomains:
            try:
                if status_container:
                    status_container.text(f'Discovering subdomains for {domain}...')
                
                subdomain_scanner.set_status_container(status_container)
                
                subdomain_results = subdomain_scanner.scan_and_process_subdomains(
                    domain=domain,
                    port=port,
                    check_whois=check_whois,
                    check_dns=check_dns,
                    scanned_domains=infra_mgmt.tracker.scanned_domains
                )
                
                if subdomain_results:
                    logger.info(f"[SCAN] Found {len(subdomain_results)} subdomains for {domain}")
                    
                    for result in subdomain_results:
                        subdomain = result['domain']
                        if not infra_mgmt.tracker.is_endpoint_scanned(subdomain, port):
                            scan_queue.add((subdomain, port))
                            logger.info(f"[SCAN] Added subdomain to queue: {subdomain}:{port}")
                
                current_sub_step += 1
                update_progress(current_sub_step)
                
                subdomain_scanner.set_status_container(None)
                
            except Exception as subdomain_error:
                logger.error(f"[SCAN] Error in subdomain scanning for {domain}: {str(subdomain_error)}")
                has_errors = True
                error_messages.append(f"Error in subdomain scanning: {str(subdomain_error)}")
                st.session_state.scan_results["error"].append(f"{domain}:{port} - Error in subdomain scanning: {str(subdomain_error)}")
                subdomain_scanner.set_status_container(None)
        
        # Update final status
        if has_errors:
            error_msg = f"{domain}:{port} - " + "; ".join(error_messages)
            if error_msg not in st.session_state.scan_results["error"]:
                st.session_state.scan_results["error"].append(error_msg)
        
        # Print final scanner status
        infra_mgmt.tracker.print_status()
        
    except Exception as e:
        logger.error(f"[SCAN] Error processing {domain}:{port}: {str(e)}")
        st.session_state.scan_results["error"].append(f"{domain}:{port} - {str(e)}")
        return False
    
    return True

def process_sans_from_certificate(session: Session, cert: Certificate, port: int = 443) -> Set[str]:
    """
    Process Subject Alternative Names from a certificate and add them to scan queue.
    
    Args:
        session: Database session
        cert: Certificate object to process
        port: Port to use for scanning
        
    Returns:
        Set[str]: Set of processed SANs
    """
    processed_sans = set()
    try:
        if cert.san:  # san is stored as JSON string
            sans = json.loads(cert.san)
            for san in sans:
                # Clean up SAN
                san = san.strip('*. ')
                if san and not session.query(Domain).filter_by(domain_name=san).first():
                    processed_sans.add(san)
                    logger.info(f"[SANS] Found new domain from certificate: {san}")
    except Exception as e:
        logger.error(f"Error processing SANs: {str(e)}")
    
    return processed_sans

def get_certificate_sans(session: Session) -> List[str]:
    """Get all unique SANs from existing certificates."""
    all_sans = set()
    try:
        certificates = session.query(Certificate).all()
        for cert in certificates:
            # Use the hybrid property which handles JSON deserialization
            sans = cert.san  # This is already a list thanks to the hybrid property
            all_sans.update(sans)
        return sorted(list(all_sans))
    except Exception as e:
        logger.error(f"Error getting certificate SANs: {str(e)}")
        notify(f"Error retrieving SANs from certificates: {str(e)}", "error")
        return []

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
            "warning": [],
            "no_cert": []
        }
    if 'scan_input' not in st.session_state:
        st.session_state.scan_input = ""
    if 'scanned_domains' not in st.session_state:
        st.session_state.scanned_domains = set()
    if 'selected_sans' not in st.session_state:
        st.session_state.selected_sans = set()
    if 'scan_queue' not in st.session_state:
        st.session_state.scan_queue = set()
    
    # Initialize scan manager if not exists
    if 'scan_manager' not in st.session_state:
        st.session_state.scan_manager = ScanManager()
    
    st.title("Domain & Certificate Scanner")
    
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
            check_sans = st.checkbox("Scan SANs", value=True)
            
            # Platform detection and chain validation options
            detect_platform = st.checkbox("Detect Platform", value=True, 
                help="Detect if certificate is served through F5, Akamai, Cloudflare, etc.")
            validate_chain = st.checkbox("Validate Certificate Chain", value=True,
                help="Validate the complete certificate chain")
        
        # Scan initiation button below both columns
        scan_button_clicked = st.button("Start Scan", type="primary", disabled=st.session_state.scan_in_progress)
        
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
            
            # Reset scan state
            st.session_state.scan_manager.reset_scan_state()
            st.session_state.scanned_domains.clear()  # Clear scanned domains for new session
            st.session_state.scan_queue.clear()  # Clear scan queue for new session
            
            # Reset scan results for new scan
            st.session_state.scan_results = {
                "success": [],
                "error": [],
                "warning": [],
                "no_cert": []
            }
            
            # Validate input
            if not st.session_state.scan_input.strip():
                notify("Please enter at least one domain to scan", "error")
                show_notifications()
                st.session_state.scan_in_progress = False
                return
            
            # Process each target
            validation_errors = False
            entries = [h.strip() for h in st.session_state.scan_input.split('\n') if h.strip()]
            
            # Create a session for validation
            with Session(engine) as session:
                for entry in entries:
                    try:
                        is_valid, hostname, port, error = st.session_state.scan_manager.process_scan_target(entry, session)
                        if not is_valid:
                            notify(f"Invalid entry '{entry}': {error}", "error")
                            validation_errors = True
                            continue
                        
                        # Add validated target to queue
                        st.session_state.scan_queue.add((hostname, port))
                        st.session_state.scan_manager.add_to_queue(hostname, port)
                    except Exception as e:
                        logger.error(f"Error validating entry '{entry}': {str(e)}")
                        notify(f"Error validating '{entry}': {str(e)}", "error")
                        validation_errors = True
                        continue
            
            # Show notifications
            with notification_placeholder:
                show_notifications()
            
            # Handle validation errors
            if validation_errors:
                notify("Please correct the validation errors above", "error")
                show_notifications()
                st.session_state.scan_in_progress = False
                return
            
            # Execute scans if we have targets
            if st.session_state.scan_queue:
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
                    progress = st.progress(0.0)
                
                # Create progress container
                progress_container = StreamlitProgressContainer(progress, queue_status)
                
                # Process targets in a single session
                with Session(engine) as session:
                    total_steps = len(st.session_state.scan_queue)
                    current_step = 0
                    
                    # Initialize progress
                    update_progress(0, 1, progress_container, current_step, total_steps)
                    
                    while st.session_state.scan_queue:
                        # Get next target from queue
                        target = st.session_state.scan_queue.pop()
                        if not target:
                            break
                        
                        current_step += 1  # Increment step before processing
                        hostname, port = target
                        target_key = f"{hostname}:{port}"
                        
                        try:
                            # Skip if this operation is already in progress
                            if st.session_state.current_operation == target_key:
                                continue
                            st.session_state.current_operation = target_key
                            
                            # Update status for current target
                            status_container.text(f"Scanning {target_key}...")
                            
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
                            
                            # Add domain to scanned domains set
                            st.session_state.scanned_domains.add(hostname)
                            
                            # Update progress
                            update_progress(1, 1, progress_container, current_step, total_steps)
                            
                            # Commit changes after each successful scan
                            session.commit()
                            
                        except Exception as e:
                            logger.error(f"[SCAN] Error processing {target_key}: {str(e)}")
                            notify(f"Error scanning {target_key}: {str(e)}", "error")
                            st.session_state.scan_results["error"].append(f"{target_key} - {str(e)}")
                            session.rollback()
                        finally:
                            # Clear current operation
                            if st.session_state.current_operation == target_key:
                                st.session_state.current_operation = None
                        
                        # Small delay to allow UI updates
                        time.sleep(0.1)
                
                # Set progress to complete
                progress_container.progress(1.0)
                progress_container.text("Scan completed!")
                
                # Clear status after completion
                status_container.empty()
                queue_status.empty()
                
                # Reset scan state
                st.session_state.scan_in_progress = False
                st.session_state.current_operation = None
                
                # Get final scan stats
                stats = st.session_state.scan_manager.get_scan_stats()
                
                # Clear any existing notifications before showing new ones
                clear_notifications()
                
                # Show consolidated scan completion message
                if stats['success_count'] > 0:
                    if len(st.session_state.scan_results["no_cert"]) > 0 or stats['error_count'] > 0:
                        notify(f"Scan completed with {stats['success_count']} successful targets, but some issues were found. Check the results for details.", "warning")
                    else:
                        notify(f"Scan completed! Successfully processed {stats['success_count']} targets.", "success")
                
                # Show results summary
                st.divider()
                st.subheader("Scan Results")
                
                # Create a container for the tabs
                results_container = st.container()
                
                # Display results in tabs within the container
                with results_container:
                    tab_domains, tab_certs, tab_dns, tab_errors = st.tabs([
                        "🌐 Domains",
                        "🔐 Certificates",
                        "📝 DNS Records",
                        "⚠️ Issues"
                    ])
                    
                    # Domains tab
                    with tab_domains:
                        with Session(engine) as session:
                            # Get all scanned domains from session state
                            scanned_domains = list(st.session_state.scanned_domains)
                            if not scanned_domains:
                                st.markdown("No domains scanned yet.")
                            else:
                                for domain in sorted(scanned_domains):
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
                    
                    # Certificates tab
                    with tab_certs:
                        with Session(engine) as session:
                            # Get all scanned domains from session state
                            scanned_domains = list(st.session_state.scanned_domains)
                            if not scanned_domains:
                                st.markdown("No certificates found yet.")
                            else:
                                for domain in sorted(scanned_domains):
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
                                                    # Add platform information
                                                    bindings = session.query(CertificateBinding).filter_by(certificate=cert).all()
                                                    platforms = [b.platform for b in bindings if b.platform]
                                                    if platforms:
                                                        st.write("**Platform:**", ", ".join(set(platforms)))
                                                
                                                # Add button to scan SANs
                                                if cert.san:
                                                    sans = cert.san  # Use the hybrid property directly
                                                    if sans:
                                                        button_key = f"scan_sans_{domain}_{cert.serial_number}"
                                                        if st.button(f"Scan SANs ({len(sans)} found)", key=button_key):
                                                            st.session_state.scan_targets = sans
                                                            st.rerun()
                                    elif domain_obj:
                                        st.markdown(f"No certificates found for {domain_obj.domain_name}")
                                        st.session_state.scan_results["no_cert"].append(f"{domain_obj.domain_name}")
                    
                    # DNS Records tab
                    with tab_dns:
                        with Session(engine) as session:
                            try:
                                # Get all scanned domains from session state
                                scanned_domains = list(st.session_state.scanned_domains)
                                if not scanned_domains:
                                    st.markdown("No DNS records found yet.")
                                else:
                                    for domain in sorted(scanned_domains):
                                        domain_obj = session.query(Domain).filter_by(domain_name=domain).first()
                                        if domain_obj:
                                            dns_records = domain_obj.dns_records
                                            if dns_records:
                                                st.markdown(f"### {domain_obj.domain_name}")
                                                records_df = []
                                                
                                                for record in dns_records:
                                                    try:
                                                        priority = str(record.priority) if record.priority is not None else 'N/A'
                                                        record_data = {
                                                            'Type': record.record_type,
                                                            'Name': record.name,
                                                            'Value': record.value,
                                                            'TTL': int(record.ttl),
                                                            'Priority': priority
                                                        }
                                                        records_df.append(record_data)
                                                    except Exception as e:
                                                        logger.error(f"Error processing DNS record: {str(e)}")
                                                        st.session_state.scan_results["error"].append(f"Error processing DNS record for {domain}: {str(e)}")
                                                        continue
                                                
                                                if records_df:
                                                    df = pd.DataFrame(records_df)
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
                                                    st.markdown(f"No DNS records found for {domain}")
                                            else:
                                                st.markdown(f"No DNS records found for {domain}")
                                        else:
                                            logger.warning(f"[DNS] Domain object not found for {domain}")
                                            st.session_state.scan_results["warning"].append(f"Domain object not found for {domain}")
                            except Exception as e:
                                logger.error(f"Error displaying DNS records: {str(e)}")
                                st.session_state.scan_results["error"].append(f"Error displaying DNS records: {str(e)}")
                    
                    # Issues tab
                    with tab_errors:
                        # Create a container for issues
                        issues_container = st.container()
                        
                        with issues_container:
                            # Debug output to verify scan results
                            st.markdown("### Debug Information")
                            st.json(st.session_state.scan_results)
                            
                            # Check for no certificates
                            if st.session_state.scan_results["no_cert"]:
                                st.markdown("### No Certificates Found")
                                for target in st.session_state.scan_results["no_cert"]:
                                    st.markdown(f"- {target}")
                                st.divider()
                            
                            # Check for errors
                            if st.session_state.scan_results["error"]:
                                st.markdown("### Errors")
                                for error in st.session_state.scan_results["error"]:
                                    st.markdown(f"- {error}")
                                st.divider()
                            
                            # Check for warnings
                            if st.session_state.scan_results["warning"]:
                                st.markdown("### Warnings")
                                for warning in st.session_state.scan_results["warning"]:
                                    st.markdown(f"- {warning}")
                            
                            # If no issues found
                            if not (st.session_state.scan_results["error"] or 
                                  st.session_state.scan_results["warning"] or 
                                  st.session_state.scan_results["no_cert"]):
                                st.markdown("### No Issues Found")
                                st.markdown("All scans completed successfully with no issues detected.")
                
                # Show notifications after all content is rendered
                with notification_placeholder:
                    show_notifications()

def calculate_progress(sub_step: int, total_sub_steps: int, current_step: int, total_steps: int) -> float:
    """
    Calculate overall progress including sub-steps.
    
    Args:
        sub_step: Current sub-step (0-based)
        total_sub_steps: Total number of sub-steps for this domain
        current_step: Current step in the overall process
        total_steps: Total number of steps in the overall process
        
    Returns:
        float: Progress value between 0 and 1
    """
    if current_step is None or total_steps is None or total_steps == 0:
        return 0.0
    
    # Calculate base progress for completed steps
    base_progress = (current_step - 1) / total_steps if current_step > 0 else 0
    
    # Calculate progress for current step
    step_progress = (sub_step / total_sub_steps) / total_steps if total_sub_steps > 0 else 0
    
    # Ensure progress stays within [0.0, 1.0]
    return max(0.0, min(1.0, base_progress + step_progress))

def update_progress(sub_step: int, total_sub_steps: int, progress_container: StreamlitProgressContainer, current_step: int, total_steps: int):
    """Update progress bar and queue status."""
    if progress_container and current_step is not None and total_steps is not None:
        progress = calculate_progress(sub_step, total_sub_steps, current_step, total_steps)
        progress_container.progress(progress)
        queue_size = st.session_state.scan_manager.infra_mgmt.tracker.queue_size()
        progress_container.text(f"Scanning target {current_step} of {total_steps} (Remaining in queue: {queue_size})")
