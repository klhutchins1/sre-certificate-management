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
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker, joinedload
import logging
from typing import Tuple, List, Set
import pandas as pd
from ..static.styles import load_warning_suppression, load_css
from ..notifications import initialize_notifications, show_notifications, notify, clear_notifications
import time
import ipaddress
from ..models import (
    Domain, Certificate, CertificateBinding, DomainDNSRecord, Host, HostIP,
    HOST_TYPE_SERVER, HOST_TYPE_CDN, HOST_TYPE_LOAD_BALANCER, ENV_PRODUCTION
)
from ..settings import settings  # Import settings for database configuration
from urllib.parse import urlparse

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

def is_ip_address(address: str) -> bool:
    """Check if a string is an IP address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def load_domain_data(session: Session, domain_name: str):
    """
    Load domain data with all necessary relationships.
    
    Args:
        session: Database session
        domain_name: Domain name or IP to load
        
    Returns:
        Domain object with loaded relationships or None
    """
    try:
        # Check if this is an IP address
        if is_ip_address(domain_name):
            # This is an IP address, handle it differently
            host = session.query(Host).options(
                joinedload(Host.ip_addresses),
                joinedload(Host.certificate_bindings).joinedload(CertificateBinding.certificate)
            ).filter_by(name=domain_name).first()
            
            if not host:
                # Create a new host for the IP
                host = Host(
                    name=domain_name,
                    host_type=HOST_TYPE_SERVER,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                # Add the IP address record
                host_ip = HostIP(
                    host=host,
                    ip_address=domain_name,
                    is_active=True,
                    last_seen=datetime.now()
                )
                session.add(host)
                session.add(host_ip)
                session.flush()
            return host

        # Not an IP address, proceed with domain lookup
        return session.query(Domain).options(
            joinedload(Domain.certificates),
            joinedload(Domain.dns_records),
            joinedload(Domain.certificates).joinedload(Certificate.certificate_bindings)
        ).filter_by(domain_name=domain_name).first()
    except Exception as e:
        logger.error(f"Error loading domain data for {domain_name}: {str(e)}")
        return None

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
        from ..scanner import ScanManager
        st.session_state.scan_manager = ScanManager()
    
    # Create database session factory
    Session = sessionmaker(bind=engine)
    
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
            
            # Create progress containers
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
            
            # Show initial status
            status_container.text("Initializing scan...")
            progress_container.text("Preparing to scan targets...")
            
            # Validate input
            if not st.session_state.scan_input.strip():
                notify("Please enter at least one domain to scan", "error")
                show_notifications()
                st.session_state.scan_in_progress = False
                # Clear progress containers
                progress_bar.empty()
                status_container.empty()
                queue_status.empty()
                return
            
            # Process each target
            validation_errors = False
            entries = [h.strip() for h in st.session_state.scan_input.split('\n') if h.strip()]
            
            # Update status for validation
            status_container.text("Validating scan targets...")
            progress_container.text("Validating input...")
            progress_container.progress(0.1)  # Show some initial progress
            
            # Create a session for validation
            with Session() as session:
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
                # Clear progress containers
                progress_bar.empty()
                status_container.empty()
                queue_status.empty()
                return
            
            # Execute scans if we have targets
            if st.session_state.scan_queue:
                # Update progress to show we're starting scans
                progress_container.progress(0.2)
                status_container.text("Starting scan operations...")
                
                # Process targets in a single session
                with Session() as session:
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
                            
                            # Process the scan target using ScanManager
                            try:
                                st.session_state.scan_manager.scan_target(
                                    session=session,
                                    domain=hostname,
                                    port=port,
                                    check_whois=check_whois,
                                    check_dns=check_dns,
                                    check_subdomains=check_subdomains,
                                    check_sans=check_sans,
                                    detect_platform=detect_platform,
                                    validate_chain=validate_chain,
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
                                
                                # Add to success results
                                st.session_state.scan_results["success"].append(target_key)
                                
                            except Exception as scan_error:
                                error_msg = str(scan_error)
                                logger.error(f"[SCAN] Error processing {target_key}: {error_msg}")
                                
                                # Check for specific error types
                                if "database is locked" in error_msg.lower():
                                    notify(f"Database busy while scanning {target_key}. The scan will continue but some data may need to be rescanned.", "warning")
                                elif "connection refused" in error_msg.lower():
                                    notify(f"Could not connect to {target_key}. The port may be closed or filtered.", "warning")
                                elif "certificate verify failed" in error_msg.lower():
                                    notify(f"Certificate validation failed for {target_key}. The certificate may be invalid or self-signed.", "warning")
                                elif "dns lookup failed" in error_msg.lower():
                                    notify(f"Could not resolve hostname for {target_key}. The domain may not exist.", "warning")
                                else:
                                    notify(f"Error scanning {target_key}: {error_msg}", "error")
                                
                                st.session_state.scan_results["error"].append(f"{target_key} - {error_msg}")
                                session.rollback()
                            
                        except Exception as e:
                            logger.error(f"[SCAN] Error in scan operation for {target_key}: {str(e)}")
                            notify(f"Unexpected error during scan of {target_key}: {str(e)}", "error")
                            st.session_state.scan_results["error"].append(f"{target_key} - {str(e)}")
                            session.rollback()
                        finally:
                            # Clear current operation
                            if st.session_state.current_operation == target_key:
                                st.session_state.current_operation = None
                            
                            # Show notifications after each target
                            with notification_placeholder:
                                show_notifications()
                        
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
                        with Session() as session:
                            try:
                                # Get all scanned domains from session state
                                scanned_domains = list(st.session_state.scanned_domains)
                                if not scanned_domains:
                                    st.markdown("No domains or IPs scanned yet.")
                                else:
                                    for domain in sorted(scanned_domains):
                                        # Load domain with relationships
                                        obj = load_domain_data(session, domain)
                                        if obj:
                                            if isinstance(obj, Host):  # IP address
                                                st.markdown(f"### IP: {obj.name}")
                                                col1, col2 = st.columns(2)
                                                with col1:
                                                    st.write("**Type:**", obj.host_type or "N/A")
                                                    st.write("**Environment:**", obj.environment or "N/A")
                                                    st.write("**Last Seen:**", obj.last_seen.strftime("%Y-%m-%d %H:%M:%S") if obj.last_seen else "N/A")
                                                    # Show reverse DNS if available
                                                    try:
                                                        import dns.resolver
                                                        import dns.reversename
                                                        addr = dns.reversename.from_address(obj.name)
                                                        answers = dns.resolver.resolve(addr, "PTR")
                                                        hostnames = [str(rdata).rstrip('.') for rdata in answers]
                                                        if hostnames:
                                                            st.write("**Hostnames:**", ", ".join(hostnames))
                                                    except Exception:
                                                        pass
                                                with col2:
                                                    # Show network information
                                                    try:
                                                        import ipaddress
                                                        ip_obj = ipaddress.ip_address(obj.name)
                                                        if isinstance(ip_obj, ipaddress.IPv4Address):
                                                            network = ipaddress.ip_network(f"{obj.name}/24", strict=False)
                                                        else:
                                                            network = ipaddress.ip_network(f"{obj.name}/64", strict=False)
                                                        st.write("**Network:**", str(network))
                                                    except Exception:
                                                        pass
                                                    # Show certificate bindings
                                                    bindings = session.query(CertificateBinding).filter_by(host=obj).all()
                                                    st.write("**Certificates:**", len(bindings))
                                                    if bindings:
                                                        st.write("**Ports:**", ", ".join(str(b.port) for b in bindings if b.port))
                                            else:  # Domain
                                                st.markdown(f"### Domain: {obj.domain_name}")
                                                col1, col2 = st.columns(2)
                                                with col1:
                                                    st.write("**Registrar:**", obj.registrar or "N/A")
                                                    st.write("**Registration Date:**", obj.registration_date.strftime("%Y-%m-%d") if obj.registration_date else "N/A")
                                                    st.write("**Owner:**", obj.owner or "N/A")
                                                with col2:
                                                    st.write("**Expiration Date:**", obj.expiration_date.strftime("%Y-%m-%d") if obj.expiration_date else "N/A")
                                                    st.write("**Certificates:**", len(obj.certificates))
                                                    st.write("**DNS Records:**", len(obj.dns_records))
                            except Exception as e:
                                logger.error(f"Error displaying domain/IP data: {str(e)}")
                                st.error(f"Error displaying domain/IP data: {str(e)}")
                    
                    # Certificates tab
                    with tab_certs:
                        with Session() as session:
                            try:
                                # Get all scanned domains from session state
                                scanned_domains = list(st.session_state.scanned_domains)
                                if not scanned_domains:
                                    st.markdown("No certificates found yet.")
                                else:
                                    for domain in sorted(scanned_domains):
                                        # Load domain with relationships
                                        obj = load_domain_data(session, domain)
                                        if obj:
                                            st.markdown(f"### {obj.name if isinstance(obj, Host) else obj.domain_name}")
                                            
                                            # Get certificates based on object type
                                            if isinstance(obj, Domain):
                                                certificates = obj.certificates
                                            else:  # Host object
                                                bindings = session.query(CertificateBinding).filter_by(host=obj).all()
                                                certificates = [b.certificate for b in bindings if b.certificate]
                                            
                                            if certificates:
                                                for cert in certificates:
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
                                                            platforms = [b.platform for b in cert.certificate_bindings if b.platform]
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
                                            else:
                                                st.markdown(f"No certificates found for {domain}")
                                                st.session_state.scan_results["no_cert"].append(f"{domain}")
                            except Exception as e:
                                logger.error(f"Error displaying certificate data: {str(e)}")
                                st.error(f"Error displaying certificate data: {str(e)}")
                    
                    # DNS Records tab
                    with tab_dns:
                        with Session() as session:
                            try:
                                # Get all scanned domains from session state
                                scanned_domains = list(st.session_state.scanned_domains)
                                if not scanned_domains:
                                    st.markdown("No DNS records found yet.")
                                else:
                                    for domain in sorted(scanned_domains):
                                        # Load domain with relationships
                                        obj = load_domain_data(session, domain)
                                        if isinstance(obj, Domain):  # Only show DNS records for domains
                                            dns_records = obj.dns_records
                                            if dns_records:
                                                st.markdown(f"### {obj.domain_name}")
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
                                        elif isinstance(obj, Host):
                                            st.markdown(f"DNS records not applicable for IP address {obj.name}")
                                        else:
                                            logger.warning(f"[DNS] Object not found for {domain}")
                                            st.session_state.scan_results["warning"].append(f"Object not found for {domain}")
                            except Exception as e:
                                logger.error(f"Error displaying DNS records: {str(e)}")
                                st.error(f"Error displaying DNS records: {str(e)}")
                    
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
