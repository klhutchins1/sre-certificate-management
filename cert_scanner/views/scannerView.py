import streamlit as st
from datetime import datetime
from sqlalchemy.orm import Session
from urllib.parse import urlparse
from ..models import (
    Certificate, Host, HostIP, CertificateScan, CertificateBinding,
    HOST_TYPE_SERVER, ENV_PRODUCTION
)

def render_scan_interface(engine):
    """Render the certificate scanning interface"""
    # Clear transitioning flag if set
    if st.session_state.get('transitioning', False):
        st.session_state.transitioning = False
        
    st.title("Scan Certificates")
    
    # Initialize session state for scan results if not exists
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = {
            "success": [],
            "error": [],
            "warning": []
        }
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Check for pre-populated SANs from certificate view
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
            
        scan_input = st.text_area(
            "Enter hostnames to scan (one per line)",
            value=default_text,
            height=150,
            placeholder="""example.com
example.com:8443
https://example.com
internal.server.local:444"""
        )
        
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
        
        if st.button("Start Scan"):
            # Clear previous results
            st.session_state.scan_results = {
                "success": [],
                "error": [],
                "warning": []
            }
            
            entries = [h.strip() for h in scan_input.split('\n') if h.strip()]
            scan_targets = []
            
            # Parse hostnames and ports
            for entry in entries:
                # Parse URL or hostname:port
                try:
                    # Handle URLs (http://, https://, etc.)
                    parsed = urlparse(entry)
                    if parsed.netloc:
                        hostname = parsed.netloc
                    else:
                        hostname = parsed.path
                    
                    # Split hostname and port if present
                    if ':' in hostname:
                        hostname, port = hostname.rsplit(':', 1)
                        try:
                            port = int(port)
                            # Validate port number
                            if port < 1 or port > 65535:
                                st.error(f"Invalid port number in {entry}: Port must be between 1 and 65535")
                                continue
                        except ValueError:
                            st.error(f"Invalid port number in {entry}: '{port}' is not a valid number")
                            continue
                    else:
                        port = 443
                    
                    # Validate hostname is not empty after parsing
                    if not hostname:
                        st.error(f"Invalid entry: {entry} - Hostname cannot be empty")
                        continue
                    
                    # Remove any remaining slashes or spaces
                    hostname = hostname.strip('/')
                    
                    scan_targets.append((hostname, port))
                except Exception as e:
                    st.error(f"Error parsing {entry}: Please check the format")
                    continue
            
            if scan_targets:
                # Create containers for progress
                progress_container = st.empty()
                
                with progress_container:
                    progress = st.progress(0)
                
                for i, (hostname, port) in enumerate(scan_targets):
                    with st.spinner(f'Scanning {hostname}:{port}...'):
                        cert_info = st.session_state.scanner.scan_certificate(hostname, port)
                        if cert_info:
                            st.session_state.scan_results["success"].append(f"{hostname}:{port}")
                            # Save to database
                            with Session(engine) as session:
                                try:
                                    # Create or update certificate
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
                                            issuer=str(cert_info.issuer),
                                            subject=str(cert_info.subject),
                                            san=str(cert_info.san),
                                            key_usage=cert_info.key_usage,
                                            signature_algorithm=cert_info.signature_algorithm
                                        )
                                        session.add(cert)
                                    
                                    # Create or update host
                                    host = session.query(Host).filter_by(
                                        name=cert_info.hostname
                                    ).first()
                                    
                                    if not host:
                                        host = Host(
                                            name=cert_info.hostname,
                                            host_type=HOST_TYPE_SERVER,  # Default type
                                            environment=ENV_PRODUCTION,  # Default environment
                                            last_seen=datetime.now()
                                        )
                                        session.add(host)
                                    else:
                                        host.last_seen = datetime.now()
                                    
                                    # Create or update bindings for each IP address
                                    for ip in cert_info.ip_addresses:
                                        # Create or update HostIP
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
                                        
                                        # Check for existing binding
                                        binding = session.query(CertificateBinding).filter_by(
                                            host_id=host.id,
                                            host_ip_id=host_ip.id,
                                            port=cert_info.port
                                        ).first()
                                        
                                        if binding:
                                            # Update existing binding
                                            binding.certificate_id = cert.id
                                            binding.last_seen = datetime.now()
                                        else:
                                            # Create new binding
                                            binding = CertificateBinding(
                                                host_id=host.id,
                                                host_ip_id=host_ip.id,
                                                certificate_id=cert.id,
                                                port=cert_info.port,
                                                binding_type='IP',
                                                last_seen=datetime.now()
                                            )
                                            session.add(binding)
                                    
                                    # Create scan record
                                    scan = CertificateScan(
                                        certificate=cert,
                                        scan_date=datetime.now(),
                                        status='Valid',
                                        port=cert_info.port
                                    )
                                    session.add(scan)
                                    
                                    session.commit()
                                except Exception as e:
                                    st.session_state.scan_results["error"].append(f"{hostname}:{port} - Database error: {str(e)}")
                                    session.rollback()
                        else:
                            st.session_state.scan_results["error"].append(f"{hostname}:{port} - Failed to retrieve certificate")
                            # Record failed scan
                            with Session(engine) as session:
                                try:
                                    # Create or get host for failed scan
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

                                    # Create scan record for failed attempt
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
                        
                        with progress_container:
                            progress.progress((i + 1) / len(scan_targets))
                
                # Only clear scan targets after successful scan
                if 'scan_targets' in st.session_state:
                    del st.session_state.scan_targets
            else:
                st.warning("Please enter at least one hostname to scan")
    
    with col2:
        st.subheader("Recent Scans")
        with Session(engine) as session:
            recent_scans = session.query(CertificateScan)\
                .outerjoin(Certificate)\
                .order_by(CertificateScan.scan_date.desc())\
                .limit(5)\
                .all()
            
            if recent_scans:
                st.markdown("<div style='font-size:0.9em'>", unsafe_allow_html=True)
                for scan in recent_scans:
                    scan_time = scan.scan_date.strftime("%Y-%m-%d %H:%M")
                    if scan.certificate:
                        cert_name = scan.certificate.common_name
                        status_color = "green" if scan.status == 'Valid' else "red"
                        st.markdown(
                            f"**{cert_name}** "
                            f"<span style='color:gray'>"
                            f"(🕒 {scan_time} • <span style='color:{status_color}'>{scan.status}</span>)</span>",
                            unsafe_allow_html=True
                        )
                    else:
                        # Get host information for failed scan
                        host = session.query(Host).filter_by(id=scan.host_id).first()
                        host_info = f"{host.name}:{scan.port}" if host else "Unknown Host"
                        st.markdown(
                            f"**{host_info}** "
                            f"<span style='color:gray'>"
                            f"(🕒 {scan_time} • <span style='color:red'>Failed</span>)</span>",
                            unsafe_allow_html=True
                        )
                st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.info("No recent scans")
    
    # Display current scan results
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
