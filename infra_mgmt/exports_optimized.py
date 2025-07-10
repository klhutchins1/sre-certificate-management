"""
Optimized Data Export Module for Performance

This is an optimized version of the export module that implements:
- Lazy loading for PDF dependencies (fpdf2)
- Optional matplotlib for chart generation
- Graceful fallbacks when dependencies are missing
- Better error handling and user feedback

Performance improvements:
- PDF libraries only loaded when needed
- Optional chart generation
- Reduced startup time
- Better dependency management
"""

# Standard library imports
from datetime import datetime
from pathlib import Path
import logging
from typing import Optional, List

# Core imports (always available)
import pandas as pd
from sqlalchemy.orm import Session

# Local application imports
from .settings import Settings
from .models import Certificate, Host, CertificateBinding
from .utils.lazy_imports import get_matplotlib, ImportTimer

# Configure logging
logger = logging.getLogger(__name__)

# PDF functionality flag
_pdf_available = None

def _check_pdf_availability() -> bool:
    """Check if PDF generation is available."""
    global _pdf_available
    if _pdf_available is None:
        try:
            from fpdf import FPDF
            _pdf_available = True
            logger.info("PDF generation available (fpdf2)")
        except ImportError:
            _pdf_available = False
            logger.warning("PDF generation not available - fpdf2 not installed")
    return _pdf_available

def _get_fpdf():
    """Lazy load FPDF class."""
    try:
        from fpdf import FPDF
        return FPDF
    except ImportError:
        return None

#------------------------------------------------------------------------------
# CSV Export Functions (Always Available)
#------------------------------------------------------------------------------

def export_certificates_to_csv(session: Session, output_path: str = None) -> str:
    """
    Export certificates to a CSV file.
    
    This function is always available and doesn't require optional dependencies.
    """
    with ImportTimer("Certificate CSV export"):
        settings = Settings()
        
        # Get certificates with their bindings
        certificates = session.query(Certificate).all()
        
        # Prepare data for export
        data = []
        for cert in certificates:
            # Get unique hosts for this certificate
            hosts = {binding.host for binding in cert.certificate_bindings}
            
            # Create a row for each certificate
            row = {
                'Serial Number': cert.serial_number,
                'Common Name': cert.common_name,
                'Status': 'Valid' if cert.valid_until > datetime.now() else 'Expired',
                'Valid From': cert.valid_from.strftime('%Y-%m-%d'),
                'Valid Until': cert.valid_until.strftime('%Y-%m-%d'),
                'Issuer': cert.issuer,
                'Subject': cert.subject,
                'Key Usage': cert.key_usage,
                'Subject Alternative Names': cert.san,
                'Hosts': ', '.join(sorted(h.name for h in hosts)),
                'IP Addresses': ', '.join(sorted(ip.ip_address for h in hosts for ip in h.ip_addresses)),
                'Platforms': ', '.join(sorted(set(b.platform for b in cert.certificate_bindings if b.platform))),
                'Last Seen': max(b.last_seen for b in cert.certificate_bindings).strftime('%Y-%m-%d %H:%M:%S') if cert.certificate_bindings else 'Never'
            }
            data.append(row)
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Generate output path if not provided
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f'exports/certificates_export_{timestamp}.csv'
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Get CSV settings from configuration
        delimiter = settings.get('exports.csv.delimiter', ',')
        encoding = settings.get('exports.csv.encoding', 'utf-8')
        
        # Export to CSV
        df.to_csv(output_path, index=False, sep=delimiter, encoding=encoding)
        
        logger.info(f"Exported {len(data)} certificates to {output_path}")
        return output_path

def export_hosts_to_csv(session: Session, output_path: str = None) -> str:
    """
    Export hosts to a CSV file.
    
    This function is always available and doesn't require optional dependencies.
    """
    with ImportTimer("Host CSV export"):
        settings = Settings()
        
        # Get hosts with their bindings
        hosts = session.query(Host).all()
        
        # Prepare data for export
        data = []
        for host in hosts:
            # If host has no bindings, create a basic row
            if not host.certificate_bindings:
                for ip in host.ip_addresses:
                    row = {
                        'Hostname': host.name,
                        'IP Address': ip.ip_address,
                        'Port': None,
                        'Platform': 'Unknown',
                        'Certificate Serial': None,
                        'Certificate Common Name': None,
                        'Certificate Status': 'No Certificate',
                        'Certificate Valid From': None,
                        'Certificate Valid Until': None,
                        'Last Seen': host.last_seen.strftime('%Y-%m-%d %H:%M:%S') if host.last_seen else None
                    }
                    data.append(row)
            else:
                # Create a row for each binding
                for binding in host.certificate_bindings:
                    cert = binding.certificate
                    for ip in host.ip_addresses:
                        if binding.host_ip_id == ip.id:
                            row = {
                                'Hostname': host.name,
                                'IP Address': ip.ip_address,
                                'Port': binding.port,
                                'Platform': binding.platform or 'Unknown',
                                'Certificate Serial': cert.serial_number,
                                'Certificate Common Name': cert.common_name,
                                'Certificate Status': 'Valid' if cert.valid_until > datetime.now() else 'Expired',
                                'Certificate Valid From': cert.valid_from.strftime('%Y-%m-%d'),
                                'Certificate Valid Until': cert.valid_until.strftime('%Y-%m-%d'),
                                'Last Seen': binding.last_seen.strftime('%Y-%m-%d %H:%M:%S')
                            }
                            data.append(row)
        
        # Create DataFrame
        df = pd.DataFrame(data)
        
        # Generate output path if not provided
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f'exports/hosts_export_{timestamp}.csv'
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Get CSV settings from configuration
        delimiter = settings.get('exports.csv.delimiter', ',')
        encoding = settings.get('exports.csv.encoding', 'utf-8')
        
        # Export to CSV
        df.to_csv(output_path, index=False, sep=delimiter, encoding=encoding)
        
        logger.info(f"Exported {len(data)} host records to {output_path}")
        return output_path

#------------------------------------------------------------------------------
# Optional Chart Generation
#------------------------------------------------------------------------------

def create_timeline_chart(certificates: List[Certificate]) -> Optional[str]:
    """
    Create a timeline chart for certificates using matplotlib (optional).
    
    Args:
        certificates: List of Certificate objects to visualize
        
    Returns:
        str: Path to the generated chart image, or None if generation fails
        
    This function uses lazy loading and gracefully handles missing matplotlib.
    """
    if not certificates:
        return None
    
    plt = get_matplotlib()
    if plt is None:
        logger.warning("Timeline chart generation skipped - matplotlib not available")
        return None
    
    try:
        with ImportTimer("Timeline chart generation"):
            from matplotlib.dates import DateFormatter
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend
            
            now = datetime.now()
            
            # Prepare data
            names = []
            start_dates = []
            end_dates = []
            colors = []
            
            for cert in certificates:
                if not cert.valid_from or not cert.valid_until:
                    continue
                    
                names.append(cert.common_name[:30] + ('...' if len(cert.common_name) > 30 else ''))
                start_dates.append(cert.valid_from)
                end_dates.append(cert.valid_until)
                colors.append('green' if cert.valid_until > now else 'red')
            
            if not names:
                return None
                
            # Create figure with optimized size
            fig_height = max(5, min(len(names) * 0.4, 20))  # Limit max height
            plt.figure(figsize=(10, fig_height))
            
            # Plot horizontal lines for each certificate
            for i in range(len(names)):
                plt.hlines(y=i, xmin=start_dates[i], xmax=end_dates[i], 
                          color=colors[i], linewidth=3)
                
            # Customize the plot
            plt.yticks(range(len(names)), names, fontsize=8)
            plt.xlabel('Date')
            plt.title('Certificate Timeline')
            
            # Format x-axis dates
            plt.gca().xaxis.set_major_formatter(DateFormatter('%Y-%m-%d'))
            plt.gcf().autofmt_xdate()
            
            # Add grid
            plt.grid(True, axis='x', linestyle='--', alpha=0.7)
            
            # Adjust layout
            plt.tight_layout()
            
            # Save as PNG
            img_path = 'exports/temp_timeline.png'
            Path(img_path).parent.mkdir(parents=True, exist_ok=True)
            plt.savefig(img_path, dpi=200, bbox_inches='tight')  # Reduced DPI for smaller files
            plt.close()  # Close the figure to free memory
            
            logger.info(f"Timeline chart generated: {img_path}")
            return img_path
            
    except Exception as e:
        logger.error(f"Failed to create timeline chart: {str(e)}")
        return None

#------------------------------------------------------------------------------
# Optional PDF Export Functions
#------------------------------------------------------------------------------

def export_certificates_to_pdf(session: Session, output_path: str = None) -> Optional[str]:
    """
    Export certificates to a PDF file using fpdf2 (optional).
    
    Args:
        session: Database session
        output_path: Optional path for the output file
        
    Returns:
        str: Path to the exported PDF file, or None if PDF generation is not available
        
    This function uses lazy loading and provides helpful error messages
    when PDF dependencies are not available.
    """
    if not _check_pdf_availability():
        logger.error("PDF export not available - please install fpdf2: pip install fpdf2")
        return None
    
    FPDF = _get_fpdf()
    if FPDF is None:
        return None
    
    try:
        with ImportTimer("Certificate PDF export"):
            settings = Settings()
            
            # Get certificates with their bindings
            certificates = session.query(Certificate).all()
            
            # Create timeline chart (optional)
            timeline_path = None
            try:
                timeline_path = create_timeline_chart(certificates)
            except Exception as e:
                logger.warning(f"Timeline chart generation failed: {str(e)}")
            
            # Create PDF object
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            
            # Add title page
            pdf.add_page()
            pdf.set_font('helvetica', 'B', 24)
            pdf.cell(0, 20, 'Certificate Report', ln=True, align='C')
            pdf.ln(20)
            
            # Add summary
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Summary', ln=True)
            pdf.set_font('helvetica', '', 12)
            pdf.cell(0, 8, f'Total Certificates: {len(certificates)}', ln=True)
            
            valid_count = sum(1 for c in certificates if c.valid_until > datetime.now())
            expired_count = len(certificates) - valid_count
            
            pdf.cell(0, 8, f'Valid Certificates: {valid_count}', ln=True)
            pdf.cell(0, 8, f'Expired Certificates: {expired_count}', ln=True)
            pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
            
            # Add timeline chart if available
            if timeline_path and Path(timeline_path).exists():
                try:
                    pdf.add_page()
                    pdf.set_font('helvetica', 'B', 14)
                    pdf.cell(0, 10, 'Certificate Timeline', ln=True)
                    pdf.image(timeline_path, x=10, w=190)
                except Exception as e:
                    logger.warning(f"Failed to add timeline to PDF: {str(e)}")
            
            # Add certificate details (limit to prevent huge PDFs)
            cert_limit = 50  # Limit for performance
            certs_to_process = certificates[:cert_limit]
            
            if len(certificates) > cert_limit:
                pdf.ln(10)
                pdf.set_font('helvetica', 'I', 10)
                pdf.cell(0, 8, f'Note: Showing first {cert_limit} certificates of {len(certificates)} total', ln=True)
            
            for cert in certs_to_process:
                pdf.add_page()
                pdf.set_font('helvetica', 'B', 16)
                
                # Truncate long certificate names
                cert_name = cert.common_name[:60] + '...' if len(cert.common_name) > 60 else cert.common_name
                pdf.cell(0, 10, f'Certificate: {cert_name}', ln=True)
                
                # Overview
                pdf.ln(5)
                pdf.set_font('helvetica', 'B', 14)
                pdf.cell(0, 10, 'Overview', ln=True)
                pdf.set_font('helvetica', '', 12)
                pdf.cell(0, 8, f'Serial Number: {cert.serial_number}', ln=True)
                pdf.cell(0, 8, f'Valid From: {cert.valid_from.strftime("%Y-%m-%d")}', ln=True)
                pdf.cell(0, 8, f'Valid Until: {cert.valid_until.strftime("%Y-%m-%d")}', ln=True)
                pdf.cell(0, 8, f'Status: {"Valid" if cert.valid_until > datetime.now() else "Expired"}', ln=True)
                
                # Bindings (limit to prevent huge PDFs)
                bindings = cert.certificate_bindings[:10]  # Limit bindings shown
                if bindings:
                    pdf.ln(5)
                    pdf.set_font('helvetica', 'B', 14)
                    pdf.cell(0, 10, f'Bindings ({len(bindings)} shown)', ln=True)
                    pdf.set_font('helvetica', '', 12)
                    
                    for binding in bindings:
                        host_name = binding.host.name if binding.host else "Unknown Host"
                        pdf.cell(0, 8, f'Host: {host_name}', ln=True)
                        if hasattr(binding, 'host_ip') and binding.host_ip:
                            pdf.cell(0, 8, f'IP: {binding.host_ip.ip_address}', ln=True)
                        if binding.port:
                            pdf.cell(0, 8, f'Port: {binding.port}', ln=True)
                        pdf.cell(0, 8, f'Platform: {binding.platform or "Not Set"}', ln=True)
                        pdf.ln(3)
            
            # Generate output path if not provided
            if output_path is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = f'exports/certificates_export_{timestamp}.pdf'
            
            # Ensure output directory exists
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            try:
                # Save PDF
                pdf.output(output_path)
                logger.info(f"PDF export completed: {output_path}")
            except Exception as e:
                logger.error(f"Failed to save PDF: {str(e)}")
                raise
            finally:
                # Clean up temporary files
                if timeline_path and Path(timeline_path).exists():
                    try:
                        Path(timeline_path).unlink()
                    except Exception as e:
                        logger.warning(f"Failed to remove temporary timeline file: {str(e)}")
            
            return output_path
            
    except Exception as e:
        logger.error(f"PDF generation failed: {str(e)}")
        return None

def export_hosts_to_pdf(session: Session, output_path: str = None) -> Optional[str]:
    """
    Export hosts to a PDF file using fpdf2 (optional).
    
    Returns None if PDF generation is not available.
    """
    if not _check_pdf_availability():
        logger.error("PDF export not available - please install fpdf2: pip install fpdf2")
        return None
    
    FPDF = _get_fpdf()
    if FPDF is None:
        return None
    
    try:
        with ImportTimer("Host PDF export"):
            settings = Settings()
            hosts = session.query(Host).all()
            
            # Create PDF object
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            
            # Add title page
            pdf.add_page()
            pdf.set_font('helvetica', 'B', 24)
            pdf.cell(0, 20, 'Host Report', ln=True, align='C')
            pdf.ln(20)
            
            # Add summary
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Summary', ln=True)
            pdf.set_font('helvetica', '', 12)
            pdf.cell(0, 8, f'Total Hosts: {len(hosts)}', ln=True)
            total_bindings = sum(len(host.certificate_bindings) for host in hosts)
            pdf.cell(0, 8, f'Total Certificate Bindings: {total_bindings}', ln=True)
            pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
            
            # Add host details (limit for performance)
            host_limit = 50
            hosts_to_process = hosts[:host_limit]
            
            if len(hosts) > host_limit:
                pdf.ln(10)
                pdf.set_font('helvetica', 'I', 10)
                pdf.cell(0, 8, f'Note: Showing first {host_limit} hosts of {len(hosts)} total', ln=True)
            
            for host in hosts_to_process:
                pdf.add_page()
                pdf.set_font('helvetica', 'B', 16)
                pdf.cell(0, 10, f'Host: {host.name}', ln=True)
                
                # IP Addresses
                pdf.ln(5)
                pdf.set_font('helvetica', 'B', 14)
                pdf.cell(0, 10, 'IP Addresses', ln=True)
                pdf.set_font('helvetica', '', 12)
                for ip in host.ip_addresses[:10]:  # Limit IPs shown
                    pdf.cell(0, 8, f'IP: {ip.ip_address}', ln=True)
                
                # Certificate Bindings
                bindings = host.certificate_bindings[:10]  # Limit bindings
                if bindings:
                    pdf.ln(5)
                    pdf.set_font('helvetica', 'B', 14)
                    pdf.cell(0, 10, f'Certificate Bindings ({len(bindings)} shown)', ln=True)
                    pdf.set_font('helvetica', '', 12)
                    
                    for binding in bindings:
                        cert = binding.certificate
                        cert_name = cert.common_name[:40] + '...' if len(cert.common_name) > 40 else cert.common_name
                        pdf.cell(0, 8, f'Certificate: {cert_name}', ln=True)
                        pdf.cell(0, 8, f'Platform: {binding.platform or "Not Set"}', ln=True)
                        pdf.cell(0, 8, f'Status: {"Valid" if cert.valid_until > datetime.now() else "Expired"}', ln=True)
                        pdf.ln(3)
            
            # Generate output path if not provided
            if output_path is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = f'exports/hosts_export_{timestamp}.pdf'
            
            # Ensure output directory exists
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Save PDF
            pdf.output(output_path)
            logger.info(f"Host PDF export completed: {output_path}")
            return output_path
            
    except Exception as e:
        logger.error(f"Host PDF generation failed: {str(e)}")
        return None

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

def get_export_capabilities() -> dict:
    """Get information about available export capabilities."""
    return {
        'csv': True,  # Always available
        'pdf': _check_pdf_availability(),
        'charts': get_matplotlib() is not None,
        'fpdf_version': _get_fpdf_version() if _check_pdf_availability() else None
    }

def _get_fpdf_version() -> Optional[str]:
    """Get fpdf2 version if available."""
    try:
        import fpdf
        return getattr(fpdf, '__version__', 'unknown')
    except ImportError:
        return None

# Export all public functions
__all__ = [
    'export_certificates_to_csv',
    'export_hosts_to_csv', 
    'export_certificates_to_pdf',
    'export_hosts_to_pdf',
    'create_timeline_chart',
    'get_export_capabilities'
]