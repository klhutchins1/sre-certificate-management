import pandas as pd
import plotly.figure_factory as ff
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from .settings import Settings
from .models import Certificate, Host, CertificateBinding
from fpdf import FPDF
import logging

logger = logging.getLogger(__name__)

def export_certificates_to_csv(session: Session, output_path: str = None) -> str:
    """Export certificates to a CSV file.
    
    Args:
        session: Database session
        output_path: Optional path for the output file. If not provided, a timestamped filename will be used.
        
    Returns:
        str: Path to the exported CSV file
    """
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
    
    return output_path

def export_hosts_to_csv(session: Session, output_path: str = None) -> str:
    """Export hosts to a CSV file.
    
    Args:
        session: Database session
        output_path: Optional path for the output file. If not provided, a timestamped filename will be used.
        
    Returns:
        str: Path to the exported CSV file
    """
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
    
    return output_path

def create_timeline_chart(certificates):
    """Create a timeline chart for certificates using matplotlib."""
    if not certificates:
        return None
        
    try:
        import matplotlib.pyplot as plt
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
                
            names.append(cert.common_name)
            start_dates.append(cert.valid_from)
            end_dates.append(cert.valid_until)
            colors.append('green' if cert.valid_until > now else 'red')
        
        if not names:
            return None
            
        # Create figure
        plt.figure(figsize=(10, max(5, len(names) * 0.5)))
        
        # Plot horizontal lines for each certificate
        for i in range(len(names)):
            plt.hlines(y=i, xmin=start_dates[i], xmax=end_dates[i], 
                      color=colors[i], linewidth=4, label=names[i])
            
        # Customize the plot
        plt.yticks(range(len(names)), names)
        plt.xlabel('Date')
        plt.title('Certificate Timeline')
        
        # Format x-axis dates
        plt.gca().xaxis.set_major_formatter(DateFormatter('%Y-%m-%d'))
        plt.gcf().autofmt_xdate()  # Rotate and align the tick labels
        
        # Add grid
        plt.grid(True, axis='x', linestyle='--', alpha=0.7)
        
        # Adjust layout
        plt.tight_layout()
        
        # Save as PNG
        img_path = 'exports/temp_timeline.png'
        Path(img_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(img_path, dpi=300, bbox_inches='tight')
        plt.close()  # Close the figure to free memory
        
        return img_path
    except Exception as e:
        logger.error(f"Failed to create timeline chart: {str(e)}")
        return None

def export_certificates_to_pdf(session: Session, output_path: str = None) -> str:
    """Export certificates to a PDF file using fpdf2."""
    settings = Settings()
    
    # Get certificates with their bindings
    certificates = session.query(Certificate).all()
    
    # Create timeline chart
    timeline_path = None
    try:
        timeline_path = create_timeline_chart(certificates)
    except Exception as e:
        logger.error(f"Failed to create timeline chart: {str(e)}")
    
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
    pdf.cell(0, 8, f'Valid Certificates: {sum(1 for c in certificates if c.valid_until > datetime.now())}', ln=True)
    pdf.cell(0, 8, f'Expired Certificates: {sum(1 for c in certificates if c.valid_until <= datetime.now())}', ln=True)
    pdf.cell(0, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', ln=True)
    
    # Add timeline chart if available
    if timeline_path and Path(timeline_path).exists():
        try:
            pdf.add_page()
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Certificate Timeline', ln=True)
            pdf.image(timeline_path, x=10, w=190)
        except Exception as e:
            logger.error(f"Failed to add timeline to PDF: {str(e)}")
    
    # Add certificate details
    for cert in certificates:
        pdf.add_page()
        pdf.set_font('helvetica', 'B', 16)
        pdf.cell(0, 10, f'Certificate: {cert.common_name}', ln=True)
        
        # Overview
        pdf.ln(5)
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, 'Overview', ln=True)
        pdf.set_font('helvetica', '', 12)
        pdf.cell(0, 8, f'Serial Number: {cert.serial_number}', ln=True)
        pdf.cell(0, 8, f'Valid From: {cert.valid_from.strftime("%Y-%m-%d")}', ln=True)
        pdf.cell(0, 8, f'Valid Until: {cert.valid_until.strftime("%Y-%m-%d")}', ln=True)
        pdf.cell(0, 8, f'Status: {"Valid" if cert.valid_until > datetime.now() else "Expired"}', ln=True)
        
        # Bindings
        if cert.certificate_bindings:
            pdf.ln(5)
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Bindings', ln=True)
            pdf.set_font('helvetica', '', 12)
            for binding in cert.certificate_bindings:
                host_name = binding.host.name if binding.host else "Unknown Host"
                host_ip = getattr(binding, 'host_ip', None)
                ip_address = host_ip.ip_address if host_ip else "No IP"
                port = binding.port if binding.port else "N/A"
                
                pdf.cell(0, 8, f'Host: {host_name}', ln=True)
                if binding.binding_type == 'IP':
                    pdf.cell(0, 8, f'IP: {ip_address}, Port: {port}', ln=True)
                pdf.cell(0, 8, f'Type: {binding.binding_type}', ln=True)
                pdf.cell(0, 8, f'Platform: {binding.platform or "Not Set"}', ln=True)
                pdf.cell(0, 8, f'Last Seen: {binding.last_seen.strftime("%Y-%m-%d %H:%M")}', ln=True)
                pdf.ln(5)
    
    # Generate output path if not provided
    if output_path is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'exports/certificates_export_{timestamp}.pdf'
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    try:
        # Save PDF
        pdf.output(output_path)
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

def export_hosts_to_pdf(session: Session, output_path: str = None) -> str:
    """Export hosts to a PDF file using fpdf2."""
    settings = Settings()
    
    # Get hosts with their bindings
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
    
    # Add host details
    for host in hosts:
        pdf.add_page()
        pdf.set_font('helvetica', 'B', 16)
        pdf.cell(0, 10, f'Host: {host.name}', ln=True)
        
        # IP Addresses
        pdf.ln(5)
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, 'IP Addresses', ln=True)
        pdf.set_font('helvetica', '', 12)
        for ip in host.ip_addresses:
            pdf.cell(0, 8, f'IP: {ip.ip_address}', ln=True)
        
        # Certificate Bindings
        if host.certificate_bindings:
            pdf.ln(5)
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Certificate Bindings', ln=True)
            pdf.set_font('helvetica', '', 12)
            for binding in host.certificate_bindings:
                cert = binding.certificate
                pdf.cell(0, 8, f'Certificate: {cert.common_name}', ln=True)
                pdf.cell(0, 8, f'Serial Number: {cert.serial_number}', ln=True)
                if binding.binding_type == 'IP':
                    pdf.cell(0, 8, f'Port: {binding.port}', ln=True)
                pdf.cell(0, 8, f'Type: {binding.binding_type}', ln=True)
                pdf.cell(0, 8, f'Platform: {binding.platform or "Not Set"}', ln=True)
                pdf.cell(0, 8, f'Status: {"Valid" if cert.valid_until > datetime.now() else "Expired"}', ln=True)
                pdf.cell(0, 8, f'Last Seen: {binding.last_seen.strftime("%Y-%m-%d %H:%M")}', ln=True)
                pdf.ln(5)
    
    # Generate output path if not provided
    if output_path is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'exports/hosts_export_{timestamp}.pdf'
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Save PDF
    pdf.output(output_path)
    
    return output_path 