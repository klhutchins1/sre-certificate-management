import pandas as pd
import plotly.figure_factory as ff
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from jinja2 import Environment, FileSystemLoader
from .settings import Settings
from .models import Certificate, Host, CertificateBinding

# Try to import WeasyPrint, but don't fail if it's not available
try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False

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
    """Create a timeline chart for certificates using plotly."""
    data = []
    
    for cert in certificates:
        data.append(dict(
            Task=cert.common_name,
            Start=cert.valid_from,
            Finish=cert.valid_until,
            Status='Valid' if cert.valid_until > datetime.now() else 'Expired'
        ))
    
    colors = {'Valid': 'rgb(0, 255, 0)', 'Expired': 'rgb(255, 0, 0)'}
    
    fig = ff.create_gantt(
        data,
        colors=colors,
        index_col='Status',
        show_colorbar=True,
        group_tasks=True,
        showgrid_x=True,
        showgrid_y=True
    )
    
    # Update layout
    fig.update_layout(
        title='Certificate Timeline',
        xaxis_title='Date',
        height=400,
        font=dict(size=10)
    )
    
    # Save as PNG for inclusion in PDF
    img_path = 'exports/temp_timeline.png'
    fig.write_image(img_path)
    
    return img_path

def export_certificates_to_pdf(session: Session, output_path: str = None) -> str:
    """Export certificates to a PDF file.
    
    Args:
        session: Database session
        output_path: Optional path for the output file. If not provided, a timestamped filename will be used.
        
    Returns:
        str: Path to the exported PDF file
        
    Raises:
        RuntimeError: If WeasyPrint is not available
    """
    if not WEASYPRINT_AVAILABLE:
        raise RuntimeError(
            "PDF export requires WeasyPrint. Please install GTK3 and try again. "
            "Visit https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows "
            "for installation instructions."
        )
    
    settings = Settings()
    
    # Get certificates with their bindings
    certificates = session.query(Certificate).all()
    
    # Create timeline chart
    timeline_path = create_timeline_chart(certificates)
    
    # Prepare data for the template
    template_data = {
        'certificates': certificates,
        'timeline_path': timeline_path,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_certificates': len(certificates),
        'valid_certificates': sum(1 for c in certificates if c.valid_until > datetime.now()),
        'expired_certificates': sum(1 for c in certificates if c.valid_until <= datetime.now()),
        'logo_path': settings.get('exports.pdf.logo')
    }
    
    # Set up Jinja2 environment
    template_dir = Path(settings.get('exports.pdf.template', 'reports')).parent
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template(Path(settings.get('exports.pdf.template', 'reports/template.html')).name)
    
    # Render HTML
    html_content = template.render(**template_data)
    
    # Generate output path if not provided
    if output_path is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'exports/certificates_export_{timestamp}.pdf'
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Convert HTML to PDF
    HTML(string=html_content).write_pdf(output_path)
    
    # Clean up temporary files
    Path(timeline_path).unlink()
    
    return output_path

def export_hosts_to_pdf(session: Session, output_path: str = None) -> str:
    """Export hosts to a PDF file.
    
    Args:
        session: Database session
        output_path: Optional path for the output file. If not provided, a timestamped filename will be used.
        
    Returns:
        str: Path to the exported PDF file
        
    Raises:
        RuntimeError: If WeasyPrint is not available
    """
    if not WEASYPRINT_AVAILABLE:
        raise RuntimeError(
            "PDF export requires WeasyPrint. Please install GTK3 and try again. "
            "Visit https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows "
            "for installation instructions."
        )
    
    settings = Settings()
    
    # Get hosts with their bindings
    hosts = session.query(Host).all()
    
    # Prepare data for the template
    template_data = {
        'hosts': hosts,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_hosts': len(hosts),
        'total_certificates': len({b.certificate for h in hosts for b in h.certificate_bindings}),
        'logo_path': settings.get('exports.pdf.logo')
    }
    
    # Set up Jinja2 environment
    template_dir = Path(settings.get('exports.pdf.template', 'reports')).parent
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template(Path(settings.get('exports.pdf.template', 'reports/hosts_template.html')).name)
    
    # Render HTML
    html_content = template.render(**template_data)
    
    # Generate output path if not provided
    if output_path is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f'exports/hosts_export_{timestamp}.pdf'
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Convert HTML to PDF
    HTML(string=html_content).write_pdf(output_path)
    
    return output_path 