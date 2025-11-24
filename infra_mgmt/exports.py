"""
Data export module for the Certificate Management System.

This module provides functionality for exporting certificate and host data in various formats:
- CSV exports with configurable delimiters and encoding
- Timeline visualizations of certificate validity periods

Features include:
- Customizable export formats and options
- Data aggregation and formatting
- Visual representations of certificate timelines
- Configurable CSV exports

The module uses configuration from the settings system and implements proper
error handling and cleanup for temporary files.
"""

#------------------------------------------------------------------------------
# Imports and Configuration
#------------------------------------------------------------------------------

# Standard library imports
from datetime import datetime
from pathlib import Path
import logging

# Third-party imports
import pandas as pd
import plotly.figure_factory as ff
from sqlalchemy.orm import Session

# Local application imports
from .settings import Settings
from .models import Certificate, Host, CertificateBinding

# Configure logging
logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------
# CSV Export Functions
#------------------------------------------------------------------------------

def export_certificates_to_csv(session: Session, output_path: str = None) -> str:
    """
    Export certificates to a CSV file.
    
    Args:
        session: Database session
        output_path: Optional path for the output file. If not provided, a timestamped filename will be used.
        
    Returns:
        str: Path to the exported CSV file
        
    The export includes:
    - Certificate details (serial number, common name, validity dates)
    - Associated hosts and IP addresses
    - Platform information
    - Current status and last seen timestamps
    
    The CSV format is configurable through settings:
    - Delimiter character
    - File encoding
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
    """
    Export hosts to a CSV file.
    
    Args:
        session: Database session
        output_path: Optional path for the output file. If not provided, a timestamped filename will be used.
        
    Returns:
        str: Path to the exported CSV file
        
    The export includes:
    - Host information (name, IP addresses)
    - Associated certificates
    - Binding details (ports, platforms)
    - Certificate status and validity dates
    
    Handles hosts both with and without certificate bindings.
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

#------------------------------------------------------------------------------
# Chart Generation
#------------------------------------------------------------------------------

def create_timeline_chart(certificates):
    """
    Create a timeline chart for certificates using matplotlib.
    
    Args:
        certificates: List of Certificate objects to visualize
        
    Returns:
        str: Path to the generated chart image, or None if generation fails
        
    Creates a horizontal timeline showing:
    - Certificate validity periods
    - Current status (color-coded)
    - Certificate names
    
    The chart is saved as a temporary PNG file and should be cleaned up
    after use.
    """
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
