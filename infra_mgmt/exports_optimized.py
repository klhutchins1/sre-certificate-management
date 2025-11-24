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
# Utility Functions
#------------------------------------------------------------------------------

def get_export_capabilities() -> dict:
    """Get information about available export capabilities."""
    return {
        'csv': True,  # Always available
        'charts': get_matplotlib() is not None,
    }

# Export all public functions
__all__ = [
    'export_certificates_to_csv',
    'export_hosts_to_csv', 
    'create_timeline_chart',
    'get_export_capabilities'
]