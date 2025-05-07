from fpdf import FPDF
from datetime import datetime

class CertificateExportService:
    @staticmethod
    def export_certificates_to_pdf(certificates, filename):
        """
        Export certificate information to PDF format.
        Args:
            certificates: Single Certificate object or list of Certificate objects
            filename (str): Output PDF file path
        Creates a detailed PDF report including:
        - Certificate overview
        - Binding information
        - Technical details
        - Subject Alternative Names
        - Current status
        Features:
        - Multi-certificate support
        - Page numbering
        - Structured sections
        - Error handling for malformed data
        """
        # Convert single certificate to list for consistent handling
        if not isinstance(certificates, (list, tuple)):
            certificates = [certificates]
        pdf = FPDF()
        for i, cert in enumerate(certificates):
            pdf.add_page()
            pdf.set_font('helvetica', 'B', 16)
            pdf.cell(0, 10, f'Certificate Details: {cert.common_name}', ln=True, align='C')
            pdf.ln(10)
            pdf.set_font('helvetica', '', 12)
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Overview', ln=True)
            pdf.set_font('helvetica', '', 12)
            pdf.cell(0, 8, f'Common Name: {cert.common_name}', ln=True)
            pdf.cell(0, 8, f'Serial Number: {cert.serial_number}', ln=True)
            pdf.cell(0, 8, f'Valid From: {cert.valid_from.strftime("%Y-%m-%d")}', ln=True)
            pdf.cell(0, 8, f'Valid Until: {cert.valid_until.strftime("%Y-%m-%d")}', ln=True)
            pdf.cell(0, 8, f'Status: {"Valid" if cert.valid_until > datetime.now() else "Expired"}', ln=True)
            pdf.ln(5)
            if cert.certificate_bindings:
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
            if cert.san:
                pdf.set_font('helvetica', 'B', 14)
                pdf.cell(0, 10, 'Subject Alternative Names', ln=True)
                pdf.set_font('helvetica', '', 12)
                try:
                    san_list = cert.san
                    if isinstance(san_list, str):
                        try:
                            san_list = eval(san_list)
                        except:
                            san_list = cert.san.split(',')
                    san_list = [s.strip() for s in san_list if s.strip()]
                    for san in san_list:
                        pdf.cell(0, 8, san, ln=True)
                except Exception as e:
                    pdf.cell(0, 8, f'Error parsing SANs: {str(e)}', ln=True)
                pdf.ln(5)
            pdf.set_font('helvetica', 'B', 14)
            pdf.cell(0, 10, 'Technical Details', ln=True)
            pdf.set_font('helvetica', '', 12)
            pdf.cell(0, 8, f'Thumbprint: {cert.thumbprint}', ln=True)
            if cert.issuer:
                issuer_dict = eval(cert.issuer)
                pdf.cell(0, 8, f'Issuer: {", ".join(f"{k}={v}" for k, v in issuer_dict.items())}', ln=True)
            if cert.subject:
                subject_dict = eval(cert.subject)
                pdf.cell(0, 8, f'Subject: {", ".join(f"{k}={v}" for k, v in subject_dict.items())}', ln=True)
            pdf.cell(0, 8, f'Key Usage: {cert.key_usage}', ln=True)
            pdf.cell(0, 8, f'Signature Algorithm: {cert.signature_algorithm}', ln=True)
            pdf.set_y(-15)
            pdf.set_font('helvetica', 'I', 8)
            pdf.cell(0, 10, f'Page {i+1} of {len(certificates)}', 0, 0, 'C')
        pdf.output(filename) 