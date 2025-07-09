import pytest
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from fpdf import FPDF

from infra_mgmt.services.CertificateExportService import CertificateExportService
from infra_mgmt.models.certificate import Certificate, CertificateBinding
from infra_mgmt.models.host import Host, HostIP


class TestCertificateExportService:
    """Test suite for CertificateExportService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test certificate data
        self.valid_from = datetime.now()
        self.valid_until = datetime.now() + timedelta(days=365)
        
        # Mock certificate with all attributes
        self.mock_cert = Mock(spec=Certificate)
        self.mock_cert.common_name = "test.example.com"
        self.mock_cert.serial_number = "1234567890ABCDEF"
        self.mock_cert.valid_from = self.valid_from
        self.mock_cert.valid_until = self.valid_until
        self.mock_cert.thumbprint = "ABCDEF1234567890"
        self.mock_cert.key_usage = "Digital Signature, Key Encipherment"
        self.mock_cert.signature_algorithm = "sha256WithRSAEncryption"
        self.mock_cert.issuer = '{"CN": "Test CA", "O": "Test Organization"}'
        self.mock_cert.subject = '{"CN": "test.example.com", "O": "Test Org"}'
        self.mock_cert.san = ["test.example.com", "www.test.example.com"]
        self.mock_cert.certificate_bindings = []

    def teardown_method(self):
        """Clean up test fixtures."""
        # Clean up temporary files
        for file in os.listdir(self.temp_dir):
            file_path = os.path.join(self.temp_dir, file)
            if os.path.isfile(file_path):
                os.unlink(file_path)
        os.rmdir(self.temp_dir)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_single_certificate(self, mock_fpdf):
        """Test exporting a single certificate to PDF."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        filename = os.path.join(self.temp_dir, "test_single.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.set_font.assert_called()
        mock_pdf.cell.assert_called()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_multiple_certificates(self, mock_fpdf):
        """Test exporting multiple certificates to PDF."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create second certificate
        mock_cert2 = Mock(spec=Certificate)
        mock_cert2.common_name = "test2.example.com"
        mock_cert2.serial_number = "FEDCBA0987654321"
        mock_cert2.valid_from = self.valid_from
        mock_cert2.valid_until = self.valid_until
        mock_cert2.thumbprint = "0987654321ABCDEF"
        mock_cert2.key_usage = "Digital Signature"
        mock_cert2.signature_algorithm = "sha384WithRSAEncryption"
        mock_cert2.issuer = '{"CN": "Test CA 2"}'
        mock_cert2.subject = '{"CN": "test2.example.com"}'
        mock_cert2.san = ["test2.example.com"]
        mock_cert2.certificate_bindings = []
        
        certificates = [self.mock_cert, mock_cert2]
        filename = os.path.join(self.temp_dir, "test_multiple.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(certificates, filename)
        
        # Verify
        assert mock_pdf.add_page.call_count == 2
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_bindings(self, mock_fpdf):
        """Test exporting certificate with binding information."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create mock host and host_ip
        mock_host = Mock(spec=Host)
        mock_host.name = "test-host"
        
        mock_host_ip = Mock(spec=HostIP)
        mock_host_ip.ip_address = "192.168.1.100"
        
        # Create mock binding
        mock_binding = Mock(spec=CertificateBinding)
        mock_binding.host = mock_host
        mock_binding.host_ip = mock_host_ip
        mock_binding.port = 443
        mock_binding.binding_type = "IP"
        mock_binding.platform = "Apache"
        mock_binding.last_seen = datetime.now()
        
        self.mock_cert.certificate_bindings = [mock_binding]
        filename = os.path.join(self.temp_dir, "test_bindings.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_san_list(self, mock_fpdf):
        """Test exporting certificate with SAN list."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.san = ["test.example.com", "www.test.example.com", "api.test.example.com"]
        filename = os.path.join(self.temp_dir, "test_san.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_san_string(self, mock_fpdf):
        """Test exporting certificate with SAN as string."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.san = "test.example.com, www.test.example.com"
        filename = os.path.join(self.temp_dir, "test_san_string.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_san_json_string(self, mock_fpdf):
        """Test exporting certificate with SAN as JSON string."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.san = '["test.example.com", "www.test.example.com"]'
        filename = os.path.join(self.temp_dir, "test_san_json.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_malformed_san(self, mock_fpdf):
        """Test exporting certificate with malformed SAN data."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf

        self.mock_cert.san = "invalid_san_data"
        filename = os.path.join(self.temp_dir, "test_malformed_san.pdf")

        # Patch eval only for the SAN parsing
        original_eval = eval
        def eval_side_effect(expr, *args, **kwargs):
            if expr == "invalid_san_data":
                raise Exception("Invalid syntax")
            return original_eval(expr, *args, **kwargs)

        with patch('builtins.eval', side_effect=eval_side_effect):
            CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_issuer_subject_dicts(self, mock_fpdf):
        """Test exporting certificate with issuer and subject as dictionaries."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.issuer = '{"CN": "Test CA", "O": "Test Organization", "C": "US"}'
        self.mock_cert.subject = '{"CN": "test.example.com", "O": "Test Org", "OU": "IT"}'
        filename = os.path.join(self.temp_dir, "test_issuer_subject.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_empty_bindings(self, mock_fpdf):
        """Test exporting certificate with empty bindings."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.certificate_bindings = []
        filename = os.path.join(self.temp_dir, "test_empty_bindings.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_none_bindings(self, mock_fpdf):
        """Test exporting certificate with None bindings."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.certificate_bindings = None
        filename = os.path.join(self.temp_dir, "test_none_bindings.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_binding_no_host(self, mock_fpdf):
        """Test exporting certificate with binding that has no host."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create mock binding without host
        mock_binding = Mock(spec=CertificateBinding)
        mock_binding.host = None
        mock_binding.host_ip = None
        mock_binding.port = 443
        mock_binding.binding_type = "IP"
        mock_binding.platform = "Apache"
        mock_binding.last_seen = datetime.now()
        
        self.mock_cert.certificate_bindings = [mock_binding]
        filename = os.path.join(self.temp_dir, "test_binding_no_host.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_binding_no_host_ip(self, mock_fpdf):
        """Test exporting certificate with binding that has no host_ip."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create mock host
        mock_host = Mock(spec=Host)
        mock_host.name = "test-host"
        
        # Create mock binding without host_ip
        mock_binding = Mock(spec=CertificateBinding)
        mock_binding.host = mock_host
        mock_binding.host_ip = None
        mock_binding.port = 443
        mock_binding.binding_type = "IP"
        mock_binding.platform = "Apache"
        mock_binding.last_seen = datetime.now()
        
        self.mock_cert.certificate_bindings = [mock_binding]
        filename = os.path.join(self.temp_dir, "test_binding_no_host_ip.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_non_ip_binding(self, mock_fpdf):
        """Test exporting certificate with non-IP binding type."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create mock host and host_ip
        mock_host = Mock(spec=Host)
        mock_host.name = "test-host"
        
        mock_host_ip = Mock(spec=HostIP)
        mock_host_ip.ip_address = "192.168.1.100"
        
        # Create mock binding with non-IP type
        mock_binding = Mock(spec=CertificateBinding)
        mock_binding.host = mock_host
        mock_binding.host_ip = mock_host_ip
        mock_binding.port = 443
        mock_binding.binding_type = "SNI"
        mock_binding.platform = "Nginx"
        mock_binding.last_seen = datetime.now()
        
        self.mock_cert.certificate_bindings = [mock_binding]
        filename = os.path.join(self.temp_dir, "test_non_ip_binding.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_none_platform(self, mock_fpdf):
        """Test exporting certificate with None platform."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create mock host and host_ip
        mock_host = Mock(spec=Host)
        mock_host.name = "test-host"
        
        mock_host_ip = Mock(spec=HostIP)
        mock_host_ip.ip_address = "192.168.1.100"
        
        # Create mock binding with None platform
        mock_binding = Mock(spec=CertificateBinding)
        mock_binding.host = mock_host
        mock_binding.host_ip = mock_host_ip
        mock_binding.port = 443
        mock_binding.binding_type = "IP"
        mock_binding.platform = None
        mock_binding.last_seen = datetime.now()
        
        self.mock_cert.certificate_bindings = [mock_binding]
        filename = os.path.join(self.temp_dir, "test_none_platform.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_none_port(self, mock_fpdf):
        """Test exporting certificate with None port."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create mock host and host_ip
        mock_host = Mock(spec=Host)
        mock_host.name = "test-host"
        
        mock_host_ip = Mock(spec=HostIP)
        mock_host_ip.ip_address = "192.168.1.100"
        
        # Create mock binding with None port
        mock_binding = Mock(spec=CertificateBinding)
        mock_binding.host = mock_host
        mock_binding.host_ip = mock_host_ip
        mock_binding.port = None
        mock_binding.binding_type = "IP"
        mock_binding.platform = "Apache"
        mock_binding.last_seen = datetime.now()
        
        self.mock_cert.certificate_bindings = [mock_binding]
        filename = os.path.join(self.temp_dir, "test_none_port.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_expired_certificate(self, mock_fpdf):
        """Test exporting an expired certificate."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Set certificate as expired
        self.mock_cert.valid_until = datetime.now() - timedelta(days=1)
        filename = os.path.join(self.temp_dir, "test_expired.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_none_issuer_subject(self, mock_fpdf):
        """Test exporting certificate with None issuer and subject."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.issuer = None
        self.mock_cert.subject = None
        filename = os.path.join(self.temp_dir, "test_none_issuer_subject.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_none_san(self, mock_fpdf):
        """Test exporting certificate with None SAN."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.san = None
        filename = os.path.join(self.temp_dir, "test_none_san.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_empty_san(self, mock_fpdf):
        """Test exporting certificate with empty SAN list."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.san = []
        filename = os.path.join(self.temp_dir, "test_empty_san.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_whitespace_san(self, mock_fpdf):
        """Test exporting certificate with SAN containing whitespace."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        self.mock_cert.san = ["  test.example.com  ", "  www.test.example.com  ", "  "]
        filename = os.path.join(self.temp_dir, "test_whitespace_san.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename)

    def test_export_certificate_creates_file(self):
        """Test that the export actually creates a PDF file."""
        filename = os.path.join(self.temp_dir, "test_actual_file.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        assert os.path.exists(filename)
        assert os.path.getsize(filename) > 0

    def test_export_multiple_certificates_creates_file(self):
        """Test that exporting multiple certificates creates a PDF file."""
        # Create second certificate
        mock_cert2 = Mock(spec=Certificate)
        mock_cert2.common_name = "test2.example.com"
        mock_cert2.serial_number = "FEDCBA0987654321"
        mock_cert2.valid_from = self.valid_from
        mock_cert2.valid_until = self.valid_until
        mock_cert2.thumbprint = "0987654321ABCDEF"
        mock_cert2.key_usage = "Digital Signature"
        mock_cert2.signature_algorithm = "sha384WithRSAEncryption"
        mock_cert2.issuer = '{"CN": "Test CA 2"}'
        mock_cert2.subject = '{"CN": "test2.example.com"}'
        mock_cert2.san = ["test2.example.com"]
        mock_cert2.certificate_bindings = []
        
        certificates = [self.mock_cert, mock_cert2]
        filename = os.path.join(self.temp_dir, "test_multiple_actual.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(certificates, filename)
        
        # Verify
        assert os.path.exists(filename)
        assert os.path.getsize(filename) > 0

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_pdf_output_error(self, mock_fpdf):
        """Test handling of PDF output errors."""
        # Setup
        mock_pdf = Mock()
        mock_pdf.output.side_effect = Exception("PDF output error")
        mock_fpdf.return_value = mock_pdf
        
        filename = os.path.join(self.temp_dir, "test_error.pdf")
        
        # Execute and verify
        with pytest.raises(Exception, match="PDF output error"):
            CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)

    @patch('infra_mgmt.services.CertificateExportService.FPDF')
    def test_export_certificate_with_complex_binding_data(self, mock_fpdf):
        """Test exporting certificate with complex binding data."""
        # Setup
        mock_pdf = Mock()
        mock_fpdf.return_value = mock_pdf
        
        # Create multiple bindings with different configurations
        mock_host1 = Mock(spec=Host)
        mock_host1.name = "web-server-1"
        
        mock_host2 = Mock(spec=Host)
        mock_host2.name = "web-server-2"
        
        mock_host_ip1 = Mock(spec=HostIP)
        mock_host_ip1.ip_address = "192.168.1.100"
        
        mock_host_ip2 = Mock(spec=HostIP)
        mock_host_ip2.ip_address = "192.168.1.101"
        
        # Create multiple bindings
        mock_binding1 = Mock(spec=CertificateBinding)
        mock_binding1.host = mock_host1
        mock_binding1.host_ip = mock_host_ip1
        mock_binding1.port = 443
        mock_binding1.binding_type = "IP"
        mock_binding1.platform = "Apache"
        mock_binding1.last_seen = datetime.now()
        
        mock_binding2 = Mock(spec=CertificateBinding)
        mock_binding2.host = mock_host2
        mock_binding2.host_ip = mock_host_ip2
        mock_binding2.port = 8443
        mock_binding2.binding_type = "SNI"
        mock_binding2.platform = "Nginx"
        mock_binding2.last_seen = datetime.now()
        
        self.mock_cert.certificate_bindings = [mock_binding1, mock_binding2]
        filename = os.path.join(self.temp_dir, "test_complex_bindings.pdf")
        
        # Execute
        CertificateExportService.export_certificates_to_pdf(self.mock_cert, filename)
        
        # Verify
        mock_pdf.add_page.assert_called_once()
        mock_pdf.output.assert_called_once_with(filename) 