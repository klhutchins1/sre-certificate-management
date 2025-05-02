from datetime import datetime
import json
import logging
from typing import Optional, Any, List, Dict, Set, Tuple
from sqlalchemy.orm import Session
from .domain_scanner import DomainInfo
from ..models import (
    IgnoredDomain, Domain, DomainDNSRecord, Certificate, 
    Host, HostIP, CertificateBinding, CertificateScan, 
    HOST_TYPE_SERVER, HOST_TYPE_CDN, HOST_TYPE_LOAD_BALANCER, 
    ENV_PRODUCTION, IgnoredCertificate
)
from ..constants import PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION
from .certificate_scanner import CertificateInfo
from ..notifications import notify
from ..settings import settings

class ScanProcessor:
    """
    Handles the processing and storage of scan results.
    
    This class is responsible for:
    - Creating and updating domain records
    - Processing and storing certificates
    - Managing DNS records
    - Creating and updating host records
    - Managing certificate bindings
    """
    
    def __init__(self, session: Session, status_container: Optional[Any] = None):
        """Initialize scan processor."""
        self.session = session
        self.status_container = status_container
        self.logger = logging.getLogger(__name__)
    
    def set_status(self, message: str) -> None:
        """Update status if container is available."""
        if self.status_container:
            self.status_container.text(message)
    
    def process_domain_info(self, domain: str, domain_info: Optional[DomainInfo]) -> Domain:
        """Process domain information and update database."""
        try:
            # Get or create domain
            domain_obj = self.session.query(Domain).filter_by(domain_name=domain).first()
            if not domain_obj:
                self.set_status(f'Creating new domain record for {domain}...')
                domain_obj = Domain(
                    domain_name=domain,
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                self.session.add(domain_obj)
            else:
                self.set_status(f'Updating existing domain record for {domain}...')
                domain_obj.updated_at = datetime.now()
            
            # Update domain information
            if domain_info:
                if domain_info.registrar:
                    domain_obj.registrar = domain_info.registrar
                if domain_info.registration_date:
                    domain_obj.registration_date = domain_info.registration_date
                if domain_info.expiration_date:
                    domain_obj.expiration_date = domain_info.expiration_date
                if domain_info.registrant:
                    domain_obj.owner = domain_info.registrant
            
            return domain_obj
            
        except ValueError as e:
            self.logger.error(f"Value error processing domain info for {domain}: {str(e)}")
            raise
        except TypeError as e:
            self.logger.error(f"Type error processing domain info for {domain}: {str(e)}")
            raise
        except Exception as e:
            self.logger.exception(f"Unexpected error processing domain info for {domain}: {str(e)}")
            raise
    
    def process_dns_records(self, domain_obj: Domain, dns_records: List[Dict[str, Any]], scan_queue: Optional[Set[Tuple[str, int]]] = None, port: int = 443) -> None:
        """Process DNS records and update database."""
        try:
            if not dns_records:
                return
                
            self.set_status(f'Updating DNS records for {domain_obj.domain_name}...')
            self.logger.info(f"[DNS] Processing {len(dns_records)} DNS records for {domain_obj.domain_name}")
            
            with self.session.no_autoflush:
                # Get existing DNS records
                existing_records = self.session.query(DomainDNSRecord).filter_by(domain_id=domain_obj.id).all()
                existing_map = {(r.record_type, r.name, r.value): r for r in existing_records}
                
                # Track which records are updated
                updated_records = set()
                
                # Process new records
                for record in dns_records:
                    record_key = (record['type'], record['name'], record['value'])
                    updated_records.add(record_key)
                    
                    # Check for CNAME records that might point to new domains
                    if record['type'] == 'CNAME' and scan_queue is not None:
                        cname_target = record['value'].rstrip('.')
                        
                        # Check if CNAME target should be ignored
                        is_ignored = False
                        patterns = self.session.query(IgnoredDomain).all()
                        for pattern in patterns:
                            if pattern.pattern.startswith('*.'):
                                suffix = pattern.pattern[2:]  # Remove *. from pattern
                                if cname_target.endswith(suffix):
                                    self.logger.info(f"[SCAN] Skipping CNAME target {cname_target} - Matches ignore pattern {pattern.pattern}")
                                    is_ignored = True
                                    break
                            elif pattern.pattern in cname_target:
                                self.logger.info(f"[SCAN] Skipping CNAME target {cname_target} - Contains ignored pattern {pattern.pattern}")
                                is_ignored = True
                                break
                            elif cname_target.endswith(pattern.pattern):
                                self.logger.info(f"[SCAN] Skipping CNAME target {cname_target} - Matches ignore pattern {pattern.pattern}")
                                is_ignored = True
                                break
                        
                        if not is_ignored:
                            scan_queue.add((cname_target, port))
                            self.logger.info(f"[SCAN] Added CNAME target to queue: {cname_target}:{port}")
                    
                    if record_key in existing_map:
                        # Update existing record
                        existing_record = existing_map[record_key]
                        existing_record.ttl = record['ttl']
                        existing_record.priority = record.get('priority')
                        existing_record.updated_at = datetime.now()
                        self.logger.debug(f"[DNS] Updated record: {record_key}")
                    else:
                        # Add new record
                        dns_record = DomainDNSRecord(
                            domain_id=domain_obj.id,
                            record_type=record['type'],
                            name=record['name'],
                            value=record['value'],
                            ttl=record['ttl'],
                            priority=record.get('priority'),
                            created_at=datetime.now(),
                            updated_at=datetime.now()
                        )
                        self.session.add(dns_record)
                        self.logger.debug(f"[DNS] Added new record: {record_key}")
                
                # Remove old records that no longer exist
                for key, record in existing_map.items():
                    if key not in updated_records:
                        self.session.delete(record)
                        self.logger.debug(f"[DNS] Removed old record: {key}")
                
                self.session.flush()
                self.logger.info(f"[DNS] Successfully processed {len(dns_records)} records for {domain_obj.domain_name}")
                
        except ValueError as e:
            self.logger.error(f"Value error processing DNS records for {domain_obj.domain_name}: {str(e)}")
            raise
        except TypeError as e:
            self.logger.error(f"Type error processing DNS records for {domain_obj.domain_name}: {str(e)}")
            raise
        except Exception as e:
            self.logger.exception(f"Unexpected error processing DNS records for {domain_obj.domain_name}: {str(e)}")
            raise
    
    def process_certificate(self, domain: str, port: int, cert_info: CertificateInfo, domain_obj: Domain, **kwargs) -> None:
        """Process certificate information and update database."""
        try:
            # Get or create certificate
            cert = self.session.query(Certificate).filter_by(
                serial_number=cert_info.serial_number
            ).first()
            
            if not cert:
                self.set_status(f'Found new certificate for {domain}...')
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
                    chain_valid=kwargs.get('validate_chain', True) and cert_info.chain_valid,
                    sans_scanned=kwargs.get('check_sans', False),
                    created_at=datetime.now(),
                    updated_at=datetime.now()
                )
                self.session.add(cert)
            else:
                self.set_status(f'Updating existing certificate for {domain}...')
                cert.thumbprint = cert_info.thumbprint
                cert.common_name = cert_info.common_name
                cert.valid_from = cert_info.valid_from
                cert.valid_until = cert_info.expiration_date
                cert._issuer = json.dumps(cert_info.issuer)
                cert._subject = json.dumps(cert_info.subject)
                cert._san = json.dumps(cert_info.san)
                cert.key_usage = json.dumps(cert_info.key_usage) if cert_info.key_usage else None
                cert.signature_algorithm = cert_info.signature_algorithm
                cert.chain_valid = kwargs.get('validate_chain', True) and cert_info.chain_valid
                cert.sans_scanned = kwargs.get('check_sans', False)
                cert.updated_at = datetime.now()
            
            # Associate certificate with domain
            if cert not in domain_obj.certificates:
                domain_obj.certificates.append(cert)
            
            # Create or update host record
            host = self.session.query(Host).filter_by(name=domain).first()
            if not host:
                self.set_status(f'Creating host record for {domain}...')
                # Set host type based on detected platform
                host_type = HOST_TYPE_SERVER
                if cert_info.platform:
                    if cert_info.platform in [PLATFORM_CLOUDFLARE, PLATFORM_AKAMAI]:
                        host_type = HOST_TYPE_CDN
                    elif cert_info.platform == PLATFORM_F5:
                        host_type = HOST_TYPE_LOAD_BALANCER
                
                host = Host(
                    name=domain,
                    host_type=host_type,
                    environment=ENV_PRODUCTION,
                    last_seen=datetime.now()
                )
                self.session.add(host)
            else:
                host.last_seen = datetime.now()
                # Update host type if platform detected
                if cert_info.platform:
                    if cert_info.platform in [PLATFORM_CLOUDFLARE, PLATFORM_AKAMAI] and host.host_type != HOST_TYPE_CDN:
                        host.host_type = HOST_TYPE_CDN
                    elif cert_info.platform == PLATFORM_F5 and host.host_type != HOST_TYPE_LOAD_BALANCER:
                        host.host_type = HOST_TYPE_LOAD_BALANCER
            
            # Create or update IP addresses
            if cert_info.ip_addresses:
                self.set_status(f'Updating IP addresses for {domain}...')
                existing_ips = {ip.ip_address for ip in host.ip_addresses}
                for ip_addr in cert_info.ip_addresses:
                    if ip_addr not in existing_ips:
                        host_ip = HostIP(
                            host=host,
                            ip_address=ip_addr,
                            is_active=True,
                            last_seen=datetime.now()
                        )
                        self.session.add(host_ip)
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
            
            binding = self.session.query(CertificateBinding).filter_by(
                host=host,
                host_ip=host_ip,
                port=port
            ).first()
            
            if not binding:
                self.set_status(f'Creating certificate binding for {domain}:{port}...')
                binding = CertificateBinding(
                    host=host,
                    host_ip=host_ip,
                    certificate=cert,
                    port=port,
                    binding_type='IP',
                    platform=cert_info.platform if kwargs.get('detect_platform', False) else None,
                    last_seen=datetime.now(),
                    manually_added=False
                )
                self.session.add(binding)
            else:
                binding.certificate = cert
                binding.last_seen = datetime.now()
                if kwargs.get('detect_platform', False):
                    binding.platform = cert_info.platform
            
            # Create scan history record
            scan_record = CertificateScan(
                certificate=cert,
                host=host,
                scan_date=datetime.now(),
                status="Success",
                port=port
            )
            self.session.add(scan_record)
            
            self.session.flush()
            
        except ValueError as e:
            self.logger.error(f"Value error processing certificate for {domain}: {str(e)}")
            raise
        except TypeError as e:
            self.logger.error(f"Type error processing certificate for {domain}: {str(e)}")
            raise
        except Exception as e:
            self.logger.exception(f"Unexpected error processing certificate for {domain}: {str(e)}")
            raise 