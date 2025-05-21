from datetime import datetime
import json
import logging
from typing import Optional, Any, List, Dict, Set, Tuple
from sqlalchemy.orm import Session
from .domain_scanner import DomainInfo
from ..models import (
    IgnoredDomain, Domain, DomainDNSRecord, Certificate, 
    Host, HostIP, CertificateBinding, CertificateScan, 
    IgnoredCertificate
)
from ..constants import HOST_TYPE_SERVER, HOST_TYPE_CDN, HOST_TYPE_LOAD_BALANCER, ENV_PRODUCTION, PLATFORM_F5, PLATFORM_AKAMAI, PLATFORM_CLOUDFLARE, PLATFORM_IIS, PLATFORM_CONNECTION
from .certificate_scanner import CertificateInfo
from ..notifications import notify
from ..settings import settings
from infra_mgmt.utils.ignore_list import IgnoreListUtil
from infra_mgmt.utils.dns_records import DNSRecordUtil
from infra_mgmt.utils.certificate_db import CertificateDBUtil

class ScanProcessor:
    """
    Handles the processing and storage of scan results for the Infrastructure Management System (IMS).

    This class is responsible for:
    - Creating and updating domain records
    - Processing and storing certificates
    - Managing DNS records
    - Creating and updating host records
    - Managing certificate bindings
    - Recording scan history

    It provides a single point of logic for persisting scan results and ensuring
    consistency between the database and the results of scanning operations.

    Example usage:
        >>> processor = ScanProcessor(session)
        >>> domain_obj = processor.process_domain_info('example.com', domain_info)
        >>> processor.process_dns_records(domain_obj, dns_records)
        >>> processor.process_certificate('example.com', 443, cert_info, domain_obj)
    """
    
    def __init__(self, session: Session, status_container: Optional[Any] = None):
        """
        Initialize scan processor with a database session and optional status container.
        
        Args:
            session (Session): SQLAlchemy session for DB operations
            status_container (Optional[Any]): UI/status container for progress updates
        """
        self.session = session
        self.status_container = status_container
        self.logger = logging.getLogger(__name__)
    
    def set_status(self, message: str) -> None:
        """
        Update status if a status container is available.
        
        Args:
            message (str): Status message to display
        """
        if self.status_container:
            self.status_container.text(message)
    
    def process_domain_info(self, domain: str, domain_info: Optional[DomainInfo]) -> Domain:
        """
        Process domain information and update or create the corresponding database record.
        
        Args:
            domain (str): Domain name
            domain_info (Optional[DomainInfo]): DomainInfo object with parsed data
        
        Returns:
            Domain: The updated or created Domain SQLAlchemy object
        
        Raises:
            ValueError, TypeError, Exception: On DB or data errors
        
        Example:
            >>> domain_obj = processor.process_domain_info('example.com', domain_info)
        """
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
    
    def process_certificate(self, domain: str, port: int, cert_info: CertificateInfo, domain_obj: Domain, **kwargs) -> None:
        """
        Process certificate information and update or create the corresponding database records.
        
        This includes:
        - Creating/updating the Certificate record
        - Associating the certificate with the domain
        - Creating/updating the Host and HostIP records
        - Creating/updating the CertificateBinding
        - Recording the scan in CertificateScan
        
        Args:
            domain (str): Domain name
            port (int): Port number
            cert_info (CertificateInfo): Parsed certificate information
            domain_obj (Domain): SQLAlchemy Domain object
            **kwargs: Additional options (e.g., validate_chain, check_sans, detect_platform)
        
        Returns:
            None
        
        Raises:
            ValueError, TypeError, Exception: On DB or data errors
        
        Example:
            >>> processor.process_certificate('example.com', 443, cert_info, domain_obj)
        """
        try:
            # Replace the certificate/host/binding update logic with:
            CertificateDBUtil.upsert_certificate_and_binding(self.session, domain, port, cert_info, domain_obj, detect_platform=kwargs.get('detect_platform', False), check_sans=kwargs.get('check_sans', False), validate_chain=kwargs.get('validate_chain', True), status_callback=self.set_status)
            
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