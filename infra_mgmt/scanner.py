"""
Main scanner orchestration module for the Infrastructure Management System (IMS).

This module coordinates scanning operations by importing and connecting
ScanManager, ScanTracker, ScanProcessor, and related components. It serves as the
central import point for all scanning-related classes and utilities, and can be
extended to provide orchestration logic or entry points for batch or scheduled scans.

Classes/Functions Imported:
    - ScanManager: Centralized manager for scanning operations.
    - ScanTracker: Tracks scan progress and state.
    - ScanProcessor: Processes scan results and handles post-processing.
    - DomainScanner: Scans and analyzes domain information.
    - SubdomainScanner: Discovers subdomains using passive methods.
    - CertificateInfo: Container for certificate information.
    - is_ip_address, get_ip_info: Utility functions for IP address handling.

Note:
    Add orchestration logic or entry points here if needed for advanced workflows.
"""

from .scanner.scan_manager import ScanManager
from .scanner.scan_tracker import ScanTracker
from .scanner.scan_processor import ScanProcessor
from .scanner.domain_scanner import DomainScanner, DomainInfo
from .scanner.subdomain_scanner import SubdomainScanner
from .scanner.certificate_scanner import CertificateInfo
from .scanner.utils import is_ip_address, get_ip_info

# Add orchestration logic or entry points here if needed. 