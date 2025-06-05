from pathlib import Path
from datetime import datetime
import json
import yaml
import shutil
import re
from typing import List, Dict, Any, Tuple, Union
from ..settings import Settings
from ..models import Certificate, IgnoredDomain, IgnoredCertificate
from infra_mgmt.utils.SessionManager import SessionManager
from ..exports import (
    export_certificates_to_csv,
    export_certificates_to_pdf,
    export_hosts_to_csv,
    export_hosts_to_pdf
)
from ..backup import create_backup
from .CertificateExportService import CertificateExportService
from sqlalchemy.orm import Session

class SettingsService:
    """
    Service class for all business logic related to settings management, backup, export, and ignore lists.
    Extracted from settingsView.py for separation of concerns and testability.
    """

    @staticmethod
    def list_backups(settings: Settings = None) -> List[Dict]:
        """
        List all available system backups with their details.
        Returns a list of backup metadata dicts.
        """
        if settings is None:
            settings = Settings()
        backup_dir = Path(settings.get("paths.backups", "data/backups"))
        if not backup_dir.exists():
            backup_dir.mkdir(parents=True, exist_ok=True)
        backups = []
        manifest_files = list(backup_dir.glob("backup_*.json"))
        for manifest_file in manifest_files:
            try:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                    manifest['manifest_file'] = str(manifest_file)
                    if 'timestamp' not in manifest:
                        filename = manifest_file.stem
                        timestamp = filename.replace('backup_', '')
                        manifest['timestamp'] = timestamp
                    if 'created' not in manifest:
                        try:
                            created = datetime.strptime(manifest['timestamp'], "%Y%m%d_%H%M%S")
                            manifest['created'] = created.isoformat()
                        except ValueError:
                            created = datetime.fromtimestamp(manifest_file.stat().st_mtime)
                            manifest['created'] = created.isoformat()
                    backups.append(manifest)
            except Exception:
                continue
        sorted_backups = sorted(
            backups,
            key=lambda x: x.get('created', x.get('timestamp', '')),
            reverse=True
        )
        return sorted_backups

    @staticmethod
    def restore_backup(manifest_file_or_dict: Union[str, Dict[str, Any]], settings: Settings = None) -> Tuple[bool, str]:
        """
        Restore from a backup manifest file or dict.
        Returns (success, message).
        """
        if settings is None:
            settings = Settings()
        db_path = settings.get("paths.database")
        if not db_path:
            return False, "Database path not configured"
        try:
            if isinstance(manifest_file_or_dict, dict):
                manifest = manifest_file_or_dict
            else:
                with open(manifest_file_or_dict) as f:
                    manifest = json.load(f)
            db_backup = Path(manifest.get("database", ""))
            config_backup = Path(manifest.get("config", ""))
            if not config_backup.is_file():
                return False, "Config backup file not found"
            if not db_backup.is_file():
                return False, "Database backup file not found"
            shutil.copy2(str(db_backup), db_path)
            with open(config_backup) as f:
                config = yaml.safe_load(f)
                settings._config = config
                settings.save()
            return True, "Backup restored successfully"
        except Exception as e:
            return False, f"Failed to restore backup: {str(e)}"

    @staticmethod
    def save_path_settings(settings: Settings, database_path: str, backup_path: str) -> bool:
        """
        Update and save path settings.
        """
        settings.update("paths.database", database_path)
        settings.update("paths.backups", backup_path)
        return settings.save()

    @staticmethod
    def save_scanning_settings(settings: Settings, default_rate_limit: int, internal_rate_limit: int, internal_domains: List[str], external_rate_limit: int, external_domains: List[str], whois_rate_limit: int, dns_rate_limit: int, ct_rate_limit: int, socket_timeout: int, request_timeout: int, dns_timeout: float, ct_enabled: bool = True, offline_mode: bool = False) -> bool:
        """
        Update and save scanning settings.
        """
        settings.update("scanning.default_rate_limit", default_rate_limit)
        settings.update("scanning.internal.rate_limit", internal_rate_limit)
        settings.update("scanning.internal.domains", internal_domains)
        settings.update("scanning.external.rate_limit", external_rate_limit)
        settings.update("scanning.external.domains", external_domains)
        settings.update("scanning.whois.rate_limit", whois_rate_limit)
        settings.update("scanning.dns.rate_limit", dns_rate_limit)
        settings.update("scanning.ct.rate_limit", ct_rate_limit)
        settings.update("scanning.timeouts.socket", socket_timeout)
        settings.update("scanning.timeouts.request", request_timeout)
        settings.update("scanning.timeouts.dns", dns_timeout)
        settings.update("scanning.ct.enabled", ct_enabled)
        settings.update("scanning.offline_mode", offline_mode)
        return settings.save()

    @staticmethod
    def save_alert_settings(settings: Settings, expiry_warnings: List[Dict], consecutive_failures: int) -> bool:
        """
        Update and save alert settings.
        """
        expiry_warnings.sort(key=lambda x: x["days"], reverse=True)
        settings.update("alerts.expiry_warnings", expiry_warnings)
        settings.update("alerts.failed_scans.consecutive_failures", consecutive_failures)
        return settings.save()

    @staticmethod
    def save_export_settings(settings: Settings, csv_delimiter: str, csv_encoding: str) -> bool:
        """
        Update and save export settings.
        """
        settings.update("exports.csv.delimiter", csv_delimiter)
        settings.update("exports.csv.encoding", csv_encoding)
        return settings.save()

    @staticmethod
    def export_certificates_to_csv(engine) -> Tuple[bool, str]:
        try:
            with SessionManager(engine) as session:
                output_path = export_certificates_to_csv(session)
            return True, output_path
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_certificates_to_pdf(engine) -> Tuple[bool, str]:
        try:
            with SessionManager(engine) as session:
                certificates = session.query(Certificate).all()
                output_path = "certificates_export.pdf"
                CertificateExportService.export_certificates_to_pdf(certificates, output_path)
            return True, output_path
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_hosts_to_csv(engine) -> Tuple[bool, str]:
        try:
            with SessionManager(engine) as session:
                output_path = export_hosts_to_csv(session)
            return True, output_path
        except Exception as e:
            return False, str(e)

    @staticmethod
    def export_hosts_to_pdf(engine) -> Tuple[bool, str]:
        try:
            with SessionManager(engine) as session:
                output_path = export_hosts_to_pdf(session)
            return True, output_path
        except Exception as e:
            return False, str(e)

    @staticmethod
    def add_ignored_domain(engine, pattern: str, reason: str = None) -> Tuple[bool, str]:
        try:
            with Session(engine) as session:
                existing = session.query(IgnoredDomain).filter_by(pattern=pattern).first()
                if existing:
                    return False, f"Pattern '{pattern}' is already in the ignore list"
                # Pattern validation (same as in view)
                if pattern.startswith('*') and pattern.endswith('*'):
                    search_term = pattern.strip('*')
                    if not re.match(r'^[a-zA-Z0-9-]+$', search_term):
                        return False, "Invalid contains pattern: Can only contain letters, numbers, and hyphens"
                elif pattern.startswith("*."):
                    base_domain = pattern[2:]
                    if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', base_domain):
                        return False, "Invalid wildcard domain pattern"
                elif pattern.startswith('*'):
                    suffix = pattern[1:]
                    if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', suffix):
                        return False, "Invalid suffix pattern"
                elif pattern.endswith('*'):
                    prefix = pattern[:-1]
                    if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', prefix):
                        return False, "Invalid prefix pattern"
                else:
                    if not re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', pattern):
                        return False, "Invalid domain format"
                ignored = IgnoredDomain(
                    pattern=pattern,
                    reason=reason if reason else None,
                    created_at=datetime.now()
                )
                session.add(ignored)
                session.commit()
            return True, f"Added '{pattern}' to ignore list"
        except Exception as e:
            return False, f"Error adding domain pattern: {str(e)}"

    @staticmethod
    def remove_ignored_domain(engine, domain_id: int) -> Tuple[bool, str]:
        try:
            with Session(engine) as session:
                domain = session.query(IgnoredDomain).get(domain_id)
                if not domain:
                    return False, "Domain pattern not found"
                session.delete(domain)
                session.commit()
            return True, f"Removed domain pattern with id {domain_id}"
        except Exception as e:
            return False, f"Error removing domain: {str(e)}"

    @staticmethod
    def add_ignored_certificate(engine, pattern: str, reason: str = None) -> Tuple[bool, str]:
        try:
            with Session(engine) as session:
                existing = session.query(IgnoredCertificate).filter_by(pattern=pattern).first()
                if existing:
                    return False, f"Pattern '{pattern}' is already in the ignore list"
                if pattern.count('*') > 2:
                    return False, "Invalid pattern: Maximum of two wildcards allowed"
                ignored = IgnoredCertificate(
                    pattern=pattern,
                    reason=reason if reason else None,
                    created_at=datetime.now()
                )
                session.add(ignored)
                session.commit()
            return True, f"Added pattern '{pattern}' to ignore list"
        except Exception as e:
            return False, f"Error adding certificate pattern: {str(e)}"

    @staticmethod
    def remove_ignored_certificate(engine, cert_id: int) -> Tuple[bool, str]:
        try:
            with Session(engine) as session:
                cert = session.query(IgnoredCertificate).get(cert_id)
                if not cert:
                    return False, "Certificate pattern not found"
                session.delete(cert)
                session.commit()
            return True, f"Removed certificate pattern with id {cert_id}"
        except Exception as e:
            return False, f"Error removing certificate pattern: {str(e)}"

    @staticmethod
    def get_ignored_domains(engine) -> List[IgnoredDomain]:
        with Session(engine) as session:
            return session.query(IgnoredDomain).order_by(IgnoredDomain.created_at.desc()).all()

    @staticmethod
    def get_ignored_certificates(engine) -> List[IgnoredCertificate]:
        with Session(engine) as session:
            return session.query(IgnoredCertificate).order_by(IgnoredCertificate.created_at.desc()).all()

    @staticmethod
    def save_proxy_detection_settings(settings: Settings, enabled: bool, ca_fingerprints: list, ca_subjects: list, ca_serials: list = None) -> bool:
        """
        Update and save proxy detection settings.
        """
        settings.update("proxy_detection.enabled", enabled)
        settings.update("proxy_detection.ca_fingerprints", ca_fingerprints)
        settings.update("proxy_detection.ca_subjects", ca_subjects)
        if ca_serials is not None:
            settings.update("proxy_detection.ca_serials", ca_serials)
        return settings.save() 