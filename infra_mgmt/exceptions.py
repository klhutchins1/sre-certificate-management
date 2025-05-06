"""
Custom exception hierarchy for the Infrastructure Management System (IMS).

This module defines domain-specific exception classes for robust, traceable error handling
across all IMS components. Use these exceptions to signal and handle errors in a structured,
consistent way, enabling better logging, debugging, and user feedback.

Each exception class should be used for its respective domain. See class docstrings for details.

Example usage:
    from infra_mgmt.exceptions import DatabaseError
    if not os.path.exists(db_path):
        raise DatabaseError(f"Invalid database path: {db_path}")
"""

class AppError(Exception):
    """
    Base class for all application errors in IMS.

    All custom exceptions should inherit from this class, allowing for broad error handling
    when needed.
    """
    pass

class DatabaseError(AppError):
    """
    Raised when a database operation fails or encounters an invalid state.

    Typical causes:
        - Invalid database path
        - Permission errors
        - Corrupted or missing database files
        - Database connection or query failures

    Example:
        raise DatabaseError("No write permission for database directory: /data")
    """
    pass

class BackupError(AppError):
    """
    Raised when a backup or restore operation fails.

    Typical causes:
        - Backup file creation failure
        - Restore file not found or invalid
        - Permission errors during backup/restore

    Example:
        raise BackupError("Failed to create backup file")
    """
    pass

class ScannerError(AppError):
    """
    Raised for errors during certificate or domain scanning operations.

    Typical causes:
        - Network resolution failures
        - Socket or SSL errors
        - Unexpected scan result formats

    Example:
        raise ScannerError("Could not resolve hostname 'example.com'")
    """
    pass

class CertificateError(AppError):
    """
    Raised for certificate-specific errors (parsing, validation, etc).

    Typical causes:
        - Invalid certificate data
        - Parsing or decoding failures
        - Certificate chain validation errors

    Example:
        raise CertificateError("Certificate has expired")
    """
    pass

class NotFoundError(AppError):
    """
    Raised when a requested resource is not found in the system.

    Example:
        raise NotFoundError("Domain not found: example.com")
    """
    pass

class PermissionError(AppError):
    """
    Raised when an operation is denied due to insufficient permissions.

    Example:
        raise PermissionError("No write permission for backup directory: /backups")
    """
    pass

# Extend with more domain-specific exceptions as needed, following the same documentation pattern. 