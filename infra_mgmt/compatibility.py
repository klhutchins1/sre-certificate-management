"""
Compatibility Module for Infrastructure Management System

This module handles platform-specific compatibility issues that need to be resolved
before importing other modules, particularly SQLAlchemy on Windows Python 3.8.

Import this module before importing SQLAlchemy or any modules that depend on it.
"""

import sys
import platform


def fix_windows_python38_sqlalchemy():
    """
    Fix Windows Python 3.8 compatibility issues with SQLAlchemy platform detection.
    
    SQLAlchemy tries to detect the platform architecture using platform.machine(),
    but on Windows Python 3.8, this can cause a TypeError when regex patterns
    are applied to bytes objects instead of strings.
    """
    
    # Only apply fixes on Windows Python 3.8
    if not (sys.platform.startswith('win') and sys.version_info[:2] == (3, 8)):
        return
    
    # Patch platform.machine() to handle bytes vs string issue
    if hasattr(platform, 'machine'):
        original_machine = platform.machine
        
        def safe_machine():
            try:
                result = original_machine()
                # Ensure we return a string, not bytes
                if isinstance(result, bytes):
                    return result.decode('utf-8', errors='ignore')
                return str(result)
            except (TypeError, UnicodeDecodeError, AttributeError):
                # Fallback to a safe default for Windows
                return 'AMD64'
        
        platform.machine = safe_machine
    
    # Patch platform.uname() to handle component type issues
    if hasattr(platform, 'uname'):
        original_uname = platform.uname
        
        def safe_uname():
            try:
                result = original_uname()
                # Convert any bytes to strings in the result
                safe_result = []
                for item in result:
                    if isinstance(item, bytes):
                        safe_result.append(item.decode('utf-8', errors='ignore'))
                    else:
                        safe_result.append(str(item))
                # Return a named tuple-like object with the same type
                return type(result)(*safe_result)
            except (TypeError, UnicodeDecodeError, AttributeError):
                # Return safe defaults for Windows
                from collections import namedtuple
                UnameTuple = namedtuple('uname_result', 
                    ['system', 'node', 'release', 'version', 'machine', 'processor'])
                return UnameTuple('Windows', 'localhost', '10', '10.0.19041', 'AMD64', 
                    'Intel64 Family 6 Model 142 Stepping 10, GenuineIntel')
        
        platform.uname = safe_uname
    
    # Patch platform.win32_ver() specifically for Windows
    if hasattr(platform, 'win32_ver'):
        original_win32_ver = platform.win32_ver
        
        def safe_win32_ver():
            try:
                return original_win32_ver()
            except (TypeError, UnicodeDecodeError, AttributeError):
                # Return safe defaults for Windows
                return ('10', '10.0.19041', 'SP0', 'Multiprocessor Free')
        
        platform.win32_ver = safe_win32_ver
    
    # Also patch the internal _syscmd_ver function if it exists and is problematic
    syscmd_ver_func = getattr(platform, '_syscmd_ver', None)
    if syscmd_ver_func:
        original_syscmd_ver = syscmd_ver_func
        
        def safe_syscmd_ver():
            try:
                return original_syscmd_ver()
            except (TypeError, UnicodeDecodeError, AttributeError):
                # Return safe defaults that won't cause regex issues
                return ('Windows', '10', '10.0.19041')
        
        setattr(platform, '_syscmd_ver', safe_syscmd_ver)


def ensure_compatibility():
    """
    Ensure all compatibility fixes are applied.
    
    This is the main function to call at the beginning of modules that
    might encounter compatibility issues.
    """
    fix_windows_python38_sqlalchemy()


# Auto-apply fixes when this module is imported
ensure_compatibility()