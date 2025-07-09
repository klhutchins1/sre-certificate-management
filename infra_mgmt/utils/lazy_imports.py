"""
Lazy Import Utilities for Performance Optimization

This module provides utilities for lazy loading of heavy dependencies to improve
application startup time and reduce memory footprint.

Key Features:
- Lazy loading of visualization libraries (plotly, matplotlib)
- Optional dependency handling
- Import error handling with fallbacks
- Performance tracking for import times
"""

import importlib
import logging
import time
from typing import Any, Optional, Dict, Callable
from functools import wraps

logger = logging.getLogger(__name__)

# Global registry for lazy-loaded modules
_loaded_modules: Dict[str, Any] = {}
_import_times: Dict[str, float] = {}

class LazyImportError(ImportError):
    """Raised when a lazy import fails and no fallback is available."""
    pass

def lazy_import(module_name: str, fallback: Optional[str] = None, 
                optional: bool = False) -> Callable:
    """
    Decorator for lazy importing modules.
    
    Args:
        module_name: Name of the module to import
        fallback: Fallback module if primary import fails
        optional: Whether the import is optional (no error if missing)
    
    Returns:
        Decorated function that imports the module on first call
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if module_name not in _loaded_modules:
                _load_module(module_name, fallback, optional)
            return func(_loaded_modules.get(module_name), *args, **kwargs)
        return wrapper
    return decorator

def _load_module(module_name: str, fallback: Optional[str] = None, 
                 optional: bool = False) -> Any:
    """Load a module with timing and error handling."""
    start_time = time.time()
    
    try:
        module = importlib.import_module(module_name)
        _loaded_modules[module_name] = module
        load_time = time.time() - start_time
        _import_times[module_name] = load_time
        logger.info(f"Lazy loaded {module_name} in {load_time:.3f}s")
        return module
    
    except ImportError as e:
        if fallback:
            logger.warning(f"Failed to import {module_name}, trying fallback {fallback}: {e}")
            try:
                module = importlib.import_module(fallback)
                _loaded_modules[module_name] = module
                load_time = time.time() - start_time
                _import_times[module_name] = load_time
                logger.info(f"Loaded fallback {fallback} for {module_name} in {load_time:.3f}s")
                return module
            except ImportError as fallback_error:
                logger.error(f"Fallback import also failed: {fallback_error}")
        
        if optional:
            logger.warning(f"Optional import {module_name} not available: {e}")
            _loaded_modules[module_name] = None
            return None
        else:
            raise LazyImportError(f"Required module {module_name} could not be imported: {e}")

def get_plotly():
    """Get plotly.express with lazy loading."""
    if 'plotly.express' not in _loaded_modules:
        _load_module('plotly.express')
    return _loaded_modules.get('plotly.express')

def get_matplotlib():
    """Get matplotlib.pyplot with lazy loading (optional)."""
    if 'matplotlib.pyplot' not in _loaded_modules:
        _load_module('matplotlib.pyplot', optional=True)
    return _loaded_modules.get('matplotlib.pyplot')

def get_weasyprint():
    """Get weasyprint with lazy loading (optional)."""
    if 'weasyprint' not in _loaded_modules:
        _load_module('weasyprint', optional=True)
    return _loaded_modules.get('weasyprint')

def get_altair():
    """Get altair with lazy loading (optional)."""
    if 'altair' not in _loaded_modules:
        _load_module('altair', optional=True)
    return _loaded_modules.get('altair')

def preload_essential_modules():
    """Preload essential modules for better performance."""
    essential_modules = [
        'plotly.express',
        'pandas',
        'numpy'
    ]
    
    for module_name in essential_modules:
        if module_name not in _loaded_modules:
            try:
                _load_module(module_name)
            except Exception as e:
                logger.error(f"Failed to preload essential module {module_name}: {e}")

def get_import_stats() -> Dict[str, Any]:
    """Get statistics about module imports."""
    return {
        'loaded_modules': list(_loaded_modules.keys()),
        'import_times': _import_times.copy(),
        'total_import_time': sum(_import_times.values()),
        'module_count': len(_loaded_modules)
    }

def clear_module_cache():
    """Clear the module cache (for testing)."""
    _loaded_modules.clear()
    _import_times.clear()

# Streamlit-specific optimizations
def lazy_streamlit_component(component_name: str):
    """Lazy load Streamlit components."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if component_name not in _loaded_modules:
                try:
                    if component_name == 'streamlit_aggrid':
                        st_aggrid = importlib.import_module('st_aggrid')
                        _loaded_modules[component_name] = {
                            'AgGrid': getattr(st_aggrid, 'AgGrid'), 
                            'GridOptionsBuilder': getattr(st_aggrid, 'GridOptionsBuilder')
                        }
                    elif component_name == 'streamlit_option_menu':
                        menu_module = importlib.import_module('streamlit_option_menu')
                        _loaded_modules[component_name] = {'option_menu': getattr(menu_module, 'option_menu')}
                    else:
                        _load_module(component_name)
                except ImportError as e:
                    logger.warning(f"Optional Streamlit component {component_name} not available: {e}")
                    _loaded_modules[component_name] = None
            
            return func(_loaded_modules.get(component_name), *args, **kwargs)
        return wrapper
    return decorator

# Context manager for performance tracking
class ImportTimer:
    """Context manager for tracking import performance."""
    
    def __init__(self, description: str):
        self.description = description
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            logger.info(f"{self.description} completed in {duration:.3f}s")

# Performance-optimized import patterns
def batch_import_modules(modules: list, optional: bool = False):
    """Import multiple modules in batch for better performance."""
    with ImportTimer(f"Batch import of {len(modules)} modules"):
        for module_name in modules:
            try:
                _load_module(module_name, optional=optional)
            except Exception as e:
                if not optional:
                    raise
                logger.warning(f"Optional module {module_name} failed to load: {e}")

# Module availability checks
def is_module_available(module_name: str) -> bool:
    """Check if a module is available for import."""
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        return False

def get_available_optional_modules() -> Dict[str, bool]:
    """Get status of all optional modules."""
    optional_modules = [
        'matplotlib',
        'weasyprint', 
        'altair',
        'seaborn',
        'bokeh'
    ]
    
    return {module: is_module_available(module) for module in optional_modules}

# Export commonly used lazy loaders
__all__ = [
    'lazy_import',
    'get_plotly',
    'get_matplotlib', 
    'get_weasyprint',
    'get_altair',
    'preload_essential_modules',
    'get_import_stats',
    'clear_module_cache',
    'lazy_streamlit_component',
    'ImportTimer',
    'batch_import_modules',
    'is_module_available',
    'get_available_optional_modules'
]