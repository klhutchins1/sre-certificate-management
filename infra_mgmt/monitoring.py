"""
Performance monitoring module for the Certificate Management System.

This module provides tools for:
- Function execution time tracking
- Database query monitoring
- UI rendering performance metrics
"""

import time
import logging
import functools
from typing import Optional, Dict, Any, Callable
from datetime import datetime
from contextlib import contextmanager

# Configure logging
logger = logging.getLogger(__name__)

class PerformanceMetrics:
    """Tracks and stores performance metrics."""
    
    def __init__(self):
        """Initialize performance metrics storage."""
        self.metrics = {}
        self.current_traces = {}
    
    def start_trace(self, name: str):
        """Start a performance trace."""
        self.current_traces[name] = {
            'start_time': time.time()
        }
    
    def end_trace(self, name: str, additional_info: Optional[Dict[str, Any]] = None):
        """End a performance trace and record metrics."""
        if name not in self.current_traces:
            return
        
        trace = self.current_traces[name]
        end_time = time.time()
        
        # Calculate metrics
        duration = end_time - trace['start_time']
        
        # Store metrics
        if name not in self.metrics:
            self.metrics[name] = []
        
        metric = {
            'timestamp': datetime.now(),
            'duration': duration,
            'additional_info': additional_info or {}
        }
        
        self.metrics[name].append(metric)
        del self.current_traces[name]
        
        # Log performance data
        logger.info(f"Performance trace for {name}:")
        logger.info(f"  Duration: {duration:.3f} seconds")
        if additional_info:
            logger.info(f"  Additional info: {additional_info}")
    
    def get_metrics(self, name: str) -> list:
        """Get metrics for a specific trace name."""
        return self.metrics.get(name, [])
    
    def get_average_duration(self, name: str) -> float:
        """Get average duration for a specific trace name."""
        metrics = self.get_metrics(name)
        if not metrics:
            return 0.0
        return sum(m['duration'] for m in metrics) / len(metrics)
    
    def clear_metrics(self, name: Optional[str] = None):
        """Clear metrics for a specific name or all metrics."""
        if name:
            self.metrics.pop(name, None)
        else:
            self.metrics.clear()

# Global metrics instance
performance_metrics = PerformanceMetrics()

@contextmanager
def measure_performance(name: str, additional_info: Optional[Dict[str, Any]] = None):
    """Context manager for measuring performance."""
    try:
        performance_metrics.start_trace(name)
        yield
    finally:
        performance_metrics.end_trace(name, additional_info)

def track_performance(name: Optional[str] = None):
    """Decorator for tracking function performance."""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            trace_name = name or f"{func.__module__}.{func.__name__}"
            with measure_performance(trace_name):
                return func(*args, **kwargs)
        return wrapper
    return decorator

# Database query monitoring
@contextmanager
def monitor_query(description: str):
    """Context manager for monitoring database query performance."""
    with measure_performance(f"query_{description}"):
        yield

# UI rendering monitoring
@contextmanager
def monitor_rendering(component_name: str):
    """Context manager for monitoring UI rendering performance."""
    with measure_performance(f"render_{component_name}"):
        yield 