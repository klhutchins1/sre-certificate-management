"""
Centralized Notification System Module

This module provides a unified interface for displaying notifications and alerts
across the entire application. It ensures consistent formatting and prevents
overlapping of multiple notifications.
"""

import streamlit as st
from typing import Dict, Any, Optional, List

def initialize_notifications() -> None:
    """Initialize the notifications session state if it doesn't exist."""
    if 'notifications' not in st.session_state:
        st.session_state.notifications = []

def notify(message: str, level: str = 'info') -> None:
    """Add a notification message.
    
    Args:
        message: The notification message to display
        level: The notification level ('info', 'success', 'warning', 'error')
    """
    if not hasattr(st.session_state, 'notifications'):
        initialize_notifications()
    
    # Add the notification to the list
    st.session_state.notifications.append({
        'message': message,
        'level': level
    })

def show_notifications() -> None:
    """Display all pending notifications in a consistent location."""
    if not hasattr(st.session_state, 'notifications'):
        return
    
    # Get and clear notifications
    notifications = st.session_state.notifications
    st.session_state.notifications = []
    
    if not notifications:
        return
    
    # Group notifications by level
    grouped: Dict[str, List[str]] = {
        'error': [],
        'warning': [],
        'info': [],
        'success': []
    }
    
    for notif in notifications:
        level = notif['level']
        if level not in grouped:
            level = 'info'
        grouped[level].append(notif['message'])
    
    # Create a container for all notifications
    with st.container():
        # Display notifications in order: error, warning, info, success
        for level in ['error', 'warning', 'info', 'success']:
            messages = grouped[level]
            if not messages:
                continue
            
            # Join multiple messages of the same level
            message = "\n".join(messages)
            
            # Display the notification using the appropriate Streamlit method
            if level == 'error':
                st.error(message)
            elif level == 'warning':
                st.warning(message)
            elif level == 'success':
                st.success(message)
            else:  # info
                st.info(message)

def clear_notifications() -> None:
    """Clear all notifications."""
    if hasattr(st.session_state, 'notifications'):
        st.session_state.notifications = [] 