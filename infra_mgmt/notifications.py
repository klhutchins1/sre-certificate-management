"""
Centralized Notification System Module

This module provides a unified interface for displaying notifications and alerts
across the entire application. It ensures consistent formatting and prevents
overlapping of multiple notifications, with page-specific scoping.
"""

import streamlit as st
from typing import Dict, Any, Optional, List

def initialize_page_notifications(page_key: str) -> None:
    """Initialize the notifications session state for a specific page if it doesn't exist."""
    if 'page_notifications' not in st.session_state:
        st.session_state.page_notifications = {}
    if page_key not in st.session_state.page_notifications:
        st.session_state.page_notifications[page_key] = []

def notify(message: str, level: str = 'info', page_key: Optional[str] = None) -> None:
    """Add a notification message for a specific page.
    
    Args:
        message: The notification message to display
        level: The notification level ('info', 'success', 'warning', 'error')
        page_key: The key for the page to associate this notification with.
                  If None, behavior might be to a default/global list or raise error,
                  but for this app, we'll require it for page-scoped messages.
    """
    if page_key is None:
        # Fallback or error if page_key is critical for your design
        # For now, let's assume a "global" key if None, or you might raise an error.
        # To enforce page_key, you could: raise ValueError("page_key must be provided for notify")
        # For this implementation, let's default to a "global_messages" if not provided,
        # but strive to always provide it from views.
        page_key = "global_messages" 

    initialize_page_notifications(page_key) # Ensures the list for this page_key exists
    
    st.session_state.page_notifications[page_key].append({
        'message': message,
        'level': level
    })

def show_notifications(page_key: str) -> None:
    """Display all pending notifications for a specific page.
    
    This function should only be called once per render cycle to prevent duplicate notifications.
    Notifications are cleared immediately upon retrieval to prevent duplicates on reruns.
    """
    if 'page_notifications' not in st.session_state or page_key not in st.session_state.page_notifications:
        return
    
    page_specific_notifications = st.session_state.page_notifications[page_key]
    
    if not page_specific_notifications:
        return
    
    # Clear notifications IMMEDIATELY to prevent duplicates if function is called multiple times
    # or if page reruns before display completes
    st.session_state.page_notifications[page_key] = []
    
    grouped: Dict[str, List[str]] = {
        'error': [],
        'warning': [],
        'info': [],
        'success': []
    }
    
    for notif in page_specific_notifications:
        level = notif['level']
        if level not in grouped:
            level = 'info' # Default to info if level is somehow unrecognized
        grouped[level].append(notif['message'])
    
    # Display all notifications in a single container, one per level
    with st.container():
        for level in ['error', 'warning', 'info', 'success']:
            messages = grouped[level]
            if not messages:
                continue
            
            # Combine all messages of the same level into one notification
            message_str = "\n\n".join(messages) # Use double newline for better separation of multiple messages
            
            if level == 'error':
                st.error(message_str)
            elif level == 'warning':
                st.warning(message_str)
            elif level == 'success':
                st.success(message_str)
            else:  # info
                st.info(message_str)

def clear_page_notifications(page_key: str) -> None:
    """Clear all notifications for a specific page."""
    if 'page_notifications' in st.session_state and page_key in st.session_state.page_notifications:
        st.session_state.page_notifications[page_key] = []

# Keep old functions for now, mark as deprecated or remove later if fully transitioned
def initialize_notifications() -> None:
    """DEPRECATED: Use initialize_page_notifications(page_key) instead."""
    if 'notifications' not in st.session_state: # This is the old global list
        st.session_state.notifications = []

def clear_notifications() -> None:
    """DEPRECATED: Use clear_page_notifications(page_key) instead."""
    if hasattr(st.session_state, 'notifications'): # This is the old global list
        st.session_state.notifications = [] 