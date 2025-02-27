"""
Centralized Notification System Module

This module provides a unified interface for displaying notifications and alerts
across the entire application. It ensures consistent formatting and prevents
overlapping of multiple notifications.
"""

import streamlit as st
from typing import Dict, Any, Optional

def initialize_notifications() -> None:
    """Initialize the notifications session state if it doesn't exist."""
    if 'notifications' not in st.session_state:
        st.session_state.notifications = {
            'container': None,
            'messages': {
                'info': [],
                'success': [],
                'warning': [],
                'error': []
            }
        }

class NotificationManager:
    """Manages all application notifications and alerts."""
    
    def __init__(self):
        """Initialize the notification manager."""
        initialize_notifications()
    
    def _create_container(self) -> None:
        """Create a container for notifications if it doesn't exist."""
        if not st.session_state.notifications['container']:
            st.session_state.notifications['container'] = st.container()
    
    def clear(self) -> None:
        """Clear all notifications."""
        st.session_state.notifications['messages'] = {
            'info': [],
            'success': [],
            'warning': [],
            'error': []
        }
    
    def add(self, message: str, level: str = 'info') -> None:
        """Add a notification message.
        
        Args:
            message: The notification message to display
            level: The notification level ('info', 'success', 'warning', 'error')
        """
        if level not in st.session_state.notifications['messages']:
            level = 'info'
        st.session_state.notifications['messages'][level].append(message)
    
    def show(self) -> None:
        """Display all pending notifications."""
        self._create_container()
        
        with st.session_state.notifications['container']:
            # Display notifications in order: error, warning, info, success
            for level in ['error', 'warning', 'info', 'success']:
                messages = st.session_state.notifications['messages'][level]
                if messages:
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
                    
                    # Add spacing between different notification types
                    st.markdown("<div style='margin-bottom: 1em'></div>", unsafe_allow_html=True)
            
            # Clear messages after displaying
            self.clear()

# Create a global instance of the notification manager
notifications = NotificationManager()

def notify(message: str, level: str = 'info') -> None:
    """Convenience function to add and show a notification.
    
    Args:
        message: The notification message to display
        level: The notification level ('info', 'success', 'warning', 'error')
    """
    notifications.add(message, level)

def show_notifications() -> None:
    """Display all pending notifications."""
    notifications.show()

def clear_notifications() -> None:
    """Clear all notifications."""
    notifications.clear() 