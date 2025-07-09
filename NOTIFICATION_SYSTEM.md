# Notification System Documentation

## Overview

The SRE Certificate Management application uses a centralized notification system to prevent overlapping notifications and ensure consistent user experience across all pages. This system replaces direct Streamlit notification calls (`st.error`, `st.warning`, `st.success`, `st.info`) with a page-scoped notification management system.

## Architecture

### Core Components

1. **`infra_mgmt/notifications.py`** - The main notification system module
2. **Page Keys** - Unique identifiers for each page/view
3. **Session State Management** - Streamlit session state for storing notifications

### Key Functions

#### `initialize_page_notifications(page_key: str)`
- Initializes the notification session state for a specific page
- Must be called at the beginning of each page render function
- Creates the page-specific notification list if it doesn't exist

#### `notify(message: str, level: str = 'info', page_key: Optional[str] = None)`
- Adds a notification message to the specified page's notification queue
- **Parameters:**
  - `message`: The notification text to display
  - `level`: Notification level ('info', 'success', 'warning', 'error')
  - `page_key`: The page identifier (required for page-scoped notifications)
- **Usage:** Call this function whenever you need to show a notification

#### `show_notifications(page_key: str)`
- Displays all pending notifications for the specified page
- Clears the notification queue after displaying
- Groups notifications by level (error, warning, info, success)
- Must be called within a notification placeholder container

#### `clear_page_notifications(page_key: str)`
- Clears all pending notifications for the specified page
- Useful for clearing notifications before specific actions

## Implementation Pattern

### 1. Page Setup
Each page should follow this pattern:

```python
# Define page key at the top of the file
PAGE_KEY = "page_name"

def render_page(engine):
    # Initialize UI components
    load_warning_suppression()
    load_css()
    
    # Initialize notifications for this page
    initialize_page_notifications(PAGE_KEY)
    
    # Create notification placeholder at the top
    notification_placeholder = st.empty()
    
    # Render page header
    render_page_header(title="Page Title")
    
    # Show notifications in the placeholder
    with notification_placeholder.container():
        show_notifications(PAGE_KEY)
    
    # Rest of page content...
```

### 2. Adding Notifications
Replace direct Streamlit calls with the notification system:

```python
# ❌ Don't do this:
st.error("Something went wrong")
st.success("Operation completed")

# ✅ Do this instead:
notify("Something went wrong", "error", page_key=PAGE_KEY)
notify("Operation completed", "success", page_key=PAGE_KEY)
```

### 3. Clearing Notifications
Clear notifications before specific actions:

```python
if st.button("Save Settings"):
    clear_page_notifications(PAGE_KEY)  # Clear existing notifications
    # Perform action...
    if success:
        notify("Settings saved successfully!", "success", page_key=PAGE_KEY)
    else:
        notify("Failed to save settings", "error", page_key=PAGE_KEY)
```

## Page Keys

Each page has a unique identifier:

| Page | Key | File |
|------|-----|------|
| Dashboard | `"dashboard"` | `dashboardView.py` |
| Certificates | `"certificates"` | `certificatesView.py` |
| Domains | `"domains"` | `domainsView.py` |
| Hosts | `"hosts"` | `hostsView.py` |
| Applications | `"applications"` | `applicationsView.py` |
| Scanner | `"scanner"` | `scannerView.py` |
| Search | `"search"` | `searchView.py` |
| History | `"history"` | `historyView.py` |
| Settings | `"settings"` | `settingsView.py` |
| Main App | `"main_app"` | `app.py` |
| Startup | `"startup"` | `run.py` |

## Benefits

### 1. **Prevents Overlapping Notifications**
- Notifications are grouped by level and displayed together
- No more multiple notification boxes cluttering the UI

### 2. **Page-Scoped Management**
- Each page maintains its own notification state
- Notifications don't interfere with other pages

### 3. **Consistent User Experience**
- All notifications follow the same formatting and behavior
- Consistent placement and styling across the application

### 4. **Better Error Handling**
- Centralized error message management
- Easier to maintain and update notification logic

## Migration Guide

### Before (Direct Streamlit Calls)
```python
def render_page():
    # ... page content ...
    if error_condition:
        st.error("An error occurred")
    if success_condition:
        st.success("Operation successful")
    if info_condition:
        st.info("Here's some information")
    if warning_condition:
        st.warning("Be careful!")
```

### After (Notification System)
```python
PAGE_KEY = "page_name"

def render_page():
    # Initialize notifications
    initialize_page_notifications(PAGE_KEY)
    
    # Create notification placeholder
    notification_placeholder = st.empty()
    
    # Show notifications
    with notification_placeholder.container():
        show_notifications(PAGE_KEY)
    
    # ... page content ...
    if error_condition:
        notify("An error occurred", "error", page_key=PAGE_KEY)
    if success_condition:
        notify("Operation successful", "success", page_key=PAGE_KEY)
    if info_condition:
        notify("Here's some information", "info", page_key=PAGE_KEY)
    if warning_condition:
        notify("Be careful!", "warning", page_key=PAGE_KEY)
```

## Exceptions

### UI Flow Messages
Some components use direct Streamlit calls for UI flow messages that are not notifications:

- **Deletion dialogs** - Warning messages that are part of the confirmation flow
- **Form validation** - Inline validation messages
- **Status indicators** - Real-time status updates

These should remain as direct Streamlit calls since they are part of the UI interaction flow, not notifications.

## Testing

The notification system is fully tested with comprehensive unit tests that verify:
- Proper initialization of page notifications
- Correct message storage and retrieval
- Proper grouping and display of notifications
- Page key validation and usage

## Troubleshooting

### Common Issues

1. **Notifications not appearing**
   - Ensure `initialize_page_notifications()` is called
   - Verify the page key is correct
   - Check that `show_notifications()` is called within a placeholder

2. **Notifications overlapping**
   - Make sure each page has a unique page key
   - Verify notifications are cleared after display

3. **Notifications persisting across pages**
   - Each page should have its own page key
   - Use `clear_page_notifications()` when needed

### Debug Mode
To debug notification issues, you can add logging:

```python
import logging
logger = logging.getLogger(__name__)

# In your notification calls
notify("Debug message", "info", page_key=PAGE_KEY)
logger.debug(f"Added notification for page {PAGE_KEY}")
```

## Future Enhancements

Potential improvements to the notification system:
- Notification persistence across page refreshes
- Notification history and management
- Custom notification styling
- Notification priority levels
- Notification dismissal functionality 