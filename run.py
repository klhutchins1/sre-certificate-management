import streamlit as st
import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Create .streamlit directory if it doesn't exist
os.makedirs(".streamlit", exist_ok=True)

def wide_space_default():
    """
    Configure Streamlit page settings for optimal display.

    Sets the page title, icon, layout, and sidebar state for the application.
    Disables Streamlit's default menu items for a cleaner UI.

    Side Effects:
        - Modifies Streamlit's global page configuration.
    """
    st.set_page_config(
        page_title="Infra Manager",
        page_icon="🔐",
        layout="wide",  # Force wide mode
        initial_sidebar_state="expanded",
        menu_items=None  # Completely disable menu items
    )

def main():
    """
    Main entry point for the Infrastructure Management System application.

    This function initializes the Streamlit configuration and imports/runs the main
    application logic from infra_mgmt.app. Handles and logs import or runtime errors.

    Side Effects:
        - Calls wide_space_default() to configure Streamlit UI.
        - Imports and runs the main application.
        - Displays error messages in the Streamlit UI if startup fails.

    Raises:
        ImportError: If the main application module cannot be imported.
        Exception: For any other runtime errors during startup.

    Edge Cases:
        - If infra_mgmt.app is missing or fails to import, logs and displays an error.
        - Any exception during startup is logged and shown to the user.
    """
    try:
        # Initialize Streamlit configuration
        wide_space_default()
        
        # Import and run the main application
        from infra_mgmt.app import main as app_main
        app_main()
    except ImportError as e:
        logger.error(f"Failed to import application: {str(e)}")
        # Use the notification system for startup errors
        from infra_mgmt.notifications import initialize_page_notifications, notify, show_notifications
        initialize_page_notifications("startup")
        notify("Failed to start the application. Please check the logs for details.", "error", page_key="startup")
        show_notifications("startup")
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        # Use the notification system for startup errors
        from infra_mgmt.notifications import initialize_page_notifications, notify, show_notifications
        initialize_page_notifications("startup")
        notify(f"An error occurred: {str(e)}", "error", page_key="startup")
        show_notifications("startup")

if __name__ == "__main__":
    main() 