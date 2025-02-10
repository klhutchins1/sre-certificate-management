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
    """Configure Streamlit page settings for optimal display."""
    st.set_page_config(
        page_title="Certificate Manager",
        page_icon="🔐",
        layout="wide",  # Force wide mode
        initial_sidebar_state="expanded",
        menu_items=None  # Completely disable menu items
    )

def main():
    """Main entry point for the Certificate Manager application."""
    try:
        # Initialize Streamlit configuration
        wide_space_default()
        
        # Import and run the main application
        from cert_scanner.app import main as app_main
        app_main()
    except ImportError as e:
        logger.error(f"Failed to import application: {str(e)}")
        st.error("Failed to start the application. Please check the logs for details.")
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        st.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main() 