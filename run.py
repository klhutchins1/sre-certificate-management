import streamlit as st
import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Create .streamlit directory if it doesn't exist
os.makedirs(".streamlit", exist_ok=True)

def wide_space_default():
    st.set_page_config(
        page_title="Certificate Manager",
        page_icon="🔐",
        layout="wide",  # Force wide mode
        initial_sidebar_state="expanded",
        menu_items=None  # Completely disable menu items
    )

wide_space_default()

from cert_scanner.app import main as app_main

# Run the main app
app_main() 