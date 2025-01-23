import streamlit as st
import os

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

# Create or update config.toml with our settings
config_path = ".streamlit/config.toml"
if not os.path.exists(config_path):
    with open(config_path, "w") as f:
        f.write("""
[browser]
gatherUsageStats = false

[client]
showErrorDetails = false
toolbarMode = "minimal"

[theme]
base = "light"
primaryColor = "#FF4B4B"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#262730"

[server]
runOnSave = true
enableCORS = false
enableXsrfProtection = true

[ui]
hideTopBar = true
hideSidebarNav = true

[global]
developmentMode = false
showWarningOnDirectExecution = false
disableWatchdogWarning = true
suppressDeprecationWarnings = true

[runner]
fastReruns = true

[layout]
showSidebarNavigation = false

[client.toolbarMode]
visible = false

[theme.layout]
layout = "wide"
wideMode = true

[browser.serverAddress]
persistWideMode = true

[browser.serverSettings]
enableWideMode = true
""")

from cert_scanner.app import main as app_main

# Run the main app
app_main() 