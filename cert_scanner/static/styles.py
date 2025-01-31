"""Central location for all CSS styles and scripts used in the application."""

import streamlit as st

def load_warning_suppression():
    """Load warning suppression script and feature policy."""
    st.markdown("""
        <script>
            // Immediately executing warning suppression
            (function() {
                // Store original console methods
                const originalConsole = {
                    warn: window.console.warn.bind(console),
                    error: window.console.error.bind(console),
                    log: window.console.log.bind(console)
                };

                // Create a no-op function
                const noop = () => {};

                // Override console methods with filtered versions
                window.console.warn = function() {
                    const msg = arguments[0] || '';
                    if (typeof msg === 'string' && (
                        msg.includes('Feature Policy') ||
                        msg.includes('iframe') ||
                        msg.includes('AgGrid') ||
                        msg.includes('allow_unsafe_jscode') ||
                        msg.includes('grid return event') ||
                        msg.includes('selectionChanged')
                    )) {
                        return;
                    }
                    return originalConsole.warn.apply(this, arguments);
                };

                window.console.error = function() {
                    const msg = arguments[0] || '';
                    if (typeof msg === 'string' && (
                        msg.includes('Feature Policy') ||
                        msg.includes('iframe') ||
                        msg.includes('sandbox')
                    )) {
                        return;
                    }
                    return originalConsole.error.apply(this, arguments);
                };
            })();
        </script>
        
        <!-- Set Feature Policy -->
        <meta http-equiv="Feature-Policy" content="
            accelerometer 'none';
            ambient-light-sensor 'none';
            autoplay 'none';
            battery 'none';
            camera 'none';
            display-capture 'none';
            document-domain 'none';
            encrypted-media 'none';
            fullscreen 'none';
            geolocation 'none';
            gyroscope 'none';
            layout-animations 'none';
            legacy-image-formats 'none';
            magnetometer 'none';
            microphone 'none';
            midi 'none';
            oversized-images 'none';
            payment 'none';
            picture-in-picture 'none';
            publickey-credentials-get 'none';
            sync-xhr 'none';
            usb 'none';
            vr 'none';
            wake-lock 'none';
            xr-spatial-tracking 'none';
            clipboard-write 'none'">
    """, unsafe_allow_html=True)

def load_css():
    """Load and apply all CSS styles for the application."""
    
    # Main layout styles
    st.markdown("""
        <style>
        /* Main app container */
        .stApp {
            max-width: none;
        }
        
        /* Main content container */
        .stMainBlockContainer {
            padding: 2rem 2rem 10rem !important;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebarContent"] {
            padding-top: 2rem;
        }
        
        /* Hide default header */
        [data-testid="stHeader"] {
            display: none;
        }
        
        /* Title and button row styling */
        [data-testid="column"] {
            padding: 0 !important;
            margin: 0 !important;
        }
        
        /* Title styling */
        h1 {
            margin: 0 !important;
            padding: 0 !important;
            line-height: 1.2 !important;
        }
        
        /* Button styling */
        .row-widget.stButton {
            width: 100%;
            margin: 0 !important;
            padding: 0 !important;
        }
        .row-widget.stButton > button {
            width: 100%;
            min-height: 45px;
            margin: 0 !important;
        }
        
        /* Divider styling */
        hr {
            margin: 1rem 0 !important;
        }
        
        /* Metrics styling */
        [data-testid="metric-container"] {
            padding: 1rem !important;
        }
        
        /* AG Grid styling */
        .ag-root-wrapper {
            border: none !important;
            box-shadow: none !important;
        }
        .ag-header {
            border-bottom: 2px solid #e0e0e0 !important;
        }
        .ag-row-selected {
            background-color: #e6f3ff !important;
            border-left: 3px solid #1e88e5 !important;
        }
        .ag-row-hover {
            background-color: #f5f5f5 !important;
        }
        .ag-row {
            cursor: pointer;
            transition: all 0.2s ease;
        }
        [data-testid="stAgGrid"] {
            min-height: 300px;
            max-height: 500px;
        }
        
        /* Form styling */
        .stForm {
            background-color: transparent !important;
            border: none !important;
        }
        .stForm > div {
            padding: 0 !important;
        }
        
        /* Warning suppression */
        iframe[title="ag-grid"] {
            display: block !important;
        }
        
        /* Certificate binding styles */
        .binding-container {
            padding: 0.3rem 0 !important;
        }
        .binding-title {
            font-size: 1.1rem !important;
            font-weight: 500 !important;
            color: rgba(255, 255, 255, 0.95) !important;
            margin-bottom: 0.4rem !important;
            letter-spacing: 0.3px !important;
            padding: 0.3rem 0 !important;
        }
        .binding-info {
            display: flex !important;
            align-items: center !important;
            gap: 1.5rem !important;
            font-size: 0.9rem !important;
            color: rgba(255, 255, 255, 0.9) !important;
            padding-left: 0.5rem !important;
        }
        .binding-info-item {
            display: inline-flex !important;
            align-items: center !important;
            gap: 0.3rem !important;
        }
        .binding-info-label {
            font-size: 0.85rem !important;
            color: rgba(255, 255, 255, 0.6) !important;
        }
        .binding-info-value {
            font-size: 0.9rem !important;
            color: rgba(255, 255, 255, 0.9) !important;
        }
        .platform-section {
            display: inline-flex !important;
            align-items: center !important;
            gap: 0.5rem !important;
            margin-left: 0.5rem !important;
        }
        
        /* Form and layout styles */
        [data-testid="stVerticalBlock"] > div {
            padding-bottom: 0.5rem !important;
        }
        .stTextInput, .stNumberInput, .stSelectbox {
            margin-top: 0 !important;
            padding-top: 0 !important;
            padding-bottom: 0.5rem !important;
        }
        .stTextInput > label, .stNumberInput > label, .stSelectbox > label {
            padding-bottom: 0.5rem !important;
        }
        .stTextInput > div > div > input, .stNumberInput > div > div > input {
            line-height: 1.6 !important;
        }
        [data-testid="stForm"] {
            border: none !important;
            padding: 0 !important;
        }
        .stButton {
            margin-top: 1rem !important;
        }
        
        /* Selectbox styles */
        div[data-testid="stSelectbox"] {
            display: inline-block !important;
            width: auto !important;
            min-width: 150px !important;
            margin: 0 !important;
        }
        div[data-testid="stSelectbox"] > div {
            min-height: unset !important;
        }
        div[data-testid="stSelectbox"] div[data-baseweb="select"] {
            height: 1.8rem !important;
            min-height: unset !important;
            background-color: rgba(255, 255, 255, 0.05) !important;
        }
        
        /* Success notification styles */
        div[data-testid="stMarkdown"] + div[data-testid="element-container"] {
            display: inline-flex !important;
            margin-left: 0.5rem !important;
        }
        .stAlert {
            padding: 0.1rem 0.4rem !important;
            min-height: unset !important;
        }
        .stAlert > div {
            padding: 0.1rem !important;
            min-height: unset !important;
        }
        
        /* Binding separator */
        .binding-separator {
            height: 1px !important;
            background-color: rgba(255, 255, 255, 0.1) !important;
            margin: 0.5rem 0 1rem 0 !important;
        }
        
        /* Status indicator styles */
        .status-indicator {
            font-weight: 500 !important;
            padding: 2px 8px !important;
            border-radius: 20px !important;
            color: white !important;
        }
        .status-valid {
            background-color: #198754 !important;
        }
        .status-expired {
            background-color: #dc3545 !important;
        }
        .status-warning {
            background-color: #ffc107 !important;
        }
        
        /* Common layout styles */
        .inline-block {
            display: inline-block !important;
        }
        .margin-bottom-2 {
            margin-bottom: 2rem !important;
        }
        
        /* Recent scans styles */
        .recent-scans {
            font-size: 0.9em !important;
        }
        .recent-scans-meta {
            color: gray !important;
        }
        .monospace-text {
            font-family: monospace !important;
        }
        
        /* Certificate status styles */
        .cert-name {
            font-weight: 500 !important;
        }
        .cert-status {
            font-weight: 500 !important;
        }
        .cert-valid {
            color: #198754 !important;
        }
        .cert-expired {
            color: #dc3545 !important;
        }
        .cert-warning {
            color: #ffc107 !important;
        }
        
        /* AG Grid custom cell styles */
        .ag-cell-valid {
            color: #198754 !important;
            font-weight: 500 !important;
        }
        .ag-cell-expired {
            color: #dc3545 !important;
            font-weight: 500 !important;
        }
        .ag-cell-warning {
            color: #ffc107 !important;
            font-weight: 500 !important;
        }
        
        /* Spacing utilities */
        .mt-0 { margin-top: 0 !important; }
        .mt-1 { margin-top: 0.25rem !important; }
        .mt-2 { margin-top: 0.5rem !important; }
        .mt-3 { margin-top: 1rem !important; }
        .mt-4 { margin-top: 1.5rem !important; }
        .mt-5 { margin-top: 2rem !important; }
        
        .mb-0 { margin-bottom: 0 !important; }
        .mb-1 { margin-bottom: 0.25rem !important; }
        .mb-2 { margin-bottom: 0.5rem !important; }
        .mb-3 { margin-bottom: 1rem !important; }
        .mb-4 { margin-bottom: 1.5rem !important; }
        .mb-5 { margin-bottom: 2rem !important; }
        
        .ml-0 { margin-left: 0 !important; }
        .ml-1 { margin-left: 0.25rem !important; }
        .ml-2 { margin-left: 0.5rem !important; }
        .ml-3 { margin-left: 1rem !important; }
        .ml-4 { margin-left: 1.5rem !important; }
        .ml-5 { margin-left: 2rem !important; }
        
        .mr-0 { margin-right: 0 !important; }
        .mr-1 { margin-right: 0.25rem !important; }
        .mr-2 { margin-right: 0.5rem !important; }
        .mr-3 { margin-right: 1rem !important; }
        .mr-4 { margin-right: 1.5rem !important; }
        .mr-5 { margin-right: 2rem !important; }
        
        /* Text utilities */
        .text-success { color: #198754 !important; }
        .text-danger { color: #dc3545 !important; }
        .text-warning { color: #ffc107 !important; }
        .text-muted { color: rgba(255, 255, 255, 0.6) !important; }
        .text-monospace { font-family: monospace !important; }
        .text-bold { font-weight: 500 !important; }
        .text-small { font-size: 0.9em !important; }
        .text-smaller { font-size: 0.85em !important; }
        
        /* Background utilities */
        .bg-success { background-color: #198754 !important; }
        .bg-danger { background-color: #dc3545 !important; }
        .bg-warning { background-color: #ffc107 !important; }
        .bg-light { background-color: rgba(255, 255, 255, 0.05) !important; }
        
        /* Border utilities */
        .rounded { border-radius: 4px !important; }
        .rounded-pill { border-radius: 20px !important; }
        .border { border: 1px solid rgba(255, 255, 255, 0.1) !important; }
        .border-top { border-top: 1px solid rgba(255, 255, 255, 0.1) !important; }
        .border-bottom { border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important; }
        
        /* Display utilities */
        .d-flex { display: flex !important; }
        .d-inline { display: inline !important; }
        .d-inline-block { display: inline-block !important; }
        .d-block { display: block !important; }
        .align-items-center { align-items: center !important; }
        .justify-content-center { justify-content: center !important; }
        .flex-wrap { flex-wrap: wrap !important; }
        .gap-1 { gap: 0.25rem !important; }
        .gap-2 { gap: 0.5rem !important; }
        .gap-3 { gap: 1rem !important; }
        .gap-4 { gap: 1.5rem !important; }
        .gap-5 { gap: 2rem !important; }
        
        /* AG Grid base styles */
        .ag-theme-streamlit {
            --ag-header-height: 40px !important;
            --ag-row-height: 35px !important;
            --ag-header-foreground-color: rgba(255, 255, 255, 0.9) !important;
            --ag-header-background-color: rgba(0, 0, 0, 0.2) !important;
            --ag-odd-row-background-color: rgba(0, 0, 0, 0.1) !important;
            --ag-row-hover-color: rgba(255, 255, 255, 0.1) !important;
            --ag-selected-row-background-color: rgba(33, 150, 243, 0.2) !important;
            --ag-font-size: 14px !important;
            --ag-font-family: inherit !important;
        }
        
        /* AG Grid cell styles */
        .ag-cell {
            padding-left: 12px !important;
            padding-right: 12px !important;
        }
        
        /* AG Grid header styles */
        .ag-header-cell {
            padding-left: 12px !important;
            padding-right: 12px !important;
            font-weight: 500 !important;
        }
        
        /* AG Grid row styles */
        .ag-row {
            border-bottom-color: rgba(255, 255, 255, 0.1) !important;
        }
        .ag-row-hover {
            background-color: rgba(255, 255, 255, 0.05) !important;
        }
        .ag-row-selected {
            background-color: rgba(33, 150, 243, 0.2) !important;
            border-left: 3px solid #2196f3 !important;
        }
        
        /* AG Grid status cell styles */
        .ag-status-valid {
            color: #198754 !important;
            font-weight: 500 !important;
        }
        .ag-status-expired {
            color: #dc3545 !important;
            font-weight: 500 !important;
        }
        .ag-status-warning {
            color: #ffc107 !important;
            font-weight: 500 !important;
        }
        
        /* AG Grid date cell styles */
        .ag-date-cell {
            font-family: monospace !important;
        }
        .ag-date-cell-expired {
            color: #dc3545 !important;
            font-weight: 500 !important;
        }
        
        /* AG Grid numeric cell styles */
        .ag-numeric-cell {
            text-align: right !important;
        }
        .ag-numeric-cell-positive {
            color: #198754 !important;
            font-weight: 500 !important;
        }
        .ag-numeric-cell-negative {
            color: #dc3545 !important;
            font-weight: 500 !important;
        }
        
        /* AG Grid platform cell styles */
        .ag-platform-cell-unknown {
            color: rgba(255, 255, 255, 0.6) !important;
            font-style: italic !important;
        }
        
        /* AG Grid certificate cell styles */
        .ag-cert-cell-none {
            color: rgba(255, 255, 255, 0.6) !important;
            font-style: italic !important;
        }
        
        /* AG Grid container styles */
        [data-testid="stAgGrid"] {
            min-height: 300px !important;
            max-height: 600px !important;
        }
        
        /* AG Grid loading overlay */
        .ag-overlay-loading-center {
            background-color: rgba(0, 0, 0, 0.7) !important;
            color: white !important;
            border: none !important;
        }
        
        /* AG Grid no rows overlay */
        .ag-overlay-no-rows-center {
            background-color: transparent !important;
            color: rgba(255, 255, 255, 0.6) !important;
            border: none !important;
            font-style: italic !important;
        }
        </style>
    """, unsafe_allow_html=True) 