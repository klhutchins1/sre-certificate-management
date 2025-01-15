import streamlit as st
from cert_scanner.app import main
from cert_scanner.db import init_db

if __name__ == "__main__":
    # Initialize database
    init_db()
    # Run the Streamlit app
    main() 