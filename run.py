import streamlit as st
from cert_scanner.app import main
from cert_scanner.db import reset_db, init_db
import sys
import os

def is_initialized():
    """Check if database is properly initialized"""
    return os.path.exists('certificates.db')

if __name__ == "__main__":
    # Initialize or reset database
    if not is_initialized() or "--reset" in sys.argv:
        if "--reset" in sys.argv:
            print("Resetting database...")
            reset_db()
        else:
            print("Initializing database...")
            init_db()
    
    # Verify database is ready
    if not os.path.exists('certificates.db'):
        st.error("Database initialization failed!")
        sys.exit(1)
    
    # Run the Streamlit app
    main() 