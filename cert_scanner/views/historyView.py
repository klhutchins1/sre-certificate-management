import streamlit as st
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..models import Certificate, CertificateScan

def render_history_view(engine):
    """Render the certificate scan history view"""
    st.title("Certificate History")
    st.info("History view under development")
