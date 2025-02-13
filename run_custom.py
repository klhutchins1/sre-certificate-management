import os
import sys
import logging
import traceback
import streamlit.web.cli as stcli

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('streamlit_runner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def run_streamlit():
    try:
        logger.info("Starting Streamlit application...")
        
        # Add the current directory to Python path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.append(current_dir)
        logger.info(f"Added directory to Python path: {current_dir}")
        
        # Get the filename of your main streamlit app
        filename = os.path.abspath("run.py")
        logger.info(f"Using Streamlit app file: {filename}")
        
        if not os.path.exists(filename):
            logger.error(f"Streamlit app file not found: {filename}")
            return
        
        # Set up the command line arguments
        sys.argv = [
            "streamlit",
            "run",
            filename,
            "--server.address=localhost",
            "--server.port=8501",
            "--server.headless=true",
            "--browser.serverAddress=localhost",
            "--server.enableCORS=true",
            "--server.enableXsrfProtection=false"
        ]
        logger.info(f"Command line arguments: {sys.argv}")
        
        # Run Streamlit
        logger.info("Starting Streamlit CLI...")
        sys.exit(stcli.main())
    except Exception as e:
        logger.error(f"Error running Streamlit: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

if __name__ == "__main__":
    try:
        run_streamlit()
    except Exception as e:
        logger.error(f"Application crashed: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        sys.exit(1) 