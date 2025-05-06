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
    """
    Launch the Streamlit application with custom command-line arguments and logging.

    This function sets up the environment, configures command-line arguments for Streamlit,
    and starts the Streamlit CLI. It ensures the correct app file is used and logs all major steps.

    Side Effects:
        - Modifies sys.argv to set Streamlit CLI arguments.
        - Adds the current directory to sys.path.
        - Writes logs to 'streamlit_runner.log' and stdout.
        - Calls sys.exit() to terminate the process after Streamlit exits.

    Raises:
        Exception: Any exception during setup or Streamlit execution is logged and re-raised.

    Edge Cases:
        - If the main app file ('run.py') does not exist, logs an error and returns without running Streamlit.
        - Any exception during execution is logged with a traceback.
    """
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