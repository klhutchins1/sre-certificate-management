import shutil
import gc
import time
import os
from sqlalchemy.orm import Session, close_all_sessions

def cleanup_temp_dir(temp_dir):
    try:
        close_all_sessions()
        gc.collect()
        time.sleep(0.1)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"Warning: Failed to clean up temporary directory {temp_dir}: {e}") 