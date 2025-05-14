import shutil
import gc
import time
import os
from sqlalchemy.orm import Session

def cleanup_temp_dir(temp_dir):
    try:
        Session.close_all()
        gc.collect()
        time.sleep(0.1)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"Warning: Failed to clean up temporary directory {temp_dir}: {e}") 