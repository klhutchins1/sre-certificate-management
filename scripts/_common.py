#!/usr/bin/env python3
"""
Common utilities for scripts in the scripts directory.
"""

import os
import yaml
from pathlib import Path

def find_project_root():
    """Find the project root directory (where config.yaml is located)."""
    current = Path(__file__).resolve()
    # _common.py is in scripts/, so go up 2 levels to reach project root
    # When imported by scripts in subdirectories, __file__ is still scripts/_common.py
    project_root = current.parent.parent
    return project_root

def load_config():
    """Load configuration from config.yaml file."""
    project_root = find_project_root()
    config_path = project_root / 'config.yaml'
    if not config_path.exists():
        print(f"⚠️  Warning: config.yaml not found at {config_path}")
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        print(f"⚠️  Warning: Could not load config.yaml: {e}")
        return None

def get_database_path_from_config():
    """Get database path from config.yaml file."""
    config = load_config()
    if config and 'paths' in config and 'database' in config['paths']:
        db_path = config['paths']['database']
        # Handle relative paths
        if not os.path.isabs(db_path):
            project_root = find_project_root()
            db_path = os.path.join(project_root, db_path)
        return db_path
    return None

