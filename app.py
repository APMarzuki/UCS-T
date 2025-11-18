#!/usr/bin/env python3
"""
UCS-T - Unified Cybersecurity Toolkit
Main Application Launcher - FIXED FOR EXE BUILD
"""

import sys
import os
import logging

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import launch_main_window
from core.logger import setup_logging


def main():
    """Main application entry point"""
    try:
        # Setup logging
        setup_logging()
        logging.info("Starting UCS-T - Unified Cybersecurity Toolkit")

        # Launch the main GUI
        launch_main_window()

    except Exception as e:
        logging.error(f"Failed to start UCS-T: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()