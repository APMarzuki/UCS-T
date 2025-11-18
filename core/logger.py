"""
Centralized logging configuration - EXE COMPATIBLE
"""

import logging
import sys
from pathlib import Path

def setup_logging():
    """Setup logging that works in EXE build"""

    # Determine if we're running as EXE or script
    is_frozen = getattr(sys, 'frozen', False)

    if is_frozen:
        # Running as EXE - use temp directory for logs
        log_dir = Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else Path.cwd()
    else:
        # Running as script - use user directory
        log_dir = Path.home() / ".ucs-t" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

    # Create formatter - NO EMOJIS for Windows EXE compatibility
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)  # Use INFO for EXE to reduce noise

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Only add file handler if not frozen (EXE)
    if not is_frozen:
        file_handler = logging.FileHandler(log_dir / "ucs-t.log", encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    root_logger.addHandler(console_handler)