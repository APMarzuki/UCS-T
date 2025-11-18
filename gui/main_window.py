"""
Main application window with tabbed interface
"""

import sys
import logging
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget,
                             QStatusBar, QMessageBox, QVBoxLayout, QWidget)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

# Import module GUI panels
from modules.scam_advisor.gui import ScamAdvisorGUI
from modules.hashvigil.gui import HashVigilGUI
from modules.pynetscanner.gui import NetScannerGUI
from modules.cyberaudit.gui import CyberAuditGUI

from .theme import apply_theme


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("UCS-T - Unified Cybersecurity Toolkit")
        self.setMinimumSize(1200, 700)

        # Apply theme
        apply_theme(self)

        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        self.tabs.setMovable(True)

        # Add modules as tabs
        self.load_modules()

        layout.addWidget(self.tabs)

        # Setup status bar
        self.statusBar().showMessage("Ready - UCS-T Initialized Successfully")

        self.logger.info("Main window initialized successfully")

    def load_modules(self):
        """Load all security modules as tabs"""
        try:
            # ScamAdvisor Module
            # Add modules as tabs
            self.scam_advisor = ScamAdvisorGUI()
            self.tabs.addTab(self.scam_advisor, "🔍 Scam Advisor")

            self.hash_vigil = HashVigilGUI()
            self.tabs.addTab(self.hash_vigil, "🔢 HashVigil")

            self.net_scanner = NetScannerGUI()
            self.tabs.addTab(self.net_scanner, "🌐 Net Scanner")

            self.cyber_audit = CyberAuditGUI()
            self.tabs.addTab(self.cyber_audit, "🛡️ Cyber Audit")

            self.logger.info("All security modules loaded successfully")

        except Exception as e:
            self.logger.error(f"Failed to load modules: {e}")
            QMessageBox.critical(self, "Module Load Error",
                                 f"Failed to load one or more modules: {e}")


def launch_main_window():
    """Launch the main application window"""
    app = QApplication(sys.argv)

    # Set application properties
    app.setApplicationName("UCS-T")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("APMarzuki")

    # Create and show main window
    window = MainWindow()
    window.show()

    # Execute application
    return app.exec()