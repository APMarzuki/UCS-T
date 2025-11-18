"""
PyNetScanner GUI Panel - Network Scanning
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QLineEdit, QTextEdit, QGroupBox,
                             QProgressBar)
from PyQt6.QtCore import Qt


class NetScannerGUI(QWidget):
    """Network Scanner main interface"""

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("🌐 PyNetScanner — Network Security Scanner")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Input group
        input_group = QGroupBox("Network Scan")
        input_layout = QVBoxLayout()

        # Target input
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address, range, or domain (e.g., 192.168.1.1/24)")

        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)

        target_layout.addWidget(self.target_input)
        target_layout.addWidget(self.scan_btn)
        input_layout.addLayout(target_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # Results group
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setPlaceholderText("Network scan results will appear here...")
        results_layout.addWidget(self.result_box)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        self.setLayout(layout)

    def start_scan(self):
        """Start real network scan"""
        target = self.target_input.text().strip()
        if not target:
            self.result_box.setText("⚠️ Please enter a target IP, range, or domain.")
            return

        # Show scanning in progress
        self.result_box.setText(f"🔄 Scanning {target}...\nPlease wait...")

        # Start scan in thread to prevent GUI freezing
        from PyQt6.QtCore import QThread, pyqtSignal

        class ScanThread(QThread):
            finished = pyqtSignal(str)

            def __init__(self, target):
                super().__init__()
                self.target = target

            def run(self):
                from .scanner import NetScanner
                scanner = NetScanner()
                result = scanner.scan(self.target)
                self.finished.emit(result)

        self.scan_thread = ScanThread(target)
        self.scan_thread.finished.connect(self.scan_complete)
        self.scan_thread.start()

    def scan_complete(self, result):
        """Handle scan completion"""
        self.result_box.setText(result)