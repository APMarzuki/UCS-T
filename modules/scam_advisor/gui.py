"""
ScamAdvisor GUI Panel
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QLineEdit, QTextEdit, QGroupBox,
                             QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from .scanner import ScamScanner


class ScanWorker(QThread):
    """Background worker for scanning"""
    finished = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, url, scanner):
        super().__init__()
        self.url = url
        self.scanner = scanner

    def run(self):
        try:
            self.progress.emit(25)
            result = self.scanner.scan(self.url)
            self.progress.emit(100)
            self.finished.emit(result)
        except Exception as e:
            self.finished.emit(f"❌ Scan failed: {str(e)}")


class ScamAdvisorGUI(QWidget):
    """ScamAdvisor main interface"""

    def __init__(self):
        super().__init__()
        self.scanner = ScamScanner()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("🔍 ScamAdvisor — Website Trust Analyzer")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Input group
        input_group = QGroupBox("Website Analysis")
        input_layout = QVBoxLayout()

        # URL input
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL or domain (e.g., example.com)")
        self.url_input.returnPressed.connect(self.run_scan)

        self.scan_btn = QPushButton("Scan Website")
        self.scan_btn.clicked.connect(self.run_scan)

        url_layout.addWidget(self.url_input)
        url_layout.addWidget(self.scan_btn)
        input_layout.addLayout(url_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        input_layout.addWidget(self.progress_bar)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # Results group
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setPlaceholderText("Scan results will appear here...")
        results_layout.addWidget(self.result_box)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        self.setLayout(layout)

    def run_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.result_box.setText("⚠️ Please enter a URL or domain to scan.")
            return

        # Disable button during scan
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        # Start background scan
        self.worker = ScanWorker(url, self.scanner)
        self.worker.finished.connect(self.scan_complete)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.start()

    def scan_complete(self, result):
        self.result_box.setText(result)
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)