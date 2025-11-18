"""
HashVigil GUI Panel - File Hash Analysis
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                             QPushButton, QLineEdit, QTextEdit, QGroupBox,
                             QProgressBar, QFileDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class HashVigilGUI(QWidget):
    """HashVigil main interface"""

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("🔢 HashVigil — File Hash Analyzer")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Input group
        input_group = QGroupBox("Hash Analysis")
        input_layout = QVBoxLayout()

        # Hash input
        hash_layout = QHBoxLayout()
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter file hash (MD5, SHA1, SHA256) or browse file...")

        self.browse_btn = QPushButton("Browse File")
        self.browse_btn.clicked.connect(self.browse_file)

        self.scan_btn = QPushButton("Analyze Hash")
        self.scan_btn.clicked.connect(self.analyze_hash)

        hash_layout.addWidget(self.hash_input)
        hash_layout.addWidget(self.browse_btn)
        hash_layout.addWidget(self.scan_btn)
        input_layout.addLayout(hash_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # Results group
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        self.result_box.setPlaceholderText("Hash analysis results will appear here...")
        results_layout.addWidget(self.result_box)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

        self.setLayout(layout)

    def browse_file(self):
        """Open file dialog to select a file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.hash_input.setText(file_path)

    def analyze_hash(self):
        """Analyze the provided hash or file with real logic"""
        hash_input = self.hash_input.text().strip()
        if not hash_input:
            self.result_box.setText("⚠️ Please enter a hash or select a file.")
            return

        # Show analysis in progress
        self.result_box.setText(f"🔄 Analyzing...\nPlease wait...")

        # Start analysis in thread
        from PyQt6.QtCore import QThread, pyqtSignal

        class AnalysisThread(QThread):
            finished = pyqtSignal(str)

            def __init__(self, input_data):
                super().__init__()
                self.input_data = input_data

            def run(self):
                from .scanner import HashAnalyzer
                analyzer = HashAnalyzer()
                result = analyzer.analyze(self.input_data)
                self.finished.emit(result)

        self.analysis_thread = AnalysisThread(hash_input)
        self.analysis_thread.finished.connect(self.analysis_complete)
        self.analysis_thread.start()

    def analysis_complete(self, result):
        """Handle analysis completion"""
        self.result_box.setText(result)