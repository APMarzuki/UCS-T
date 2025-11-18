"""
UI Theme and styling - FIXED VERSION
"""

from PyQt6.QtGui import QPalette, QColor
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QStyleFactory

def apply_theme(app):
    """Apply dark theme to the application - FIXED for PyQt6"""
    try:
        # Set Fusion style (correct way for PyQt6)
        fusion_style = QStyleFactory.create('Fusion')
        if fusion_style:
            app.setStyle(fusion_style)

        # Dark theme palette
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
        palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
        palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)

        app.setPalette(palette)

        # Additional styling
        app.setStyleSheet("""
            QMainWindow {
                background-color: #353535;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #353535;
            }
            QTabBar::tab {
                background-color: #353535;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid #555;
            }
            QTabBar::tab:selected {
                background-color: #2a82da;
            }
            QTabBar::tab:hover {
                background-color: #404040;
            }
            QStatusBar {
                background-color: #353535;
                color: white;
            }
            QGroupBox {
                color: white;
                border: 1px solid #555;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QTextEdit, QLineEdit {
                background-color: #252525;
                color: white;
                border: 1px solid #555;
                padding: 5px;
            }
            QPushButton {
                background-color: #2a82da;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1a6fc7;
            }
            QPushButton:pressed {
                background-color: #155a9c;
            }
        """)

    except Exception as e:
        print(f"Theme warning: {e}")
        # Continue without theme if it fails