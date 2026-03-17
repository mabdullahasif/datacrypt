"""
DataCrypt GUI — Entry Point
Launches the secure file encryption desktop application.

Usage:
    python main.py

Requirements:
    pip install PySide6
"""

import sys
import os

# Ensure the gui/ directory is on the module path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from app import DataCryptWindow
from modules.theme import get_stylesheet


def main():
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)

    # Apply application-wide properties
    app.setApplicationName("DataCrypt")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("DataCrypt")

    # Apply the dark theme
    app.setStyleSheet(get_stylesheet())

    # Create and show the main window
    window = DataCryptWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
