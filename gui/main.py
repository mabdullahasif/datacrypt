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
from PySide6.QtGui import QIcon

from app import DataCryptWindow
from modules.theme import get_stylesheet


def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def main():
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)

    # Set icon
    icon_path = get_resource_path("app_icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    else:
        # Check current dir as fallback for dev mode
        dev_icon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_icon.png")
        if os.path.exists(dev_icon):
            app.setWindowIcon(QIcon(dev_icon))

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
