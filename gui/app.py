"""
DataCrypt GUI — Main Application Window
Assembles all modules into a cohesive, premium dark-themed interface.
"""

import os
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from modules.encryption_controller import EncryptionController
from modules.file_selector import FileSelectorWidget
from modules.password_manager import PasswordManagerWidget
from modules.progress_monitor import ProgressMonitorWidget
from modules.theme import get_stylesheet


class DataCryptWindow(QMainWindow):
    """Main application window for DataCrypt."""

    def __init__(self):
        super().__init__()
        self._controller = EncryptionController(self)
        self._setup_window()
        self._setup_ui()
        self._connect_signals()
        self._update_button_states()

    # ── Window Setup ─────────────────────────────────────────────────────

    def _setup_window(self):
        self.setWindowTitle("DataCrypt — Secure File Encryption")
        self.setMinimumSize(700, 820)
        self.resize(760, 900)

        # Center on screen
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            x = (geo.width() - self.width()) // 2
            y = (geo.height() - self.height()) // 2
            self.move(x, y)

    # ── UI Construction ──────────────────────────────────────────────────

    def _setup_ui(self):
        # Central widget with scroll area for smaller screens
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 16, 20, 16)
        main_layout.setSpacing(12)

        # ── Header ──
        header = self._build_header()
        main_layout.addLayout(header)

        # ── Separator ──
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        main_layout.addWidget(sep)

        # ── File selector card ──
        self._file_selector = FileSelectorWidget()
        main_layout.addWidget(self._file_selector)

        # ── Password card ──
        self._password_manager = PasswordManagerWidget()
        main_layout.addWidget(self._password_manager)

        # ── Options card ──
        self._options_card = self._build_options_card()
        main_layout.addWidget(self._options_card)

        # ── Progress card ──
        self._progress_monitor = ProgressMonitorWidget()
        main_layout.addWidget(self._progress_monitor)

        # ── Action buttons ──
        actions_row = self._build_action_buttons()
        main_layout.addLayout(actions_row)

        # ── Log area ──
        self._log_label = QLabel("")
        self._log_label.setObjectName("label_status")
        self._log_label.setWordWrap(True)
        self._log_label.setMinimumHeight(40)
        main_layout.addWidget(self._log_label)

        main_layout.addStretch()

        scroll.setWidget(central)
        self.setCentralWidget(scroll)

        # ── Status bar ──
        status = QStatusBar()
        engine_path = EncryptionController.get_engine_path()
        if EncryptionController.engine_exists():
            status.showMessage(f"Engine: {os.path.basename(engine_path)}  •  Ready")
        else:
            status.showMessage(f"⚠ Engine not found: {engine_path}")
        self.setStatusBar(status)

    def _build_header(self) -> QHBoxLayout:
        header = QHBoxLayout()

        # Title
        title_col = QVBoxLayout()
        title = QLabel("🔐  DataCrypt")
        title.setObjectName("label_title")
        subtitle = QLabel("Secure File Encryption & Decryption")
        subtitle.setObjectName("label_subtitle")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        title_col.setSpacing(2)

        header.addLayout(title_col)
        header.addStretch()

        # Version badge
        version_label = QLabel("v1.0.0")
        version_label.setObjectName("label_fileinfo")
        version_label.setStyleSheet(
            "padding: 4px 10px; border-radius: 4px; "
            "background-color: #243044; border: 1px solid #2a3a52;"
        )
        header.addWidget(version_label, alignment=Qt.AlignmentFlag.AlignTop)

        return header

    def _build_options_card(self) -> QGroupBox:
        card = QGroupBox("⚙️  Options")
        layout = QVBoxLayout(card)
        layout.setSpacing(10)

        # ── Cipher + KDF row ──
        cipher_row = QHBoxLayout()

        cipher_label = QLabel("Cipher:")
        cipher_label.setFixedWidth(60)
        self._cipher_combo = QComboBox()
        self._cipher_combo.addItem("AES-256-GCM", "aes")
        self._cipher_combo.addItem("ChaCha20-Poly1305", "chacha20")
        self._cipher_combo.setToolTip("Encryption cipher algorithm")

        kdf_label = QLabel("Security:")
        kdf_label.setFixedWidth(65)
        self._kdf_combo = QComboBox()
        self._kdf_combo.addItem("Standard (64 MB)", "standard")
        self._kdf_combo.addItem("High (256 MB)", "high")
        self._kdf_combo.addItem("Paranoid (1 GB)", "paranoid")
        self._kdf_combo.setToolTip("Key derivation security level (higher = slower but more secure)")

        cipher_row.addWidget(cipher_label)
        cipher_row.addWidget(self._cipher_combo)
        cipher_row.addSpacing(16)
        cipher_row.addWidget(kdf_label)
        cipher_row.addWidget(self._kdf_combo)
        cipher_row.addStretch()
        layout.addLayout(cipher_row)

        # ── Output location ──
        output_row = QHBoxLayout()

        output_label = QLabel("Output:")
        output_label.setFixedWidth(60)

        self._radio_same_folder = QRadioButton("Same folder")
        self._radio_same_folder.setChecked(True)
        self._radio_custom_folder = QRadioButton("Custom folder:")

        self._custom_output_path = QLabel("")
        self._custom_output_path.setObjectName("label_fileinfo")

        self._btn_browse_output = QPushButton("Browse…")
        self._btn_browse_output.setFixedWidth(80)
        self._btn_browse_output.setEnabled(False)

        output_row.addWidget(output_label)
        output_row.addWidget(self._radio_same_folder)
        output_row.addWidget(self._radio_custom_folder)
        output_row.addWidget(self._custom_output_path, 1)
        output_row.addWidget(self._btn_browse_output)
        layout.addLayout(output_row)

        return card

    def _build_action_buttons(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        self._btn_encrypt = QPushButton("🔒  Encrypt")
        self._btn_encrypt.setObjectName("btn_encrypt")
        self._btn_encrypt.setToolTip("Encrypt selected files")
        self._btn_encrypt.setMinimumWidth(130)

        self._btn_decrypt = QPushButton("🔓  Decrypt")
        self._btn_decrypt.setObjectName("btn_decrypt")
        self._btn_decrypt.setToolTip("Decrypt selected files")
        self._btn_decrypt.setMinimumWidth(130)

        self._btn_cancel = QPushButton("❌  Cancel")
        self._btn_cancel.setObjectName("btn_cancel")
        self._btn_cancel.setToolTip("Cancel current operation")
        self._btn_cancel.setEnabled(False)

        self._btn_clear = QPushButton("🗑  Clear")
        self._btn_clear.setToolTip("Clear all selections and fields")

        row.addWidget(self._btn_encrypt)
        row.addWidget(self._btn_decrypt)
        row.addStretch()
        row.addWidget(self._btn_cancel)
        row.addWidget(self._btn_clear)

        return row

    # ── Signal Connections ───────────────────────────────────────────────

    def _connect_signals(self):
        # Action buttons
        self._btn_encrypt.clicked.connect(self._on_encrypt)
        self._btn_decrypt.clicked.connect(self._on_decrypt)
        self._btn_cancel.clicked.connect(self._on_cancel)
        self._btn_clear.clicked.connect(self._on_clear)

        # Output folder selection
        self._radio_custom_folder.toggled.connect(self._on_output_mode_changed)
        self._btn_browse_output.clicked.connect(self._on_browse_output)

        # File selection updates button states
        self._file_selector.path_selected.connect(lambda _: self._update_button_states())
        self._password_manager.password_changed.connect(lambda _: self._update_button_states())

        # Controller signals
        self._controller.operation_started.connect(self._on_operation_started)
        self._controller.file_started.connect(self._on_file_started)
        self._controller.progress_updated.connect(self._on_progress_updated)
        self._controller.file_finished.connect(self._on_file_finished)
        self._controller.operation_finished.connect(self._on_operation_finished)
        self._controller.log_message.connect(self._on_log_message)

    # ── Slot: Actions ────────────────────────────────────────────────────

    def _on_encrypt(self):
        # Validate engine
        if not EncryptionController.engine_exists():
            self._show_error(
                "Engine Not Found",
                f"The datacrypt engine binary was not found at:\n"
                f"{EncryptionController.get_engine_path()}\n\n"
                f"Please build the engine first:\n"
                f"  cd datacrypt && go build -o datacrypt.exe ./cmd/datacrypt"
            )
            return

        # Validate file selection
        files = self._file_selector.get_all_files()
        if not files:
            self._show_error("No Files Selected", "Please select a file or folder to encrypt.")
            return

        # Validate password
        valid, error = self._password_manager.is_valid()
        if not valid:
            self._show_error("Password Error", error)
            return

        # Get options
        password = self._password_manager.get_password()
        cipher = self._cipher_combo.currentData()
        kdf = self._kdf_combo.currentData()
        output_dir = self._get_output_dir()

        # Start encryption
        self._controller.encrypt_files(
            files=files,
            password=password,
            cipher=cipher,
            kdf_preset=kdf,
            output_dir=output_dir,
        )

    def _on_decrypt(self):
        # Validate engine
        if not EncryptionController.engine_exists():
            self._show_error(
                "Engine Not Found",
                f"The datacrypt engine binary was not found at:\n"
                f"{EncryptionController.get_engine_path()}\n\n"
                f"Please build the engine first."
            )
            return

        # Validate file selection
        files = self._file_selector.get_all_files()
        if not files:
            self._show_error("No Files Selected", "Please select encrypted file(s) to decrypt.")
            return

        # Validate password (lighter validation for decryption)
        valid, error = self._password_manager.is_valid_for_decrypt()
        if not valid:
            self._show_error("Password Error", error)
            return

        password = self._password_manager.get_password()
        output_dir = self._get_output_dir()

        # Start decryption
        self._controller.decrypt_files(
            files=files,
            password=password,
            output_dir=output_dir,
        )

    def _on_cancel(self):
        if self._controller.is_running():
            reply = QMessageBox.question(
                self,
                "Cancel Operation",
                "Are you sure you want to cancel the current operation?\n"
                "Partially encrypted files may be left behind.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self._controller.cancel()
                self._progress_monitor.cancel_operation()
                self._update_button_states()

    def _on_clear(self):
        self._file_selector.clear()
        self._password_manager.clear()
        self._progress_monitor.reset()
        self._log_label.setText("")
        self._cipher_combo.setCurrentIndex(0)
        self._kdf_combo.setCurrentIndex(0)
        self._radio_same_folder.setChecked(True)
        self._custom_output_path.setText("")
        self._update_button_states()

    # ── Slot: Output folder ──────────────────────────────────────────────

    def _on_output_mode_changed(self, custom_checked: bool):
        self._btn_browse_output.setEnabled(custom_checked)
        if not custom_checked:
            self._custom_output_path.setText("")

    def _on_browse_output(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Output Folder"
        )
        if path:
            self._custom_output_path.setText(path)

    # ── Slot: Controller events ──────────────────────────────────────────

    def _on_operation_started(self):
        files = self._file_selector.get_all_files()
        total_bytes = sum(os.path.getsize(f) for f in files if os.path.isfile(f))
        mode_label = "Encrypting" if self._controller._mode == "encrypt" else "Decrypting"
        self._progress_monitor.start_operation(len(files), total_bytes, mode_label)
        self._btn_encrypt.setEnabled(False)
        self._btn_decrypt.setEnabled(False)
        self._btn_cancel.setEnabled(True)
        self._btn_clear.setEnabled(False)

    def _on_file_started(self, filename: str, index: int):
        self._progress_monitor.update_file_progress(filename, index)

    def _on_progress_updated(self, processed_bytes: int):
        self._progress_monitor.update_bytes_progress(processed_bytes)

    def _on_file_finished(self, filename: str, success: bool, error: str):
        pass  # Logging is handled by log_message signal

    def _on_operation_finished(self, success: bool, message: str):
        self._progress_monitor.finish_operation(success, message)
        self._log_label.setText(message)

        if success:
            self._log_label.setStyleSheet("color: #3fb950;")
        else:
            self._log_label.setStyleSheet("color: #f85149;")

        # Security: clear password fields after operation
        self._password_manager.clear()
        self._update_button_states()

    def _on_log_message(self, message: str):
        self._log_label.setText(message)

    # ── Helpers ──────────────────────────────────────────────────────────

    def _get_output_dir(self) -> str:
        if self._radio_custom_folder.isChecked():
            return self._custom_output_path.text()
        return ""

    def _update_button_states(self):
        has_files = bool(self._file_selector.get_selected_path())
        has_password = bool(self._password_manager.get_password())
        is_running = self._controller.is_running()

        self._btn_encrypt.setEnabled(has_files and has_password and not is_running)
        self._btn_decrypt.setEnabled(has_files and has_password and not is_running)
        self._btn_cancel.setEnabled(is_running)
        self._btn_clear.setEnabled(not is_running)

    def _show_error(self, title: str, message: str):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setStyleSheet(
            "QMessageBox { background-color: #1a2233; }"
            "QLabel { color: #e6edf3; }"
            "QPushButton { min-width: 80px; }"
        )
        msg.exec()

    # ── Override: Close event ────────────────────────────────────────────

    def closeEvent(self, event):
        if self._controller.is_running():
            reply = QMessageBox.question(
                self,
                "Operation In Progress",
                "An encryption operation is still running.\n"
                "Are you sure you want to quit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return

            self._controller.cancel()

        # Security: clear all sensitive data
        self._password_manager.clear()
        event.accept()
