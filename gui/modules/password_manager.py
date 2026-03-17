"""
DataCrypt GUI — Password Manager Widget
Secure password entry with strength meter, show/hide toggle, and generator.
"""

import ctypes
import platform

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
    QApplication,
)

from .password_generator import (
    DEFAULT_LENGTH,
    MAX_LENGTH,
    MIN_LENGTH,
    evaluate_strength,
    generate_password,
)


class PasswordManagerWidget(QGroupBox):
    """
    Password entry card with:
    - Password + Confirm fields with show/hide toggle
    - Strength meter with real-time scoring
    - Built-in password generator with configurable options
    - Copy-to-clipboard button
    """

    password_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__("🔑  Password", parent)
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # ── Password field ──
        pw_row = QHBoxLayout()
        pw_label = QLabel("Password:")
        pw_label.setFixedWidth(100)
        self._password_input = QLineEdit()
        self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_input.setPlaceholderText("Enter encryption password…")
        self._show_pw_btn = QPushButton("👁")
        self._show_pw_btn.setFixedWidth(40)
        self._show_pw_btn.setCheckable(True)
        self._show_pw_btn.setToolTip("Show / hide password")
        pw_row.addWidget(pw_label)
        pw_row.addWidget(self._password_input, 1)
        pw_row.addWidget(self._show_pw_btn)
        layout.addLayout(pw_row)

        # ── Confirm field ──
        confirm_row = QHBoxLayout()
        confirm_label = QLabel("Confirm:")
        confirm_label.setFixedWidth(100)
        self._confirm_input = QLineEdit()
        self._confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_input.setPlaceholderText("Confirm password…")
        self._show_confirm_btn = QPushButton("👁")
        self._show_confirm_btn.setFixedWidth(40)
        self._show_confirm_btn.setCheckable(True)
        self._show_confirm_btn.setToolTip("Show / hide confirmation")
        confirm_row.addWidget(confirm_label)
        confirm_row.addWidget(self._confirm_input, 1)
        confirm_row.addWidget(self._show_confirm_btn)
        layout.addLayout(confirm_row)

        # ── Match indicator ──
        self._match_label = QLabel("")
        self._match_label.setObjectName("label_strength")
        self._match_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self._match_label)

        # ── Strength meter ──
        strength_row = QHBoxLayout()
        strength_label = QLabel("Strength:")
        strength_label.setFixedWidth(100)
        self._strength_bar = QProgressBar()
        self._strength_bar.setRange(0, 100)
        self._strength_bar.setValue(0)
        self._strength_bar.setTextVisible(False)
        self._strength_bar.setFixedHeight(8)
        self._strength_text = QLabel("")
        self._strength_text.setObjectName("label_strength")
        self._strength_text.setFixedWidth(90)
        strength_row.addWidget(strength_label)
        strength_row.addWidget(self._strength_bar, 1)
        strength_row.addWidget(self._strength_text)
        layout.addLayout(strength_row)

        # ── Generator section ──
        gen_row = QHBoxLayout()

        self._btn_generate = QPushButton("🔑  Generate Password")
        self._btn_generate.setObjectName("btn_generate")
        self._btn_generate.setToolTip("Generate a cryptographically secure password")

        self._btn_copy = QPushButton("📋  Copy")
        self._btn_copy.setObjectName("btn_copy")
        self._btn_copy.setToolTip("Copy password to clipboard")

        length_label = QLabel("Length:")
        self._length_spin = QSpinBox()
        self._length_spin.setRange(MIN_LENGTH, MAX_LENGTH)
        self._length_spin.setValue(DEFAULT_LENGTH)
        self._length_spin.setToolTip(f"Password length ({MIN_LENGTH}–{MAX_LENGTH})")

        gen_row.addWidget(self._btn_generate)
        gen_row.addWidget(self._btn_copy)
        gen_row.addStretch()
        gen_row.addWidget(length_label)
        gen_row.addWidget(self._length_spin)
        layout.addLayout(gen_row)

        # ── Generator options ──
        opts_row = QHBoxLayout()
        self._chk_upper = QCheckBox("A-Z")
        self._chk_upper.setChecked(True)
        self._chk_lower = QCheckBox("a-z")
        self._chk_lower.setChecked(True)
        self._chk_digits = QCheckBox("0-9")
        self._chk_digits.setChecked(True)
        self._chk_symbols = QCheckBox("!@#$%")
        self._chk_symbols.setChecked(True)

        opts_row.addWidget(QLabel("Include:"))
        opts_row.addWidget(self._chk_upper)
        opts_row.addWidget(self._chk_lower)
        opts_row.addWidget(self._chk_digits)
        opts_row.addWidget(self._chk_symbols)
        opts_row.addStretch()
        layout.addLayout(opts_row)

    def _connect_signals(self):
        self._password_input.textChanged.connect(self._on_password_changed)
        self._confirm_input.textChanged.connect(self._on_password_changed)
        self._show_pw_btn.toggled.connect(self._toggle_password_vis)
        self._show_confirm_btn.toggled.connect(self._toggle_confirm_vis)
        self._btn_generate.clicked.connect(self._on_generate)
        self._btn_copy.clicked.connect(self._on_copy)

    # ── Slots ────────────────────────────────────────────────────────────

    def _toggle_password_vis(self, checked: bool):
        self._password_input.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        self._show_pw_btn.setText("🔒" if checked else "👁")

    def _toggle_confirm_vis(self, checked: bool):
        self._confirm_input.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )
        self._show_confirm_btn.setText("🔒" if checked else "👁")

    def _on_password_changed(self):
        pw = self._password_input.text()
        confirm = self._confirm_input.text()

        # Strength
        score, label, color = evaluate_strength(pw)
        self._strength_bar.setValue(score)
        self._strength_text.setText(label)
        self._strength_text.setStyleSheet(f"color: {color};")
        self._strength_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background: {color}; border-radius: 4px; }}"
        )

        # Match indicator
        if confirm:
            if pw == confirm:
                self._match_label.setText("✅ Passwords match")
                self._match_label.setStyleSheet("color: #3fb950;")
            else:
                self._match_label.setText("❌ Passwords do not match")
                self._match_label.setStyleSheet("color: #f85149;")
        else:
            self._match_label.setText("")

        self.password_changed.emit(pw)

    def _on_generate(self):
        try:
            password = generate_password(
                length=self._length_spin.value(),
                uppercase=self._chk_upper.isChecked(),
                lowercase=self._chk_lower.isChecked(),
                digits=self._chk_digits.isChecked(),
                symbols=self._chk_symbols.isChecked(),
            )
            self._password_input.setText(password)
            self._confirm_input.setText(password)
        except ValueError as e:
            self._match_label.setText(f"⚠ {e}")
            self._match_label.setStyleSheet("color: #d29922;")

    def _on_copy(self):
        """Copy password to clipboard, then schedule clearing it."""
        pw = self._password_input.text()
        if not pw:
            return

        clipboard = QApplication.clipboard()
        clipboard.setText(pw)

        # Try to disable clipboard history on Windows
        self._try_disable_clipboard_history()

        self._btn_copy.setText("✅ Copied!")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(2000, lambda: self._btn_copy.setText("📋  Copy"))

        # Clear clipboard after 30 seconds for security
        QTimer.singleShot(30000, self._clear_clipboard)

    def _clear_clipboard(self):
        clipboard = QApplication.clipboard()
        if clipboard.text() == self._password_input.text():
            clipboard.clear()

    @staticmethod
    def _try_disable_clipboard_history():
        """Attempt to exclude the current clipboard content from Windows
        clipboard history by calling AddClipboardFormatListener patterns."""
        if platform.system() != "Windows":
            return
        try:
            # Signal to Windows that this clipboard content is sensitive
            # by setting the ExcludeClipboardContentFromMonitorProcessing flag
            user32 = ctypes.windll.user32
            # This uses the Cloud Clipboard exclusion hint
            CLIPBOARD_EXCLUDE = 0x0003
            user32.SetPropW(
                user32.GetClipboardOwner(),
                "ExcludeClipboardContentFromMonitorProcessing",
                CLIPBOARD_EXCLUDE,
            )
        except Exception:
            pass  # Best-effort: not all Windows versions support this

    # ── Public API ───────────────────────────────────────────────────────

    def get_password(self) -> str:
        """Return the current password value."""
        return self._password_input.text()

    def passwords_match(self) -> bool:
        """Return True if password and confirm fields match."""
        pw = self._password_input.text()
        confirm = self._confirm_input.text()
        return bool(pw) and pw == confirm

    def is_valid(self) -> tuple[bool, str]:
        """Validate password entry. Returns (valid, error_message)."""
        pw = self._password_input.text()
        confirm = self._confirm_input.text()

        if not pw:
            return False, "Password is required"
        if len(pw) < 8:
            return False, "Password must be at least 8 characters"
        if not confirm:
            return False, "Please confirm the password"
        if pw != confirm:
            return False, "Passwords do not match"

        score, _, _ = evaluate_strength(pw)
        if score < 20:
            return False, "Password is too weak. Use a longer password with mixed characters."

        return True, ""

    def is_valid_for_decrypt(self) -> tuple[bool, str]:
        """Lighter validation for decryption (no confirm needed)."""
        pw = self._password_input.text()
        if not pw:
            return False, "Password is required"
        return True, ""

    def clear(self):
        """Securely clear all password fields."""
        self._password_input.clear()
        self._confirm_input.clear()
        self._strength_bar.setValue(0)
        self._strength_text.setText("")
        self._match_label.setText("")
