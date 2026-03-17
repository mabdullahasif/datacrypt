"""
DataCrypt GUI — File / Folder / Drive Selector Widget
Supports native file dialog, folder browser, drive picker, and drag-and-drop.
"""

import os
import string
import platform

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class DropZoneLabel(QLabel):
    """A label that accepts file/folder drops."""

    file_dropped = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("label_drop_zone")
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setText("📂  Drag and drop files or folders here")
        self.setWordWrap(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("dragActive", True)
            self.style().unpolish(self)
            self.style().polish(self)

    def dragLeaveEvent(self, event):
        self.setProperty("dragActive", False)
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event):
        self.setProperty("dragActive", False)
        self.style().unpolish(self)
        self.style().polish(self)

        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path:
                self.file_dropped.emit(path)
                self.setText(f"📂  {os.path.basename(path)}")


class FileSelectorWidget(QGroupBox):
    """
    File selection card with:
    - Select File / Select Folder / Select Drive buttons
    - Drag-and-drop zone
    - Path display with file info
    """

    path_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__("File Selection", parent)
        self._selected_path = ""
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # ── Selection buttons ──
        btn_row = QHBoxLayout()

        self._btn_file = QPushButton("Select File")
        self._btn_file.setToolTip("Browse for a file to encrypt or decrypt")

        self._btn_folder = QPushButton("Select Folder")
        self._btn_folder.setToolTip("Select an entire folder (all files will be processed)")

        self._btn_drive = QPushButton("Select Drive")
        self._btn_drive.setToolTip("Select a drive from This PC")

        btn_row.addWidget(self._btn_file)
        btn_row.addWidget(self._btn_folder)
        btn_row.addWidget(self._btn_drive)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # ── Path display ──
        path_row = QHBoxLayout()
        path_label = QLabel("Path:")
        path_label.setFixedWidth(40)
        self._path_input = QLineEdit()
        self._path_input.setReadOnly(True)
        self._path_input.setPlaceholderText("No file or folder selected…")
        self._btn_clear = QPushButton("✕")
        self._btn_clear.setFixedWidth(36)
        self._btn_clear.setToolTip("Clear selection")
        path_row.addWidget(path_label)
        path_row.addWidget(self._path_input, 1)
        path_row.addWidget(self._btn_clear)
        layout.addLayout(path_row)

        # ── File info label ──
        self._info_label = QLabel("")
        self._info_label.setObjectName("label_fileinfo")
        layout.addWidget(self._info_label)

        # ── Drop zone ──
        self._drop_zone = DropZoneLabel()
        layout.addWidget(self._drop_zone)

    def _connect_signals(self):
        self._btn_file.clicked.connect(self._on_select_file)
        self._btn_folder.clicked.connect(self._on_select_folder)
        self._btn_drive.clicked.connect(self._on_select_drive)
        self._btn_clear.clicked.connect(self._on_clear)
        self._drop_zone.file_dropped.connect(self._set_path)

    # ── Slots ────────────────────────────────────────────────────────────

    def _on_select_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            "",
            "All Files (*.*)",
        )
        if path:
            self._set_path(path)

    def _on_select_folder(self):
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Folder",
            "",
            QFileDialog.Option.ShowDirsOnly,
        )
        if path:
            self._set_path(path)

    def _on_select_drive(self):
        """Show drive selection based on the OS."""
        drives = self._get_available_drives()
        if not drives:
            self._info_label.setText("⚠ No drives detected")
            return

        # Use a simple combo popup approach
        from PySide6.QtWidgets import QDialog, QDialogButtonBox

        dialog = QDialog(self)
        dialog.setWindowTitle("Select Drive")
        dialog.setMinimumWidth(300)
        dlg_layout = QVBoxLayout(dialog)

        dlg_layout.addWidget(QLabel("Select a drive:"))
        combo = QComboBox()
        for drive in drives:
            combo.addItem(drive)
        dlg_layout.addWidget(combo)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        dlg_layout.addWidget(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = combo.currentText()
            if selected:
                self._set_path(selected)

    def _on_clear(self):
        self._selected_path = ""
        self._path_input.clear()
        self._info_label.setText("")
        self._drop_zone.setText("Drag and drop files or folders here")
        self.path_selected.emit("")

    def _set_path(self, path: str):
        """Set the selected path and update UI."""
        path = os.path.normpath(path)
        self._selected_path = path
        self._path_input.setText(path)
        self._drop_zone.setText(f"{os.path.basename(path) or path}")

        # Display file/folder info
        try:
            if os.path.isfile(path):
                size = os.path.getsize(path)
                self._info_label.setText(
                    f"File: {os.path.basename(path)}  •  Size: {self._format_size(size)}"
                )
            elif os.path.isdir(path):
                file_count = sum(1 for _, _, files in os.walk(path) for _ in files)
                self._info_label.setText(
                    f"Folder: {os.path.basename(path) or path}  •  {file_count} file(s)"
                )
            else:
                self._info_label.setText(f"⚠ Path not found: {path}")
        except OSError as e:
            self._info_label.setText(f"⚠ {e}")

        self.path_selected.emit(path)

    @staticmethod
    def _get_available_drives() -> list[str]:
        """Return a list of available drives on the system."""
        system = platform.system()
        if system == "Windows":
            drives = []
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    try:
                        # Try to get volume label
                        label = ""
                        try:
                            import ctypes
                            buf = ctypes.create_unicode_buffer(256)
                            ctypes.windll.kernel32.GetVolumeInformationW(
                                drive, buf, 256, None, None, None, None, 0
                            )
                            label = buf.value
                        except Exception:
                            pass
                        display = f"{drive}"
                        if label:
                            display = f"{label} ({drive[:-1]})"
                        drives.append(display)
                    except Exception:
                        drives.append(drive)
            return drives
        elif system == "Darwin":
            # macOS: list volumes
            volumes_dir = "/Volumes"
            if os.path.exists(volumes_dir):
                return [
                    os.path.join(volumes_dir, v)
                    for v in os.listdir(volumes_dir)
                    if os.path.isdir(os.path.join(volumes_dir, v))
                ]
            return ["/"]
        else:
            # Linux: list mount points
            mounts = ["/"]
            for mount_dir in ["/mnt", "/media", "/run/media"]:
                if os.path.exists(mount_dir):
                    try:
                        for entry in os.listdir(mount_dir):
                            full = os.path.join(mount_dir, entry)
                            if os.path.isdir(full):
                                mounts.append(full)
                    except PermissionError:
                        pass
            return mounts

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}" if unit != "B" else f"{size} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    # ── Public API ───────────────────────────────────────────────────────

    def get_selected_path(self) -> str:
        return self._selected_path

    def get_all_files(self) -> list[str]:
        """Return all files to process (resolves folders recursively)."""
        path = self._selected_path
        if not path or not os.path.exists(path):
            return []

        if os.path.isfile(path):
            return [path]

        if os.path.isdir(path):
            files = []
            for root, _, filenames in os.walk(path):
                for fname in filenames:
                    files.append(os.path.join(root, fname))
            return sorted(files)

        return []

    def clear(self):
        self._on_clear()
