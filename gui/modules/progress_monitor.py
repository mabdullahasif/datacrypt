"""
DataCrypt GUI — Progress Monitor Widget
Displays encryption/decryption progress with ETA calculation.
"""

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)


class ProgressMonitorWidget(QGroupBox):
    """
    Progress card showing:
    - Progress bar with percentage
    - Current file name being processed
    - Files processed counter (batch mode)
    - Estimated time remaining (ETA)
    - Transfer speed
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__("📊  Progress", parent)
        self._start_time: float = 0
        self._total_bytes: int = 0
        self._processed_bytes: int = 0
        self._total_files: int = 0
        self._processed_files: int = 0
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # ── Progress bar ──
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFormat("%p%")
        layout.addWidget(self._progress_bar)

        # ── Status row ──
        status_row = QHBoxLayout()
        self._status_label = QLabel("Ready")
        self._status_label.setObjectName("label_fileinfo")
        self._speed_label = QLabel("")
        self._speed_label.setObjectName("label_fileinfo")
        self._speed_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_row.addWidget(self._status_label, 1)
        status_row.addWidget(self._speed_label)
        layout.addLayout(status_row)

        # ── File counter + ETA row ──
        info_row = QHBoxLayout()
        self._file_counter = QLabel("")
        self._file_counter.setObjectName("label_fileinfo")
        self._eta_label = QLabel("")
        self._eta_label.setObjectName("label_eta")
        self._eta_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        info_row.addWidget(self._file_counter, 1)
        info_row.addWidget(self._eta_label)
        layout.addLayout(info_row)

    # ── Public API ───────────────────────────────────────────────────────

    def start_operation(self, total_files: int, total_bytes: int, operation: str = "Encrypting"):
        """Initialize progress tracking for a new operation."""
        self._start_time = time.time()
        self._total_bytes = total_bytes
        self._processed_bytes = 0
        self._total_files = total_files
        self._processed_files = 0
        self._progress_bar.setValue(0)
        self._status_label.setText(f"⏳ {operation}…")
        self._file_counter.setText(f"0 / {total_files} files")
        self._eta_label.setText("Calculating ETA…")
        self._speed_label.setText("")

    def update_file_progress(self, filename: str, file_index: int):
        """Update the currently processing file."""
        self._processed_files = file_index
        self._status_label.setText(f"⏳ Processing: {filename}")
        self._file_counter.setText(f"{file_index} / {self._total_files} files")

    def update_bytes_progress(self, processed: int):
        """Update total bytes processed across all files."""
        self._processed_bytes = processed

        if self._total_bytes > 0:
            percent = min(int(processed / self._total_bytes * 100), 100)
            self._progress_bar.setValue(percent)

            # Calculate speed and ETA
            elapsed = time.time() - self._start_time
            if elapsed > 0.5:
                speed = processed / elapsed
                remaining_bytes = self._total_bytes - processed
                if speed > 0:
                    eta_seconds = remaining_bytes / speed
                    self._eta_label.setText(f"⏱ {self._format_eta(eta_seconds)} remaining")
                    self._speed_label.setText(f"{self._format_speed(speed)}")

    def finish_operation(self, success: bool = True, message: str = ""):
        """Mark the operation as complete."""
        elapsed = time.time() - self._start_time

        if success:
            self._progress_bar.setValue(100)
            speed_avg = self._processed_bytes / elapsed if elapsed > 0 else 0
            self._status_label.setText(
                message or f"✅ Complete — {self._format_time(elapsed)}"
            )
            self._speed_label.setText(f"Avg: {self._format_speed(speed_avg)}")
        else:
            self._status_label.setText(message or "❌ Operation failed")
            self._speed_label.setText("")

        self._eta_label.setText("")
        self._file_counter.setText(
            f"{self._processed_files} / {self._total_files} files"
        )

    def cancel_operation(self):
        """Mark the operation as cancelled."""
        self._status_label.setText("🚫 Operation cancelled")
        self._eta_label.setText("")
        self._speed_label.setText("")

    def reset(self):
        """Reset all progress indicators."""
        self._progress_bar.setValue(0)
        self._status_label.setText("Ready")
        self._file_counter.setText("")
        self._eta_label.setText("")
        self._speed_label.setText("")
        self._start_time = 0
        self._total_bytes = 0
        self._processed_bytes = 0
        self._total_files = 0
        self._processed_files = 0

    # ── Formatting helpers ───────────────────────────────────────────────

    @staticmethod
    def _format_eta(seconds: float) -> str:
        if seconds < 1:
            return "< 1 second"
        if seconds < 60:
            return f"~{int(seconds)} seconds"
        if seconds < 3600:
            m = int(seconds // 60)
            s = int(seconds % 60)
            return f"~{m}m {s}s"
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"~{h}h {m}m"

    @staticmethod
    def _format_time(seconds: float) -> str:
        if seconds < 1:
            return f"{seconds*1000:.0f} ms"
        if seconds < 60:
            return f"{seconds:.1f}s"
        m = int(seconds // 60)
        s = seconds % 60
        return f"{m}m {s:.1f}s"

    @staticmethod
    def _format_speed(bytes_per_sec: float) -> str:
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.0f} B/s"
        if bytes_per_sec < 1024 * 1024:
            return f"{bytes_per_sec/1024:.1f} KB/s"
        if bytes_per_sec < 1024 * 1024 * 1024:
            return f"{bytes_per_sec/1024/1024:.1f} MB/s"
        return f"{bytes_per_sec/1024/1024/1024:.1f} GB/s"
