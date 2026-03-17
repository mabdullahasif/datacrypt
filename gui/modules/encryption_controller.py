"""
DataCrypt GUI — Encryption Controller
Manages subprocess calls to the datacrypt CLI engine.
Handles progress monitoring, error reporting, cancellation, and batch operations.
"""

import os
import re
import sys
import time

from PySide6.QtCore import QProcess, QTimer, Signal, QObject


# ─── Engine Binary Discovery ────────────────────────────────────────────

def _find_engine_binary() -> str:
    """Locate the datacrypt engine binary."""
    # This file is at: datacrypt/gui/modules/encryption_controller.py
    # We need to reach:  datacrypt/  (3 levels up)
    this_file = os.path.abspath(__file__)              # .../gui/modules/encryption_controller.py
    modules_dir = os.path.dirname(this_file)           # .../gui/modules/
    gui_dir = os.path.dirname(modules_dir)             # .../gui/
    project_root = os.path.dirname(gui_dir)            # .../datacrypt/
    candidates = [
        os.path.join(project_root, "datacrypt.exe"),
        os.path.join(project_root, "datacrypt"),
        os.path.join(project_root, "build", "datacrypt.exe"),
        os.path.join(project_root, "build", "datacrypt"),
    ]

    # Also check system PATH
    import shutil
    path_binary = shutil.which("datacrypt")
    if path_binary:
        candidates.insert(0, path_binary)

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    # Fallback: return the expected location
    if sys.platform == "win32":
        return os.path.join(project_root, "datacrypt.exe")
    return os.path.join(project_root, "datacrypt")


ENGINE_BINARY = _find_engine_binary()

# ─── File extension ──────────────────────────────────────────────────────
ENCRYPTED_EXTENSION = ".secure"


class EncryptionController(QObject):
    """
    Controls encryption/decryption operations by calling the datacrypt CLI.

    Signals:
        operation_started: Emitted when an operation begins.
        file_started(filename, index): Emitted when a file starts processing.
        progress_updated(processed_bytes): Emitted with cumulative bytes processed.
        file_finished(filename, success, error): Emitted when a file completes.
        operation_finished(success, message): Emitted when all files are done.
        log_message(message): Emitted for status/log messages.
    """

    operation_started = Signal()
    file_started = Signal(str, int)       # filename, index
    progress_updated = Signal(int)        # total bytes processed so far
    file_finished = Signal(str, bool, str)  # filename, success, error_msg
    operation_finished = Signal(bool, str)  # success, message
    log_message = Signal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._process: QProcess | None = None
        self._timer: QTimer | None = None
        self._cancelled = False

        # Batch state
        self._files: list[str] = []
        self._current_index = 0
        self._password = ""
        self._cipher = "aes"
        self._kdf_preset = "standard"
        self._mode = "encrypt"
        self._output_dir = ""

        # Progress tracking
        self._total_bytes = 0
        self._cumulative_bytes = 0
        self._current_file_size = 0
        self._current_output_path = ""
        self._success_count = 0
        self._error_messages: list[str] = []

    # ── Public API ───────────────────────────────────────────────────────

    def encrypt_files(
        self,
        files: list[str],
        password: str,
        cipher: str = "aes",
        kdf_preset: str = "standard",
        output_dir: str = "",
    ):
        """Start encrypting a list of files."""
        self._mode = "encrypt"
        self._start_batch(files, password, cipher, kdf_preset, output_dir)

    def decrypt_files(
        self,
        files: list[str],
        password: str,
        output_dir: str = "",
    ):
        """Start decrypting a list of files."""
        self._mode = "decrypt"
        self._start_batch(files, password, "aes", "standard", output_dir)

    def cancel(self):
        """Cancel the current operation."""
        self._cancelled = True
        if self._process and self._process.state() == QProcess.ProcessState.Running:
            self._process.kill()
            self._process.waitForFinished(3000)
        if self._timer:
            self._timer.stop()
        self._secure_clear_password()
        self.log_message.emit("🚫 Operation cancelled by user")

    def is_running(self) -> bool:
        """Check if an operation is in progress."""
        return (
            self._process is not None
            and self._process.state() == QProcess.ProcessState.Running
        )

    @staticmethod
    def get_engine_path() -> str:
        return ENGINE_BINARY

    @staticmethod
    def engine_exists() -> bool:
        return os.path.isfile(ENGINE_BINARY) and os.access(ENGINE_BINARY, os.X_OK)

    # ── Internal: Batch coordination ─────────────────────────────────────

    def _start_batch(
        self,
        files: list[str],
        password: str,
        cipher: str,
        kdf_preset: str,
        output_dir: str,
    ):
        self._files = files
        self._current_index = 0
        self._password = password
        self._cipher = cipher
        self._kdf_preset = kdf_preset
        self._output_dir = output_dir
        self._cancelled = False
        self._success_count = 0
        self._error_messages = []
        self._cumulative_bytes = 0

        # Calculate total bytes
        self._total_bytes = sum(
            os.path.getsize(f) for f in files if os.path.isfile(f)
        )

        self.operation_started.emit()
        self.log_message.emit(
            f"🔐 Starting {self._mode} on {len(files)} file(s) "
            f"({self._format_size(self._total_bytes)})"
        )

        self._process_next_file()

    def _process_next_file(self):
        """Process the next file in the batch."""
        if self._cancelled:
            self._finish_batch()
            return

        if self._current_index >= len(self._files):
            self._finish_batch()
            return

        filepath = self._files[self._current_index]
        filename = os.path.basename(filepath)

        self.file_started.emit(filename, self._current_index)
        self.log_message.emit(f"  ⏳ [{self._current_index+1}/{len(self._files)}] {filename}")

        if not os.path.isfile(filepath):
            self._error_messages.append(f"{filename}: File not found")
            self.file_finished.emit(filename, False, "File not found")
            self._current_index += 1
            # Use timer to avoid deep recursion
            QTimer.singleShot(10, self._process_next_file)
            return

        self._current_file_size = os.path.getsize(filepath)

        # Build command
        if self._mode == "encrypt":
            self._run_encrypt(filepath)
        else:
            self._run_decrypt(filepath)

    def _run_encrypt(self, filepath: str):
        """Encrypt a single file via subprocess."""
        filename = os.path.basename(filepath)

        # Determine output path
        if self._output_dir:
            output_path = os.path.join(
                self._output_dir, filename + ENCRYPTED_EXTENSION
            )
        else:
            output_path = filepath + ENCRYPTED_EXTENSION

        self._current_output_path = output_path

        args = [
            "encrypt",
            "-p", self._password,
            "--cipher", self._cipher,
            "--kdf-preset", self._kdf_preset,
            "--no-progress",
            "-o", output_path,
            filepath,
        ]

        self._start_process(args)

    def _run_decrypt(self, filepath: str):
        """Decrypt a single file via subprocess."""
        filename = os.path.basename(filepath)

        # Determine output path
        if self._output_dir:
            base = filename
            # Strip encrypted extensions
            for ext in (ENCRYPTED_EXTENSION, ".dcrypt"):
                if base.endswith(ext):
                    base = base[:-len(ext)]
                    break
            output_path = os.path.join(self._output_dir, base)
        else:
            output_path = filepath
            for ext in (ENCRYPTED_EXTENSION, ".dcrypt"):
                if output_path.endswith(ext):
                    output_path = output_path[:-len(ext)]
                    break
            if output_path == filepath:
                output_path = filepath + ".decrypted"

        self._current_output_path = output_path

        args = [
            "decrypt",
            "-p", self._password,
            "--no-progress",
            "-o", output_path,
            filepath,
        ]

        self._start_process(args)

    def _start_process(self, args: list[str]):
        """Launch the datacrypt subprocess."""
        self._process = QProcess(self)
        self._process.setProgram(ENGINE_BINARY)
        self._process.setArguments(args)

        self._process.finished.connect(self._on_process_finished)
        self._process.errorOccurred.connect(self._on_process_error)

        # Start output file size monitoring
        self._timer = QTimer(self)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._poll_progress)
        self._timer.start()

        self._process.start()

    def _poll_progress(self):
        """Monitor output file growth for progress estimation."""
        if not self._current_output_path:
            return

        try:
            if os.path.exists(self._current_output_path):
                current_size = os.path.getsize(self._current_output_path)
                # For encryption, output ≈ input + small overhead
                estimated_bytes = min(current_size, self._current_file_size)
                total_done = self._cumulative_bytes + estimated_bytes
                self.progress_updated.emit(total_done)
        except OSError:
            pass

    def _on_process_finished(self, exit_code: int, exit_status):
        """Handle subprocess completion."""
        if self._timer:
            self._timer.stop()

        filename = os.path.basename(self._files[self._current_index])

        # Read any error output
        stderr_data = ""
        if self._process:
            stderr_bytes = self._process.readAllStandardError()
            stderr_data = stderr_bytes.data().decode("utf-8", errors="replace")

        if self._cancelled:
            return

        if exit_code == 0:
            self._success_count += 1
            self._cumulative_bytes += self._current_file_size
            self.progress_updated.emit(self._cumulative_bytes)
            self.file_finished.emit(filename, True, "")
            self.log_message.emit(f" {filename}")
        else:
            # Parse error from stderr
            error_msg = self._parse_error(stderr_data)
            self._error_messages.append(f"{filename}: {error_msg}")
            self.file_finished.emit(filename, False, error_msg)
            self.log_message.emit(f" {filename}: {error_msg}")

        self._current_index += 1
        QTimer.singleShot(50, self._process_next_file)

    def _on_process_error(self, error):
        """Handle process launch errors."""
        if self._timer:
            self._timer.stop()

        error_map = {
            QProcess.ProcessError.FailedToStart: "Engine binary not found or not executable",
            QProcess.ProcessError.Crashed: "Engine process crashed",
            QProcess.ProcessError.Timedout: "Operation timed out",
            QProcess.ProcessError.WriteError: "Failed to communicate with engine",
            QProcess.ProcessError.ReadError: "Failed to read engine output",
        }
        msg = error_map.get(error, f"Unknown process error ({error})")

        if self._current_index < len(self._files):
            filename = os.path.basename(self._files[self._current_index])
            self._error_messages.append(f"{filename}: {msg}")
            self.file_finished.emit(filename, False, msg)
            self.log_message.emit(f"  {filename}: {msg}")

        self._current_index += 1
        QTimer.singleShot(50, self._process_next_file)

    def _finish_batch(self):
        """Complete the batch operation."""
        self._secure_clear_password()

        total = len(self._files)
        if self._cancelled:
            self.operation_finished.emit(False, "Operation cancelled")
        elif self._success_count == total:
            self.operation_finished.emit(
                True,
                f"✅ All {total} file(s) processed successfully"
            )
        elif self._success_count > 0:
            self.operation_finished.emit(
                False,
                f"⚠ {self._success_count}/{total} succeeded, "
                f"{total - self._success_count} failed"
            )
        else:
            first_error = self._error_messages[0] if self._error_messages else "Unknown error"
            self.operation_finished.emit(False, f" Failed: {first_error}")

    def _secure_clear_password(self):
        """Zero the password string from memory (best-effort in Python)."""
        if self._password:
            # Python strings are immutable, but we can overwrite the reference
            # and reduce the window of exposure
            pw_bytes = bytearray(self._password.encode())
            for i in range(len(pw_bytes)):
                pw_bytes[i] = 0
            self._password = ""

    @staticmethod
    def _parse_error(stderr: str) -> str:
        """Extract a user-friendly error message from stderr."""
        # Look for common error patterns
        if "message authentication failed" in stderr:
            return "Wrong password or file is corrupted"
        if "invalid file format" in stderr or "bad magic" in stderr:
            return "Not a valid encrypted file"
        if "permission denied" in stderr.lower():
            return "Permission denied — check file access"
        if "no such file" in stderr.lower() or "cannot access" in stderr.lower():
            return "File not found"
        if "password" in stderr.lower() and "empty" in stderr.lower():
            return "Password is required"

        # Try to extract the last meaningful line
        lines = [
            l.strip() for l in stderr.strip().split("\n")
            if l.strip() and not l.strip().startswith("Usage:")
        ]
        for line in reversed(lines):
            # Look for error markers
            if "Error:" in line or "" in line:
                # Clean up the error message
                msg = re.sub(r"^.*Error:\s*", "", line)
                msg = re.sub(r"^.*\s*", "", msg)
                return msg.strip() or "Unknown error"

        return stderr.strip()[:200] if stderr.strip() else "Unknown error"

    @staticmethod
    def _format_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}" if unit != "B" else f"{size} {unit}"
            size /= 1024
        return f"{size:.1f} TB"
