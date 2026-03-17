# DataCrypt

**A cross-platform file encryption application built with modern cryptographic standards.**

DataCrypt securely encrypts and decrypts any file type — documents, images, videos, archives, executables, databases — using industry-accepted cryptographic primitives with no custom cryptography.

---

## Features

### Core Encryption Engine
- **AES-256-GCM** encryption (default) with hardware acceleration support
- **ChaCha20-Poly1305** as an alternative cipher (ideal for ARM/mobile)
- **Argon2id** key derivation with configurable memory, iterations, and parallelism
- **RSA-4096** and **X25519 (Curve25519)** asymmetric encryption for secure key sharing
- **Authenticated encryption** with built-in integrity verification and tamper detection
- **Streaming encryption** — handles files of any size without loading into memory
- **Metadata protection** — original filename and size are encrypted within the file
- **Batch file encryption** — encrypt multiple files in one command
- **Secure file wiping** — DoD 5220.22-M multi-pass overwrite before deletion
- **Progress indicators** with visual progress bars
- **Cross-platform** — builds for Windows, Linux, and macOS

### Desktop GUI (PySide6)
- **Dark glassmorphism theme** — premium dark interface with gradient accents
- **File / Folder / Drive selection** — native OS file dialogs with drag-and-drop support
- **Password manager** — secure entry with real-time strength meter and show/hide toggle
- **Password generator** — cryptographically secure (Python `secrets` module / `os.urandom`)
  - Configurable: 16–128 characters, uppercase, lowercase, digits, symbols
  - Auto-fills both password fields, one-click copy to clipboard
- **Cipher selection** — choose between AES-256-GCM and ChaCha20-Poly1305
- **Security presets** — Standard (64 MB), High (256 MB), Paranoid (1 GB) KDF settings
- **Progress monitoring** — progress bar, ETA, transfer speed, file counter
- **Batch operations** — encrypt/decrypt entire folders recursively
- **Output control** — same folder or custom output directory
- **Security hardening** — passwords cleared after use, clipboard auto-cleared after 30s

## Security Properties

| Property | Implementation |
|---|---|
| **Confidentiality** | AES-256-GCM or ChaCha20-Poly1305 |
| **Integrity** | AEAD authentication tags (128-bit) |
| **Key Derivation** | Argon2id (memory-hard, GPU/ASIC resistant) |
| **Nonce Safety** | Counter-based derivation from CSPRNG base |
| **Forward Secrecy** | Unique random salt per file → unique key per file |
| **Tamper Detection** | Any modification causes decryption failure |
| **Chunk Binding** | AAD binds chunks to position (prevents reordering) |
| **Memory Protection** | Keys zeroed after use, SecureBuffer type |
| **Metadata Privacy** | Original filename/size encrypted in header |

---

## Quick Start

### Prerequisites

- [Go 1.22+](https://go.dev/dl/) — for building the encryption engine
- [Python 3.10+](https://python.org/downloads/) — for the desktop GUI
- **PySide6** — `pip install PySide6`

### Build the Engine

```bash
cd datacrypt
go mod tidy
go build -o datacrypt.exe ./cmd/datacrypt

# Or use Make
make build
```

### Launch the Desktop GUI

```bash
# Install GUI dependencies
cd gui
pip install -r requirements.txt

# Launch
python main.py
```

### Cross-Compile the Engine

```bash
# Build for all platforms
make build-all

# Or individually
make build-linux    # Linux amd64 + arm64
make build-macos    # macOS amd64 + arm64 (Apple Silicon)
make build-windows  # Windows amd64
```

---

## Desktop GUI

The desktop GUI provides a visual interface for all encryption operations. It communicates with the Go encryption engine (`datacrypt.exe`) through a clean subprocess API.

### GUI Window Sections

The main window is divided into these sections, top to bottom:

- **Header** — App title, subtitle, version badge
- **File Selection** — Select File / Select Folder / Select Drive buttons, path display, file info, drag-and-drop zone
- **Password** — Password and Confirm fields with show/hide toggle, real-time strength meter, password generator with length and character options, copy button
- **Options** — Cipher dropdown (AES-256-GCM / ChaCha20-Poly1305), security preset (Standard / High / Paranoid), output location (same folder or custom)
- **Progress** — Progress bar with percentage, current file name, ETA, transfer speed, file counter
- **Actions** — Encrypt, Decrypt, Cancel, and Clear buttons
- **Status Bar** — Engine path and connection status

### GUI Features

| Feature | Details |
|---|---|
| **File Selection** | Native OS dialogs, folder recursion, drive picker (Windows/macOS/Linux) |
| **Drag & Drop** | Drop files or folders directly onto the application |
| **Password Entry** | Hidden input, show/hide toggle, confirm field with match indicator |
| **Password Generator** | CSPRNG-backed, 16–128 chars, configurable character pools |
| **Strength Meter** | Real-time scoring based on length + diversity + entropy |
| **Clipboard Security** | Auto-clears after 30s, Windows clipboard history exclusion |
| **Cipher Selection** | AES-256-GCM or ChaCha20-Poly1305 dropdown |
| **KDF Presets** | Standard / High / Paranoid Argon2id settings |
| **Progress Bar** | Percentage, ETA, transfer speed, file counter |
| **Batch Mode** | Process entire folders recursively |
| **Error Handling** | Clear messages for wrong password, corruption, permissions |
| **Output Options** | Same folder or custom output directory |
| **Encrypted Extension** | `.secure` for GUI-created files |

### GUI Security Protections

- **Passwords never logged** — no console or file logging of sensitive data
- **Password fields cleared** after every operation (success or failure)
- **Secure password zeroing** — bytearray overwrite before reference release
- **Clipboard auto-clear** — copied passwords removed after 30 seconds
- **Windows clipboard history** — excluded via Win32 API (best-effort)
- **Engine separation** — GUI never performs crypto; delegates to the Go binary
- **Close protection** — warns if operation is running; clears passwords on exit

### GUI Architecture

```
gui/
├── main.py                         # Entry point (high-DPI, theme)
├── app.py                          # Main window (assembles widgets)
├── requirements.txt                # PySide6 dependency
└── modules/
    ├── __init__.py
    ├── theme.py                    # Dark glassmorphism QSS stylesheet
    ├── file_selector.py            # File / Folder / Drive + drag-drop
    ├── password_manager.py         # Password entry + strength meter
    ├── password_generator.py       # CSPRNG password generation
    ├── encryption_controller.py    # Subprocess wrapper for engine
    └── progress_monitor.py         # Progress bar + ETA + speed
```

---

## CLI Usage

### Encrypt a File

```bash
# Password-based encryption (default: AES-256-GCM + Argon2id)
datacrypt encrypt document.pdf

# Use ChaCha20-Poly1305 cipher
datacrypt encrypt --cipher chacha20 photo.jpg

# Use higher security KDF settings
datacrypt encrypt --kdf-preset high secret.txt
datacrypt encrypt --kdf-preset paranoid classified.doc

# Custom KDF parameters
datacrypt encrypt --kdf-memory 524288 --kdf-iterations 5 --kdf-parallelism 8 data.bin

# Specify output path
datacrypt encrypt -o encrypted.bin document.pdf

# Batch encryption
datacrypt encrypt *.txt report.xlsx backup.zip
```

### Decrypt a File

```bash
# Decrypt (cipher and KDF params auto-detected from file header)
datacrypt decrypt document.pdf.dcrypt

# Restore original filename
datacrypt decrypt --restore-name document.pdf.dcrypt

# Specify output path
datacrypt decrypt -o original.pdf document.pdf.dcrypt

# Batch decryption
datacrypt decrypt *.dcrypt
```

### Asymmetric Encryption (RSA-4096)

```bash
# Generate RSA key pair
datacrypt keygen --type rsa
# Creates: datacrypt-rsa.key (private), datacrypt-rsa.pub (public)

# Encrypt for a recipient using their public key
datacrypt encrypt --rsa-key recipient.pub secret.pdf

# Recipient decrypts with their private key
datacrypt decrypt --rsa-key private.key secret.pdf.dcrypt
```

### Asymmetric Encryption (X25519 / Curve25519)

```bash
# Generate X25519 key pair
datacrypt keygen --type ecc
# Creates: datacrypt-ecc.key (private), datacrypt-ecc.pub (public)

# Encrypt using ECC
datacrypt encrypt --ecc-key recipient-ecc.pub data.csv

# Decrypt using ECC
datacrypt decrypt --ecc-key private-ecc.key data.csv.dcrypt
```

### Secure File Wiping

```bash
# Securely delete a file (3 passes, DoD 5220.22-M)
datacrypt wipe secret.txt

# 7-pass overwrite for maximum security
datacrypt wipe --passes 7 classified.doc

# Skip confirmation
datacrypt wipe --force temporary.tmp

# Batch wipe
datacrypt wipe *.tmp *.bak
```

### Inspect Encrypted Files

```bash
# View file metadata without decrypting
datacrypt inspect document.pdf.dcrypt
```

**Output:**
```
📋 File Information: document.pdf.dcrypt

   Format Version:    1
   Cipher:            AES-256-GCM
   Key Exchange:      Password (Argon2id)
   KDF Memory:        65536 KB (64.00 MB)
   KDF Iterations:    3
   KDF Parallelism:   4
   Chunk Size:        65536 bytes (64.00 KB)
   Metadata:          128 bytes (encrypted)
```

---

## Project Architecture

```
datacrypt/
├── cmd/
│   └── datacrypt/
│       └── main.go                # CLI entry point
├── internal/
│   ├── crypto/
│   │   ├── aead.go                # AES-256-GCM & ChaCha20-Poly1305
│   │   ├── kdf.go                 # Argon2id key derivation
│   │   ├── asymmetric.go          # RSA-4096 & X25519 key exchange
│   │   ├── random.go              # CSPRNG wrappers
│   │   └── memory.go              # Secure memory (zeroing, SecureBuffer)
│   ├── engine/
│   │   ├── format.go              # Binary file format (.dcrypt)
│   │   ├── encrypt.go             # Streaming chunk-based encryption
│   │   └── decrypt.go             # Streaming chunk-based decryption
│   ├── wipe/
│   │   └── wipe.go                # DoD 5220.22-M secure file deletion
│   └── cli/
│       ├── root.go                # CLI root command + version
│       ├── encrypt.go             # encrypt subcommand
│       ├── decrypt.go             # decrypt subcommand
│       ├── keygen.go              # keygen subcommand (RSA/ECC)
│       ├── inspect.go             # inspect subcommand
│       └── wipe.go                # wipe subcommand
├── gui/                           # Desktop GUI (PySide6)
│   ├── main.py                    # GUI entry point
│   ├── app.py                     # Main application window
│   ├── requirements.txt           # Python dependencies
│   └── modules/
│       ├── theme.py               # Dark glassmorphism stylesheet
│       ├── file_selector.py       # File/folder/drive selector + drag-drop
│       ├── password_manager.py    # Password entry + strength meter
│       ├── password_generator.py  # CSPRNG password generation
│       ├── encryption_controller.py # Engine subprocess controller
│       └── progress_monitor.py    # Progress bar + ETA + speed
├── go.mod
├── go.sum
├── Makefile                       # Cross-platform build targets
└── README.md
```

---

## Encrypted File Format (.dcrypt)

```
┌──────────────────────────────────────────┐
│              HEADER                      │
│  Magic "DCRYPT01"   │ 8 bytes            │
│  Version            │ 1 byte             │
│  Cipher ID          │ 1 byte             │
│  Key Exchange Mode  │ 1 byte             │
│  KDF Memory (KB)    │ 4 bytes            │
│  KDF Iterations     │ 4 bytes            │
│  KDF Parallelism    │ 1 byte             │
│  Salt               │ 32 bytes           │
│  Chunk Size         │ 4 bytes            │
│  Encrypted Key Len  │ 2 bytes            │
│  Encrypted Key      │ variable           │
│  Metadata Nonce     │ 12 bytes           │
│  Metadata Length    │ 4 bytes            │
│  Encrypted Metadata │ variable           │
├──────────────────────────────────────────┤
│  Base Nonce         │ 12 bytes           │
├──────────────────────────────────────────┤
│           ENCRYPTED CHUNKS               │
│  [chunk_len 4B][nonce 12B][ct + tag 16B] │
│  [chunk_len 4B][nonce 12B][ct + tag 16B] │
│  ...                                     │
└──────────────────────────────────────────┘
```

---

## Cryptographic Design

### Key Derivation

Password-based keys are derived using **Argon2id**, the recommended variant that resists:
- **Side-channel attacks** (Argon2i properties)
- **GPU/ASIC brute-force** (Argon2d memory-hardness)

| Preset | Memory | Iterations | Parallelism |
|---|---|---|---|
| `standard` | 64 MB | 3 | 4 |
| `high` | 256 MB | 4 | 8 |
| `paranoid` | 1 GB | 6 | 8 |

### Authenticated Encryption

Both ciphers provide **AEAD** (Authenticated Encryption with Associated Data):
- Encryption produces a 128-bit authentication tag
- Any modification to ciphertext OR header causes decryption failure
- Each chunk has its own nonce derived from a CSPRNG base + counter XOR
- Chunks are bound to their position via AAD (prevents reordering/truncation)

### Key Exchange

| Mode | Mechanism |
|---|---|
| **Password** | Argon2id derives 256-bit key from password + salt |
| **RSA-4096** | Generate random data key → encrypt with RSA-OAEP (SHA-256) |
| **X25519** | Ephemeral ECDH → HKDF-SHA256 → encrypt data key with AES-GCM |

---

## Security Best Practices

1. **Use strong passwords** — 16+ characters with mixed case, numbers, and symbols
2. **Use the password generator** — the GUI generates CSPRNG-backed passwords up to 128 characters
3. **Use key files for automation** — generate RSA/ECC keys instead of scripting passwords
4. **Use `--kdf-preset paranoid`** for highly sensitive files (or select "Paranoid" in the GUI)
5. **Securely wipe originals** — use `datacrypt wipe` after encryption
6. **Backup private keys** — losing your private key means losing access to all files encrypted with it
7. **Never share private keys** — only share `.pub` files
8. **Verify file integrity** — decryption will automatically fail if the file is tampered with
9. **Clear clipboard** — the GUI auto-clears copied passwords after 30 seconds


