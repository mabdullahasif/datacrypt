# DataCrypt — Full Project Documentation

> A cross-platform file encryption application with a Go encryption engine and Python desktop GUI.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Encryption Engine (Go)](#encryption-engine-go)
   - [Cryptographic Primitives](#cryptographic-primitives)
   - [Streaming Engine](#streaming-engine)
   - [CLI Commands](#cli-commands)
   - [Secure File Wipe](#secure-file-wipe)
4. [Desktop GUI (Python)](#desktop-gui-python)
   - [Theme & Styling](#theme--styling)
   - [File Selection](#file-selection)
   - [Password Management](#password-management)
   - [Encryption Controller](#encryption-controller)
   - [Progress Monitoring](#progress-monitoring)
5. [Encrypted File Format](#encrypted-file-format)
6. [Cryptographic Design](#cryptographic-design)
7. [Security Considerations](#security-considerations)
8. [Build & Run Instructions](#build--run-instructions)
9. [API Reference](#api-reference)

---

## Architecture Overview

DataCrypt follows a strict separation between the cryptographic engine and the user interface.

```
 ┌─────────────────────────────────────────────────────┐
 │                  Desktop GUI (Python)               │
 │        PySide6  •  Dark Glassmorphism Theme         │
 │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │
 │  │  File    │ │ Password │ │ Options  │ │Progress│  │
 │  │ Selector │ │ Manager  │ │  Panel   │ │Monitor │  │
 │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬───┘  │
 │       └────────┬───┴────────────┘            │      │
 │         ┌──────▼──────┐                      │      │
 │         │ Encryption  │◄─────────────────────┘      │
 │         │ Controller  │                             │
 │         └──────┬──────┘                             │
 └────────────────┼────────────────────────────────────┘
                  │ QProcess (subprocess)
 ┌────────────────▼─────────────────────────────────────┐
 │               Encryption Engine (Go)                 │
 │  ┌───────────────┐  ┌──────────────────────┐         │
 │  │ CLI Interface │  │ Streaming Engine     │         │
 │  │ (cobra)       │──│ encrypt/decrypt/wipe │         │
 │  └───────┬───────┘  └──────────┬───────────┘         │
 │          │           ┌─────────▼────────────┐        │
 │          │           │ Crypto Primitives    │        │
 │          │           │ AES-GCM │ ChaCha20   │        │
 │          │           │ Argon2id│ RSA/X25519 │        │
 │          │           │ CSPRNG  │ SecureMem  │        │
 │          │           └──────────────────────┘        │
 └──────────────────────────────────────────────────────┘
```

The GUI never performs any cryptographic operations. All encryption, decryption, key derivation, and file wiping is handled by the compiled Go binary (`datacrypt.exe`), called via subprocess.

---

## Project Structure

```
datacrypt/
├── cmd/
│   └── datacrypt/
│       └── main.go                    Entry point → compiles to datacrypt.exe
│
├── internal/
│   ├── crypto/
│   │   ├── aead.go                    AES-256-GCM & ChaCha20-Poly1305 AEAD ciphers
│   │   ├── kdf.go                     Argon2id key derivation with presets
│   │   ├── asymmetric.go              RSA-4096 & X25519 key exchange
│   │   ├── random.go                  CSPRNG wrappers (crypto/rand)
│   │   └── memory.go                  Secure memory zeroing & SecureBuffer
│   │
│   ├── engine/
│   │   ├── format.go                  .dcrypt binary file format
│   │   ├── encrypt.go                 Streaming chunk-based encryption
│   │   └── decrypt.go                 Streaming chunk-based decryption
│   │
│   ├── wipe/
│   │   └── wipe.go                    DoD 5220.22-M secure file deletion
│   │
│   └── cli/
│       ├── root.go                    CLI root command & version
│       ├── encrypt.go                 encrypt subcommand
│       ├── decrypt.go                 decrypt subcommand
│       ├── keygen.go                  keygen subcommand (RSA/ECC)
│       ├── inspect.go                 inspect subcommand
│       └── wipe.go                    wipe subcommand
│
├── gui/
│   ├── main.py                        GUI entry point (high-DPI, theme)
│   ├── app.py                         Main window (assembles all widgets)
│   ├── requirements.txt               Python dependencies (PySide6)
│   └── modules/
│       ├── __init__.py                Package init
│       ├── theme.py                   Dark glassmorphism QSS stylesheet
│       ├── file_selector.py           File/folder/drive selector + drag-drop
│       ├── password_manager.py        Password entry + strength meter
│       ├── password_generator.py      CSPRNG password generation
│       ├── encryption_controller.py   Engine subprocess controller
│       └── progress_monitor.py        Progress bar + ETA + speed
│
├── go.mod                             Go module definition
├── go.sum                             Dependency checksums
├── Makefile                           Cross-platform build targets
├── README.md                          Project README
└── documentation.md                   This file
```

**File count: 31 files** (16 Go, 9 Python, 3 config, 2 docs, 1 binary)

---

## Encryption Engine (Go)

### Cryptographic Primitives

All cryptographic operations use Go's standard library and `golang.org/x/crypto`. No custom cryptography is implemented.

#### aead.go — Authenticated Encryption

Implements two AEAD ciphers:

| Cipher | Algorithm | Key | Nonce | Tag | Best For |
|---|---|---|---|---|---|
| `CipherAES256GCM` (0) | AES-256-GCM | 256-bit | 96-bit | 128-bit | Intel/AMD with AES-NI |
| `CipherChaCha20Poly1305` (1) | ChaCha20-Poly1305 | 256-bit | 96-bit | 128-bit | ARM/mobile, no AES-NI |

**Chunk nonce derivation:**

Each chunk gets a unique nonce by XOR-ing the randomly-generated base nonce with the chunk index:

```
chunk_nonce[i] = base_nonce XOR little_endian(i)
```

This guarantees nonce uniqueness per file without storing nonces per chunk.

**Additional Authenticated Data (AAD):**

Each chunk includes AAD binding it to its position:

```
AAD = [chunk_index (8 bytes)] [is_final (1 byte)]
```

This prevents chunk reordering, duplication, and truncation attacks.

**Exported functions:**

```go
func NewAEAD(cipherID uint8, key []byte) (cipher.AEAD, error)
func SealChunk(aead cipher.AEAD, baseNonce []byte, chunkIndex uint64, plaintext []byte, isFinal bool) ([]byte, error)
func OpenChunk(aead cipher.AEAD, baseNonce []byte, chunkIndex uint64, encryptedChunk []byte, isFinal bool) ([]byte, error)
func DeriveChunkNonce(baseNonce []byte, chunkIndex uint64) []byte
func BuildAAD(chunkIndex uint64, isFinal bool) []byte
func CipherName(id uint8) string
func CipherIDFromName(name string) (uint8, error)
```

---

#### kdf.go — Key Derivation

Uses Argon2id, the recommended variant combining:
- Argon2i resistance to side-channel attacks
- Argon2d resistance to GPU/ASIC brute-force

**Presets:**

| Preset | Memory | Iterations | Parallelism | Use Case |
|---|---|---|---|---|
| `standard` | 64 MB | 3 | 4 | Everyday encryption |
| `high` | 256 MB | 4 | 8 | Sensitive documents |
| `paranoid` | 1 GB | 6 | 8 | Maximum security |

**Exported functions:**

```go
func DeriveKey(password []byte, salt []byte, params KDFParams) (*SecureBuffer, error)
func GetKDFPreset(preset KDFPreset) (KDFParams, error)
func ValidateKDFParams(params KDFParams) error
func KDFPresetFromName(name string) (KDFPreset, error)
```

---

#### asymmetric.go — Key Exchange

Supports two asymmetric modes for encrypting files for specific recipients:

**RSA-4096:**
- Key generation: 4096-bit RSA key pair
- Key wrapping: RSA-OAEP with SHA-256
- PEM format: PKCS#1 (private), PKIX (public)
- Private key permissions: 0600, public key: 0644

**X25519 (Curve25519 ECDH):**
- Key generation: X25519 ECDH key pair
- Key exchange: Ephemeral ECDH → shared secret
- Key derivation: HKDF-SHA256 with info `"datacrypt-x25519-key-v1"`
- Data key wrapping: AES-256-GCM using the derived shared key
- Output format: `[ephemeral_pub 32B][nonce 12B][encrypted_key + tag]`

**Exported functions:**

```go
// RSA
func GenerateRSAKeyPair() (*rsa.PrivateKey, error)
func RSAEncryptKey(publicKey *rsa.PublicKey, dataKey []byte) ([]byte, error)
func RSADecryptKey(privateKey *rsa.PrivateKey, encryptedKey []byte) ([]byte, error)
func SaveRSAPrivateKey(key *rsa.PrivateKey, path string) error
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error)

// X25519
func GenerateX25519KeyPair() (*ecdh.PrivateKey, error)
func X25519DeriveSharedKey(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) (*SecureBuffer, error)
func ECCEncryptKey(recipientPubKey *ecdh.PublicKey, dataKey []byte) ([]byte, error)
func ECCDecryptKey(privateKey *ecdh.PrivateKey, encryptedPayload []byte) ([]byte, error)
```

---

#### random.go — Secure Randomness

All randomness comes from `crypto/rand.Reader`:
- Windows: `CryptGenRandom` (BCrypt)
- Linux: `getrandom` syscall / `/dev/urandom`
- macOS: `getentropy`

```go
func SecureRandom(n int) ([]byte, error)  // n bytes from CSPRNG
func GenerateSalt() ([]byte, error)       // 32 bytes
func GenerateNonce() ([]byte, error)      // 12 bytes
func GenerateKey() ([]byte, error)        // 32 bytes
```

---

#### memory.go — Secure Memory

**ZeroBytes:**
Uses `unsafe.Pointer` arithmetic to overwrite each byte individually. This resists compiler dead-store elimination, which could optimize away a simple loop that writes zeros to memory that is about to be freed. `runtime.KeepAlive` prevents the GC from collecting the slice before zeroing completes.

**SecureBuffer:**
A wrapper type that holds sensitive key material and provides `Destroy()` for explicit zeroing:

```go
buf := crypto.NewSecureBufferFrom(keyBytes)  // copies data, zeros original
key := buf.Bytes()                            // use the key
buf.Destroy()                                 // zeros and nil-s the data
```

**ConstantTimeCompare:**
XOR-based comparison that always examines every byte, preventing timing side-channel attacks when comparing passwords or keys.

---

### Streaming Engine

#### encrypt.go — File Encryption

The encryption pipeline:

```
Input File
    │
    ▼
1. Generate random 32-byte salt
2. Obtain data key:
   ├─ Password mode: Argon2id(password, salt) → 256-bit key
   ├─ RSA mode: random key → RSA-OAEP wrap → store in header
   └─ ECC mode: random key → X25519 ECDH wrap → store in header
3. Create AEAD cipher (AES-GCM or ChaCha20-Poly1305)
4. Encrypt metadata (original filename, size, timestamp)
5. Write binary header
6. Generate and write base nonce (12 bytes)
7. For each chunk (64 KB default):
   │  a. Read plaintext chunk
   │  b. Derive chunk nonce = base_nonce XOR chunk_index
   │  c. Build AAD = [chunk_index, is_final]
   │  d. Encrypt: SealChunk(plaintext, nonce, AAD)
   │  e. Write: [chunk_length 4B][nonce 12B][ciphertext + tag 16B]
   │  f. Zero plaintext from memory
   └─ g. Report progress
8. Zero all sensitive data (key, salt, nonce)
    │
    ▼
Output File (.dcrypt)
```

On any error during encryption, the partial output file is automatically deleted.

#### decrypt.go — File Decryption

The decryption pipeline:

```
Input File (.dcrypt)
    │
    ▼
1. Read and validate header (magic, version, cipher, key mode)
2. Obtain data key:
   ├─ Password mode: Argon2id(password, header.salt) → key
   ├─ RSA mode: RSA-OAEP unwrap(header.encrypted_key, private_key)
   └─ ECC mode: X25519 ECDH unwrap(header.encrypted_key, private_key)
3. Create AEAD cipher
4. Decrypt and verify metadata
5. Determine output path (custom, restored name, or stripped extension)
6. Read base nonce
7. For each chunk:
   │  a. Read chunk length (4 bytes)
   │  b. Read encrypted chunk
   │  c. Peek ahead to detect last chunk
   │  d. Decrypt: OpenChunk(encrypted, nonce, AAD)
   │  e. Write plaintext
   │  f. Zero plaintext from memory
   └─ g. Report progress
8. Verify total decrypted size matches metadata
9. Zero all sensitive data
    │
    ▼
Output File (original)
```

`InspectFile(path)` reads only the header without requiring a password, allowing users to see cipher, KDF settings, and metadata size.

---

### CLI Commands

Built with the [Cobra](https://github.com/spf13/cobra) CLI framework.

#### encrypt

```
datacrypt encrypt [flags] [files...]
```

| Flag | Default | Description |
|---|---|---|
| `-c, --cipher` | `aes` | Cipher: `aes` or `chacha20` |
| `-o, --output` | `{input}.dcrypt` | Output path (single file only) |
| `--kdf-preset` | `standard` | KDF preset: `standard`, `high`, `paranoid` |
| `--kdf-memory` | — | Custom KDF memory (KB), overrides preset |
| `--kdf-iterations` | — | Custom KDF iterations, overrides preset |
| `--kdf-parallelism` | — | Custom KDF parallelism, overrides preset |
| `--chunk-size` | `65536` | Chunk size in bytes (4 KB – 16 MB) |
| `--rsa-key` | — | RSA public key file for asymmetric encryption |
| `--ecc-key` | — | X25519 public key file for asymmetric encryption |
| `-p, --password` | — | Password via flag (insecure, prefer prompt) |
| `--no-progress` | `false` | Disable progress bar |

#### decrypt

```
datacrypt decrypt [flags] [files...]
```

| Flag | Default | Description |
|---|---|---|
| `-o, --output` | auto | Output path (single file only) |
| `--rsa-key` | — | RSA private key for decryption |
| `--ecc-key` | — | X25519 private key for decryption |
| `-p, --password` | — | Password via flag (insecure) |
| `--restore-name` | `false` | Restore original filename from metadata |
| `--no-progress` | `false` | Disable progress bar |

Cipher and KDF parameters are auto-detected from the file header.

#### keygen

```
datacrypt keygen [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-t, --type` | `rsa` | Key type: `rsa` (RSA-4096) or `ecc` (X25519) |
| `--output-dir` | `.` | Directory to save key files |
| `-n, --name` | `datacrypt-{type}` | Base name for key files |

Output: `{name}.key` (private, 0600 permissions) and `{name}.pub` (public, 0644).

#### inspect

```
datacrypt inspect [file]
```

Displays file header information without decrypting: format version, cipher, key exchange mode, KDF parameters, chunk size, and metadata size.

#### wipe

```
datacrypt wipe [flags] [files...]
```

| Flag | Default | Description |
|---|---|---|
| `-n, --passes` | `3` | Number of overwrite passes |
| `-f, --force` | `false` | Skip confirmation prompt |

DoD 5220.22-M pattern: zeros → ones → random data, repeated for the number of passes.

---

### Secure File Wipe

The wipe module (`internal/wipe/wipe.go`) implements multi-pass secure deletion:

1. Open file for writing
2. For each pass:
   - Even passes: overwrite entire file with `0x00`
   - Odd passes: overwrite with `0xFF`
   - Final pass: overwrite with random data
3. `fsync` after each pass
4. Truncate file to 0 bytes
5. Delete file from filesystem

This makes data recovery extremely difficult even with forensic tools.

---

## Desktop GUI (Python)

The GUI is built with PySide6 (Qt 6 for Python) and communicates with the Go engine via subprocess.

### Theme & Styling

**File:** `gui/modules/theme.py`

Implements a premium dark glassmorphism design with:

- **Background:** Deep navy gradient (`#0d1017` → `#1a2233`)
- **Cards:** Semi-transparent dark panels with subtle borders
- **Accent colors:** Blue `#4a8eff`, Cyan `#39d2c0`, Purple `#8957e5`
- **Status colors:** Green `#3fb950` (success), Red `#f85149` (danger)
- **Typography:** Segoe UI / system font stack
- **Border radius:** 8px for cards, 6px for inputs, 20px for buttons

The complete stylesheet is returned by `get_stylesheet()` and applied via `app.setStyleSheet()`.

Role-specific button styling:
- Encrypt button: green gradient with glow effect
- Decrypt button: blue gradient
- Cancel button: red gradient
- Generate/Copy buttons: purple/cyan accents

---

### File Selection

**File:** `gui/modules/file_selector.py`

**Components:**
- Three mode buttons: Select File, Select Folder, Select Drive
- Path display with clear button
- File info label (name, size)
- Drag-and-drop zone (accepts files and folders)

**Drive detection (cross-platform):**
- **Windows:** Iterates drive letters A–Z, checks existence, gets volume labels via Win32 API (`GetVolumeInformationW`)
- **macOS:** Lists entries in `/Volumes/`
- **Linux:** Lists mount points under `/`, `/mnt/`, `/media/`, `/run/media/`

**File collection:**
- Single file: returns `[path]`
- Directory: recursively walks all files using `os.walk()`, returns sorted list
- All file types supported without restriction

---

### Password Management

**File:** `gui/modules/password_manager.py`

**UI components:**
- Password field (masked) with show/hide toggle button
- Confirm password field (masked) with show/hide toggle
- Real-time match indicator (✓ match / ✗ mismatch)
- Strength progress bar with color coding
- Strength label (Very Weak → Very Strong)

**Password generator integration:**
- Generate button calls `generate_password()` from `password_generator.py`
- Auto-fills both password and confirm fields
- Copy button with clipboard auto-clear after 30 seconds

**Validation:**
- `is_valid()` — For encryption: checks non-empty, ≥8 chars, passwords match, strength score ≥20
- `is_valid_for_decrypt()` — For decryption: checks non-empty only

**Security:**
- Clipboard auto-clear after 30 seconds via `QTimer`
- Windows clipboard history exclusion via Win32 `SetPropW` API (best-effort)
- `clear()` method resets all fields

---

### Password Generator

**File:** `gui/modules/password_generator.py`

**Algorithm:**
1. Build alphabet from selected character pools (uppercase, lowercase, digits, symbols)
2. Guarantee at least one character from each selected pool using `secrets.choice()`
3. Fill remaining positions with `secrets.choice(alphabet)`
4. Shuffle entire password using Fisher-Yates algorithm with `secrets.randbelow()` (CSPRNG)

**Randomness source:** Python's `secrets` module, backed by `os.urandom()` → OS CSPRNG.

**Strength evaluation scoring (0–100):**

| Factor | Points | Criteria |
|---|---|---|
| Length | 0–40 | 0 at 0 chars, 40 at 32+ chars |
| Uppercase | 0–10 | Present = 10 |
| Lowercase | 0–10 | Present = 10 |
| Digits | 0–10 | Present = 10 |
| Symbols | 0–10 | Present = 10 |
| Entropy | 0–20 | Based on unique character ratio |

**Labels:**

| Score | Label | Color |
|---|---|---|
| 0–19 | Very Weak | Red `#f85149` |
| 20–39 | Weak | Orange `#f0883e` |
| 40–59 | Moderate | Yellow `#d29922` |
| 60–79 | Strong | Light green `#56d364` |
| 80–100 | Very Strong | Green `#3fb950` |

---

### Encryption Controller

**File:** `gui/modules/encryption_controller.py`

**Engine discovery (`_find_engine_binary`):**
Searches for `datacrypt.exe` in this order:
1. System PATH (`shutil.which("datacrypt")`)
2. Project root (`e:\datacrypt\datacrypt.exe`)
3. Build directory (`e:\datacrypt\build\datacrypt.exe`)

The project root is resolved by navigating 3 directories up from this file:
```
gui/modules/encryption_controller.py → gui/modules/ → gui/ → datacrypt/
```

**Batch processing:**
Files are processed sequentially (one subprocess per file) to avoid resource exhaustion and enable per-file error handling.

**CLI command construction:**

Encryption:
```
datacrypt.exe encrypt -p "PASSWORD" --cipher aes --kdf-preset standard --no-progress -o "file.secure" "file.txt"
```

Decryption:
```
datacrypt.exe decrypt -p "PASSWORD" --no-progress -o "file.txt" "file.txt.secure"
```

**Progress monitoring:**
Since `--no-progress` disables CLI output, the controller polls output file size every 150ms using a `QTimer`:
```
progress = output_file_size / expected_output_size * 100
```

**Error parsing:**
The controller reads stderr and maps Go error messages to user-friendly text:
- `"wrong key"` / `"authentication"` → "Wrong password or file is corrupted"
- `"invalid file format"` → "Not a valid encrypted file"
- `"permission denied"` → "Permission denied"
- `"no such file"` → "File not found"

**Qt signals emitted:**
- `operation_started` — Batch begins
- `file_started(filename, index)` — Individual file processing starts
- `progress_updated(bytes)` — Progress update
- `file_finished(filename, success, error)` — Individual result
- `operation_finished(success, message)` — Batch complete
- `log_message(message)` — Status messages

---

### Progress Monitoring

**File:** `gui/modules/progress_monitor.py`

**Displayed information:**
- Progress bar with percentage
- Current file name being processed
- File counter (e.g., "3 / 10 files")
- Transfer speed (B/s, KB/s, MB/s, GB/s)
- Estimated time remaining (ETA)

**Speed calculation:**
```
elapsed = current_time - start_time
speed = bytes_processed / elapsed
```

**ETA calculation:**
```
remaining_bytes = total_bytes - bytes_processed
eta_seconds = remaining_bytes / speed
```

---

## Encrypted File Format

### .dcrypt Format (v1)

```
Offset  Size      Field                Description
──────  ────      ─────                ───────────
0       8         Magic                "DCRYPT01" file signature
8       1         Version              Format version (1)
9       1         CipherID             0 = AES-256-GCM, 1 = ChaCha20-Poly1305
10      1         KeyExchangeMode      0 = Password, 1 = RSA, 2 = ECC
11      4         KDFMemory            Argon2id memory in KB
15      4         KDFIterations        Argon2id time cost
19      1         KDFParallelism       Argon2id threads
20      32        Salt                 Random salt for key derivation
52      4         ChunkSize            Plaintext chunk size in bytes
56      2         EncryptedKeyLen      Length of wrapped key (0 for password mode)
58      var       EncryptedKey         Wrapped data key (RSA/ECC modes only)
var     12        MetadataNonce        Nonce for metadata encryption
var     4         MetadataLen          Length of encrypted metadata
var     var       EncryptedMetadata    Encrypted JSON (original name, size, time)
var     12        BaseNonce            Random base nonce for chunk encryption

Repeated for each chunk:
var     4         ChunkLen             Total length of following encrypted chunk
var     12        ChunkNonce           Derived nonce (base XOR index)
var     var       Ciphertext           Encrypted data
var     16        AuthTag              128-bit authentication tag
```

### .secure Extension

The GUI uses `.secure` instead of `.dcrypt` for its encrypted files. The internal format is identical.

### Metadata Structure

```json
{
  "original_name": "document.pdf",
  "original_size": 1048576,
  "created_at": "2026-03-18T02:00:00Z",
  "cipher": "AES-256-GCM",
  "chunk_size": 65536
}
```

Metadata is encrypted with the same AEAD cipher as the file data, using AAD `"datacrypt-metadata"` for domain separation.

---

## Cryptographic Design

### Key Hierarchy

**Password Mode:**
```
User Password
     │
     ▼
Argon2id(password, salt, memory, iterations, parallelism)
     │
     ▼
256-bit Data Key ──────► AEAD Cipher ──────► Encrypted Chunks
```

**RSA Mode:**
```
crypto/rand ──► 256-bit Random Data Key ──► AEAD Cipher ──► Encrypted Chunks
                        │
                        ▼
              RSA-OAEP(SHA-256) ──► Wrapped Key (stored in header)
```

**ECC Mode:**
```
crypto/rand ──► 256-bit Random Data Key ──► AEAD Cipher ──► Encrypted Chunks
                        │
Ephemeral X25519 ──► ECDH ──► HKDF-SHA256 ──► AES-GCM Wrap ──► Wrapped Key
```

### Nonce Management

Each file uses a unique randomly-generated base nonce. Per-chunk nonces are derived deterministically:

```
chunk_nonce = base_nonce ⊕ little_endian_uint64(chunk_index)
```

This guarantees:
- No nonce reuse within a file (unique chunk index per chunk)
- No nonce reuse across files (unique base nonce per file)
- No need to store per-chunk nonces (derivable from base + index)

### Tamper Detection

Three layers of integrity protection:

1. **Per-chunk authentication:** Each chunk has a 128-bit GCM/Poly1305 tag
2. **Chunk binding:** AAD includes chunk index and is-final flag, preventing reordering
3. **Size verification:** Total decrypted size is compared against encrypted metadata

Any modification to any part of the file (header, nonces, ciphertext, or tags) causes decryption to fail with a clear error.

---

## Security Considerations

### What DataCrypt Protects Against

- **Brute-force:** Argon2id memory-hardness makes GPU/ASIC attacks expensive
- **Rainbow tables:** Unique random salt per file
- **Tampering:** AEAD authentication tags on every chunk
- **Chunk reordering:** AAD binds chunks to specific positions
- **File truncation:** is-final flag in AAD prevents truncation
- **Nonce reuse:** Counter-derived nonces from CSPRNG base
- **Key leakage in memory:** SecureBuffer zeroing, unsafe.Pointer writes
- **Timing attacks:** Constant-time comparison for secrets

### Known Limitations

- **Go garbage collector:** May copy key material before zeroing (Go does not guarantee no copies)
- **Python strings are immutable:** Secure zeroing in the GUI is best-effort
- **`-p` flag:** Passing passwords via command-line flags exposes them in the process list
- **Swap/hibernate:** Key material may be written to disk by the OS
- **Clipboard history:** Windows clipboard history exclusion is best-effort

### Best Practices

1. Use the interactive password prompt, not `-p` flag
2. Use 16+ character passwords with mixed character types
3. Use the built-in password generator for maximum entropy
4. Select "Paranoid" KDF preset for high-value files
5. Use `datacrypt wipe` to securely delete originals after encryption
6. Back up private keys (RSA/ECC) — there is no recovery without them
7. Never share `.key` files — only share `.pub` files
8. Verify decryption works before deleting originals

---

## Build & Run Instructions

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.22+ | Build the encryption engine |
| Python | 3.10+ | Run the desktop GUI |
| PySide6 | 6.6+ | Qt 6 GUI framework |

### Build the Engine

```bash
cd datacrypt
go mod tidy
go build -trimpath -o datacrypt.exe ./cmd/datacrypt
```

The `-trimpath` flag removes local filesystem paths from the binary for reproducible builds.

### Cross-Compile

```bash
# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -trimpath -o datacrypt-linux-amd64 ./cmd/datacrypt

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -trimpath -o datacrypt-darwin-arm64 ./cmd/datacrypt

# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -trimpath -o datacrypt.exe ./cmd/datacrypt
```

Or use the Makefile:

```bash
make build-all    # All platforms
make build-linux  # Linux amd64 + arm64
make build-macos  # macOS amd64 + arm64
make build-windows # Windows amd64
```

### Run the Desktop GUI

```bash
cd gui
pip install -r requirements.txt
python main.py
```

The GUI automatically locates `datacrypt.exe` in the project root directory.

### PATH Setup (Windows)

If `go` is not recognized:

```powershell
# Temporary (current session)
$env:PATH = "C:\Program Files\Go\bin;" + $env:PATH

# Permanent (user-level)
[Environment]::SetEnvironmentVariable("Path", "C:\Program Files\Go\bin;" + [Environment]::GetEnvironmentVariable("Path", "User"), "User")
```

Restart your terminal after the permanent change.

---

## API Reference

### Encryption (Go)

```go
// Encrypt a single file
engine.EncryptFile(inputPath string, opts engine.EncryptOptions) error

// Decrypt a single file
engine.DecryptFile(inputPath string, opts engine.DecryptOptions) error

// Inspect file header (no password needed)
engine.InspectFile(path string) (*engine.FileHeader, error)

// Secure file deletion
wipe.SecureWipe(path string, opts wipe.WipeOptions) error

// Key derivation
crypto.DeriveKey(password, salt []byte, params crypto.KDFParams) (*crypto.SecureBuffer, error)

// AEAD cipher creation
crypto.NewAEAD(cipherID uint8, key []byte) (cipher.AEAD, error)

// Key generation
crypto.GenerateRSAKeyPair() (*rsa.PrivateKey, error)
crypto.GenerateX25519KeyPair() (*ecdh.PrivateKey, error)

// Secure randomness
crypto.SecureRandom(n int) ([]byte, error)
crypto.GenerateSalt() ([]byte, error)
crypto.GenerateNonce() ([]byte, error)
crypto.GenerateKey() ([]byte, error)
```

### GUI Controller (Python)

```python
# Create controller
controller = EncryptionController()

# Encrypt files
controller.encrypt_files(
    files=["file1.pdf", "file2.jpg"],
    password="SecurePassword123!",
    cipher="aes",           # or "chacha20"
    kdf_preset="standard",  # or "high", "paranoid"
    output_dir=""            # empty = same folder
)

# Decrypt files
controller.decrypt_files(
    files=["file1.pdf.secure"],
    password="SecurePassword123!",
    output_dir=""
)

# Cancel operation
controller.cancel()

# Connect signals
controller.operation_started.connect(on_started)
controller.file_finished.connect(on_file_done)
controller.operation_finished.connect(on_complete)
controller.progress_updated.connect(on_progress)
```

### Password Generator (Python)

```python
from modules.password_generator import generate_password, evaluate_strength

# Generate a 32-character password
pw = generate_password(length=32, uppercase=True, lowercase=True, digits=True, symbols=True)

# Evaluate strength
score, label, color = evaluate_strength(pw)
# score: 0-100, label: "Very Strong", color: "#3fb950"
```
