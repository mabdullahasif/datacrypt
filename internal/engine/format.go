// Package engine defines the DataCrypt encrypted file format.
// The format is designed for streaming, authenticated, chunk-based encryption.
package engine

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/datacrypt/datacrypt/internal/crypto"
)

// File format constants
var MagicBytes = [8]byte{'D', 'C', 'R', 'Y', 'P', 'T', '0', '1'}

const (
	FormatVersion    uint8  = 1
	DefaultChunkSize uint32 = 65536 // 64 KB
	MaxChunkSize     uint32 = 16777216 // 16 MB
	MinChunkSize     uint32 = 4096 // 4 KB
)

// FileHeader represents the header of an encrypted DataCrypt file.
type FileHeader struct {
	Magic           [8]byte
	Version         uint8
	CipherID        uint8
	KeyExchangeMode uint8
	KDFMemory       uint32
	KDFIterations   uint32
	KDFParallelism  uint8
	Salt            [32]byte
	ChunkSize       uint32
	EncryptedKeyLen uint16
	EncryptedKey    []byte // Only populated for asymmetric modes
	MetadataNonce   [12]byte
	MetadataLen     uint32
	EncryptedMeta   []byte // Encrypted JSON metadata
}

// FileMetadata contains protected information about the original file.
type FileMetadata struct {
	OriginalName string    `json:"original_name"`
	OriginalSize int64     `json:"original_size"`
	CreatedAt    time.Time `json:"created_at"`
	Cipher       string    `json:"cipher"`
	ChunkSize    uint32    `json:"chunk_size"`
}

// WriteHeader serializes and writes the file header to the writer.
func WriteHeader(w io.Writer, h *FileHeader) error {
	// Magic bytes
	if _, err := w.Write(h.Magic[:]); err != nil {
		return fmt.Errorf("engine/format: failed to write magic: %w", err)
	}

	// Fixed-size fields
	fixedFields := []interface{}{
		h.Version,
		h.CipherID,
		h.KeyExchangeMode,
		h.KDFMemory,
		h.KDFIterations,
		h.KDFParallelism,
	}

	for _, f := range fixedFields {
		if err := binary.Write(w, binary.LittleEndian, f); err != nil {
			return fmt.Errorf("engine/format: failed to write header field: %w", err)
		}
	}

	// Salt (32 bytes)
	if _, err := w.Write(h.Salt[:]); err != nil {
		return fmt.Errorf("engine/format: failed to write salt: %w", err)
	}

	// Chunk size
	if err := binary.Write(w, binary.LittleEndian, h.ChunkSize); err != nil {
		return fmt.Errorf("engine/format: failed to write chunk size: %w", err)
	}

	// Encrypted key (for asymmetric modes)
	if err := binary.Write(w, binary.LittleEndian, h.EncryptedKeyLen); err != nil {
		return fmt.Errorf("engine/format: failed to write encrypted key length: %w", err)
	}
	if h.EncryptedKeyLen > 0 {
		if _, err := w.Write(h.EncryptedKey); err != nil {
			return fmt.Errorf("engine/format: failed to write encrypted key: %w", err)
		}
	}

	// Metadata nonce
	if _, err := w.Write(h.MetadataNonce[:]); err != nil {
		return fmt.Errorf("engine/format: failed to write metadata nonce: %w", err)
	}

	// Encrypted metadata
	if err := binary.Write(w, binary.LittleEndian, h.MetadataLen); err != nil {
		return fmt.Errorf("engine/format: failed to write metadata length: %w", err)
	}
	if h.MetadataLen > 0 {
		if _, err := w.Write(h.EncryptedMeta); err != nil {
			return fmt.Errorf("engine/format: failed to write encrypted metadata: %w", err)
		}
	}

	return nil
}

// ReadHeader reads and deserializes a file header from the reader.
func ReadHeader(r io.Reader) (*FileHeader, error) {
	h := &FileHeader{}

	// Magic bytes
	if _, err := io.ReadFull(r, h.Magic[:]); err != nil {
		return nil, fmt.Errorf("engine/format: failed to read magic bytes: %w", err)
	}
	if h.Magic != MagicBytes {
		return nil, fmt.Errorf("engine/format: invalid file format (bad magic bytes)")
	}

	// Fixed-size fields
	fixedFields := []interface{}{
		&h.Version,
		&h.CipherID,
		&h.KeyExchangeMode,
		&h.KDFMemory,
		&h.KDFIterations,
		&h.KDFParallelism,
	}

	for _, f := range fixedFields {
		if err := binary.Read(r, binary.LittleEndian, f); err != nil {
			return nil, fmt.Errorf("engine/format: failed to read header field: %w", err)
		}
	}

	// Validate version
	if h.Version != FormatVersion {
		return nil, fmt.Errorf("engine/format: unsupported version %d (expected %d)", h.Version, FormatVersion)
	}

	// Validate cipher
	if h.CipherID > crypto.CipherChaCha20Poly1305 {
		return nil, fmt.Errorf("engine/format: unknown cipher ID %d", h.CipherID)
	}

	// Validate key exchange mode
	if h.KeyExchangeMode > crypto.KeyExchangeECC {
		return nil, fmt.Errorf("engine/format: unknown key exchange mode %d", h.KeyExchangeMode)
	}

	// Salt
	if _, err := io.ReadFull(r, h.Salt[:]); err != nil {
		return nil, fmt.Errorf("engine/format: failed to read salt: %w", err)
	}

	// Chunk size
	if err := binary.Read(r, binary.LittleEndian, &h.ChunkSize); err != nil {
		return nil, fmt.Errorf("engine/format: failed to read chunk size: %w", err)
	}
	if h.ChunkSize < MinChunkSize || h.ChunkSize > MaxChunkSize {
		return nil, fmt.Errorf("engine/format: invalid chunk size %d (must be %d–%d)", h.ChunkSize, MinChunkSize, MaxChunkSize)
	}

	// Encrypted key length
	if err := binary.Read(r, binary.LittleEndian, &h.EncryptedKeyLen); err != nil {
		return nil, fmt.Errorf("engine/format: failed to read encrypted key length: %w", err)
	}
	if h.EncryptedKeyLen > 0 {
		h.EncryptedKey = make([]byte, h.EncryptedKeyLen)
		if _, err := io.ReadFull(r, h.EncryptedKey); err != nil {
			return nil, fmt.Errorf("engine/format: failed to read encrypted key: %w", err)
		}
	}

	// Metadata nonce
	if _, err := io.ReadFull(r, h.MetadataNonce[:]); err != nil {
		return nil, fmt.Errorf("engine/format: failed to read metadata nonce: %w", err)
	}

	// Metadata
	if err := binary.Read(r, binary.LittleEndian, &h.MetadataLen); err != nil {
		return nil, fmt.Errorf("engine/format: failed to read metadata length: %w", err)
	}
	if h.MetadataLen > 0 {
		if h.MetadataLen > 65536 { // Sanity check: metadata shouldn't exceed 64KB
			return nil, fmt.Errorf("engine/format: metadata too large (%d bytes)", h.MetadataLen)
		}
		h.EncryptedMeta = make([]byte, h.MetadataLen)
		if _, err := io.ReadFull(r, h.EncryptedMeta); err != nil {
			return nil, fmt.Errorf("engine/format: failed to read encrypted metadata: %w", err)
		}
	}

	return h, nil
}

// EncryptMetadata encrypts file metadata using the given AEAD cipher and key.
func EncryptMetadata(meta *FileMetadata, cipherID uint8, key []byte) (nonce [12]byte, encrypted []byte, err error) {
	plaintext, err := json.Marshal(meta)
	if err != nil {
		return nonce, nil, fmt.Errorf("engine/format: failed to marshal metadata: %w", err)
	}

	aead, err := crypto.NewAEAD(cipherID, key)
	if err != nil {
		return nonce, nil, err
	}

	nonceBytes, err := crypto.GenerateNonce()
	if err != nil {
		return nonce, nil, err
	}
	copy(nonce[:], nonceBytes)

	encrypted = aead.Seal(nil, nonceBytes, plaintext, []byte("datacrypt-metadata"))

	return nonce, encrypted, nil
}

// DecryptMetadata decrypts and parses file metadata.
func DecryptMetadata(encrypted []byte, nonce [12]byte, cipherID uint8, key []byte) (*FileMetadata, error) {
	aead, err := crypto.NewAEAD(cipherID, key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce[:], encrypted, []byte("datacrypt-metadata"))
	if err != nil {
		return nil, fmt.Errorf("engine/format: metadata decryption failed (wrong key or tampered): %w", err)
	}

	var meta FileMetadata
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return nil, fmt.Errorf("engine/format: failed to parse metadata: %w", err)
	}

	return &meta, nil
}
