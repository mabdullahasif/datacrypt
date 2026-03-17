// Package crypto provides cryptographic primitives for DataCrypt.
// This file implements AEAD cipher construction (AES-256-GCM and ChaCha20-Poly1305).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher identifiers
const (
	CipherAES256GCM        uint8 = 0
	CipherChaCha20Poly1305 uint8 = 1
)

// Standard sizes
const (
	KeySize   = 32 // 256 bits
	NonceSize = 12 // 96 bits (standard for both AES-GCM and ChaCha20-Poly1305)
	TagSize   = 16 // 128 bits
	SaltSize  = 32 // 256 bits
)

// CipherName returns the human-readable name for a cipher ID.
func CipherName(id uint8) string {
	switch id {
	case CipherAES256GCM:
		return "AES-256-GCM"
	case CipherChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	default:
		return "Unknown"
	}
}

// CipherIDFromName returns the cipher ID from a string name.
func CipherIDFromName(name string) (uint8, error) {
	switch name {
	case "aes", "aes-256-gcm", "AES-256-GCM":
		return CipherAES256GCM, nil
	case "chacha", "chacha20", "chacha20-poly1305", "ChaCha20-Poly1305":
		return CipherChaCha20Poly1305, nil
	default:
		return 0, fmt.Errorf("unknown cipher: %s (supported: aes, chacha20)", name)
	}
}

// NewAEAD creates a new AEAD cipher instance for the given cipher ID and key.
// The key must be exactly 32 bytes (256 bits).
func NewAEAD(cipherID uint8, key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto/aead: key must be %d bytes, got %d", KeySize, len(key))
	}

	switch cipherID {
	case CipherAES256GCM:
		return newAESGCM(key)
	case CipherChaCha20Poly1305:
		return newChaCha20Poly1305(key)
	default:
		return nil, fmt.Errorf("crypto/aead: unsupported cipher ID: %d", cipherID)
	}
}

// newAESGCM creates a new AES-256-GCM AEAD instance.
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto/aead: failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto/aead: failed to create GCM: %w", err)
	}

	return aead, nil
}

// newChaCha20Poly1305 creates a new ChaCha20-Poly1305 AEAD instance.
func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("crypto/aead: failed to create ChaCha20-Poly1305: %w", err)
	}

	return aead, nil
}

// DeriveChunkNonce creates a unique nonce for a specific chunk by XOR-ing
// the base nonce with the chunk index. This guarantees nonce uniqueness
// across all chunks encrypted under the same key.
func DeriveChunkNonce(baseNonce []byte, chunkIndex uint64) []byte {
	if len(baseNonce) != NonceSize {
		panic("crypto/aead: base nonce must be 12 bytes")
	}

	nonce := make([]byte, NonceSize)
	copy(nonce, baseNonce)

	// XOR the last 8 bytes with the chunk counter
	counterBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(counterBytes, chunkIndex)

	for i := 0; i < 8; i++ {
		nonce[NonceSize-8+i] ^= counterBytes[i]
	}

	return nonce
}

// BuildAAD constructs the Additional Authenticated Data for a chunk.
// AAD includes the chunk index and a flag indicating if this is the final chunk.
// This binds the chunk to its position and prevents reordering/truncation attacks.
func BuildAAD(chunkIndex uint64, isFinal bool) []byte {
	aad := make([]byte, 9)
	binary.LittleEndian.PutUint64(aad[:8], chunkIndex)
	if isFinal {
		aad[8] = 1
	}
	return aad
}

// SealChunk encrypts a plaintext chunk using the AEAD cipher.
// Returns: nonce || ciphertext (which includes the 16-byte auth tag).
func SealChunk(aead cipher.AEAD, baseNonce []byte, chunkIndex uint64, plaintext []byte, isFinal bool) ([]byte, error) {
	nonce := DeriveChunkNonce(baseNonce, chunkIndex)
	aad := BuildAAD(chunkIndex, isFinal)

	// Seal appends the ciphertext (with tag) to the nonce prefix
	result := make([]byte, NonceSize, NonceSize+len(plaintext)+TagSize)
	copy(result, nonce)

	result = aead.Seal(result, nonce, plaintext, aad)

	// Zero the intermediate nonce
	ZeroBytes(nonce)

	return result, nil
}

// OpenChunk decrypts an encrypted chunk using the AEAD cipher.
// The input format is: nonce || ciphertext (with tag).
// Returns the decrypted plaintext.
func OpenChunk(aead cipher.AEAD, baseNonce []byte, chunkIndex uint64, encryptedChunk []byte, isFinal bool) ([]byte, error) {
	if len(encryptedChunk) < NonceSize+TagSize {
		return nil, fmt.Errorf("crypto/aead: encrypted chunk too short (%d bytes)", len(encryptedChunk))
	}

	// Extract nonce from the chunk
	chunkNonce := encryptedChunk[:NonceSize]
	ciphertext := encryptedChunk[NonceSize:]

	// Verify the nonce matches what we expect
	expectedNonce := DeriveChunkNonce(baseNonce, chunkIndex)
	if !ConstantTimeCompare(chunkNonce, expectedNonce) {
		ZeroBytes(expectedNonce)
		return nil, fmt.Errorf("crypto/aead: chunk %d nonce mismatch (possible tampering)", chunkIndex)
	}
	ZeroBytes(expectedNonce)

	aad := BuildAAD(chunkIndex, isFinal)

	plaintext, err := aead.Open(nil, chunkNonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto/aead: chunk %d decryption failed (tampering or wrong key): %w", chunkIndex, err)
	}

	return plaintext, nil
}
