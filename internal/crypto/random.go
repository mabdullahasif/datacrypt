// Package crypto provides cryptographic primitives for DataCrypt.
// This file implements cryptographically secure random number generation.
package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
)

// SecureRandom reads exactly n bytes from the system CSPRNG (crypto/rand).
// It returns an error if the system entropy pool cannot supply the requested bytes.
func SecureRandom(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("crypto/random: requested byte count must be positive, got %d", n)
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("crypto/random: failed to read %d bytes from CSPRNG: %w", n, err)
	}

	return buf, nil
}

// GenerateSalt generates a 32-byte cryptographic salt.
func GenerateSalt() ([]byte, error) {
	return SecureRandom(SaltSize)
}

// GenerateNonce generates a 12-byte nonce for AEAD ciphers.
func GenerateNonce() ([]byte, error) {
	return SecureRandom(NonceSize)
}

// GenerateKey generates a 32-byte (256-bit) random key.
func GenerateKey() ([]byte, error) {
	return SecureRandom(KeySize)
}
