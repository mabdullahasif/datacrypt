// Package crypto provides cryptographic primitives for DataCrypt.
// This file implements Argon2id key derivation with configurable parameters.
package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// KDFPreset defines a named set of Argon2id parameters.
type KDFPreset string

const (
	KDFStandard KDFPreset = "standard"
	KDFHigh     KDFPreset = "high"
	KDFParanoid KDFPreset = "paranoid"
)

// KDFParams holds Argon2id configuration.
type KDFParams struct {
	Memory      uint32 // Memory in KB
	Iterations  uint32 // Number of iterations (time cost)
	Parallelism uint8  // Degree of parallelism
}

// Preset parameter sets following OWASP recommendations.
var kdfPresets = map[KDFPreset]KDFParams{
	KDFStandard: {Memory: 65536, Iterations: 3, Parallelism: 4},     // 64 MB
	KDFHigh:     {Memory: 262144, Iterations: 4, Parallelism: 8},    // 256 MB
	KDFParanoid: {Memory: 1048576, Iterations: 6, Parallelism: 8},   // 1 GB
}

// GetKDFPreset returns the KDFParams for a named preset.
func GetKDFPreset(preset KDFPreset) (KDFParams, error) {
	params, ok := kdfPresets[preset]
	if !ok {
		return KDFParams{}, fmt.Errorf("crypto/kdf: unknown preset %q (use: standard, high, paranoid)", preset)
	}
	return params, nil
}

// ValidateKDFParams validates custom KDF parameters.
func ValidateKDFParams(params KDFParams) error {
	if params.Memory < 8192 {
		return fmt.Errorf("crypto/kdf: memory must be >= 8192 KB (8 MB), got %d KB", params.Memory)
	}
	if params.Iterations < 1 {
		return fmt.Errorf("crypto/kdf: iterations must be >= 1, got %d", params.Iterations)
	}
	if params.Parallelism < 1 {
		return fmt.Errorf("crypto/kdf: parallelism must be >= 1, got %d", params.Parallelism)
	}
	return nil
}

// DeriveKey derives a 256-bit encryption key from a password using Argon2id.
//
// Argon2id is the recommended variant that provides resistance against both
// side-channel attacks (from Argon2i) and GPU/ASIC attacks (from Argon2d).
//
// The salt MUST be unique per encryption operation and at least 16 bytes (we use 32).
// The returned key is exactly 32 bytes (256 bits), suitable for AES-256-GCM
// or ChaCha20-Poly1305.
func DeriveKey(password []byte, salt []byte, params KDFParams) (*SecureBuffer, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("crypto/kdf: password must not be empty")
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("crypto/kdf: salt must be at least 16 bytes, got %d", len(salt))
	}
	if err := ValidateKDFParams(params); err != nil {
		return nil, err
	}

	// Argon2id: memory-hard, resistant to both side-channel and GPU attacks
	keyBytes := argon2.IDKey(
		password,
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		KeySize,
	)

	// Wrap in a SecureBuffer for automatic zeroing
	key := NewSecureBufferFrom(keyBytes)

	return key, nil
}

// KDFPresetFromName converts a string name to a KDFPreset.
func KDFPresetFromName(name string) (KDFPreset, error) {
	switch name {
	case "standard", "std":
		return KDFStandard, nil
	case "high":
		return KDFHigh, nil
	case "paranoid", "max":
		return KDFParanoid, nil
	default:
		return "", fmt.Errorf("crypto/kdf: unknown preset %q (use: standard, high, paranoid)", name)
	}
}
