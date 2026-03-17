// Package crypto provides cryptographic primitives for DataCrypt.
// This file implements asymmetric key operations: RSA-4096 and X25519 (Curve25519).
package crypto

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/hkdf"
)

// Key exchange mode identifiers
const (
	KeyExchangePassword uint8 = 0
	KeyExchangeRSA      uint8 = 1
	KeyExchangeECC      uint8 = 2
)

// KeyExchangeModeName returns the human-readable name for a key exchange mode.
func KeyExchangeModeName(mode uint8) string {
	switch mode {
	case KeyExchangePassword:
		return "Password (Argon2id)"
	case KeyExchangeRSA:
		return "RSA-4096"
	case KeyExchangeECC:
		return "X25519 (Curve25519)"
	default:
		return "Unknown"
	}
}

// ============================================================================
// RSA-4096
// ============================================================================

// GenerateRSAKeyPair generates a new RSA-4096 key pair.
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to generate RSA-4096 key: %w", err)
	}
	return privateKey, nil
}

// RSAEncryptKey encrypts a data key using RSA-OAEP with SHA-256.
// This is used to wrap a symmetric data key for the recipient.
func RSAEncryptKey(publicKey *rsa.PublicKey, dataKey []byte) ([]byte, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dataKey, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: RSA-OAEP encryption failed: %w", err)
	}
	return encryptedKey, nil
}

// RSADecryptKey decrypts a wrapped data key using RSA-OAEP with SHA-256.
func RSADecryptKey(privateKey *rsa.PrivateKey, encryptedKey []byte) ([]byte, error) {
	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: RSA-OAEP decryption failed: %w", err)
	}
	return dataKey, nil
}

// SaveRSAPrivateKey saves an RSA private key to a PEM file.
func SaveRSAPrivateKey(key *rsa.PrivateKey, path string) error {
	derBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("crypto/asym: failed to create private key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("crypto/asym: failed to write private key: %w", err)
	}

	return nil
}

// SaveRSAPublicKey saves an RSA public key to a PEM file.
func SaveRSAPublicKey(key *rsa.PublicKey, path string) error {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("crypto/asym: failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("crypto/asym: failed to create public key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("crypto/asym: failed to write public key: %w", err)
	}

	return nil
}

// LoadRSAPrivateKey loads an RSA private key from a PEM file.
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto/asym: failed to decode PEM block from %s", path)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to parse RSA private key: %w", err)
	}

	return key, nil
}

// LoadRSAPublicKey loads an RSA public key from a PEM file.
func LoadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto/asym: failed to decode PEM block from %s", path)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("crypto/asym: key is not an RSA public key")
	}

	return rsaPub, nil
}

// ============================================================================
// X25519 (Curve25519 ECDH)
// ============================================================================

// GenerateX25519KeyPair generates a new X25519 key pair for ECDH key exchange.
func GenerateX25519KeyPair() (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to generate X25519 key: %w", err)
	}
	return privateKey, nil
}

// X25519DeriveSharedKey performs X25519 ECDH and derives a 256-bit key using HKDF-SHA256.
// The ephemeralPublicKey is included in the HKDF info to bind the derived key to the exchange.
func X25519DeriveSharedKey(privateKey *ecdh.PrivateKey, peerPublicKey *ecdh.PublicKey) (*SecureBuffer, error) {
	// Perform ECDH
	sharedSecret, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: X25519 ECDH failed: %w", err)
	}
	defer ZeroBytes(sharedSecret)

	// Use HKDF-SHA256 to derive a proper encryption key from the shared secret
	info := []byte("datacrypt-x25519-key-v1")
	hkdfReader := hkdf.New(crypto.SHA256.New, sharedSecret, nil, info)

	keyBytes := make([]byte, KeySize)
	if _, err := hkdfReader.Read(keyBytes); err != nil {
		ZeroBytes(keyBytes)
		return nil, fmt.Errorf("crypto/asym: HKDF key derivation failed: %w", err)
	}

	return NewSecureBufferFrom(keyBytes), nil
}

// SaveX25519PrivateKey saves an X25519 private key to a PEM file.
func SaveX25519PrivateKey(key *ecdh.PrivateKey, path string) error {
	block := &pem.Block{
		Type:  "X25519 PRIVATE KEY",
		Bytes: key.Bytes(),
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("crypto/asym: failed to create private key file: %w", err)
	}
	defer file.Close()

	return pem.Encode(file, block)
}

// SaveX25519PublicKey saves an X25519 public key to a PEM file.
func SaveX25519PublicKey(key *ecdh.PublicKey, path string) error {
	block := &pem.Block{
		Type:  "X25519 PUBLIC KEY",
		Bytes: key.Bytes(),
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("crypto/asym: failed to create public key file: %w", err)
	}
	defer file.Close()

	return pem.Encode(file, block)
}

// LoadX25519PrivateKey loads an X25519 private key from a PEM file.
func LoadX25519PrivateKey(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto/asym: failed to decode PEM block from %s", path)
	}

	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to parse X25519 private key: %w", err)
	}

	return key, nil
}

// LoadX25519PublicKey loads an X25519 public key from a PEM file.
func LoadX25519PublicKey(path string) (*ecdh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("crypto/asym: failed to decode PEM block from %s", path)
	}

	curve := ecdh.X25519()
	key, err := curve.NewPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to parse X25519 public key: %w", err)
	}

	return key, nil
}

// ECCEncryptKey encrypts a data key using X25519 ECDH + HKDF.
// Returns: ephemeral public key || encrypted data key (using derived shared key with AES-256-GCM).
func ECCEncryptKey(recipientPubKey *ecdh.PublicKey, dataKey []byte) ([]byte, error) {
	// Generate ephemeral X25519 key pair
	ephemeralPriv, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: failed to generate ephemeral key: %w", err)
	}

	// Derive shared key via ECDH + HKDF
	sharedKey, err := X25519DeriveSharedKey(ephemeralPriv, recipientPubKey)
	if err != nil {
		return nil, err
	}
	defer sharedKey.Destroy()

	// Encrypt the data key with AES-256-GCM using the shared key
	aead, err := NewAEAD(CipherAES256GCM, sharedKey.Bytes())
	if err != nil {
		return nil, err
	}

	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	encryptedDataKey := aead.Seal(nil, nonce, dataKey, nil)

	// Format: [ephemeral pub key (32 bytes)] [nonce (12 bytes)] [encrypted data key + tag]
	ephPubBytes := ephemeralPriv.PublicKey().Bytes()
	result := make([]byte, 0, len(ephPubBytes)+len(nonce)+len(encryptedDataKey))
	result = append(result, ephPubBytes...)
	result = append(result, nonce...)
	result = append(result, encryptedDataKey...)

	return result, nil
}

// ECCDecryptKey decrypts a wrapped data key using X25519 ECDH + HKDF.
// Input format: ephemeral public key (32 bytes) || nonce (12 bytes) || encrypted data key + tag.
func ECCDecryptKey(privateKey *ecdh.PrivateKey, encryptedPayload []byte) ([]byte, error) {
	if len(encryptedPayload) < 32+NonceSize+TagSize {
		return nil, fmt.Errorf("crypto/asym: ECC encrypted payload too short")
	}

	// Extract components
	curve := ecdh.X25519()
	ephPubKey, err := curve.NewPublicKey(encryptedPayload[:32])
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: invalid ephemeral public key: %w", err)
	}

	nonce := encryptedPayload[32 : 32+NonceSize]
	ciphertext := encryptedPayload[32+NonceSize:]

	// Derive shared key
	sharedKey, err := X25519DeriveSharedKey(privateKey, ephPubKey)
	if err != nil {
		return nil, err
	}
	defer sharedKey.Destroy()

	// Decrypt the data key
	aead, err := NewAEAD(CipherAES256GCM, sharedKey.Bytes())
	if err != nil {
		return nil, err
	}

	dataKey, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto/asym: ECC key decryption failed: %w", err)
	}

	return dataKey, nil
}
