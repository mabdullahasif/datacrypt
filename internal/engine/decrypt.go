// Package engine implements the DataCrypt streaming decryption engine.
package engine

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/datacrypt/datacrypt/internal/crypto"
)

// DecryptOptions configures a file decryption operation.
type DecryptOptions struct {
	// Password (for password mode)
	Password []byte

	// Asymmetric keys (for RSA/ECC modes)
	RSAPrivateKeyPath string
	ECCPrivateKeyPath string

	// Output
	OutputPath string

	// If true, restore the original filename from metadata
	RestoreFilename bool

	// Progress callback: (bytesProcessed, totalBytes)
	// totalBytes may be -1 if original size is unknown
	OnProgress func(processed, total int64)
}

// DecryptFile decrypts a DataCrypt encrypted file.
func DecryptFile(inputPath string, opts DecryptOptions) error {
	// Open input file
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("engine/decrypt: cannot open input: %w", err)
	}
	defer inFile.Close()

	// Read header
	header, err := ReadHeader(inFile)
	if err != nil {
		return fmt.Errorf("engine/decrypt: %w", err)
	}

	// Obtain the encryption key based on key exchange mode
	var dataKey *crypto.SecureBuffer

	switch header.KeyExchangeMode {
	case crypto.KeyExchangePassword:
		if len(opts.Password) == 0 {
			return fmt.Errorf("engine/decrypt: password is required")
		}

		kdfParams := crypto.KDFParams{
			Memory:      header.KDFMemory,
			Iterations:  header.KDFIterations,
			Parallelism: header.KDFParallelism,
		}

		dataKey, err = crypto.DeriveKey(opts.Password, header.Salt[:], kdfParams)
		if err != nil {
			return fmt.Errorf("engine/decrypt: key derivation failed: %w", err)
		}

	case crypto.KeyExchangeRSA:
		if opts.RSAPrivateKeyPath == "" {
			return fmt.Errorf("engine/decrypt: RSA private key path is required")
		}

		rsaPriv, err := crypto.LoadRSAPrivateKey(opts.RSAPrivateKeyPath)
		if err != nil {
			return fmt.Errorf("engine/decrypt: %w", err)
		}

		keyBytes, err := crypto.RSADecryptKey(rsaPriv, header.EncryptedKey)
		if err != nil {
			return fmt.Errorf("engine/decrypt: %w", err)
		}
		dataKey = crypto.NewSecureBufferFrom(keyBytes)

	case crypto.KeyExchangeECC:
		if opts.ECCPrivateKeyPath == "" {
			return fmt.Errorf("engine/decrypt: ECC private key path is required")
		}

		eccPriv, err := crypto.LoadX25519PrivateKey(opts.ECCPrivateKeyPath)
		if err != nil {
			return fmt.Errorf("engine/decrypt: %w", err)
		}

		keyBytes, err := crypto.ECCDecryptKey(eccPriv, header.EncryptedKey)
		if err != nil {
			return fmt.Errorf("engine/decrypt: %w", err)
		}
		dataKey = crypto.NewSecureBufferFrom(keyBytes)

	default:
		return fmt.Errorf("engine/decrypt: unsupported key exchange mode %d", header.KeyExchangeMode)
	}

	defer dataKey.Destroy()

	// Create AEAD cipher
	aead, err := crypto.NewAEAD(header.CipherID, dataKey.Bytes())
	if err != nil {
		return fmt.Errorf("engine/decrypt: %w", err)
	}

	// Decrypt metadata
	var meta *FileMetadata
	if header.MetadataLen > 0 {
		meta, err = DecryptMetadata(header.EncryptedMeta, header.MetadataNonce, header.CipherID, dataKey.Bytes())
		if err != nil {
			return fmt.Errorf("engine/decrypt: %w", err)
		}
	}

	// Determine output path
	outputPath := opts.OutputPath
	if outputPath == "" {
		if opts.RestoreFilename && meta != nil && meta.OriginalName != "" {
			outputPath = filepath.Join(filepath.Dir(inputPath), meta.OriginalName)
		} else {
			// Strip .dcrypt extension
			outputPath = strings.TrimSuffix(inputPath, ".dcrypt")
			if outputPath == inputPath {
				outputPath = inputPath + ".decrypted"
			}
		}
	}

	// Avoid overwriting the input file
	absInput, _ := filepath.Abs(inputPath)
	absOutput, _ := filepath.Abs(outputPath)
	if absInput == absOutput {
		return fmt.Errorf("engine/decrypt: output path cannot be the same as input path")
	}

	// Read base nonce
	baseNonce := make([]byte, crypto.NonceSize)
	if _, err := io.ReadFull(inFile, baseNonce); err != nil {
		return fmt.Errorf("engine/decrypt: failed to read base nonce: %w", err)
	}

	// Create output file
	outFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("engine/decrypt: failed to create output: %w", err)
	}
	defer func() {
		outFile.Close()
		if err != nil {
			os.Remove(outputPath)
		}
	}()

	// Stream-decrypt chunks
	var chunkIndex uint64
	var totalProcessed int64
	var originalSize int64 = -1
	if meta != nil {
		originalSize = meta.OriginalSize
	}

	for {
		// Read chunk length
		var chunkLen uint32
		if readErr := binary.Read(inFile, binary.LittleEndian, &chunkLen); readErr != nil {
			if readErr == io.EOF {
				break // No more chunks
			}
			return fmt.Errorf("engine/decrypt: failed to read chunk %d length: %w", chunkIndex, readErr)
		}

		if chunkLen == 0 {
			break
		}

		// Validate chunk size (nonce + at least tag)
		maxChunkLen := header.ChunkSize + uint32(crypto.NonceSize) + uint32(crypto.TagSize)
		if chunkLen > maxChunkLen {
			return fmt.Errorf("engine/decrypt: chunk %d size %d exceeds maximum %d (possible corruption)", chunkIndex, chunkLen, maxChunkLen)
		}

		// Read encrypted chunk
		encryptedChunk := make([]byte, chunkLen)
		if _, readErr := io.ReadFull(inFile, encryptedChunk); readErr != nil {
			return fmt.Errorf("engine/decrypt: failed to read chunk %d: %w", chunkIndex, readErr)
		}

		// Determine if this might be the last chunk by peeking ahead
		var nextChunkLen uint32
		peekErr := binary.Read(inFile, binary.LittleEndian, &nextChunkLen)
		isLast := peekErr == io.EOF || nextChunkLen == 0

		// If we read a next chunk length, seek back
		if peekErr == nil && nextChunkLen > 0 {
			// We need to "unread" the 4 bytes. Since we read from a file, seek back.
			if _, seekErr := inFile.Seek(-4, io.SeekCurrent); seekErr != nil {
				return fmt.Errorf("engine/decrypt: seek error: %w", seekErr)
			}
		}

		// Decrypt chunk
		plaintext, decErr := crypto.OpenChunk(aead, baseNonce, chunkIndex, encryptedChunk, isLast)
		if decErr != nil {
			return fmt.Errorf("engine/decrypt: %w", decErr)
		}

		// Write plaintext
		if _, writeErr := outFile.Write(plaintext); writeErr != nil {
			crypto.ZeroBytes(plaintext)
			return fmt.Errorf("engine/decrypt: failed to write chunk %d: %w", chunkIndex, writeErr)
		}

		totalProcessed += int64(len(plaintext))
		crypto.ZeroBytes(plaintext)
		chunkIndex++

		// Report progress
		if opts.OnProgress != nil {
			opts.OnProgress(totalProcessed, originalSize)
		}

		if isLast {
			break
		}
	}

	// Verify total size matches metadata
	if meta != nil && totalProcessed != meta.OriginalSize {
		return fmt.Errorf("engine/decrypt: size mismatch: decrypted %d bytes, expected %d (file truncated or corrupted)",
			totalProcessed, meta.OriginalSize)
	}

	// Clean up
	crypto.ZeroBytes(baseNonce)

	return nil
}

// DecryptFiles decrypts multiple files (batch mode).
func DecryptFiles(inputPaths []string, opts DecryptOptions) []error {
	errors := make([]error, len(inputPaths))
	for i, path := range inputPaths {
		fileOpts := opts
		fileOpts.OutputPath = "" // Let each file determine its own output
		errors[i] = DecryptFile(path, fileOpts)
	}
	return errors
}

// InspectFile reads and returns the header and metadata of an encrypted file
// without decrypting the contents. This is useful for displaying file info.
func InspectFile(inputPath string) (*FileHeader, error) {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("engine/inspect: cannot open file: %w", err)
	}
	defer inFile.Close()

	header, err := ReadHeader(inFile)
	if err != nil {
		return nil, fmt.Errorf("engine/inspect: %w", err)
	}

	return header, nil
}
