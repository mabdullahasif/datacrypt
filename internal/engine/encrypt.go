// Package engine implements the DataCrypt streaming encryption engine.
// It processes files in configurable chunks to support large files without
// loading them entirely into memory.
package engine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/datacrypt/datacrypt/internal/crypto"
)

// EncryptOptions configures a file encryption operation.
type EncryptOptions struct {
	// Cipher selection
	CipherID uint8

	// Key derivation
	Password  []byte
	KDFParams crypto.KDFParams

	// Asymmetric encryption (optional)
	KeyExchangeMode   uint8
	RSAPublicKeyPath  string
	ECCPublicKeyPath  string

	// Streaming
	ChunkSize uint32

	// Output
	OutputPath string

	// Progress callback: (bytesProcessed, totalBytes)
	OnProgress func(processed, total int64)
}

// EncryptFile encrypts a file using the specified options.
// The output is written to OutputPath (or inputPath + ".dcrypt" if empty).
func EncryptFile(inputPath string, opts EncryptOptions) error {
	// Validate input
	inputInfo, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("engine/encrypt: cannot access input file: %w", err)
	}
	if inputInfo.IsDir() {
		return fmt.Errorf("engine/encrypt: input is a directory, not a file")
	}

	// Default chunk size
	if opts.ChunkSize == 0 {
		opts.ChunkSize = DefaultChunkSize
	}
	if opts.ChunkSize < MinChunkSize || opts.ChunkSize > MaxChunkSize {
		return fmt.Errorf("engine/encrypt: chunk size must be %d–%d bytes", MinChunkSize, MaxChunkSize)
	}

	// Determine output path
	outputPath := opts.OutputPath
	if outputPath == "" {
		outputPath = inputPath + ".dcrypt"
	}

	// Generate salt
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("engine/encrypt: %w", err)
	}

	// Derive or obtain the encryption key
	var dataKey *crypto.SecureBuffer
	var encryptedKeyBytes []byte

	switch opts.KeyExchangeMode {
	case crypto.KeyExchangePassword:
		// Derive key from password using Argon2id
		if len(opts.Password) == 0 {
			return fmt.Errorf("engine/encrypt: password is required for password mode")
		}
		dataKey, err = crypto.DeriveKey(opts.Password, salt, opts.KDFParams)
		if err != nil {
			return fmt.Errorf("engine/encrypt: key derivation failed: %w", err)
		}

	case crypto.KeyExchangeRSA:
		// Generate random data key, wrap with RSA
		randomKey, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("engine/encrypt: %w", err)
		}
		dataKey = crypto.NewSecureBufferFrom(randomKey)

		rsaPub, err := crypto.LoadRSAPublicKey(opts.RSAPublicKeyPath)
		if err != nil {
			dataKey.Destroy()
			return fmt.Errorf("engine/encrypt: %w", err)
		}
		encryptedKeyBytes, err = crypto.RSAEncryptKey(rsaPub, dataKey.Bytes())
		if err != nil {
			dataKey.Destroy()
			return fmt.Errorf("engine/encrypt: %w", err)
		}

	case crypto.KeyExchangeECC:
		// Generate random data key, wrap with ECC
		randomKey, err := crypto.GenerateKey()
		if err != nil {
			return fmt.Errorf("engine/encrypt: %w", err)
		}
		dataKey = crypto.NewSecureBufferFrom(randomKey)

		eccPub, err := crypto.LoadX25519PublicKey(opts.ECCPublicKeyPath)
		if err != nil {
			dataKey.Destroy()
			return fmt.Errorf("engine/encrypt: %w", err)
		}
		encryptedKeyBytes, err = crypto.ECCEncryptKey(eccPub, dataKey.Bytes())
		if err != nil {
			dataKey.Destroy()
			return fmt.Errorf("engine/encrypt: %w", err)
		}

	default:
		return fmt.Errorf("engine/encrypt: unsupported key exchange mode %d", opts.KeyExchangeMode)
	}

	defer dataKey.Destroy()

	// Create AEAD cipher
	aead, err := crypto.NewAEAD(opts.CipherID, dataKey.Bytes())
	if err != nil {
		return fmt.Errorf("engine/encrypt: %w", err)
	}

	// Prepare metadata
	meta := &FileMetadata{
		OriginalName: filepath.Base(inputPath),
		OriginalSize: inputInfo.Size(),
		CreatedAt:    time.Now().UTC(),
		Cipher:       crypto.CipherName(opts.CipherID),
		ChunkSize:    opts.ChunkSize,
	}

	metaNonce, encryptedMeta, err := EncryptMetadata(meta, opts.CipherID, dataKey.Bytes())
	if err != nil {
		return fmt.Errorf("engine/encrypt: %w", err)
	}

	// Build file header
	header := &FileHeader{
		Magic:           MagicBytes,
		Version:         FormatVersion,
		CipherID:        opts.CipherID,
		KeyExchangeMode: opts.KeyExchangeMode,
		KDFMemory:       opts.KDFParams.Memory,
		KDFIterations:   opts.KDFParams.Iterations,
		KDFParallelism:  opts.KDFParams.Parallelism,
		ChunkSize:       opts.ChunkSize,
		EncryptedKeyLen: uint16(len(encryptedKeyBytes)),
		EncryptedKey:    encryptedKeyBytes,
		MetadataNonce:   metaNonce,
		MetadataLen:     uint32(len(encryptedMeta)),
		EncryptedMeta:   encryptedMeta,
	}
	copy(header.Salt[:], salt)

	// Generate base nonce for chunk encryption
	baseNonce, err := crypto.GenerateNonce()
	if err != nil {
		return fmt.Errorf("engine/encrypt: %w", err)
	}

	// Open input file
	inFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("engine/encrypt: failed to open input: %w", err)
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("engine/encrypt: failed to create output: %w", err)
	}
	defer func() {
		outFile.Close()
		// If we had an error, clean up partial output
		if err != nil {
			os.Remove(outputPath)
		}
	}()

	// Write header
	if err = WriteHeader(outFile, header); err != nil {
		return fmt.Errorf("engine/encrypt: %w", err)
	}

	// Write base nonce
	if _, err = outFile.Write(baseNonce); err != nil {
		return fmt.Errorf("engine/encrypt: failed to write base nonce: %w", err)
	}

	// Stream-encrypt chunks
	buf := make([]byte, opts.ChunkSize)
	var chunkIndex uint64
	var totalProcessed int64

	for {
		n, readErr := io.ReadFull(inFile, buf)

		if n > 0 {
			isLast := readErr == io.EOF || readErr == io.ErrUnexpectedEOF
			
			// Detect if this is truly the last chunk
			if !isLast && readErr == nil {
				// Try to peek ahead to see if there's more data
				// If we read a full chunk, there might be more
			}

			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				isLast = true
			}

			encryptedChunk, sealErr := crypto.SealChunk(aead, baseNonce, chunkIndex, buf[:n], isLast)
			if sealErr != nil {
				return fmt.Errorf("engine/encrypt: chunk %d: %w", chunkIndex, sealErr)
			}

			// Write chunk length (4 bytes) + encrypted chunk
			chunkLen := uint32(len(encryptedChunk))
			lenBuf := make([]byte, 4)
			lenBuf[0] = byte(chunkLen)
			lenBuf[1] = byte(chunkLen >> 8)
			lenBuf[2] = byte(chunkLen >> 16)
			lenBuf[3] = byte(chunkLen >> 24)

			if _, err = outFile.Write(lenBuf); err != nil {
				return fmt.Errorf("engine/encrypt: failed to write chunk length: %w", err)
			}
			if _, err = outFile.Write(encryptedChunk); err != nil {
				return fmt.Errorf("engine/encrypt: failed to write chunk %d: %w", chunkIndex, err)
			}

			// Zero sensitive plaintext
			crypto.ZeroBytes(buf[:n])

			totalProcessed += int64(n)
			chunkIndex++

			// Report progress
			if opts.OnProgress != nil {
				opts.OnProgress(totalProcessed, inputInfo.Size())
			}

			if isLast {
				break
			}
		}

		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return fmt.Errorf("engine/encrypt: read error at chunk %d: %w", chunkIndex, readErr)
		}

		if readErr == io.EOF && n == 0 {
			// Empty read at EOF — write a final empty chunk for integrity
			encryptedChunk, sealErr := crypto.SealChunk(aead, baseNonce, chunkIndex, []byte{}, true)
			if sealErr != nil {
				return fmt.Errorf("engine/encrypt: final chunk: %w", sealErr)
			}

			chunkLen := uint32(len(encryptedChunk))
			lenBuf := make([]byte, 4)
			lenBuf[0] = byte(chunkLen)
			lenBuf[1] = byte(chunkLen >> 8)
			lenBuf[2] = byte(chunkLen >> 16)
			lenBuf[3] = byte(chunkLen >> 24)

			if _, err = outFile.Write(lenBuf); err != nil {
				return fmt.Errorf("engine/encrypt: failed to write final chunk length: %w", err)
			}
			if _, err = outFile.Write(encryptedChunk); err != nil {
				return fmt.Errorf("engine/encrypt: failed to write final chunk: %w", err)
			}
			break
		}
	}

	// Clean up sensitive data
	crypto.ZeroBytes(baseNonce)
	crypto.ZeroBytes(salt)

	return nil
}

// EncryptFiles encrypts multiple files (batch mode).
func EncryptFiles(inputPaths []string, opts EncryptOptions) []error {
	errors := make([]error, len(inputPaths))
	for i, path := range inputPaths {
		fileOpts := opts
		fileOpts.OutputPath = "" // Let each file get its own .dcrypt extension
		errors[i] = EncryptFile(path, fileOpts)
	}
	return errors
}
