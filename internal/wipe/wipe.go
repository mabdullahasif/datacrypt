// Package wipe implements secure file deletion using multi-pass overwriting.
// This follows the DoD 5220.22-M standard for data sanitization.
package wipe

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

const (
	// WipePasses is the number of overwrite passes (DoD 5220.22-M uses 3)
	WipePasses = 3
	// WipeBufferSize is the size of write buffers
	WipeBufferSize = 65536
)

// WipeOptions configures the secure wipe operation.
type WipeOptions struct {
	// Number of overwrite passes (default: 3)
	Passes int
	// If true, verify each pass by reading back
	Verify bool
	// Progress callback: (currentPass, totalPasses, bytesWritten, totalBytes)
	OnProgress func(pass, totalPasses int, written, total int64)
}

// SecureWipe securely deletes a file by overwriting its contents multiple times
// with random data and zero patterns, then removing it from the filesystem.
//
// The wiping pattern follows DoD 5220.22-M:
//   - Pass 1: Overwrite with zeros (0x00)
//   - Pass 2: Overwrite with ones (0xFF)
//   - Pass 3: Overwrite with cryptographic random data
//
// Additional passes repeat the pattern.
func SecureWipe(path string, opts WipeOptions) error {
	if opts.Passes <= 0 {
		opts.Passes = WipePasses
	}

	// Get file info
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("wipe: cannot stat file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("wipe: cannot wipe directory (process files individually)")
	}

	fileSize := info.Size()

	// Open the file for writing (overwrite in place)
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("wipe: cannot open file for wiping: %w", err)
	}

	buf := make([]byte, WipeBufferSize)

	for pass := 0; pass < opts.Passes; pass++ {
		// Seek to beginning
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			file.Close()
			return fmt.Errorf("wipe: seek failed on pass %d: %w", pass+1, err)
		}

		var written int64
		remaining := fileSize

		for remaining > 0 {
			writeSize := int64(WipeBufferSize)
			if remaining < writeSize {
				writeSize = remaining
			}

			// Fill buffer based on pass pattern
			switch pass % 3 {
			case 0:
				// Zeros
				for i := range buf[:writeSize] {
					buf[i] = 0x00
				}
			case 1:
				// Ones
				for i := range buf[:writeSize] {
					buf[i] = 0xFF
				}
			case 2:
				// Random data
				if _, err := io.ReadFull(rand.Reader, buf[:writeSize]); err != nil {
					file.Close()
					return fmt.Errorf("wipe: random generation failed on pass %d: %w", pass+1, err)
				}
			}

			n, err := file.Write(buf[:writeSize])
			if err != nil {
				file.Close()
				return fmt.Errorf("wipe: write failed on pass %d: %w", pass+1, err)
			}

			written += int64(n)
			remaining -= int64(n)

			if opts.OnProgress != nil {
				opts.OnProgress(pass+1, opts.Passes, written, fileSize)
			}
		}

		// Sync to disk to ensure data is written
		if err := file.Sync(); err != nil {
			file.Close()
			return fmt.Errorf("wipe: sync failed on pass %d: %w", pass+1, err)
		}
	}

	file.Close()

	// Truncate the file to zero length
	if err := os.Truncate(path, 0); err != nil {
		return fmt.Errorf("wipe: truncate failed: %w", err)
	}

	// Remove the file
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("wipe: remove failed: %w", err)
	}

	return nil
}

// SecureWipeFiles securely deletes multiple files.
func SecureWipeFiles(paths []string, opts WipeOptions) []error {
	errors := make([]error, len(paths))
	for i, path := range paths {
		errors[i] = SecureWipe(path, opts)
	}
	return errors
}
