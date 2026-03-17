// Package cli implements the DataCrypt command-line interface.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Version information (set at build time)
	Version   = "1.0.0"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

// rootCmd is the base command for DataCrypt.
var rootCmd = &cobra.Command{
	Use:   "datacrypt",
	Short: "DataCrypt — Secure file encryption tool",
	Long: `DataCrypt is a cross-platform file encryption application that uses
modern cryptographic standards to securely encrypt and decrypt files.

Supported ciphers:
  • AES-256-GCM (default)
  • ChaCha20-Poly1305

Key derivation: Argon2id with configurable parameters
Key exchange: Password, RSA-4096, or X25519 (Curve25519)

All operations use authenticated encryption with integrity verification.`,
	Version: Version,
}

func init() {
	rootCmd.SetVersionTemplate(fmt.Sprintf(
		"DataCrypt v%s\nBuild: %s\nCommit: %s\n",
		Version, BuildDate, GitCommit,
	))
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// formatBytes formats byte counts into human-readable strings.
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
