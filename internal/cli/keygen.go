package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/datacrypt/datacrypt/internal/crypto"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate cryptographic key pairs",
	Long: `Generate RSA-4096 or X25519 (Curve25519) key pairs for asymmetric encryption.

The private key is saved with restrictive permissions (owner read-only).
The public key can be shared with anyone who needs to encrypt files for you.

Examples:
  datacrypt keygen --type rsa
  datacrypt keygen --type rsa --output-dir ./keys
  datacrypt keygen --type ecc
  datacrypt keygen --type ecc --name mykey`,
	RunE: runKeygen,
}

func init() {
	keygenCmd.Flags().StringP("type", "t", "rsa", "Key type: rsa (RSA-4096) or ecc (X25519)")
	keygenCmd.Flags().String("output-dir", ".", "Directory to save key files")
	keygenCmd.Flags().StringP("name", "n", "", "Base name for key files (default: datacrypt-{type})")

	rootCmd.AddCommand(keygenCmd)
}

func runKeygen(cmd *cobra.Command, args []string) error {
	keyType, _ := cmd.Flags().GetString("type")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	name, _ := cmd.Flags().GetString("name")

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	switch keyType {
	case "rsa":
		return generateRSAKeys(outputDir, name)
	case "ecc", "x25519", "curve25519":
		return generateECCKeys(outputDir, name)
	default:
		return fmt.Errorf("unsupported key type %q (use: rsa, ecc)", keyType)
	}
}

func generateRSAKeys(outputDir, name string) error {
	if name == "" {
		name = "datacrypt-rsa"
	}

	privPath := filepath.Join(outputDir, name+".key")
	pubPath := filepath.Join(outputDir, name+".pub")

	// Check if files already exist
	for _, path := range []string{privPath, pubPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("key file already exists: %s (remove it first or use a different name)", path)
		}
	}

	fmt.Fprintf(os.Stderr, "🔑 Generating RSA-4096 key pair...\n")
	fmt.Fprintf(os.Stderr, "   This may take a moment...\n")

	startTime := time.Now()

	privateKey, err := crypto.GenerateRSAKeyPair()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	elapsed := time.Since(startTime)

	if err := crypto.SaveRSAPrivateKey(privateKey, privPath); err != nil {
		return err
	}

	if err := crypto.SaveRSAPublicKey(&privateKey.PublicKey, pubPath); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\n   ✅ RSA-4096 key pair generated in %v\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "   🔒 Private key: %s (keep this secret!)\n", privPath)
	fmt.Fprintf(os.Stderr, "   🔓 Public key:  %s (share with others)\n", pubPath)

	return nil
}

func generateECCKeys(outputDir, name string) error {
	if name == "" {
		name = "datacrypt-ecc"
	}

	privPath := filepath.Join(outputDir, name+".key")
	pubPath := filepath.Join(outputDir, name+".pub")

	// Check if files already exist
	for _, path := range []string{privPath, pubPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("key file already exists: %s (remove it first or use a different name)", path)
		}
	}

	fmt.Fprintf(os.Stderr, "🔑 Generating X25519 (Curve25519) key pair...\n")

	startTime := time.Now()

	privateKey, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}

	elapsed := time.Since(startTime)

	if err := crypto.SaveX25519PrivateKey(privateKey, privPath); err != nil {
		return err
	}

	if err := crypto.SaveX25519PublicKey(privateKey.PublicKey(), pubPath); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\n   ✅ X25519 key pair generated in %v\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "   🔒 Private key: %s (keep this secret!)\n", privPath)
	fmt.Fprintf(os.Stderr, "   🔓 Public key:  %s (share with others)\n", pubPath)

	return nil
}
