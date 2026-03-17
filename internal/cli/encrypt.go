package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/datacrypt/datacrypt/internal/crypto"
	"github.com/datacrypt/datacrypt/internal/engine"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [files...]",
	Short: "Encrypt one or more files",
	Long: `Encrypt files using AES-256-GCM or ChaCha20-Poly1305.

By default, files are encrypted using a password with AES-256-GCM.
The encrypted output is saved with a .dcrypt extension.

Examples:
  datacrypt encrypt document.pdf
  datacrypt encrypt --cipher chacha20 photo.jpg
  datacrypt encrypt --kdf-preset high secret.txt
  datacrypt encrypt --rsa-key recipient.pub report.xlsx
  datacrypt encrypt --ecc-key recipient-ecc.pub data.csv
  datacrypt encrypt -o encrypted.bin document.pdf
  datacrypt encrypt *.txt  (batch mode)`,
	Args: cobra.MinimumNArgs(1),
	RunE: runEncrypt,
}

func init() {
	encryptCmd.Flags().StringP("cipher", "c", "aes", "Cipher to use: aes (AES-256-GCM) or chacha20 (ChaCha20-Poly1305)")
	encryptCmd.Flags().StringP("output", "o", "", "Output file path (only for single file encryption)")
	encryptCmd.Flags().String("kdf-preset", "standard", "KDF preset: standard, high, or paranoid")
	encryptCmd.Flags().Uint32("kdf-memory", 0, "Custom KDF memory in KB (overrides preset)")
	encryptCmd.Flags().Uint32("kdf-iterations", 0, "Custom KDF iterations (overrides preset)")
	encryptCmd.Flags().Uint8("kdf-parallelism", 0, "Custom KDF parallelism (overrides preset)")
	encryptCmd.Flags().Uint32("chunk-size", 0, "Chunk size in bytes (default: 65536)")
	encryptCmd.Flags().String("rsa-key", "", "RSA public key file for asymmetric encryption")
	encryptCmd.Flags().String("ecc-key", "", "X25519 public key file for asymmetric encryption")
	encryptCmd.Flags().StringP("password", "p", "", "Password (INSECURE: prefer interactive prompt)")
	encryptCmd.Flags().Bool("no-progress", false, "Disable progress indicator")

	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	// Determine cipher
	cipherName, _ := cmd.Flags().GetString("cipher")
	cipherID, err := crypto.CipherIDFromName(cipherName)
	if err != nil {
		return err
	}

	// Determine KDF parameters
	kdfPresetName, _ := cmd.Flags().GetString("kdf-preset")
	kdfPreset, err := crypto.KDFPresetFromName(kdfPresetName)
	if err != nil {
		return err
	}
	kdfParams, err := crypto.GetKDFPreset(kdfPreset)
	if err != nil {
		return err
	}

	// Allow custom KDF overrides
	if mem, _ := cmd.Flags().GetUint32("kdf-memory"); mem > 0 {
		kdfParams.Memory = mem
	}
	if iter, _ := cmd.Flags().GetUint32("kdf-iterations"); iter > 0 {
		kdfParams.Iterations = iter
	}
	if par, _ := cmd.Flags().GetUint8("kdf-parallelism"); par > 0 {
		kdfParams.Parallelism = par
	}

	// Determine key exchange mode
	rsaKeyPath, _ := cmd.Flags().GetString("rsa-key")
	eccKeyPath, _ := cmd.Flags().GetString("ecc-key")

	var keyMode uint8
	if rsaKeyPath != "" && eccKeyPath != "" {
		return fmt.Errorf("cannot specify both --rsa-key and --ecc-key")
	}

	switch {
	case rsaKeyPath != "":
		keyMode = crypto.KeyExchangeRSA
	case eccKeyPath != "":
		keyMode = crypto.KeyExchangeECC
	default:
		keyMode = crypto.KeyExchangePassword
	}

	// Obtain password (for password mode)
	var password []byte
	if keyMode == crypto.KeyExchangePassword {
		passwordFlag, _ := cmd.Flags().GetString("password")
		if passwordFlag != "" {
			fmt.Fprintln(os.Stderr, "⚠  Warning: passing password via command line is insecure. Use interactive prompt instead.")
			password = []byte(passwordFlag)
		} else {
			password, err = readPasswordWithConfirm()
			if err != nil {
				return err
			}
		}
		defer crypto.ZeroBytes(password)
	}

	// Other options
	chunkSize, _ := cmd.Flags().GetUint32("chunk-size")
	outputPath, _ := cmd.Flags().GetString("output")
	noProgress, _ := cmd.Flags().GetBool("no-progress")

	if len(args) > 1 && outputPath != "" {
		return fmt.Errorf("--output can only be used with a single input file")
	}

	// Print encryption info
	fmt.Fprintf(os.Stderr, "🔐 DataCrypt Encryption\n")
	fmt.Fprintf(os.Stderr, "   Cipher:       %s\n", crypto.CipherName(cipherID))
	fmt.Fprintf(os.Stderr, "   Key Mode:     %s\n", crypto.KeyExchangeModeName(keyMode))
	fmt.Fprintf(os.Stderr, "   KDF Preset:   %s (mem=%dKB, iter=%d, par=%d)\n",
		kdfPresetName, kdfParams.Memory, kdfParams.Iterations, kdfParams.Parallelism)
	fmt.Fprintln(os.Stderr)

	// Process files
	startTime := time.Now()
	successCount := 0

	for _, inputPath := range args {
		fmt.Fprintf(os.Stderr, "   ⏳ Encrypting: %s\n", inputPath)

		opts := engine.EncryptOptions{
			CipherID:         cipherID,
			Password:         password,
			KDFParams:        kdfParams,
			KeyExchangeMode:  keyMode,
			RSAPublicKeyPath: rsaKeyPath,
			ECCPublicKeyPath: eccKeyPath,
			ChunkSize:        chunkSize,
			OutputPath:       outputPath,
		}

		if !noProgress {
			opts.OnProgress = makeProgressFunc()
		}

		if err := engine.EncryptFile(inputPath, opts); err != nil {
			fmt.Fprintf(os.Stderr, "   ❌ Error: %v\n", err)
			continue
		}

		out := outputPath
		if out == "" {
			out = inputPath + ".dcrypt"
		}
		fmt.Fprintf(os.Stderr, "   ✅ Encrypted → %s\n", out)
		successCount++
	}

	elapsed := time.Since(startTime)
	fmt.Fprintf(os.Stderr, "\n   Done: %d/%d files encrypted in %v\n", successCount, len(args), elapsed.Round(time.Millisecond))

	if successCount < len(args) {
		return fmt.Errorf("%d file(s) failed to encrypt", len(args)-successCount)
	}

	return nil
}

// readPasswordWithConfirm reads a password from stdin with confirmation.
func readPasswordWithConfirm() ([]byte, error) {
	fmt.Fprint(os.Stderr, "🔑 Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}

	fmt.Fprint(os.Stderr, "🔑 Confirm password: ")
	confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		crypto.ZeroBytes(password)
		return nil, fmt.Errorf("failed to read password confirmation: %w", err)
	}

	if !crypto.ConstantTimeCompare(password, confirm) {
		crypto.ZeroBytes(password)
		crypto.ZeroBytes(confirm)
		return nil, fmt.Errorf("passwords do not match")
	}

	crypto.ZeroBytes(confirm)
	return password, nil
}

// readPassword reads a password from stdin without confirmation.
func readPassword() ([]byte, error) {
	fmt.Fprint(os.Stderr, "🔑 Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}

	return password, nil
}

// makeProgressFunc creates a progress reporting function.
func makeProgressFunc() func(processed, total int64) {
	var lastPercent int
	return func(processed, total int64) {
		if total <= 0 {
			fmt.Fprintf(os.Stderr, "\r   📊 Progress: %s processed", formatBytes(processed))
			return
		}
		percent := int(float64(processed) / float64(total) * 100)
		if percent != lastPercent {
			lastPercent = percent
			barLen := 30
			filled := barLen * percent / 100
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)
			fmt.Fprintf(os.Stderr, "\r   📊 [%s] %d%% (%s / %s)", bar, percent, formatBytes(processed), formatBytes(total))
			if percent == 100 {
				fmt.Fprintln(os.Stderr)
			}
		}
	}
}
