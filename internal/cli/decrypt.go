package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/datacrypt/datacrypt/internal/crypto"
	"github.com/datacrypt/datacrypt/internal/engine"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt [files...]",
	Short: "Decrypt one or more encrypted files",
	Long: `Decrypt files that were encrypted with DataCrypt.

The cipher and KDF parameters are automatically read from the file header.
You only need to provide the password or private key.

Examples:
  datacrypt decrypt document.pdf.dcrypt
  datacrypt decrypt --rsa-key private.pem report.xlsx.dcrypt
  datacrypt decrypt --ecc-key private-ecc.pem data.csv.dcrypt
  datacrypt decrypt --restore-name document.pdf.dcrypt
  datacrypt decrypt -o original.pdf document.pdf.dcrypt
  datacrypt decrypt *.dcrypt  (batch mode)`,
	Args: cobra.MinimumNArgs(1),
	RunE: runDecrypt,
}

func init() {
	decryptCmd.Flags().StringP("output", "o", "", "Output file path (only for single file)")
	decryptCmd.Flags().String("rsa-key", "", "RSA private key file for decryption")
	decryptCmd.Flags().String("ecc-key", "", "X25519 private key file for decryption")
	decryptCmd.Flags().StringP("password", "p", "", "Password (INSECURE: prefer interactive prompt)")
	decryptCmd.Flags().Bool("restore-name", false, "Restore original filename from metadata")
	decryptCmd.Flags().Bool("no-progress", false, "Disable progress indicator")

	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	rsaKeyPath, _ := cmd.Flags().GetString("rsa-key")
	eccKeyPath, _ := cmd.Flags().GetString("ecc-key")
	outputPath, _ := cmd.Flags().GetString("output")
	restoreName, _ := cmd.Flags().GetBool("restore-name")
	noProgress, _ := cmd.Flags().GetBool("no-progress")
	passwordFlag, _ := cmd.Flags().GetString("password")

	if len(args) > 1 && outputPath != "" {
		return fmt.Errorf("--output can only be used with a single input file")
	}

	fmt.Fprintf(os.Stderr, "🔓 DataCrypt Decryption\n\n")

	startTime := time.Now()
	successCount := 0

	for _, inputPath := range args {
		fmt.Fprintf(os.Stderr, "   ⏳ Decrypting: %s\n", inputPath)

		// Inspect the file to determine key exchange mode
		header, err := engine.InspectFile(inputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "   ❌ Error: %v\n", err)
			continue
		}

		fmt.Fprintf(os.Stderr, "   Cipher:       %s\n", crypto.CipherName(header.CipherID))
		fmt.Fprintf(os.Stderr, "   Key Mode:     %s\n", crypto.KeyExchangeModeName(header.KeyExchangeMode))

		// Obtain password/key based on header
		var password []byte
		opts := engine.DecryptOptions{
			OutputPath:        outputPath,
			RestoreFilename:   restoreName,
			RSAPrivateKeyPath: rsaKeyPath,
			ECCPrivateKeyPath: eccKeyPath,
		}

		switch header.KeyExchangeMode {
		case crypto.KeyExchangePassword:
			if passwordFlag != "" {
				password = []byte(passwordFlag)
			} else {
				password, err = readPassword()
				if err != nil {
					fmt.Fprintf(os.Stderr, "   ❌ Error: %v\n", err)
					continue
				}
			}
			opts.Password = password
			defer crypto.ZeroBytes(password)

		case crypto.KeyExchangeRSA:
			if rsaKeyPath == "" {
				fmt.Fprintf(os.Stderr, "   ❌ Error: this file requires an RSA private key (--rsa-key)\n")
				continue
			}

		case crypto.KeyExchangeECC:
			if eccKeyPath == "" {
				fmt.Fprintf(os.Stderr, "   ❌ Error: this file requires an X25519 private key (--ecc-key)\n")
				continue
			}
		}

		if !noProgress {
			opts.OnProgress = makeProgressFunc()
		}

		if err := engine.DecryptFile(inputPath, opts); err != nil {
			fmt.Fprintf(os.Stderr, "   ❌ Error: %v\n", err)
			continue
		}

		fmt.Fprintf(os.Stderr, "   ✅ Decrypted successfully\n")
		successCount++
	}

	elapsed := time.Since(startTime)
	fmt.Fprintf(os.Stderr, "\n   Done: %d/%d files decrypted in %v\n", successCount, len(args), elapsed.Round(time.Millisecond))

	if successCount < len(args) {
		return fmt.Errorf("%d file(s) failed to decrypt", len(args)-successCount)
	}

	return nil
}
