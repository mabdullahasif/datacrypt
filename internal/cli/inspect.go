package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/datacrypt/datacrypt/internal/crypto"
	"github.com/datacrypt/datacrypt/internal/engine"
)

var inspectCmd = &cobra.Command{
	Use:   "inspect [file]",
	Short: "Display information about an encrypted file",
	Long: `Inspect an encrypted .dcrypt file and display its header information,
including the cipher used, KDF parameters, and key exchange mode.

This does NOT require a password or key.

Examples:
  datacrypt inspect document.pdf.dcrypt`,
	Args: cobra.ExactArgs(1),
	RunE: runInspect,
}

func init() {
	rootCmd.AddCommand(inspectCmd)
}

func runInspect(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	header, err := engine.InspectFile(inputPath)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "📋 File Information: %s\n\n", inputPath)
	fmt.Fprintf(os.Stderr, "   Format Version:    %d\n", header.Version)
	fmt.Fprintf(os.Stderr, "   Cipher:            %s\n", crypto.CipherName(header.CipherID))
	fmt.Fprintf(os.Stderr, "   Key Exchange:      %s\n", crypto.KeyExchangeModeName(header.KeyExchangeMode))
	fmt.Fprintf(os.Stderr, "   KDF Memory:        %d KB (%s)\n", header.KDFMemory, formatBytes(int64(header.KDFMemory)*1024))
	fmt.Fprintf(os.Stderr, "   KDF Iterations:    %d\n", header.KDFIterations)
	fmt.Fprintf(os.Stderr, "   KDF Parallelism:   %d\n", header.KDFParallelism)
	fmt.Fprintf(os.Stderr, "   Chunk Size:        %d bytes (%s)\n", header.ChunkSize, formatBytes(int64(header.ChunkSize)))

	if header.EncryptedKeyLen > 0 {
		fmt.Fprintf(os.Stderr, "   Encrypted Key:     %d bytes\n", header.EncryptedKeyLen)
	}
	if header.MetadataLen > 0 {
		fmt.Fprintf(os.Stderr, "   Metadata:          %d bytes (encrypted)\n", header.MetadataLen)
	}

	return nil
}
