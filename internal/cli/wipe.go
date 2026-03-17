package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/datacrypt/datacrypt/internal/wipe"
)

var wipeCmd = &cobra.Command{
	Use:   "wipe [files...]",
	Short: "Securely delete files (unrecoverable)",
	Long: `Securely wipe files by overwriting their contents multiple times
with zeros, ones, and random data (DoD 5220.22-M standard), then
deleting them from the filesystem.

⚠️  WARNING: This operation is IRREVERSIBLE. Wiped files cannot be recovered.

Examples:
  datacrypt wipe secret.txt
  datacrypt wipe --passes 7 classified.doc
  datacrypt wipe --force *.tmp
  datacrypt wipe sensitive.pdf backup.zip`,
	Args: cobra.MinimumNArgs(1),
	RunE: runWipe,
}

func init() {
	wipeCmd.Flags().IntP("passes", "n", 3, "Number of overwrite passes (default: 3, DoD 5220.22-M)")
	wipeCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompt")

	rootCmd.AddCommand(wipeCmd)
}

func runWipe(cmd *cobra.Command, args []string) error {
	passes, _ := cmd.Flags().GetInt("passes")
	force, _ := cmd.Flags().GetBool("force")

	if passes < 1 {
		return fmt.Errorf("passes must be at least 1")
	}

	// Confirmation prompt
	if !force {
		fmt.Fprintf(os.Stderr, "⚠️  WARNING: The following %d file(s) will be PERMANENTLY DESTROYED:\n\n", len(args))
		for _, path := range args {
			info, err := os.Stat(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "   ❌ %s (not found)\n", path)
				continue
			}
			fmt.Fprintf(os.Stderr, "   🗑️  %s (%s)\n", path, formatBytes(info.Size()))
		}
		fmt.Fprintf(os.Stderr, "\n   Overwrite passes: %d\n", passes)
		fmt.Fprintf(os.Stderr, "\n   This action is IRREVERSIBLE. Continue? [y/N]: ")

		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response != "y" && response != "yes" {
			fmt.Fprintln(os.Stderr, "   Aborted.")
			return nil
		}
	}

	fmt.Fprintf(os.Stderr, "\n🗑️  Secure Wipe (%d passes)\n\n", passes)

	startTime := time.Now()
	successCount := 0

	for _, path := range args {
		fmt.Fprintf(os.Stderr, "   ⏳ Wiping: %s\n", path)

		opts := wipe.WipeOptions{
			Passes: passes,
			OnProgress: func(pass, totalPasses int, written, total int64) {
				percent := int(float64(written) / float64(total) * 100)
				fmt.Fprintf(os.Stderr, "\r   📊 Pass %d/%d: %d%%",
					pass, totalPasses, percent)
				if pass == totalPasses && percent == 100 {
					fmt.Fprintln(os.Stderr)
				}
			},
		}

		if err := wipe.SecureWipe(path, opts); err != nil {
			fmt.Fprintf(os.Stderr, "   ❌ Error: %v\n", err)
			continue
		}

		fmt.Fprintf(os.Stderr, "   ✅ Securely wiped: %s\n", path)
		successCount++
	}

	elapsed := time.Since(startTime)
	fmt.Fprintf(os.Stderr, "\n   Done: %d/%d files securely wiped in %v\n",
		successCount, len(args), elapsed.Round(time.Millisecond))

	if successCount < len(args) {
		return fmt.Errorf("%d file(s) failed to wipe", len(args)-successCount)
	}

	return nil
}
