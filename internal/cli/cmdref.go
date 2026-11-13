package cli

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// newCmdrefCommand regenerates the Markdown command reference from the cobra
// tree, so the docs cannot drift from the flags.
func newCmdrefCommand() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:    "cmdref",
		Short:  "Generate the Markdown command reference",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			root := cmd.Root()
			root.DisableAutoGenTag = true
			return doc.GenMarkdownTree(root, dir)
		},
	}
	cmd.Flags().StringVarP(&dir, "directory", "d", "docs/cmdref", "directory to write the reference into")
	return cmd
}
