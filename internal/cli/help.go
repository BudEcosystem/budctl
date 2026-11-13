package cli

import (
	"os"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// Flag descriptions are wrapped with a hanging indent, so a long one continues
// under its own column instead of under the flag names.
var flagUsages = regexp.MustCompile(`\.(LocalFlags|InheritedFlags)\.FlagUsages`)

func init() {
	cobra.AddTemplateFunc("wrappedFlagUsages", func(fs *pflag.FlagSet) string {
		return fs.FlagUsagesWrapped(helpWidth())
	})
}

func wrapFlagHelp(root *cobra.Command) {
	root.SetUsageTemplate(flagUsages.ReplaceAllString(root.UsageTemplate(), "(wrappedFlagUsages .$1)"))
}

// helpWidth is the terminal's width, capped for readability. Help piped into
// a pager still reads the terminal through stderr or stdin, and falls back to
// 100 columns when there is none.
func helpWidth() int {
	for _, f := range []*os.File{os.Stdout, os.Stderr, os.Stdin} {
		if width, _, err := term.GetSize(int(f.Fd())); err == nil && width > 0 {
			return min(width-1, 100)
		}
	}
	return 100
}
