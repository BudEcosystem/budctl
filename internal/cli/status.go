package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/output"
	"github.com/BudEcosystem/budctl/status"
	"github.com/spf13/cobra"
)

type statusParams struct {
	environment  string
	wait         bool
	waitDuration time.Duration
	format       string
}

func newStatusCommand() *cobra.Command {
	p := &statusParams{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show each component's ArgoCD sync and health",
		Long: `Show how an installed environment is doing, as ArgoCD sees it: the root
Application, and each component's Application, synced or not, healthy or not.

Exit code 0 means every Application is Synced and Healthy, 1 means at least one
is not (or --wait timed out), and 3 means budctl could not read the cluster.`,
		Example: `  budctl status
  budctl status --environment production --wait --wait-duration 30m
  budctl status -o json`,
		Args:        cobra.NoArgs,
		Annotations: needsCluster("required"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := clusterFrom(cmd.Context())
			if err != nil {
				return err
			}
			if p.format != "table" && p.format != "json" {
				return fmt.Errorf("--output must be table or json")
			}
			out := cmd.OutOrStdout()
			color := useColor()
			var r status.Report
			if p.wait {
				r, err = status.Wait(cmd.Context(), client, p.environment, p.waitDuration, 5*time.Second, func(r status.Report) {
					if p.format == "table" && !r.Ready() {
						fmt.Fprintln(out, painter(color).paint(ansiGray, "waiting: "+pending(r)))
					}
				})
			} else {
				r, err = status.Collect(cmd.Context(), client, p.environment)
			}
			if len(r.Environments) == 0 && err != nil {
				return err
			}
			if p.format == "json" {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(r); encErr != nil {
					return encErr
				}
			} else {
				printStatus(out, r, color, p.environment == "")
			}
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(), "budctl:", err)
				return &ExitError{Code: 1}
			}
			if !r.Ready() {
				return &ExitError{Code: 1}
			}
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&p.environment, "environment", "", "the environment to show (default: every environment)")
	fs.BoolVar(&p.wait, "wait", false, "wait until every Application is Synced and Healthy")
	fs.DurationVar(&p.waitDuration, "wait-duration", 15*time.Minute, "how long --wait waits")
	fs.StringVarP(&p.format, "output", "o", "table", "table | json")
	return cmd
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = output.Gray
)

// statePalette colours ArgoCD's sync, health and operation states: green is
// done, yellow is drift, cyan is in progress, red is broken.
var statePalette = map[string]string{
	"Synced": ansiGreen, "OutOfSync": ansiYellow,
	"Healthy": ansiGreen, "Progressing": ansiCyan, "Suspended": ansiGray,
	"Degraded": ansiRed, "Missing": ansiRed,
	"Succeeded": ansiGreen, "Running": ansiCyan, "Terminating": ansiCyan,
	"Failed": ansiRed, "Error": ansiRed,
	"Unknown": ansiGray,
}

// painter colours text when stdout is a terminal. Columns are padded before
// they are coloured, so escape codes never upset the alignment.
type painter bool

func (p painter) paint(code, s string) string {
	if !p || code == "" {
		return s
	}
	return code + s + ansiReset
}

func (p painter) state(s string, width int) string {
	return p.paint(statePalette[s], fmt.Sprintf("%-*s", width, s))
}

// printStatus prints a header per environment unless headers is false, when
// --environment already named the one being shown.
func printStatus(out io.Writer, r status.Report, color, headers bool) {
	p := painter(color)
	// The root is shown only when it is not ready: then the Applications below
	// may not reflect what is in Git.
	if r.Root != nil && !r.Root.Ready() {
		fmt.Fprintf(out, "%s %s %s  %s  %s\n", p.paint(ansiRed, "✗"), p.paint(ansiGray, "root Application"), p.paint(ansiBold, r.Root.Name),
			p.state(r.Root.Sync, 0), p.state(r.Root.Health, 0))
		if r.Root.Message != "" {
			fmt.Fprintf(out, "    %s %s\n", p.paint(statePalette[r.Root.Operation], r.Root.Operation+":"), p.paint(ansiGray, oneLine(r.Root.Message, 200)))
		}
		fmt.Fprintln(out, p.paint(ansiYellow, "    the Applications below may not match the repository"))
	}
	for _, e := range r.Environments {
		if headers {
			title := "environment " + e.Name
			fmt.Fprintf(out, "\n%s\n", p.paint(ansiBold+ansiCyan, "── "+title+" "+strings.Repeat("─", max(0, 58-len(title)))))
		}
		if len(e.Applications) == 0 {
			fmt.Fprintln(out, p.paint(ansiGray, "  no Applications generated yet"))
		}
		for _, a := range e.Applications {
			mark := p.paint(ansiGreen, "✓")
			if !a.Ready() {
				mark = p.paint(ansiRed, "✗")
			}
			fmt.Fprintf(out, "  %s %s %s %s %s %s\n", mark, p.paint(ansiBold, fmt.Sprintf("%-14s", a.Component)),
				p.state(a.Sync, 10), p.state(a.Health, 12), a.Chart, p.paint(ansiGray, a.Revision))
			if !a.Ready() && a.Message != "" {
				fmt.Fprintf(out, "      %s %s\n", p.paint(statePalette[a.Operation], a.Operation+":"), p.paint(ansiGray, oneLine(a.Message, 200)))
			}
		}
	}
	fmt.Fprintln(out)
	if r.Ready() {
		fmt.Fprintln(out, p.paint(ansiBold+ansiGreen, "✓ Every Application is Synced and Healthy."))
	} else if len(r.Environments) > 0 {
		fmt.Fprintln(out, p.paint(ansiBold+ansiYellow, "! "+pending(r)+"."))
	}
}

func pending(r status.Report) string {
	n, total := 0, 0
	for _, e := range r.Environments {
		for _, a := range e.Applications {
			total++
			if !a.Ready() {
				n++
			}
		}
	}
	return fmt.Sprintf("%d of %d Applications not yet Synced and Healthy", n, total)
}

// oneLine keeps a long ArgoCD message to one readable line; -o json has it
// in full. ArgoCD wraps the cause in layers of context, so the end is kept.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return "…" + s[len(s)-max:]
	}
	return s
}
