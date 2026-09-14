// Package output renders a finished run. It shares one result set with the TUI:
// both read engine.Report, so the two surfaces cannot disagree (FRD-020 G5).
package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/internal/engine"
)

var statusColor = map[string]string{
	"PASS": "\033[32m", "BLOCK": "\033[31m", "RISK": "\033[33m",
	"INFO": "\033[36m", "SKIP": "\033[90m",
}

const reset = "\033[0m"
const bold = "\033[1m"

type Options struct {
	Color   bool
	Verbose bool
}

// UseColor honours NO_COLOR and a non-terminal stdout, so piping to a file or a
// CI log never emits escapes.
func UseColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func paint(s, status string, color bool) string {
	if !color {
		return s
	}
	return statusColor[status] + s + reset
}

// Table is the human-readable rendering. Status is always printed as a text
// token as well as a colour, so colour is never the only signal.
func Table(w io.Writer, rep engine.Report, opts Options) {
	byGroup := map[string][]engine.Result{}
	order := []string{}
	for _, r := range rep.Results {
		if _, seen := byGroup[r.Group]; !seen {
			order = append(order, r.Group)
		}
		byGroup[r.Group] = append(byGroup[r.Group], r)
	}
	sort.SliceStable(order, func(i, j int) bool {
		return groupRank(order[i]) < groupRank(order[j])
	})

	// Every individual check is detail, printed on request. By default the
	// output is the summary: on an unreachable cluster the full table is eighty
	// lines, most of them one cause repeated, and the verdict scrolls away.
	for _, g := range order {
		if !opts.Verbose {
			break
		}
		title := fmt.Sprintf("── %s ", g)
		fmt.Fprintf(w, "\n%s%s%s\n", bolded(opts.Color), title+strings.Repeat("─", max(0, 62-len(title))), resetIf(opts.Color))
		rs := byGroup[g]
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
		for _, r := range rs {
			st := r.Status()
			fmt.Fprintf(w, "  [%s] %-34s %s\n", paint(pad(st), st, opts.Color), r.ID, r.Summary)
			show := opts.Verbose || r.State == engine.StateFail
			if show {
				for _, d := range r.Detail {
					fmt.Fprintf(w, "        %s\n", d)
				}
				if r.Remedy != "" {
					fmt.Fprintf(w, "        → %s\n", r.Remedy)
				}
				for _, e := range r.Evidence {
					fmt.Fprintf(w, "        · %s\n", e.What)
					if opts.Verbose && e.Output != "" {
						for _, line := range strings.Split(strings.TrimRight(e.Output, "\n"), "\n") {
							fmt.Fprintf(w, "          %s\n", line)
						}
					}
				}
			}
			if opts.Verbose && r.DoesNotProve != "" {
				fmt.Fprintf(w, "        does not prove: %s\n", r.DoesNotProve)
			}
		}
	}

	// Order is the order of usefulness: the verdict, then the one thing to fix
	// first when there is one, then what blocks, what degrades, what never ran.
	fmt.Fprintf(w, "\n%sVerdict: %s%s\n", bolded(opts.Color), rep.Verdict, resetIf(opts.Color))
	fmt.Fprintf(w, "%d passed · %d blocking · %d risk · %d not verified\n",
		rep.Counts["PASS"], rep.Counts["BLOCK"], rep.Counts["RISK"], rep.Counts["SKIP"])

	cause, blocked := engine.RootCause(rep.Results)
	if cause != nil {
		fmt.Fprintf(w, "\n%sFix this first — the cluster could not be reached%s\n", bolded(opts.Color), resetIf(opts.Color))
		fmt.Fprintf(w, "  %s\n", cause.Summary)
		if cause.Remedy != "" {
			fmt.Fprintf(w, "  → %s\n", cause.Remedy)
		}
		fmt.Fprintf(w, "  %d checks could not run until this is fixed, so this reflects only what could be checked from here.\n", blocked)
	}

	printed := 0
	for _, r := range rep.Results {
		if !r.IsBlocker() || (cause != nil && r.ID == cause.ID) {
			continue
		}
		if printed == 0 {
			fmt.Fprintf(w, "\n%sBLOCKING — the install will fail%s\n", paint("", "BLOCK", opts.Color)+bolded(opts.Color), resetIf(opts.Color))
		}
		printed++
		fmt.Fprintf(w, "  • %s\n    %s\n", r.ID, r.Summary)
		if r.Remedy != "" {
			fmt.Fprintf(w, "    → %s\n", r.Remedy)
		}
	}
	if printed == 0 && cause == nil {
		fmt.Fprintf(w, "\nNothing blocks the install.\n")
	}

	if rep.Counts["RISK"] > 0 {
		fmt.Fprintf(w, "\nRISKS — installs, but a capability is degraded\n")
		for _, r := range rep.Results {
			if r.IsRisk() {
				fmt.Fprintf(w, "  • %s\n    %s\n", r.ID, r.Summary)
			}
		}
	}

	// Skips are never folded into passes (FRD-020 D5), and are grouped by cause
	// so thirty identical reasons read as the one fact they are.
	if rep.Counts["SKIP"] > 0 {
		groups := engine.GroupSkips(rep.Results)
		fmt.Fprintf(w, "\nNOT VERIFIED — %d checks did not run, for %d reason(s); these are not passes\n", rep.Counts["SKIP"], len(groups))
		for _, g := range groups {
			if len(g.IDs) == 1 {
				fmt.Fprintf(w, "  · %s — %s\n", g.IDs[0], g.Reason)
				continue
			}
			fmt.Fprintf(w, "  · %d checks — %s\n", len(g.IDs), g.Reason)
			if opts.Verbose {
				fmt.Fprintf(w, "      %s\n", strings.Join(g.IDs, ", "))
			}
		}
	}

	if !opts.Verbose {
		fmt.Fprintf(w, "\nEvery check with its evidence: --verbose.  Save the full report: --save.\n")
	}
}

func JSON(w io.Writer, rep engine.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *struct {
		Message string `xml:"message,attr"`
	} `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

func JUnit(w io.Writer, rep engine.Report) error {
	suite := junitSuite{Name: "budctl readiness"}
	for _, r := range rep.Results {
		c := junitCase{Name: r.ID, ClassName: r.Group}
		switch {
		case r.State == engine.StateFail:
			suite.Failures++
			c.Failure = &junitFailure{Message: r.Summary, Text: strings.Join(append(r.Detail, r.Remedy), "\n")}
		case r.State == engine.StateSkip:
			suite.Skipped++
			c.Skipped = &struct {
				Message string `xml:"message,attr"`
			}{Message: r.Summary}
		}
		suite.Tests++
		suite.Cases = append(suite.Cases, c)
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suite)
}

func groupRank(g string) int {
	for i, name := range engine.GroupOrder {
		if name == g {
			return i
		}
	}
	return len(engine.GroupOrder)
}

func pad(s string) string {
	if len(s) >= 5 {
		return s
	}
	return s + strings.Repeat(" ", 5-len(s))
}

func bolded(color bool) string {
	if color {
		return bold
	}
	return ""
}

func resetIf(color bool) string {
	if color {
		return reset
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
