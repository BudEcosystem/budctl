// Package output renders a finished run. It shares one result set with the TUI:
// both read check.Report, so the two surfaces cannot disagree (FRD-020 G5).
package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/check"
)

var statusColor = map[string]string{
	"PASS": "\033[32m", "BLOCK": "\033[31m", "RISK": "\033[33m",
	"INFO": "\033[36m", "SKIP": gray,
}

const reset = "\033[0m"
const bold = "\033[1m"

type Options struct {
	Color   bool
	Verbose bool
	// Width wraps long lines to this many columns with a hanging indent, so a
	// terminal never breaks them mid-word. 0 leaves lines whole, which is what
	// a file or a CI log wants.
	Width int
}

func paint(s, status string, color bool) string {
	if !color {
		return s
	}
	return statusColor[status] + s + reset
}

// Table is the human-readable rendering. Status is always printed as a text
// token as well as a colour, so colour is never the only signal.
func Table(w io.Writer, rep check.Report, opts Options) {
	p := printer{w: w, opts: opts}
	byGroup := map[string][]check.Result{}
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
	if opts.Verbose {
		for _, g := range order {
			fmt.Fprintf(w, "\n%s\n", p.style(bold+cyan, "── "+g+" "+strings.Repeat("─", max(0, 58-len(g)))))
			rs := byGroup[g]
			sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
			for _, r := range rs {
				st := r.Status()
				label := "  [" + paint(pad(st), st, opts.Color) + "] " + r.ID
				p.item(label, "      ", r.Summary)
				for _, d := range r.Detail {
					p.line("        ", "          ", d, "")
				}
				if r.Remedy != "" {
					p.line("        "+p.style(green, "→")+" ", "          ", r.Remedy, "")
				}
				for _, e := range r.Evidence {
					p.line("        "+p.style(gray, "·")+" ", "          ", e.What, gray)
					if e.Output != "" {
						for _, line := range strings.Split(strings.TrimRight(e.Output, "\n"), "\n") {
							fmt.Fprintf(w, "          %s\n", line)
						}
					}
				}
				if r.DoesNotProve != "" {
					p.line("        "+p.style(gray, "does not prove:")+" ", "          ", r.DoesNotProve, gray)
				}
			}
		}
	}

	// Order is the order of usefulness: the verdict, then the one thing to fix
	// first when there is one, then what blocks, what degrades, what never ran.
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s %s\n", p.style(bold, "Verdict:"), p.style(bold+verdictColor[rep.Verdict], string(rep.Verdict)))
	fmt.Fprintf(w, "%s · %s · %s · %s\n",
		p.count(rep.Counts["PASS"], "passed", green), p.count(rep.Counts["BLOCK"], "blocking", red),
		p.count(rep.Counts["RISK"], "risk", yellow), p.count(rep.Counts["SKIP"], "not verified", gray))

	cause, blocked := check.RootCause(rep.Results)
	if cause != nil {
		p.heading(red, "Fix this first", "the cluster could not be reached")
		p.line("  ", "  ", cause.Summary, "")
		if cause.Remedy != "" {
			p.line("  "+p.style(green, "→")+" ", "    ", cause.Remedy, "")
		}
		p.line("  ", "  ", fmt.Sprintf("%d checks could not run until this is fixed, so this reflects only what could be checked from here.", blocked), gray)
	}

	printed := 0
	for _, r := range rep.Results {
		if !r.IsBlocker() || (cause != nil && r.ID == cause.ID) {
			continue
		}
		if printed == 0 {
			p.heading(red, "BLOCKING", "the install will fail")
		}
		printed++
		p.entry("✗", red, r.ID, r.Summary, r.Remedy, "")
	}
	if printed == 0 && cause == nil {
		fmt.Fprintf(w, "\n%s\n", p.style(green+bold, "✓ Nothing blocks the install."))
	}

	if rep.Counts["RISK"] > 0 {
		p.heading(yellow, "RISKS", "installs, but a capability is degraded")
		for _, r := range rep.Results {
			if r.IsRisk() {
				p.entry("!", yellow, r.ID, r.Summary, "", "")
			}
		}
	}

	// Skips are never folded into passes (FRD-020 D5), and are grouped by cause
	// so thirty identical reasons read as the one fact they are.
	if rep.Counts["SKIP"] > 0 {
		groups := check.GroupSkips(rep.Results)
		reasons := "reasons"
		if len(groups) == 1 {
			reasons = "reason"
		}
		checks := "checks did"
		if rep.Counts["SKIP"] == 1 {
			checks = "check did"
		}
		p.heading(cyan, "NOT VERIFIED", fmt.Sprintf("%d %s not run, for %d %s; these are not passes",
			rep.Counts["SKIP"], checks, len(groups), reasons))
		for _, g := range groups {
			p.entry("·", gray, strings.Join(g.IDs, ", "), g.Reason, "", gray)
		}
	}

	if !opts.Verbose {
		fmt.Fprintln(w)
		p.line("", "", "Every check with its evidence: --verbose.  Save the full report: --save.", gray)
	}
}

const (
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	under   = "\033[4m"
)

var verdictColor = map[check.Verdict]string{
	check.Ready: green, check.ReadyWithRisks: yellow, check.NotReady: red,
}

// printer writes the table's lines, wrapping them to Options.Width.
type printer struct {
	w    io.Writer
	opts Options
}

// style colours s when colour is on.
func (p printer) style(code, s string) string {
	if !p.opts.Color || code == "" {
		return s
	}
	return code + s + reset
}

// count prints "3 blocking" in its colour, and a zero in grey, so the eye
// lands on what is non-zero.
func (p printer) count(n int, label, code string) string {
	if n == 0 {
		code = gray
	}
	return p.style(code, fmt.Sprintf("%d %s", n, label))
}

// heading is a section title: the name in its colour, then what it means.
func (p printer) heading(code, name, meaning string) {
	fmt.Fprintln(p.w)
	p.line(p.style(bold+code, name)+p.style(gray, " — "), "", meaning, bold)
}

// entry is one finding: a marker and the check id, then its explanation and
// remedy indented beneath, so ids line up down the left edge. base is the
// colour of the explanation; "" is the terminal's own.
func (p printer) entry(marker, code, id, text, remedy, base string) {
	// Ids stay legible: a grey entry (not verified) keeps its id in plain bold.
	idCode := bold + code
	if code == gray {
		idCode = bold
	}
	p.line("  "+p.style(code, marker)+" ", "    ", p.style(idCode, id), "")
	p.line("    ", "    ", text, base)
	if remedy != "" {
		p.line("    "+p.style(green, "→")+" ", "      ", remedy, "")
	}
}

// item prints a label padded to the summary column, then text wrapping under
// rest.
func (p printer) item(label, rest, text string) {
	pad := 45 - visible(label)
	if pad < 1 {
		pad = 1
	}
	p.line(label+strings.Repeat(" ", pad), rest, text, "")
}

// line prints text after first, wrapping to the width with each further line
// starting with rest. With colour on, the text is highlighted on a base colour.
func (p printer) line(first, rest, text, base string) {
	// Text that already carries colour (a check id) is not highlighted again.
	if p.opts.Color && !strings.Contains(text, "\033") {
		text = highlight(text, base)
	}
	for i, l := range wrap(text, p.opts.Width-visible(first), p.opts.Width-visible(rest)) {
		prefix := rest
		if i == 0 {
			prefix = first
		}
		if p.opts.Color && base != "" {
			l = base + l + reset
		}
		fmt.Fprintf(p.w, "%s%s\n", prefix, l)
	}
}

// tokens are what highlight colours inside a message, in priority order:
// `commands`, URLs, "quoted names", --flags, sizes and counts, check ids.
var tokens = regexp.MustCompile("(`[^`]+`)" +
	`|((?:https?|ssh)://[^\s,)]+)` +
	`|("[^"\s][^"]*")` +
	`|(--[a-z][a-z0-9-]*(?:=[^\s,)]+)?)` +
	`|(\b\d+(?:\.\d+)?\s?(?:GiB|MiB|TiB|KiB|Gi|Mi|Ti|GB|MB|cores?|%))` +
	`|(\b(?:` + strings.Join(append(check.GroupOrder, "externaldatastores"), "|") + `)\.[a-z0-9-]+\b)`)

var tokenColors = []string{cyan, blue + under, green, cyan, yellow, magenta}

// highlight colours the tokens in text, returning to base after each.
func highlight(text, base string) string {
	restore := reset + base
	return tokens.ReplaceAllStringFunc(text, func(m string) string {
		sub := tokens.FindStringSubmatchIndex(m)
		for g := 1; g*2 < len(sub); g++ {
			if sub[g*2] >= 0 {
				return tokenColors[g-1] + m + restore
			}
		}
		return m
	})
}

// wrap splits text into lines of at most firstWidth, then restWidth, runes,
// breaking at spaces. A word longer than a line is kept whole. Widths of 0 or
// less disable wrapping.
func wrap(text string, firstWidth, restWidth int) []string {
	text = strings.TrimSpace(text)
	if firstWidth <= 0 || restWidth <= 0 {
		return []string{text}
	}
	var lines []string
	limit := firstWidth
	var current strings.Builder
	n := 0
	for _, word := range strings.Fields(text) {
		wl := visible(word)
		if n > 0 && n+1+wl > limit {
			lines = append(lines, current.String())
			current.Reset()
			n = 0
			limit = restWidth
		}
		if n > 0 {
			current.WriteByte(' ')
			n++
		}
		current.WriteString(word)
		n += wl
	}
	return append(lines, current.String())
}

// visible is a string's printed width, ignoring colour escapes.
func visible(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\033':
			esc = true
		case esc:
			if r == 'm' {
				esc = false
			}
		default:
			n++
		}
	}
	return n
}

func JSON(w io.Writer, rep check.Report) error {
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

func JUnit(w io.Writer, rep check.Report) error {
	suite := junitSuite{Name: "budctl readiness"}
	for _, r := range rep.Results {
		c := junitCase{Name: r.ID, ClassName: r.Group}
		switch {
		case r.State == check.StateFail:
			suite.Failures++
			c.Failure = &junitFailure{Message: r.Summary, Text: strings.Join(append(r.Detail, r.Remedy), "\n")}
		case r.State == check.StateSkip:
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
	for i, name := range check.GroupOrder {
		if name == g {
			return i
		}
	}
	return len(check.GroupOrder)
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

// Gray is the muted grey Claude Code prints its secondary text in (#999999).
// ANSI bright black, the usual choice, is near-invisible on many dark themes.
const Gray = "\033[38;2;153;153;153m"

const gray = Gray
