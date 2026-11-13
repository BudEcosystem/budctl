package output

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/BudEcosystem/budctl/check"
)

func TestWrapBreaksAtSpacesWithinWidth(t *testing.T) {
	lines := wrap("the quick brown fox jumps over the lazy dog", 15, 10)
	want := []string{"the quick brown", "fox jumps", "over the", "lazy dog"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("wrap = %q, want %q", lines, want)
	}
	if got := wrap("an-unbreakable-word-longer-than-the-line", 10, 10); len(got) != 1 {
		t.Fatalf("a long word was split: %q", got)
	}
	if got := wrap("no width means no wrapping at all", 0, 0); len(got) != 1 {
		t.Fatalf("width 0 wrapped: %q", got)
	}
}

func TestTableWrapsToWidthWithHangingIndent(t *testing.T) {
	long := strings.Repeat("a reason that goes on ", 12)
	rep := check.Summarize([]check.Result{
		{ID: "nodes.capacity", Group: "nodes", State: check.StateFail, Severity: check.Block, Summary: long, Remedy: long},
		{ID: "registry.auth", Group: "registry", State: check.StateSkip, Severity: check.Block, Summary: long},
	})
	var b strings.Builder
	Table(&b, rep, Options{Width: 60})
	for _, line := range strings.Split(b.String(), "\n") {
		if n := utf8.RuneCountInString(line); n > 60 {
			t.Errorf("line is %d columns, over the 60 asked for: %q", n, line)
		}
	}
	if !strings.Contains(b.String(), "\n    → a reason") || !strings.Contains(b.String(), "\n      that goes") {
		t.Errorf("a remedy should wrap under itself:\n%s", b.String())
	}
}

func TestColourHighlightsTokensWithoutBreakingWidth(t *testing.T) {
	rep := check.Summarize([]check.Result{{
		ID: "nodes.imagefs", Group: "nodes", State: check.StateFail, Severity: check.Block,
		Summary: "kay has 67.6GiB free, see nodes.ready; " + strings.Repeat("filler words here ", 8),
		Remedy:  "re-run `budctl check --only nodes` with --verbose, or read https://example.com/docs",
	}})
	var b strings.Builder
	Table(&b, rep, Options{Color: true, Width: 60})
	out := b.String()
	for token, colour := range map[string]string{
		"67.6GiB": yellow, "nodes.ready": magenta, "`budctl check --only nodes`": cyan,
		"--verbose": cyan, "https://example.com/docs": blue + under,
	} {
		if !strings.Contains(out, colour+token+reset) {
			t.Errorf("%s is not highlighted", token)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if n := visible(line); n > 60 {
			t.Errorf("colour pushed a line to %d visible columns: %q", n, line)
		}
	}
	var plain strings.Builder
	Table(&plain, rep, Options{Width: 60})
	if strings.Contains(plain.String(), "\033") {
		t.Error("escape codes were written with colour off")
	}
}
