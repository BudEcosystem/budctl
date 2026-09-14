package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BudEcosystem/budctl/internal/engine"
)

func detailModel(t *testing.T, w, h int) *Model {
	t.Helper()
	m := sampleModel(t, w, h)
	var tm tea.Model = m
	pump(tm, press("d"))
	if m.state != stateDetail {
		t.Fatal("d did not open the detail view")
	}
	return m
}

// selectCheck moves the list selection to a check by id, the way an operator
// would with the arrow keys.
func selectCheck(t *testing.T, m *Model, id string) {
	t.Helper()
	var tm tea.Model = m
	for i := 0; i < len(m.list.Items()); i++ {
		if r, ok := m.selected(); ok && r.ID == id {
			return
		}
		pump(tm, press("down"))
	}
	t.Fatalf("could not select %s", id)
}

func TestDetailTabsFilterByStatusWithCounts(t *testing.T) {
	m := detailModel(t, 130, 40)
	bar := stripANSI(m.tabBar())
	for _, want := range []string{"All 6", "Blocking 2", "Risks 1", "Not verified 2", "Passed 1"} {
		if !strings.Contains(bar, want) {
			t.Errorf("tab bar missing %q: %s", want, bar)
		}
	}
	var tm tea.Model = m
	pump(tm, press("2"))
	if n := len(m.list.Items()); n != 2 {
		t.Fatalf("Blocking tab shows %d items, want 2", n)
	}
	for _, it := range m.list.Items() {
		if !it.(resultItem).r.IsBlocker() {
			t.Fatalf("a non-blocker is listed under Blocking: %s", it.(resultItem).r.ID)
		}
	}
}

// The list opens on what matters, not on alphabetical order.
func TestDetailListsWorstFirst(t *testing.T) {
	m := detailModel(t, 130, 40)
	first := m.list.Items()[0].(resultItem).r
	if !first.IsBlocker() {
		t.Fatalf("the list opens on %s (%s), not a blocker", first.ID, first.Status())
	}
}

// The record keeps everything a reviewer needs, including what a result does
// NOT prove.
func TestDetailRecordShowsEvidenceRemedyAndBounds(t *testing.T) {
	m := detailModel(t, 130, 60)
	selectCheck(t, m, "nodes.imagefs")
	rec := stripANSI(m.detailVP.View())
	for _, want := range []string{"nodes.imagefs", "BLOCK", "Fix", "grow the image filesystem", "Evidence", "kubelet /stats/summary", "Does not prove", "█"} {
		if !strings.Contains(rec, want) {
			t.Errorf("record pane missing %q", want)
		}
	}
}

func TestDetailNarrowTerminalOpensTheRecordOnEnter(t *testing.T) {
	m := detailModel(t, 80, 40)
	selectCheck(t, m, "nodes.imagefs")
	var tm tea.Model = m
	if m.detailOpen {
		t.Fatal("record open before enter")
	}
	pump(tm, press("enter"))
	if !m.detailOpen || !strings.Contains(stripANSI(tm.View()), "Does not prove") {
		t.Fatal("enter did not open the record on a narrow terminal")
	}
	pump(tm, press("esc"))
	if m.detailOpen || m.state != stateDetail {
		t.Fatal("esc should close the record and stay in the list")
	}
	pump(tm, press("esc"))
	if m.state != stateSummary {
		t.Fatal("esc from the list should return to the summary")
	}
}

// Evidence is what an operator pastes into a ticket, so a line too long for the
// card wraps rather than losing its tail — the unit after a figure is exactly
// the part a truncation used to drop ("of 187.9…").
func TestDetailEvidenceWrapsInsteadOfTruncating(t *testing.T) {
	r := engine.Result{ID: "nodes.imagefs", Group: "nodes", State: engine.StateFail, Severity: engine.Block,
		Summary: "1 node is below the floor",
		Evidence: []engine.Evidence{{What: "kubelet /stats/summary",
			Output: "node/bud-hetzner-ax52-0 imageFs available 46.7GiB of 187.9GiB capacity-END\nsecond line"}}}
	card := stripANSI(recordCard(r, 60))
	flat := strings.Join(strings.Fields(card), " ")
	for _, want := range []string{"187.9GiB", "capacity-END", "second line"} {
		if !strings.Contains(flat, want) {
			t.Errorf("evidence lost %q to the card width:\n%s", want, card)
		}
	}
	if strings.Contains(card, "…") {
		t.Errorf("evidence was truncated:\n%s", card)
	}
	for _, l := range strings.Split(card, "\n") {
		if w := lipgloss.Width(l); w > 60 {
			t.Errorf("a wrapped evidence line is %d columns in a 60-column card: %q", w, l)
		}
	}
}
