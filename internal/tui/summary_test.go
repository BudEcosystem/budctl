package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/BudEcosystem/budctl/internal/engine"
)

func sampleModel(t *testing.T, w, h int) *Model {
	t.Helper()
	c := testCtx(t)
	c.Answers.Domain = "bud.example.com"
	c.Answers.ModelStorageGi = 600
	return finishedModel(c, sampleReport(), w, h)
}

// The screenshot this guards against: on a 30-row terminal the verdict had
// scrolled off the top under thirty-odd "cluster unreachable" lines.
func TestSummaryUnreachableClusterFitsOneScreen(t *testing.T) {
	m := unreachableModel(t, 110, 30)
	view := stripANSI(m.View())
	if rows := strings.Count(view, "\n") + 1; rows > 30 {
		t.Fatalf("summary is %d rows on a 30-row terminal — it overflows and the verdict scrolls away", rows)
	}
	for _, want := range []string{"NOT READY", "Fix this first", "blocking", "q quit"} {
		if !strings.Contains(view, want) {
			t.Errorf("first screen missing %q", want)
		}
	}
}

// Thirty identical causes are one finding.
func TestSummaryGroupsSkipsByCause(t *testing.T) {
	m := unreachableModel(t, 110, 400)
	body := stripANSI(m.summaryBody())
	if n := strings.Count(body, "cluster unreachable:"); n > 1 {
		t.Fatalf("skips still listed one per line (%d 'cluster unreachable:' lines)", n)
	}
	if !strings.Contains(body, "checks — cluster unreachable") {
		t.Fatalf("no grouped line for unreachable-cluster skips:\n%s", body)
	}
	m.showSkipped = true
	if !strings.Contains(stripANSI(m.summaryBody()), "nodes.imagefs") {
		t.Fatal("expanding the groups did not reveal the check ids behind them")
	}
}

func TestSummaryLeadsWithBlockersAndDrawsTheirGauges(t *testing.T) {
	m := sampleModel(t, 110, 200)
	body := stripANSI(m.summaryBody())
	bIdx, rIdx, sIdx := strings.Index(body, "BLOCKING"), strings.Index(body, "RISKS"), strings.Index(body, "NOT VERIFIED")
	if bIdx < 0 || rIdx < 0 || sIdx < 0 || !(bIdx < rIdx && rIdx < sIdx) {
		t.Fatalf("order must be blocking, risks, not verified (%d, %d, %d)", bIdx, rIdx, sIdx)
	}
	for _, want := range []string{"nodes.imagefs", "grow the image filesystem", "config.valkey-indexes", "ax52-0", "47.0 GiB / 80.0 GiB", "█"} {
		if !strings.Contains(body, want) {
			t.Errorf("summary omits %q", want)
		}
	}
}

func TestSummaryShowsTheVerdictTiles(t *testing.T) {
	view := stripANSI(sampleModel(t, 120, 50).View())
	for _, want := range []string{"NOT READY", "verdict", "blocking", "risks", "passed", "not verified"} {
		if !strings.Contains(view, want) {
			t.Errorf("stat row missing %q", want)
		}
	}
	narrow := stripANSI(sampleModel(t, 60, 40).View())
	if !strings.Contains(narrow, "2 blocking · 1 risk") {
		t.Errorf("narrow terminals should get a one-line headline:\n%s", narrow)
	}
}

func TestSummarySaysWhenMoreContentIsBelow(t *testing.T) {
	m := unreachableModel(t, 110, 22)
	m.showSkipped = true
	m.layoutSummary()
	if !strings.Contains(stripANSI(m.View()), "more below") {
		t.Fatal("a clipped summary gives no sign more exists")
	}
	var tm tea.Model = m
	tm = pump(tm, press("G"))
	if !strings.Contains(stripANSI(tm.View()), "more above") {
		t.Fatal("scrolled to the end, but nothing says there is content above")
	}
}

func TestSummaryAsksToSaveBeforeQuitting(t *testing.T) {
	m := sampleModel(t, 110, 40)
	var tm tea.Model = m
	tm = pump(tm, press("q"))
	if !m.confirmQuit || !strings.Contains(stripANSI(tm.View()), "Save the report before quitting?") {
		t.Fatal("q on an unsaved report did not offer to save")
	}
	tm = pump(tm, press("esc"))
	if m.confirmQuit {
		t.Fatal("esc did not cancel the quit")
	}
}

func TestSummarySaveThenQuitDoesNotAskAgain(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(wd) }()

	m := sampleModel(t, 110, 40)
	var tm tea.Model = m
	tm = pump(tm, press("s"))
	if m.savedTo == "" {
		t.Fatalf("save failed: %s", m.saveErr)
	}
	if !strings.Contains(stripANSI(tm.View()), "saved") {
		t.Fatal("no confirmation that the report was saved")
	}
	_, cmd := m.Update(press("q"))
	if m.confirmQuit || cmd == nil {
		t.Fatal("quitting a saved report asked again instead of quitting")
	}
}

func TestSaveWritesBothFormats(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(wd) }()

	c := testCtx(t)
	c.Answers.Domain = "bud.example.com"
	c.Answers.ModelStorageGi = 600
	if _, err := SaveReport(sampleReport(), c.Answers); err != nil {
		t.Fatal(err)
	}
	jsonFiles, _ := filepath.Glob(filepath.Join(dir, "budctl-readiness-*.json"))
	mdFiles, _ := filepath.Glob(filepath.Join(dir, "budctl-readiness-*.md"))
	if len(jsonFiles) != 1 || len(mdFiles) != 1 {
		t.Fatalf("expected one .json and one .md, got %v %v", jsonFiles, mdFiles)
	}
	var rep engine.Report
	raw, _ := os.ReadFile(jsonFiles[0])
	if err := json.Unmarshal(raw, &rep); err != nil || rep.Verdict != engine.NotReady || len(rep.Results) != 6 {
		t.Fatalf("saved JSON is not the report: %v %s %d", err, rep.Verdict, len(rep.Results))
	}
	if len(rep.Results[0].Gauges) == 0 && len(rep.Results[1].Gauges) == 0 {
		found := false
		for _, r := range rep.Results {
			if len(r.Gauges) > 0 {
				found = true
			}
		}
		if !found {
			t.Error("gauges were not carried into the saved JSON")
		}
	}
	md, _ := os.ReadFile(mdFiles[0])
	for _, want := range []string{"## Checked against", "bud.example.com", "600 GiB", "## Blocking", "**Fix:**",
		"ax52-0: 47.0 GiB of 80.0 GiB needed — **short**", "## Not verified", "2 checks — --no-probe"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown report omits %q", want)
		}
	}
}

func TestSavedReportNeverContainsTheRegistryToken(t *testing.T) {
	c := testCtx(t)
	c.Answers.RegistryUser, c.Answers.RegistryPass = "robot$acme", "s3cr3t-token"
	if strings.Contains(markdownReport(sampleReport(), c.Answers), "s3cr3t-token") {
		t.Fatal("the registry token reached the shareable report")
	}
}
