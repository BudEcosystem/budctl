package tui

import (
	"context"
	"reflect"
	"regexp"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/BudEcosystem/budctl/internal/adapters"
	_ "github.com/BudEcosystem/budctl/internal/checks"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func press(k string) tea.KeyMsg {
	switch k {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
}

// pump delivers messages the way the Bubble Tea runtime would, executing the
// commands each Update returns and feeding their messages back in. A command
// that does not return promptly is a timer — a cursor blink, a spinner tick —
// and is dropped, which is what makes the loop terminate.
func pump(m tea.Model, msgs ...tea.Msg) tea.Model {
	for _, msg := range msgs {
		var cmd tea.Cmd
		m, cmd = m.Update(msg)
		m = drain(m, cmd, 0)
	}
	return m
}

func drain(m tea.Model, cmd tea.Cmd, depth int) tea.Model {
	if cmd == nil || depth > 12 {
		return m
	}
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	var msg tea.Msg
	select {
	case msg = <-ch:
	case <-time.After(25 * time.Millisecond):
		return m
	}
	if msg == nil {
		return m
	}
	if _, quit := msg.(tea.QuitMsg); quit {
		return m
	}
	// tea.Batch and tea.Sequence both deliver a slice of commands.
	if v := reflect.ValueOf(msg); v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			if c, ok := v.Index(i).Interface().(tea.Cmd); ok {
				m = drain(m, c, depth+1)
			}
		}
		return m
	}
	var next tea.Cmd
	m, next = m.Update(msg)
	return drain(m, next, depth+1)
}

func testCtx(t *testing.T) *engine.Ctx {
	t.Helper()
	c := engine.NewCtx()
	c.Answers = intake.Defaults()
	p, err := intake.LoadProfile()
	if err != nil {
		t.Fatal(err)
	}
	c.Profile = p
	return c
}

// unreachableModel runs the REAL engine the way it ran on an operator's laptop
// whose kubeconfig had no current context. Every probe target is removed so the
// test stays offline; the result is the report that once produced an unreadable
// screen.
func unreachableModel(t *testing.T, width, height int) *Model {
	t.Helper()
	c := testCtx(t)
	c.Answers.Domain = "bud.example.com"
	c.Answers.ConfigRepo = "https://example.invalid/config.git"
	c.Profile.Egress = nil
	c.Profile.EgressTCP = nil
	c.Profile.Registries = nil
	c.Net = adapters.NewNet(150 * time.Millisecond)
	c.OCI = adapters.NewOCI(c.Net)
	c.Helm = adapters.NewHelm()
	c.Opts.NoProbe = true
	c.Opts.ArgoCDEnabled = true
	c.Set("kube.error", "invalid configuration: no configuration has been provided")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep := engine.Summarize(engine.Run(ctx, c, engine.Selection{}, nil))
	return finishedModel(c, rep, width, height)
}

func finishedModel(c *engine.Ctx, rep engine.Report, width, height int) *Model {
	m := New(context.Background(), c, engine.Selection{}, true, "")
	m.width, m.height = width, height
	m.report = rep
	m.finished = true
	m.state = stateSummary
	m.layoutSummary()
	m.layoutDetail()
	return m
}

func sampleReport() engine.Report {
	return engine.Summarize([]engine.Result{
		{ID: "nodes.imagefs", Group: "nodes", State: engine.StateFail, Severity: engine.Block,
			Summary: "4 nodes are below the 80 GiB image-filesystem floor",
			Remedy:  "grow the image filesystem to at least 80 GiB free per node",
			Gauges: []engine.Gauge{
				{Label: "ax52-0", Have: 47 << 30, Need: 80 << 30, Unit: "bytes"},
				{Label: "ax52-3", Have: 120 << 30, Need: 80 << 30, Unit: "bytes"},
			},
			Evidence:     []engine.Evidence{{What: "kubelet /stats/summary", Output: "node/ax52-0 imageFs 47GiB"}},
			DoesNotProve: "headroom for the model runtime images"},
		{ID: "config.valkey-indexes", Group: "config", State: engine.StateFail, Severity: engine.Block,
			Summary: "1 Valkey index carries two logical uses", Remedy: "give every entry its own index"},
		{ID: "registry.pinned-tags", Group: "registry", State: engine.StateFail, Severity: engine.Risk,
			Summary: "4 image references are not pinned to an immutable tag"},
		{ID: "storage.provision", Group: "storage", State: engine.StateSkip, Severity: engine.Block,
			Summary: "--no-probe: not verified, and therefore not confirmed working"},
		{ID: "egress.install", Group: "egress", State: engine.StateSkip, Severity: engine.Block,
			Summary: "--no-probe: not verified, and therefore not confirmed working"},
		{ID: "cluster.version", Group: "cluster", State: engine.StatePass, Severity: engine.Block,
			Summary: "Kubernetes v1.30 ≥ 1.25"},
	})
}

// withTrueColor renders styles as they would appear on a real colour terminal,
// then restores the renderer — tests otherwise run with no colour profile.
func withTrueColor(t *testing.T, dark bool) {
	t.Helper()
	prevProfile := lipgloss.ColorProfile()
	prevDark := lipgloss.HasDarkBackground()
	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(dark)
	t.Cleanup(func() {
		lipgloss.SetColorProfile(prevProfile)
		lipgloss.SetHasDarkBackground(prevDark)
	})
}
