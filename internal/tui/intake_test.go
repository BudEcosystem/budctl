package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"

	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// setupModel is a real application model on its intake screen, restricted to
// the platform group so the run the form starts is instant and offline.
func setupModel(t *testing.T, prime func(*engine.Ctx)) *Model {
	t.Helper()
	c := testCtx(t)
	if prime != nil {
		prime(c)
	}
	m := New(context.Background(), c, engine.Selection{Only: []string{"platform"}}, false, "")
	var tm tea.Model = m
	tm = pump(tm, tea.WindowSizeMsg{Width: 110, Height: 40})
	tm = drain(tm, m.Init(), 0)
	return tm.(*Model)
}

// walk presses enter until the form completes or stops advancing, recording
// every screen. It proves the wizard can actually be traversed end to end.
func walk(t *testing.T, m *Model) (*Model, string) {
	t.Helper()
	var seen strings.Builder
	var tm tea.Model = m
	for i := 0; i < 80 && m.state == stateSetup; i++ {
		seen.WriteString(stripANSI(m.View()))
		tm = pump(tm, press("enter"))
		m = tm.(*Model)
	}
	return m, seen.String()
}

// The operator should never need --help to discover a question exists.
func TestIntakeWalksEveryPageAndAsksEveryQuestion(t *testing.T) {
	m := setupModel(t, func(c *engine.Ctx) {
		c.Answers.Domain = "bud.example.com"
		c.Answers.ConfigRepo = "ssh://git@github.com/acme/cfg"
		c.Answers.ModelStorageGi = 600
	})
	m, seen := walk(t, m)

	if m.state == stateSetup {
		t.Fatalf("pressing enter through valid answers never completed the form; last screen:\n%s", stripANSI(m.View()))
	}
	for _, want := range []string{
		"Root domain", "How TLS certificates are obtained",
		"Data stores", "Model storage (GiB)", "How many models", "Observability retention",
		"Concurrent deployments", "GPU deployments expected?", "OpenSandbox",
		"Install via ArgoCD?", "Config repository URL",
		"registry.bud.studio username", "Values file",
		"Probe from inside the cluster?",
	} {
		if !strings.Contains(seen, want) {
			t.Errorf("the wizard never asked %q", want)
		}
	}
	if m.ctx.Answers.Domain != "bud.example.com" || m.ctx.Answers.ModelStorageGi != 600 {
		t.Errorf("completed answers were not applied: %+v", m.ctx.Answers)
	}
}

// Pages the answers make irrelevant must not appear.
func TestIntakeSkipsIrrelevantPages(t *testing.T) {
	m := setupModel(t, func(c *engine.Ctx) {
		c.Answers.Domain = "bud.example.com"
		c.Answers.ConfigRepo = "ssh://git@github.com/acme/cfg"
		c.Answers.ModelStorageGi = 600
	})
	_, seen := walk(t, m)
	for _, hidden := range []string{"registry.bud.studio token", "Chart directory", "SOPS secrets file", "Internal CA bundle"} {
		if strings.Contains(seen, hidden) {
			t.Errorf("asked %q although nothing it depends on was answered", hidden)
		}
	}
}

// A blank domain stops the wizard on the first page with the reason visible.
func TestIntakeWillNotAdvancePastABlankDomain(t *testing.T) {
	m := setupModel(t, nil)
	var tm tea.Model = m
	for i := 0; i < 6; i++ {
		tm = pump(tm, press("enter"))
	}
	m = tm.(*Model)
	if m.state != stateSetup {
		t.Fatal("the form completed with no domain")
	}
	view := stripANSI(m.View())
	if !strings.Contains(view, "Root domain") || !strings.Contains(view, "required") {
		t.Fatalf("stuck on the domain without saying why:\n%s", view)
	}
	// The error line is drawn inside the height the form was given; it must
	// not push the screen onto the terminal's bottom row.
	if h := strings.Count(view, "\n") + 1; h >= 40 {
		t.Errorf("with the validation error showing, the screen is %d lines in a 40-line terminal", h)
	}
}

// The consequence line re-evaluates as the operator types — the property the
// form was redesigned around.
func TestIntakeConsequenceUpdatesWhileTyping(t *testing.T) {
	m := setupModel(t, nil)
	var tm tea.Model = m
	for _, r := range "acme.io" {
		tm = pump(tm, press(string(r)))
	}
	view := stripANSI(tm.(*Model).View())
	if !strings.Contains(view, "admin.acme.io") {
		t.Fatalf("typing a domain did not update its consequence line:\n%s", view)
	}
}

// The token is never drawn.
func TestIntakeMasksTheRegistryToken(t *testing.T) {
	q := newQuestions(testCtx(t), "")
	q.Domain, q.ModelStorage, q.ConfigRepo = "bud.example.com", "600", "ssh://git@github.com/acme/cfg"
	q.RegistryUser, q.RegistryPass = "robot$acme", "s3cr3t-token"
	f := buildIntakeForm(q, 100)
	var tm tea.Model = f
	tm = drain(tm, f.Init(), 0)
	reachedToken := false
	for i := 0; i < 60; i++ {
		view := stripANSI(tm.View())
		if strings.Contains(view, "registry.bud.studio token") {
			reachedToken = true
		}
		if strings.Contains(view, "s3cr3t-token") {
			t.Fatal("the registry token was rendered in clear text")
		}
		tm = pump(tm, press("enter"))
		if tm.(*huh.Form).State != huh.StateNormal {
			break
		}
	}
	// Without this the test passes by never reaching the field it guards.
	if !reachedToken {
		t.Fatal("the walk never reached the token field, so masking was not tested")
	}
}

func TestIntakeEscAbortsWithoutRunning(t *testing.T) {
	m := setupModel(t, nil)
	var tm tea.Model = m
	tm = pump(tm, tea.KeyMsg{Type: tea.KeyCtrlC})
	if !tm.(*Model).Aborted() {
		t.Fatal("ctrl+c on the form did not abort")
	}
}

// Every field on a page must be on screen once its consequence text has
// loaded. huh sizes a page before any DescriptionFunc text exists, so a page
// measured then is too short and scrolls its first field off the top the moment
// the text arrives — which is how the Data stores question came to be clipped.
func TestIntakeEveryFieldOnAPageIsVisible(t *testing.T) {
	const height = 40 // setupModel's terminal
	pages := map[string][]string{
		"1 · Where Bud will live":   {"Root domain", "How TLS certificates are obtained"},
		"2 · What it needs to hold": {"Data stores", "Model storage (GiB)", "How many models", "Observability retention (days)"},
		"3 · What it will run":      {"Concurrent deployments", "GPU deployments expected?", "Enable the OpenSandbox code interpreter?"},
		"4 · How it is delivered":   {"Install via ArgoCD?"},
		"4 · Where ArgoCD reads":    {"Config repository URL"},
		"5 · Registry access":       {"registry.bud.studio username"},
		"6 · Your configuration":    {"Values file"},
		"7 · Ready to check":        {"Probe from inside the cluster?"},
	}
	m := setupModel(t, func(c *engine.Ctx) {
		c.Answers.Domain = "bud.example.com"
		c.Answers.ConfigRepo = "ssh://git@github.com/acme/cfg"
	})

	reached := map[string]bool{}
	var tm tea.Model = m
	for i := 0; i < 80 && m.state == stateSetup; i++ {
		view := stripANSI(m.View())
		if h := strings.Count(view, "\n") + 1; h >= height {
			t.Errorf("intake screen is %d lines in a %d-line terminal; the bottom row must stay free", h, height)
		}
		for page, fields := range pages {
			if !strings.Contains(view, page) {
				continue
			}
			reached[page] = true
			for _, f := range fields {
				if !strings.Contains(view, f) {
					t.Errorf("page %q is on screen but its field %q is not:\n%s", page, f, view)
				}
			}
		}
		tm = pump(tm, press("enter"))
		m = tm.(*Model)
	}
	for page := range pages {
		if !reached[page] {
			t.Errorf("never reached page %q", page)
		}
	}
}

// The CA bundle is asked for exactly when it can matter: a certificate the
// operator supplies themselves is the case budctl cannot verify without the
// issuing root, and the answer is dropped again if the method changes.
func TestIntakeAsksForTheCABundleOnlyForAProvidedCertificate(t *testing.T) {
	m := setupModel(t, func(c *engine.Ctx) {
		c.Answers.Domain = "bud.example.com"
		c.Answers.TLS = intake.TLSProvided
		c.Answers.ConfigRepo = "ssh://git@github.com/acme/cfg"
	})
	_, seen := walk(t, m)
	if !strings.Contains(seen, "Internal CA bundle") {
		t.Errorf("a provided certificate was answered but the CA bundle was never asked for:\n%s", seen)
	}

	q := newQuestions(testCtx(t), "")
	q.TLS = string(intake.TLSProvided)
	q.CABundle = "/etc/pki/internal-root.pem"
	c := testCtx(t)
	q.apply(c)
	if c.Answers.CABundle != "/etc/pki/internal-root.pem" {
		t.Errorf("the answered CA bundle did not reach the run: %q", c.Answers.CABundle)
	}
	q.TLS = string(intake.TLSACMEHTTP01)
	c = testCtx(t)
	q.apply(c)
	if c.Answers.CABundle != "" {
		t.Errorf("a CA bundle left over from a changed TLS method was still applied: %q", c.Answers.CABundle)
	}
}

// A path that cannot be loaded is refused while the operator is still on the
// field, not at the first handshake.
func TestIntakeRejectsAnUnusableCABundle(t *testing.T) {
	q := newQuestions(testCtx(t), "")
	if err := q.validateCABundle("/no/such/root.pem"); err == nil {
		t.Error("a missing CA bundle file was accepted")
	}
	empty := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(empty, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := q.validateCABundle(empty); err == nil {
		t.Error("a file holding no PEM certificate was accepted")
	}
	if err := q.validateCABundle(""); err != nil {
		t.Errorf("an empty CA bundle is optional, but was rejected: %v", err)
	}
}
