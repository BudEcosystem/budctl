package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/engine"
)

// A report saved from the interactive view is the one an operator attaches to a
// ticket. It once went out with no budctl version, no catalogue and "cluster:
// unreachable" over a run that had just passed 48 checks against that cluster,
// because only the non-interactive path stamped the report, and it did so after
// the interactive view had already written the file.
func TestInteractiveRunReportNamesTheBuildAndTheCluster(t *testing.T) {
	c := testCtx(t)
	c.Opts.BudctlVersion = "0.3.1-test"
	c.Answers.Domain = "bud.example.com"
	c.Platform.Distribution = engine.DistVanilla
	c.Platform.Version = "v1.36.3+k3s1"

	// One offline check with no dependencies: the run finishes at once and
	// needs neither a cluster nor a network.
	m := New(context.Background(), c, engine.Selection{Only: []string{"toolchain.age-identity"}}, true, "")
	_ = m.startRun()

	var rep engine.Report
	deadline := time.After(30 * time.Second)
	for done := false; !done; {
		select {
		case msg := <-m.statusCh:
			if d, ok := msg.(doneMsg); ok {
				rep, done = d.report, true
			}
		case <-deadline:
			t.Fatal("the run never finished")
		}
	}

	for key, want := range map[string]string{
		"budctlVersion":  "0.3.1-test",
		"catalogVersion": c.Profile.CatalogVersion,
		"serverVersion":  "v1.36.3+k3s1",
		"domain":         "bud.example.com",
	} {
		if got := rep.Meta[key]; got != want {
			t.Errorf("report meta %s = %q, want %q", key, got, want)
		}
	}

	md := markdownReport(rep, c.Answers)
	for _, want := range []string{"0.3.1-test", c.Profile.CatalogVersion, "v1.36.3+k3s1"} {
		if !strings.Contains(md, want) {
			t.Errorf("saved markdown does not mention %q", want)
		}
	}
	if strings.Contains(md, "unreachable") {
		t.Errorf("saved markdown calls a reachable cluster unreachable:\n%s", md)
	}
}
