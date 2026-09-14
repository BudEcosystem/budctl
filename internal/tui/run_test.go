package tui

import (
	"context"
	"strings"
	"testing"

	"github.com/BudEcosystem/budctl/internal/engine"
)

// The run screen shows the whole shape of the run up front, live progress, and
// findings as they land.
func TestRunScreenShowsProgressGroupsAndLiveCounts(t *testing.T) {
	c := testCtx(t)
	c.Answers.Domain = "bud.example.com"
	m := New(context.Background(), c, engine.Selection{}, true, "")
	m.width, m.height = 110, 40
	m.planRun()
	m.state = stateRunning
	m.current = "storage"
	m.groupDone["platform"] = m.groupTotal["platform"]
	m.done = m.groupTotal["platform"] + 2
	m.groupDone["storage"] = 2
	m.liveBlock = 1

	view := stripANSI(m.View())
	for _, want := range []string{"Checking storage", "of " + itoa(m.total) + " checks", "✗ 1 blocking", "platform", "storage", "2 of", "waiting"} {
		if !strings.Contains(view, want) {
			t.Errorf("run screen missing %q:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "✓") {
		t.Error("a finished group is not marked done")
	}
}
