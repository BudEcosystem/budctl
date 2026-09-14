package engine

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Selection narrows a run.
type Selection struct {
	Only []string // group or check ids; empty means everything
	Skip []string
}

func (s Selection) wants(c *Check) bool {
	for _, sk := range s.Skip {
		if sk == c.Group || sk == c.ID {
			return false
		}
	}
	if len(s.Only) == 0 {
		return true
	}
	for _, on := range s.Only {
		if on == c.Group || on == c.ID {
			return true
		}
	}
	return false
}

// Observer streams results as they land so the TUI can render progressively.
type Observer interface {
	CheckStarted(c *Check)
	CheckFinished(r Result)
}

type nopObserver struct{}

func (nopObserver) CheckStarted(*Check)  {}
func (nopObserver) CheckFinished(Result) {}

// Run executes the selected checks group by group. Within a group checks run
// concurrently; groups are sequential so that a later group can rely on what an
// earlier one recorded on Ctx — "platform" in particular.
//
// A check that panics becomes a RISK naming itself as a budctl bug rather than
// taking the whole run down: a readiness tool that dies partway tells the
// operator nothing about the rest of the cluster.
func Run(ctx context.Context, c *Ctx, sel Selection, obs Observer) []Result {
	if obs == nil {
		obs = nopObserver{}
	}
	selected := []*Check{}
	for _, ch := range All() {
		if sel.wants(ch) {
			selected = append(selected, ch)
		}
	}
	// Pull in dependencies of selected groups so `--only storage` still detects
	// the platform first instead of silently branching wrong.
	selected = withDependencies(selected, sel)

	byGroup := map[string][]*Check{}
	order := []string{}
	for _, ch := range selected {
		if _, seen := byGroup[ch.Group]; !seen {
			order = append(order, ch.Group)
		}
		byGroup[ch.Group] = append(byGroup[ch.Group], ch)
	}

	limit := runtime.NumCPU()
	if limit > 8 {
		limit = 8
	}
	if limit < 2 {
		limit = 2
	}

	var out []Result
	for _, g := range order {
		checks := byGroup[g]
		results := make([]Result, len(checks))
		sem := make(chan struct{}, limit)
		var wg sync.WaitGroup
		for i, ch := range checks {
			wg.Add(1)
			go func(i int, ch *Check) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				results[i] = runOne(ctx, c, ch, obs)
			}(i, ch)
		}
		wg.Wait()
		out = append(out, results...)
	}
	return out
}

func withDependencies(selected []*Check, sel Selection) []*Check {
	need := map[string]bool{}
	for _, ch := range selected {
		for _, dep := range ch.DependsOn {
			need[dep] = true
		}
	}
	if len(need) == 0 {
		return selected
	}
	have := map[string]bool{}
	for _, ch := range selected {
		have[ch.Group] = true
	}
	extra := []*Check{}
	for _, ch := range All() {
		if need[ch.Group] && !have[ch.Group] {
			for _, sk := range sel.Skip {
				if sk == ch.Group {
					goto next
				}
			}
			extra = append(extra, ch)
		}
	next:
	}
	return append(extra, selected...)
}

func runOne(ctx context.Context, c *Ctx, ch *Check, obs Observer) (res Result) {
	obs.CheckStarted(ch)
	started := c.Now()
	defer func() {
		if p := recover(); p != nil {
			res = Result{
				ID: ch.ID, Group: ch.Group, State: StateFail, Severity: Risk,
				Summary: fmt.Sprintf("check panicked: %v", p),
				Remedy:  "this is a bug in budctl, not necessarily in the cluster; re-run with --skip " + ch.Group,
			}
		}
		res.Duration = c.Now().Sub(started)
		obs.CheckFinished(res)
	}()

	if ch.Probe && c.Opts.NoProbe {
		return ch.Skip("--no-probe: not verified, and therefore not confirmed working")
	}
	timeout := c.Opts.CheckTimeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return ch.Run(cctx, c)
}
