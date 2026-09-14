package engine

import (
	"sort"
	"strings"
)

// SkipGroup is a set of checks that were not verified for the same reason.
//
// When the cluster is unreachable, thirty-odd checks skip with the identical
// root cause. Listing each on its own line buries the one thing worth reading —
// why nothing could run — under a wall of near-duplicate lines. Grouping lives
// here rather than in a renderer so the TUI, the table and the saved report all
// collapse skips the same way (FRD-020 G5).
type SkipGroup struct {
	Reason string
	IDs    []string
}

// skipReasonKey collapses "cluster unreachable: no StorageClass could be read"
// and "cluster unreachable: there is no node list to read" to one reason. The
// text before the first colon is the cause; the rest is which data was missing.
func skipReasonKey(summary string) string {
	s := strings.TrimSpace(summary)
	if i := strings.Index(s, ": "); i > 0 && i < 90 {
		return s[:i]
	}
	return s
}

// GroupSkips returns skipped checks grouped by cause, largest group first.
func GroupSkips(results []Result) []SkipGroup {
	byKey := map[string]*SkipGroup{}
	order := []string{}
	for _, r := range results {
		if r.State != StateSkip {
			continue
		}
		k := skipReasonKey(r.Summary)
		g, ok := byKey[k]
		if !ok {
			// A group of one keeps the full sentence; it is the only instance,
			// so there is nothing to lose by showing all of it.
			g = &SkipGroup{Reason: k}
			byKey[k] = g
			order = append(order, k)
		}
		g.IDs = append(g.IDs, r.ID)
	}
	out := make([]SkipGroup, 0, len(order))
	for _, k := range order {
		g := *byKey[k]
		if len(g.IDs) == 1 {
			for _, r := range results {
				if r.ID == g.IDs[0] {
					g.Reason = r.Summary
				}
			}
		}
		sort.Strings(g.IDs)
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].IDs) > len(out[j].IDs) })
	return out
}

// RootCause returns the single failure that explains why a large share of the
// run could not look at anything — today, an unreachable cluster. When it exists
// it is the headline: fixing it is a precondition for every other finding
// meaning anything, so it must not sit in a list beside them.
func RootCause(results []Result) (*Result, int) {
	var cause *Result
	for i := range results {
		if results[i].ID == "toolchain.kubeconfig" && results[i].State == StateFail {
			cause = &results[i]
		}
	}
	if cause == nil {
		return nil, 0
	}
	blocked := 0
	for _, r := range results {
		if r.State == StateSkip && strings.HasPrefix(strings.TrimSpace(r.Summary), "cluster unreachable") {
			blocked++
		}
	}
	return cause, blocked
}
