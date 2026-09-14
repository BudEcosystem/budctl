// Package engine defines the check contract and the runner. It imports nothing
// from the UI layers: the same results back the TUI and --output json.
package engine

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Severity is what a failure MEANS, per FRD-020 §4. There is no fourth level.
type Severity string

const (
	// Block: the ApplicationSet sync, or a chart in it, will fail.
	Block Severity = "BLOCK"
	// Risk: the install succeeds; a named capability is degraded or absent.
	Risk Severity = "RISK"
	// Info: context the operator should see. Never affects the verdict.
	Info Severity = "INFO"
)

// State is what HAPPENED to the check, which is orthogonal to severity.
type State string

const (
	StatePass State = "pass"
	StateFail State = "fail"
	StateInfo State = "info"
	// StateSkip is never a pass. FRD-020 D5: "we did not look" and "we looked
	// and it was fine" are different facts, and the summary reports them apart.
	StateSkip State = "skip"
)

// Evidence is the raw material behind a result: the request that was made and
// what came back. The TUI expands it; the JSON output carries it.
type Evidence struct {
	What   string `json:"what"`
	Output string `json:"output,omitempty"`
}

// Result is what a check returns. Summary is the one-line claim; Remedy states
// what to DO, not a restatement of the failure; DoesNotProve bounds the claim so
// a pass cannot be read as more than it verified (FRD-020 G3).
type Result struct {
	ID           string        `json:"check"`
	Group        string        `json:"group"`
	State        State         `json:"state"`
	Severity     Severity      `json:"severity"`
	Summary      string        `json:"summary"`
	Detail       []string      `json:"detail,omitempty"`
	Evidence     []Evidence    `json:"evidence,omitempty"`
	Remedy       string        `json:"remedy,omitempty"`
	DoesNotProve string        `json:"does_not_prove,omitempty"`
	Gauges       []Gauge       `json:"gauges,omitempty"`
	Duration     time.Duration `json:"duration_ms"`
}

// Status is what the operator sees: a passing check reads PASS, a failing one
// reads as its severity.
func (r Result) Status() string {
	switch r.State {
	case StatePass:
		return "PASS"
	case StateInfo:
		return string(Info)
	case StateSkip:
		return "SKIP"
	default:
		if r.Severity == "" {
			return string(Block)
		}
		return string(r.Severity)
	}
}

func (r Result) IsBlocker() bool { return r.State == StateFail && r.Severity == Block }
func (r Result) IsRisk() bool    { return r.State == StateFail && r.Severity == Risk }

// Check is one question about the cluster. Severity is what a failure means
// when Run does not override it.
type Check struct {
	ID       string
	Group    string
	Severity Severity
	// Probe marks a check that creates objects in the cluster (FRD-020 §6).
	Probe bool
	// DependsOn names groups that must finish first (e.g. everything after
	// "platform", which selects the OpenShift vs vanilla variant).
	DependsOn []string
	Run       func(ctx context.Context, c *Ctx) Result
}

// Helpers so a check body reads as a claim rather than as struct assembly.

func (ch *Check) Pass(summary string, detail ...string) Result {
	return Result{ID: ch.ID, Group: ch.Group, State: StatePass, Severity: ch.Severity, Summary: summary, Detail: detail}
}

func (ch *Check) Fail(summary, remedy string, detail ...string) Result {
	return Result{ID: ch.ID, Group: ch.Group, State: StateFail, Severity: ch.Severity, Summary: summary, Remedy: remedy, Detail: detail}
}

// FailAs overrides the declared severity — used where the same check is a
// blocker in one configuration and a risk in another.
func (ch *Check) FailAs(sev Severity, summary, remedy string, detail ...string) Result {
	return Result{ID: ch.ID, Group: ch.Group, State: StateFail, Severity: sev, Summary: summary, Remedy: remedy, Detail: detail}
}

func (ch *Check) Infof(format string, a ...any) Result {
	return Result{ID: ch.ID, Group: ch.Group, State: StateInfo, Severity: Info, Summary: fmt.Sprintf(format, a...)}
}

// Skip always carries a reason. A skip with no reason is indistinguishable from
// a pass in a scan of the output, which is exactly the failure D5 forbids.
func (ch *Check) Skip(reason string) Result {
	return Result{ID: ch.ID, Group: ch.Group, State: StateSkip, Severity: ch.Severity, Summary: reason}
}

// Verdict is the run-level answer.
type Verdict string

const (
	Ready          Verdict = "READY"
	ReadyWithRisks Verdict = "READY WITH RISKS"
	NotReady       Verdict = "NOT READY"
)

type Report struct {
	Verdict  Verdict           `json:"verdict"`
	Counts   map[string]int    `json:"counts"`
	Results  []Result          `json:"results"`
	Platform string            `json:"platform"`
	Meta     map[string]string `json:"meta,omitempty"`
}

func Summarize(results []Result) Report {
	rep := Report{Counts: map[string]int{}, Results: results, Verdict: Ready}
	for _, r := range results {
		rep.Counts[r.Status()]++
		if r.IsBlocker() {
			rep.Verdict = NotReady
		} else if r.IsRisk() && rep.Verdict == Ready {
			rep.Verdict = ReadyWithRisks
		}
	}
	sort.SliceStable(rep.Results, func(i, j int) bool {
		return rep.Results[i].Group < rep.Results[j].Group
	})
	return rep
}

// With appends detail lines. Chaining keeps a check body reading as a claim:
//
//	return ch.Pass("all nodes Ready").With(names...)
func (r Result) With(detail ...string) Result {
	r.Detail = append(r.Detail, detail...)
	return r
}

// WithEvidence attaches the raw request/response behind the claim.
func (r Result) WithEvidence(ev ...Evidence) Result {
	r.Evidence = append(r.Evidence, ev...)
	return r
}

// Bounds records what this result does NOT establish, so a pass is never read
// as more than it verified (FRD-020 G3).
func (r Result) Bounds(s string) Result {
	r.DoesNotProve = s
	return r
}

// Gauge is a measured quantity set against what the install needs from it —
// free image-filesystem space against the floor, provisionable storage against
// the requirement. It is optional and additive: a result without gauges is
// complete, and renderers that ignore them lose nothing but the bar.
//
// It exists because "47.4GiB free" and "80 GiB required" read as two numbers,
// while a half-filled bar reads as a shortfall at a glance.
type Gauge struct {
	Label string  `json:"label"`
	Have  float64 `json:"have"`
	Need  float64 `json:"need"`
	// Unit is "bytes" or "cores"; renderers format Have and Need with it.
	Unit string `json:"unit"`
}

// Short reports whether the measured quantity falls below the need.
func (g Gauge) Short() bool { return g.Have < g.Need }

// WithGauges attaches measurements to a result.
func (r Result) WithGauges(g ...Gauge) Result {
	r.Gauges = append(r.Gauges, g...)
	return r
}
