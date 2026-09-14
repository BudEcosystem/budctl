package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// SaveReport writes the .json and .md for a finished run and returns both paths.
// The CLI's --save and the TUI's save key share it, so the two surfaces can
// never produce different files for the same run.
func SaveReport(rep engine.Report, answers intake.Answers) (string, error) {
	stamp := time.Now().Format("20060102-150405")
	base := "budctl-readiness-" + stamp

	jsonPath := base + ".json"
	f, err := os.Create(jsonPath)
	if err != nil {
		return "", err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	err = enc.Encode(rep)
	_ = f.Close()
	if err != nil {
		return "", err
	}

	mdPath := base + ".md"
	if err := os.WriteFile(mdPath, []byte(markdownReport(rep, answers)), 0o644); err != nil {
		return "", err
	}
	return jsonPath + " and " + mdPath, nil
}

// partition splits results into the three lists every surface leads with.
func partition(results []engine.Result) (blockers, risks, skipped []engine.Result) {
	for _, r := range results {
		switch {
		case r.IsBlocker():
			blockers = append(blockers, r)
		case r.IsRisk():
			risks = append(risks, r)
		case r.State == engine.StateSkip:
			skipped = append(skipped, r)
		}
	}
	return
}

// markdownReport is the shareable artefact. It states what the cluster was
// checked AGAINST, because a verdict without its target is not interpretable.
// Credentials in the answers are deliberately never written.
func markdownReport(rep engine.Report, a intake.Answers) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Bud cluster readiness — %s\n\n", rep.Verdict)
	fmt.Fprintf(&b, "%d passed · %d blocking · %d risk · %d informational · %d not verified\n\n",
		rep.Counts["PASS"], rep.Counts["BLOCK"], rep.Counts["RISK"],
		rep.Counts["INFO"], rep.Counts["SKIP"])

	b.WriteString("## Checked against\n\n")
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| domain | %s |\n", orDash(a.Domain))
	fmt.Fprintf(&b, "| TLS | %s |\n", orDash(string(a.TLS)))
	fmt.Fprintf(&b, "| model storage | %d GiB across ~%d models |\n", a.ModelStorageGi, a.ModelCount)
	fmt.Fprintf(&b, "| concurrent deployments | %d |\n", a.Deployments)
	fmt.Fprintf(&b, "| accelerators | %s |\n", yesNo(a.GPU))
	fmt.Fprintf(&b, "| data stores | %s |\n", inClusterOrExternal(a.InClusterData))
	cluster := rep.Platform
	if sv := rep.Meta["serverVersion"]; sv != "" {
		cluster += " " + sv
	}
	if cause, _ := engine.RootCause(rep.Results); cause != nil || rep.Meta["serverVersion"] == "" {
		cluster = "unreachable — see below"
	}
	fmt.Fprintf(&b, "| cluster | %s |\n", cluster)
	fmt.Fprintf(&b, "| budctl | %s (catalogue %s) |\n", orDash(rep.Meta["budctlVersion"]), orDash(rep.Meta["catalogVersion"]))

	if cause, blocked := engine.RootCause(rep.Results); cause != nil {
		b.WriteString("\n## Fix this first — the cluster could not be reached\n\n")
		fmt.Fprintf(&b, "%s\n\n", cause.Summary)
		if cause.Remedy != "" {
			fmt.Fprintf(&b, "**Fix:** %s\n\n", cause.Remedy)
		}
		fmt.Fprintf(&b, "%d checks could not run until this is fixed, so this report reflects only what could be checked from the machine budctl ran on.\n", blocked)
	}

	blockers, risks, _ := partition(rep.Results)

	b.WriteString("\n## Blocking — the install will fail\n\n")
	if len(blockers) == 0 {
		b.WriteString("None.\n")
	}
	for _, r := range blockers {
		fmt.Fprintf(&b, "### `%s`\n\n%s\n\n", r.ID, r.Summary)
		for _, g := range r.Gauges {
			mark := "ok"
			if g.Short() {
				mark = "**short**"
			}
			fmt.Fprintf(&b, "- %s: %s of %s needed — %s\n", g.Label, formatQty(g.Have, g.Unit), formatQty(g.Need, g.Unit), mark)
		}
		for _, d := range r.Detail {
			fmt.Fprintf(&b, "- %s\n", d)
		}
		if r.Remedy != "" {
			fmt.Fprintf(&b, "\n**Fix:** %s\n", r.Remedy)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Risks — the install succeeds, a capability is degraded\n\n")
	if len(risks) == 0 {
		b.WriteString("None.\n\n")
	}
	for _, r := range risks {
		fmt.Fprintf(&b, "- **`%s`** — %s\n", r.ID, r.Summary)
		if r.Remedy != "" {
			fmt.Fprintf(&b, "  - *Fix:* %s\n", r.Remedy)
		}
	}

	b.WriteString("\n## Not verified\n\n")
	b.WriteString("These are **not** passes — budctl did not look. Grouped by cause.\n\n")
	for _, g := range engine.GroupSkips(rep.Results) {
		if len(g.IDs) == 1 {
			fmt.Fprintf(&b, "- `%s` — %s\n", g.IDs[0], g.Reason)
			continue
		}
		fmt.Fprintf(&b, "- **%d checks — %s**\n  - `%s`\n", len(g.IDs), g.Reason, strings.Join(g.IDs, "`, `"))
	}
	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func inClusterOrExternal(inCluster bool) string {
	if inCluster {
		return "in-cluster (installed by the ApplicationSet)"
	}
	return "external / managed"
}
