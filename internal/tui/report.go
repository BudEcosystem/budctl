package tui

import (
	"github.com/BudEcosystem/budctl/check"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/output"
)

// SaveReport writes the .json and .md for a finished run. It delegates to
// output.Save, so the CLI's --save and the TUI's save key can never produce
// different files for the same run.
func SaveReport(rep check.Report, answers intake.Answers) (string, error) {
	return output.Save(rep, answers)
}

func markdownReport(rep check.Report, a intake.Answers) string {
	return output.Markdown(rep, a)
}

// partition splits results into the three lists every surface leads with.
func partition(results []check.Result) (blockers, risks, skipped []check.Result) {
	for _, r := range results {
		switch {
		case r.IsBlocker():
			blockers = append(blockers, r)
		case r.IsRisk():
			risks = append(risks, r)
		case r.State == check.StateSkip:
			skipped = append(skipped, r)
		}
	}
	return
}
