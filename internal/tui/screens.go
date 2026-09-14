package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// setupView frames the huh form with the tool's title and a line of context,
// so the first screen reads as the start of a guided flow rather than a bare
// prompt.
func (m *Model) setupView() string {
	return lipgloss.NewStyle().Padding(1, 2).Render(m.setupChrome() + m.form.View())
}

// setupChrome is everything the intake screen draws above the form. It is its
// own function because the form's height is derived from what is left of the
// terminal once this is drawn.
func (m *Model) setupChrome() string {
	w := m.contentWidth()
	head := titleBar("budctl · cluster readiness", "answer once, then every check runs against it", w)
	intro := sMuted.Render(wrapTo(
		"Readiness has no meaning without a target. Each answer decides what a check compares to, "+
			"and the line under it shows the consequence of the value you choose.", w-2))
	return head + "\n" + intro + "\n\n"
}

// runView shows the run as it happens: a progress card with live counts, and a
// row per group so the operator can see which part of the cluster is being
// examined and how far along it is.
func (m *Model) runView() string {
	w := m.contentWidth()
	pct := 0.0
	if m.total > 0 {
		pct = float64(m.done) / float64(m.total)
	}

	barW := w - 8
	if barW > 80 {
		barW = 80
	}
	m.prog.Width = barW

	label := "Starting"
	if m.current != "" {
		label = "Checking " + m.current
	}
	line1 := m.spin.View() + " " + sBold.Render(label)
	counter := sMuted.Render(fmt.Sprintf("%d of %d checks", m.done, m.total))
	gap := barW - lipgloss.Width(line1) - lipgloss.Width(counter)
	if gap < 1 {
		gap = 1
	}
	live := []string{}
	if m.liveBlock > 0 {
		live = append(live, sBlock.Render(fmt.Sprintf("✗ %d blocking", m.liveBlock)))
	}
	if m.liveRisk > 0 {
		live = append(live, sRisk.Render(fmt.Sprintf("▲ %d risk", m.liveRisk)))
	}
	liveLine := sMuted.Render("nothing blocking so far")
	if len(live) > 0 {
		liveLine = strings.Join(live, sMuted.Render("  ·  ")) + sMuted.Render("  so far")
	}
	progressCard := card("",
		line1+strings.Repeat(" ", gap)+counter+"\n"+m.prog.ViewAs(pct)+"\n"+liveLine,
		barW+4, pal.Accent)

	rows := []string{}
	for _, g := range m.groupOrder {
		total, done := m.groupTotal[g], m.groupDone[g]
		var icon, status string
		switch {
		case done >= total && total > 0:
			icon, status = sPass.Render("✓"), sMuted.Render(fmt.Sprintf("%d %s", total, plural(total, "check", "checks")))
		case g == m.current:
			icon, status = m.spin.View(), sAccent.Render(fmt.Sprintf("%d of %d", done, total))
		default:
			icon, status = sSkip.Render("·"), sMuted.Render("waiting")
		}
		rows = append(rows, fmt.Sprintf("  %s %s %s", icon, sText.Width(22).Render(g), status))
	}

	head := titleBar("budctl · cluster readiness", m.ctx.Answers.Domain, w)
	return lipgloss.NewStyle().Padding(1, 2).Render(
		head + "\n\n" + progressCard + "\n\n" + strings.Join(rows, "\n"))
}

func (m *Model) contentWidth() int {
	if m.width <= 0 {
		return 100
	}
	w := m.width - 4 // two columns of padding on each side
	if w > 120 {
		w = 120
	}
	return w
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
