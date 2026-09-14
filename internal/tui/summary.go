package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BudEcosystem/budctl/internal/engine"
)

// The summary is what the operator leaves with. It pins the verdict and the
// headline figures, scrolls the findings beneath them, and leads with whatever
// makes the rest provisional — an unreachable cluster — then what blocks, what
// degrades and what was never verified.

func (m *Model) summaryHeader() string {
	w := m.contentWidth()
	where := "cluster unreachable"
	if m.ctx.Kube != nil && m.ctx.Platform.Version != "" {
		where = fmt.Sprintf("%s %s", m.ctx.Platform.Distribution, m.ctx.Platform.Version)
	}
	right := where
	if d := m.ctx.Answers.Domain; d != "" {
		right += "  ·  " + d
	}
	head := titleBar("budctl · cluster readiness", right, w)
	switch {
	case m.savedTo != "":
		head += "\n" + sPass.Render("✓ saved "+m.savedTo)
	case m.saveErr != "":
		head += "\n" + sBlock.Render("✗ save failed: "+m.saveErr)
	}
	return head + "\n\n" + m.statRow(w) + "\n"
}

// statRow is the headline: the verdict and four counts as tiles. Below 76
// columns the tiles would wrap into noise, so it degrades to one line.
func (m *Model) statRow(w int) string {
	rep := m.report
	vColor := pal.Pass
	switch rep.Verdict {
	case engine.NotReady:
		vColor = pal.Block
	case engine.ReadyWithRisks:
		vColor = pal.Risk
	}
	countColor := func(n int, c lipgloss.AdaptiveColor) lipgloss.AdaptiveColor {
		if n == 0 {
			return pal.Subtle
		}
		return c
	}

	if w < 76 {
		return lipgloss.NewStyle().Foreground(vColor).Bold(true).Render(string(rep.Verdict)) + "  " +
			sMuted.Render(fmt.Sprintf("%d blocking · %d risk · %d passed · %d not verified",
				rep.Counts["BLOCK"], rep.Counts["RISK"], rep.Counts["PASS"], rep.Counts["SKIP"]))
	}

	verdictW := w * 30 / 100
	tileW := (w - verdictW) / 4
	return lipgloss.JoinHorizontal(lipgloss.Top,
		statCard(string(rep.Verdict), "verdict", vColor, verdictW),
		statCard(fmt.Sprint(rep.Counts["BLOCK"]), "blocking", countColor(rep.Counts["BLOCK"], pal.Block), tileW),
		statCard(fmt.Sprint(rep.Counts["RISK"]), "risks", countColor(rep.Counts["RISK"], pal.Risk), tileW),
		statCard(fmt.Sprint(rep.Counts["PASS"]), "passed", countColor(rep.Counts["PASS"], pal.Pass), tileW),
		statCard(fmt.Sprint(rep.Counts["SKIP"]), "not verified", pal.Skip, tileW),
	)
}

func (m *Model) summaryFooter() string {
	more := ""
	if !m.vp.AtBottom() {
		below := m.vp.TotalLineCount() - m.vp.YOffset - m.vp.VisibleLineCount()
		if below > 0 {
			more = sAccent.Render(fmt.Sprintf("↓ %d more below", below)) + "   "
		}
	} else if m.vp.YOffset > 0 {
		more = sMuted.Render(fmt.Sprintf("↑ %d more above", m.vp.YOffset)) + "   "
	}
	return more + m.help.ShortHelpView(m.summaryKeys.ShortHelp())
}

// summaryBody builds the scrollable findings. Cards are sized to the content
// width so a long remedy wraps inside its box instead of running off screen.
func (m *Model) summaryBody() string {
	rep := m.report
	w := m.contentWidth()
	inner := w - 4
	blocks := []string{}

	cause, blocked := engine.RootCause(rep.Results)
	if cause != nil {
		body := sText.Render(wrapTo(cause.Summary, inner))
		if cause.Remedy != "" {
			body += "\n" + sAccent.Render(wrapTo("→ "+cause.Remedy, inner))
		}
		if blocked > 0 {
			body += "\n" + sMuted.Render(wrapTo(fmt.Sprintf(
				"%d checks could not run until this is fixed, so everything below reflects only what could be checked from this machine.", blocked), inner))
		}
		blocks = append(blocks, card("✗  Fix this first — the cluster could not be reached", body, w, pal.Block))
	}

	blockers, risks, _ := partition(rep.Results)
	shown := 0
	for _, r := range blockers {
		if cause != nil && r.ID == cause.ID {
			continue
		}
		if shown == 0 {
			blocks = append(blocks, sBlock.Bold(true).Render(fmt.Sprintf("BLOCKING — the install will fail (%d)", len(blockers)-boolInt(cause != nil))))
		}
		shown++
		body := sText.Render(wrapTo(r.Summary, inner))
		if len(r.Gauges) > 0 {
			bars := []string{}
			for _, g := range r.Gauges {
				bars = append(bars, gaugeBar(g, inner))
			}
			body += "\n\n" + strings.Join(bars, "\n")
		}
		if r.Remedy != "" {
			body += "\n\n" + sAccent.Render(wrapTo("→ "+r.Remedy, inner))
		}
		blocks = append(blocks, card("✗  "+r.ID, body, w, pal.Block))
	}
	if shown == 0 && cause == nil {
		blocks = append(blocks, card("✓  Nothing blocks the install", sMuted.Render("Every check that could run found the cluster able to host Bud."), w, pal.Pass))
	}

	if len(risks) > 0 {
		lines := []string{}
		for _, r := range risks {
			lines = append(lines, sRisk.Bold(true).Render("▲ "+r.ID))
			lines = append(lines, sMuted.Render(wrapTo(r.Summary, inner-2)))
		}
		blocks = append(blocks, card(fmt.Sprintf("RISKS — installs, but a capability is degraded (%d)", len(risks)),
			strings.Join(lines, "\n"), w, pal.Risk))
	}

	groups := engine.GroupSkips(rep.Results)
	if len(groups) > 0 {
		lines := []string{sMuted.Render("These are not passes — each group says why the checks could not run.")}
		for _, g := range groups {
			label := g.IDs[0] + " — " + g.Reason
			if len(g.IDs) > 1 {
				label = fmt.Sprintf("%d checks — %s", len(g.IDs), g.Reason)
			}
			lines = append(lines, sSkip.Render("○ ")+sText.Render(wrapTo(label, inner-2)))
			if m.showSkipped && len(g.IDs) > 1 {
				lines = append(lines, "  "+sMuted.Render(wrapTo(strings.Join(g.IDs, ", "), inner-4)))
			}
		}
		title := fmt.Sprintf("NOT VERIFIED — %d checks, %d reason(s)", rep.Counts["SKIP"], len(groups))
		blocks = append(blocks, card(title, strings.Join(lines, "\n"), w, pal.Skip))
	}

	return strings.Join(blocks, "\n")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// layoutSummary sizes the viewport to whatever the pinned header and footer
// leave, so the page never overflows the terminal and pushes the verdict off.
func (m *Model) layoutSummary() {
	w := m.contentWidth()
	header := m.summaryHeader()
	footerH := 1
	h := m.height - lipgloss.Height(header) - footerH - 3 // top/bottom padding and a gap
	if m.height <= 0 {
		h = 1 << 12
	}
	if h < 3 {
		h = 3
	}
	offset := m.vp.YOffset
	m.vp.Width = w
	m.vp.Height = h
	m.vp.SetContent(m.summaryBody())
	m.vp.SetYOffset(offset)
}

func (m *Model) summaryView() string {
	header := m.summaryHeader()
	var body string
	if m.confirmQuit {
		body = dialog("Save the report before quitting?",
			sText.Render("The findings disappear when budctl exits.")+"\n\n"+
				sAccent.Render("y")+sMuted.Render(" save and quit    ")+
				sAccent.Render("n")+sMuted.Render(" quit without saving    ")+
				sAccent.Render("esc")+sMuted.Render(" back"),
			m.contentWidth(), m.vp.Height)
	} else {
		body = m.vp.View()
	}
	return lipgloss.NewStyle().Padding(1, 2, 0, 2).Render(
		header + "\n" + body + "\n" + m.summaryFooter())
}

func (m *Model) updateSummary(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if cmd, handled := m.handleQuit(k); handled {
		return m, cmd
	}
	switch {
	case key.Matches(k, m.summaryKeys.Up):
		m.vp.ScrollUp(1)
	case key.Matches(k, m.summaryKeys.Down):
		m.vp.ScrollDown(1)
	case k.String() == "pgup" || k.String() == "b":
		m.vp.PageUp()
	case k.String() == "pgdown" || k.String() == " ":
		m.vp.PageDown()
	case k.String() == "g" || k.String() == "home":
		m.vp.GotoTop()
	case k.String() == "G" || k.String() == "end":
		m.vp.GotoBottom()
	case key.Matches(k, m.summaryKeys.Skipped):
		m.showSkipped = !m.showSkipped
		m.layoutSummary()
	case key.Matches(k, m.summaryKeys.Detail):
		m.state = stateDetail
		m.layoutDetail()
	case key.Matches(k, m.summaryKeys.Save):
		m.save()
		m.layoutSummary()
	}
	return m, nil
}

// handleQuit is shared by the summary and detail screens. Quitting with an
// unsaved report asks once: the findings vanish with the alt-screen, and "I
// should have saved that" is worth asking before it becomes true.
func (m *Model) handleQuit(k tea.KeyMsg) (tea.Cmd, bool) {
	if m.confirmQuit {
		switch k.String() {
		case "y", "Y":
			m.save()
			if m.saveErr != "" {
				m.confirmQuit = false
				m.layoutSummary()
				return nil, true
			}
			return tea.Quit, true
		case "n", "N":
			return tea.Quit, true
		case "esc":
			m.confirmQuit = false
		}
		return nil, true
	}
	switch k.String() {
	case "ctrl+c":
		return tea.Quit, true
	case "q", "esc":
		if k.String() == "esc" && m.state == stateDetail {
			return nil, false // esc in the detail view means "back", not "quit"
		}
		if m.savedTo == "" {
			m.confirmQuit = true
			return nil, true
		}
		return tea.Quit, true
	}
	return nil, false
}
