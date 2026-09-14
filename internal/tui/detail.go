package tui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/BudEcosystem/budctl/internal/engine"
)

// The detail view is for working through one finding: a status-filtered,
// searchable list of every check on the left and the selected check's full
// record — evidence, measurements, remedy, and what it does NOT prove — on the
// right. Below 100 columns the two panes cannot both be read, so the list takes
// the screen and enter opens the record.

var detailTabs = []struct {
	label string
	keep  func(engine.Result) bool
}{
	{"All", func(engine.Result) bool { return true }},
	{"Blocking", func(r engine.Result) bool { return r.IsBlocker() }},
	{"Risks", func(r engine.Result) bool { return r.IsRisk() }},
	{"Not verified", func(r engine.Result) bool { return r.State == engine.StateSkip }},
	{"Passed", func(r engine.Result) bool { return r.State == engine.StatePass }},
}

type resultItem struct{ r engine.Result }

func (i resultItem) FilterValue() string { return i.r.ID + " " + i.r.Summary }

type resultDelegate struct{}

func (resultDelegate) Height() int                         { return 2 }
func (resultDelegate) Spacing() int                        { return 0 }
func (resultDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (resultDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	it, ok := item.(resultItem)
	if !ok {
		return
	}
	st := it.r.Status()
	width := m.Width() - 3
	if width < 20 {
		width = 20
	}
	selected := index == m.Index()

	gutter := "  "
	idStyle := sText
	if selected {
		gutter = sAccent.Render("▌ ")
		idStyle = sBold
	}
	icon := lipgloss.NewStyle().Foreground(statusColor(st)).Render(statusIcon(st))
	line1 := gutter + icon + " " + idStyle.Render(ansi.Truncate(it.r.ID, width-2, "…"))
	line2 := "    " + sMuted.Render(ansi.Truncate(it.r.Summary, width-2, "…"))
	fmt.Fprint(w, line1+"\n"+line2)
}

func newResultList() list.Model {
	l := list.New(nil, resultDelegate{}, 40, 20)
	l.SetShowTitle(false)
	l.SetShowHelp(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.DisableQuitKeybindings()
	l.Styles.FilterPrompt = sAccent
	l.Styles.FilterCursor = sAccent
	l.Styles.NoItems = sMuted.Padding(0, 2)
	return l
}

// tabItems returns the results for a status tab, worst first, so the list opens
// on the findings that matter rather than on alphabetical order.
func (m *Model) tabItems(tab int) []list.Item {
	rank := map[string]int{"BLOCK": 0, "RISK": 1, "SKIP": 2, "INFO": 3, "PASS": 4}
	rs := []engine.Result{}
	for _, r := range m.report.Results {
		if detailTabs[tab].keep(r) {
			rs = append(rs, r)
		}
	}
	sort.SliceStable(rs, func(i, j int) bool {
		if rank[rs[i].Status()] != rank[rs[j].Status()] {
			return rank[rs[i].Status()] < rank[rs[j].Status()]
		}
		return rs[i].ID < rs[j].ID
	})
	items := make([]list.Item, len(rs))
	for i, r := range rs {
		items[i] = resultItem{r}
	}
	return items
}

func (m *Model) wide() bool { return m.contentWidth() >= 100 }

func (m *Model) layoutDetail() {
	w := m.contentWidth()
	h := m.height - 7 // padding, title, tabs, footer
	if m.height <= 0 {
		h = 40
	}
	if h < 6 {
		h = 6
	}
	listW := w
	if m.wide() {
		listW = w * 42 / 100
		m.detailVP.Width = w - listW - 2
	} else {
		m.detailVP.Width = w
	}
	m.detailVP.Height = h
	m.list.SetSize(listW, h)
	m.list.SetItems(m.tabItems(m.tab))
	m.refreshDetailPane()
}

func (m *Model) selected() (engine.Result, bool) {
	if it, ok := m.list.SelectedItem().(resultItem); ok {
		return it.r, true
	}
	return engine.Result{}, false
}

func (m *Model) refreshDetailPane() {
	r, ok := m.selected()
	if !ok {
		m.detailVP.SetContent(sMuted.Render("No check matches this filter."))
		return
	}
	m.detailVP.SetContent(recordCard(r, m.detailVP.Width))
	m.detailVP.GotoTop()
}

// recordCard renders one check's complete record. Its border carries the
// status, and "does not prove" is kept — a pass is never presented as more than
// it verified.
func recordCard(r engine.Result, width int) string {
	inner := width - 4
	st := r.Status()
	parts := []string{badge(st) + "  " + sMuted.Render(r.Group), sText.Render(wrapTo(r.Summary, inner))}

	if len(r.Gauges) > 0 {
		bars := []string{}
		for _, g := range r.Gauges {
			bars = append(bars, gaugeBar(g, inner))
		}
		parts = append(parts, strings.Join(bars, "\n"))
	}
	if len(r.Detail) > 0 {
		lines := []string{}
		for _, d := range r.Detail {
			lines = append(lines, sMuted.Render("• ")+sText.Render(wrapTo(d, inner-2)))
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	if r.Remedy != "" {
		parts = append(parts, sBold.Render("Fix")+"\n"+sAccent.Render(wrapTo(r.Remedy, inner)))
	}
	if len(r.Evidence) > 0 {
		lines := []string{sBold.Render("Evidence")}
		for _, e := range r.Evidence {
			lines = append(lines, sMuted.Render(wrapTo("$ "+e.What, inner)))
			if out := strings.TrimSpace(e.Output); out != "" {
				for _, l := range strings.Split(out, "\n") {
					// Wrap with a hanging indent: a continuation is visibly part
					// of the line above, and no figure loses its unit.
					wrapped := strings.Split(ansi.Wrap(l, inner-4, ""), "\n")
					for i, w := range wrapped {
						indent := "    "
						if i == 0 {
							indent = "  "
						}
						lines = append(lines, indent+sText.Render(w))
					}
				}
			}
		}
		parts = append(parts, strings.Join(lines, "\n"))
	}
	if r.DoesNotProve != "" {
		parts = append(parts, sBold.Render("Does not prove")+"\n"+sMuted.Render(wrapTo(r.DoesNotProve, inner)))
	}
	return card(r.ID, strings.Join(parts, "\n\n"), width, statusColor(st))
}

func (m *Model) tabBar() string {
	counts := make([]int, len(detailTabs))
	for _, r := range m.report.Results {
		for i, t := range detailTabs {
			if t.keep(r) {
				counts[i]++
			}
		}
	}
	tabs := []string{}
	for i, t := range detailTabs {
		label := fmt.Sprintf(" %s %d ", t.label, counts[i])
		if i == m.tab {
			tabs = append(tabs, lipgloss.NewStyle().Foreground(pal.Accent).Background(pal.SelBg).Bold(true).Render(label))
		} else {
			tabs = append(tabs, sMuted.Render(label))
		}
	}
	return strings.Join(tabs, " ")
}

func (m *Model) detailView() string {
	w := m.contentWidth()
	head := titleBar("budctl · all checks", string(m.report.Verdict), w)

	var body string
	switch {
	case m.confirmQuit:
		body = dialog("Save the report before quitting?",
			sText.Render("The findings disappear when budctl exits.")+"\n\n"+
				sAccent.Render("y")+sMuted.Render(" save and quit    ")+
				sAccent.Render("n")+sMuted.Render(" quit without saving    ")+
				sAccent.Render("esc")+sMuted.Render(" back"),
			w, m.detailVP.Height)
	case m.wide():
		body = lipgloss.JoinHorizontal(lipgloss.Top, m.list.View(), "  ", m.detailVP.View())
	case m.detailOpen:
		body = m.detailVP.View()
	default:
		body = m.list.View()
	}

	footer := m.help.ShortHelpView(m.detailKeys.ShortHelp())
	if m.savedTo != "" {
		footer = sPass.Render("✓ saved ") + sMuted.Render(m.savedTo) + "   " + footer
	}
	return lipgloss.NewStyle().Padding(1, 2, 0, 2).Render(
		head + "\n" + m.tabBar() + "\n\n" + body + "\n" + footer)
}

func (m *Model) updateDetail(msg tea.Msg) (tea.Model, tea.Cmd) {
	k, isKey := msg.(tea.KeyMsg)

	// While the operator is typing a search, every key belongs to the filter.
	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		m.refreshDetailPane()
		return m, cmd
	}

	if isKey {
		if cmd, handled := m.handleQuit(k); handled {
			return m, cmd
		}
		switch k.String() {
		case "esc", "backspace":
			if m.detailOpen {
				m.detailOpen = false
				return m, nil
			}
			if m.list.FilterState() == list.FilterApplied {
				m.list.ResetFilter()
				m.refreshDetailPane()
				return m, nil
			}
			m.state = stateSummary
			m.layoutSummary()
			return m, nil
		case "tab":
			m.setTab((m.tab + 1) % len(detailTabs))
			return m, nil
		case "shift+tab":
			m.setTab((m.tab - 1 + len(detailTabs)) % len(detailTabs))
			return m, nil
		case "1", "2", "3", "4", "5":
			m.setTab(int(k.String()[0] - '1'))
			return m, nil
		case "enter":
			if !m.wide() {
				m.detailOpen = !m.detailOpen
			}
			return m, nil
		case "s":
			m.save()
			return m, nil
		}
		if m.detailOpen && !m.wide() {
			switch {
			case key.Matches(k, m.summaryKeys.Up):
				m.detailVP.ScrollUp(1)
			case key.Matches(k, m.summaryKeys.Down):
				m.detailVP.ScrollDown(1)
			}
			return m, nil
		}
		// Page the record pane from the list in wide mode.
		if m.wide() {
			switch k.String() {
			case "pgdown", " ":
				m.detailVP.PageDown()
				return m, nil
			case "pgup", "b":
				m.detailVP.PageUp()
				return m, nil
			}
		}
	}

	var cmd tea.Cmd
	before := m.list.Index()
	m.list, cmd = m.list.Update(msg)
	if m.list.Index() != before {
		m.refreshDetailPane()
	}
	return m, cmd
}

func (m *Model) setTab(t int) {
	m.tab = t
	m.list.ResetFilter()
	m.list.SetItems(m.tabItems(t))
	m.list.Select(0)
	m.refreshDetailPane()
}
