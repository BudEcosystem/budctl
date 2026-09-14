// Package tui is the interactive surface of budctl: a guided intake, a live
// run, a summary and a browsable detail view. It is a view over engine.Report
// and nothing else — the TUI and --output json derive from one result set, so
// the two cannot disagree (FRD-020 G5).
package tui

import (
	"context"
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/BudEcosystem/budctl/internal/engine"
)

type appState int

const (
	stateSetup appState = iota
	stateRunning
	stateSummary
	stateDetail
)

type startedMsg struct{ check *engine.Check }
type finishedMsg struct{ result engine.Result }
type doneMsg struct{ report engine.Report }

// Model is the whole application.
type Model struct {
	ctx    *engine.Ctx
	sel    engine.Selection
	runCtx context.Context
	state  appState
	width  int
	height int

	// intake
	q    *questions
	form *huh.Form

	// run
	spin       spinner.Model
	prog       progress.Model
	statusCh   chan tea.Msg
	groupOrder []string
	groupTotal map[string]int
	groupDone  map[string]int
	current    string
	done       int
	total      int
	liveBlock  int
	liveRisk   int

	// results
	report      engine.Report
	finished    bool
	vp          viewport.Model
	showSkipped bool
	confirmQuit bool
	savedTo     string
	saveErr     string
	aborted     bool

	// detail
	tab        int
	list       list.Model
	detailVP   viewport.Model
	detailOpen bool

	help        help.Model
	summaryKeys summaryKeyMap
	detailKeys  detailKeyMap
}

// New builds the model. skipSetup starts the run immediately, for an operator
// who has already answered everything and asked not to be prompted.
func New(ctx context.Context, c *engine.Ctx, sel engine.Selection, skipSetup bool, appsDomain string) *Model {
	m := &Model{
		ctx: c, sel: sel, runCtx: ctx,
		statusCh:    make(chan tea.Msg, 512),
		groupTotal:  map[string]int{},
		groupDone:   map[string]int{},
		spin:        spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(sAccent)),
		help:        help.New(),
		summaryKeys: newSummaryKeys(),
		detailKeys:  newDetailKeys(),
		vp:          viewport.New(80, 20),
		detailVP:    viewport.New(60, 20),
	}
	m.help.Styles.ShortKey = sMuted
	// Help descriptions are text people read, so they take Muted (AA), not the
	// decorative Subtle shade that borders use.
	m.help.Styles.ShortDesc = sMuted
	m.help.Styles.ShortSeparator = lipgloss.NewStyle().Foreground(pal.Subtle)
	m.list = newResultList()

	if skipSetup {
		m.state = stateRunning
	} else {
		m.state = stateSetup
		m.q = newQuestions(c, appsDomain)
		m.form = buildIntakeForm(m.q, 0)
	}
	return m
}

func (m *Model) Init() tea.Cmd {
	if m.state == stateSetup {
		return m.form.Init()
	}
	return m.startRun()
}

// observer bridges the engine's streaming callbacks onto the message loop.
type observer struct{ ch chan tea.Msg }

func (o observer) CheckStarted(c *engine.Check)  { o.ch <- startedMsg{check: c} }
func (o observer) CheckFinished(r engine.Result) { o.ch <- finishedMsg{result: r} }

// newProgress builds the run bar on Lip Gloss's colour profile rather than
// letting Bubbles detect its own through termenv, so --no-color and NO_COLOR
// reach the bar the same way they reach everything else.
func newProgress() progress.Model {
	barHex := pal.Accent.Light
	if lipgloss.HasDarkBackground() {
		barHex = pal.Accent.Dark
	}
	return progress.New(progress.WithSolidFill(barHex), progress.WithoutPercentage(),
		progress.WithColorProfile(lipgloss.ColorProfile()))
}

func (m *Model) startRun() tea.Cmd {
	m.state = stateRunning
	m.planRun()
	m.prog = newProgress()
	go func() {
		results := engine.Run(m.runCtx, m.ctx, m.sel, observer{ch: m.statusCh})
		rep := engine.Summarize(results)
		rep.Stamp(m.ctx)
		m.statusCh <- doneMsg{report: rep}
	}()
	return tea.Batch(m.waitForMsg(), m.spin.Tick)
}

// planRun lays out the group rows before the first check starts, so the screen
// shows the whole shape of the run rather than growing as groups appear.
func (m *Model) planRun() {
	for _, ch := range engine.All() {
		if !wants(m.sel, ch) {
			continue
		}
		if _, ok := m.groupTotal[ch.Group]; !ok {
			m.groupOrder = append(m.groupOrder, ch.Group)
		}
		m.groupTotal[ch.Group]++
		m.total++
	}
}

func wants(sel engine.Selection, ch *engine.Check) bool {
	for _, s := range sel.Skip {
		if s == ch.Group || s == ch.ID {
			return false
		}
	}
	if len(sel.Only) == 0 {
		return true
	}
	for _, o := range sel.Only {
		if o == ch.Group || o == ch.ID {
			return true
		}
	}
	return false
}

func (m *Model) waitForMsg() tea.Cmd {
	return func() tea.Msg { return <-m.statusCh }
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ws, ok := msg.(tea.WindowSizeMsg); ok {
		m.width, m.height = ws.Width, ws.Height
		m.resize()
	}

	switch m.state {
	case stateSetup:
		return m.updateSetup(msg)
	case stateRunning:
		return m.updateRunning(msg)
	case stateSummary:
		return m.updateSummary(msg)
	case stateDetail:
		return m.updateDetail(msg)
	}
	return m, nil
}

func (m *Model) resize() {
	if m.form != nil && m.width > 0 {
		w := m.width - 6
		if w > 96 {
			w = 96
		}
		m.form = m.form.WithWidth(w)
		m.form = m.form.WithHeight(m.formHeight())
	}
	if m.finished {
		m.layoutSummary()
		m.layoutDetail()
	}
}

// formHeight is the height the intake form is given explicitly. Left to itself
// huh measures each page on the first WindowSizeMsg, before any DescriptionFunc
// text has loaded (those arrive later as messages), so every page is measured
// short and scrolls its first field off the top once the consequence lines
// appear — and again as they grow while the operator types. A fixed height
// taken from the terminal cannot be stale in that way.
func (m *Model) formHeight() int {
	const (
		padding = 2 // one line above and below the screen
		slack   = 1 // leave the bottom row free: drawing into it scrolls some terminals
	)
	h := m.height - padding - lipgloss.Height(m.setupChrome()) - slack
	if h < 10 {
		h = 10 // a terminal this short scrolls; a form this short is unusable
	}
	return h
}

// ── setup ───────────────────────────────────────────────────────────────────

func (m *Model) updateSetup(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		m.aborted = true
		return m, tea.Quit
	}
	fm, cmd := m.form.Update(msg)
	if f, ok := fm.(*huh.Form); ok {
		m.form = f
	}
	switch m.form.State {
	case huh.StateAborted:
		m.aborted = true
		return m, tea.Quit
	case huh.StateCompleted:
		// The form validates page by page; this is the last gate, independent
		// of which pages were visited.
		if err := m.q.validateAll(); err != nil {
			m.aborted = true
			fmt.Fprintln(os.Stderr, "budctl:", err)
			return m, tea.Quit
		}
		m.q.apply(m.ctx)
		return m, m.startRun()
	}
	return m, cmd
}

// ── running ─────────────────────────────────────────────────────────────────

func (m *Model) updateRunning(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.aborted = true
			return m, tea.Quit
		}
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case startedMsg:
		if _, ok := m.groupTotal[msg.check.Group]; !ok {
			// A dependency group the selection pulled in: add it rather than
			// letting the counts silently disagree with what ran.
			m.groupOrder = append(m.groupOrder, msg.check.Group)
			m.groupTotal[msg.check.Group] = 1
			m.total++
		}
		m.current = msg.check.Group
		return m, m.waitForMsg()
	case finishedMsg:
		m.done++
		m.groupDone[msg.result.Group]++
		if m.groupDone[msg.result.Group] > m.groupTotal[msg.result.Group] {
			m.groupTotal[msg.result.Group] = m.groupDone[msg.result.Group]
			m.total++
		}
		if msg.result.IsBlocker() {
			m.liveBlock++
		} else if msg.result.IsRisk() {
			m.liveRisk++
		}
		return m, m.waitForMsg()
	case doneMsg:
		m.report = msg.report
		m.finished = true
		m.state = stateSummary
		m.layoutSummary()
		m.layoutDetail()
		return m, nil
	}
	return m, nil
}

// ── public surface ──────────────────────────────────────────────────────────

func (m *Model) View() string {
	switch m.state {
	case stateSetup:
		return m.setupView()
	case stateRunning:
		return m.runView()
	case stateSummary:
		return m.summaryView()
	default:
		return m.detailView()
	}
}

// Report is the finished report, so the caller sets the exit code from the
// same result set the operator just read.
func (m *Model) Report() engine.Report { return m.report }

// Aborted reports whether the operator quit before a run completed.
func (m *Model) Aborted() bool { return m.aborted }

// SavedTo reports where the operator saved the report, if they did.
func (m *Model) SavedTo() string { return m.savedTo }

func (m *Model) save() {
	answers := m.ctx.Answers
	paths, err := SaveReport(m.report, answers)
	if err != nil {
		m.saveErr = err.Error()
		return
	}
	m.saveErr = ""
	m.savedTo = paths
}

// Run starts the interactive program.
func Run(ctx context.Context, c *engine.Ctx, sel engine.Selection, skipSetup bool, appsDomain string) (engine.Report, bool, error) {
	m := New(ctx, c, sel, skipSetup, appsDomain)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	final, err := p.Run()
	fm, ok := final.(*Model)
	if !ok {
		fm = m
	}
	if fm.SavedTo() != "" {
		// The alt-screen takes the in-app confirmation with it; say it again on
		// the shell where it survives.
		fmt.Fprintln(os.Stderr, "report saved to "+fm.SavedTo())
	}
	return fm.Report(), fm.Aborted(), err
}
