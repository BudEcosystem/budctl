package tui

import "github.com/charmbracelet/bubbles/key"

// Key maps drive both behaviour and the help bar, so what the bar advertises is
// exactly what the keys do.

type summaryKeyMap struct {
	Up, Down, Page, Skipped, Detail, Save, Quit key.Binding
}

func newSummaryKeys() summaryKeyMap {
	return summaryKeyMap{
		Up:      key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:    key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Page:    key.NewBinding(key.WithKeys("pgdown", "pgup", " ", "b"), key.WithHelp("space/b", "page")),
		Skipped: key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "expand not-verified")),
		Detail:  key.NewBinding(key.WithKeys("d", "enter", "tab"), key.WithHelp("d", "browse all checks")),
		Save:    key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "save report")),
		Quit:    key.NewBinding(key.WithKeys("q", "esc", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

func (k summaryKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Down, k.Skipped, k.Detail, k.Save, k.Quit}
}
func (k summaryKeyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

type detailKeyMap struct {
	Move, Tab, Filter, Open, Back, Save, Quit key.Binding
}

func newDetailKeys() detailKeyMap {
	return detailKeyMap{
		Move:   key.NewBinding(key.WithKeys("up", "down", "k", "j"), key.WithHelp("↑/↓", "select")),
		Tab:    key.NewBinding(key.WithKeys("tab", "shift+tab", "1", "2", "3", "4", "5"), key.WithHelp("tab", "status filter")),
		Filter: key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		Open:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
		Back:   key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("esc", "summary")),
		Save:   key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "save")),
		Quit:   key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}

func (k detailKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Move, k.Tab, k.Filter, k.Back, k.Save, k.Quit}
}
func (k detailKeyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }
