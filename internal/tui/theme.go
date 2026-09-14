package tui

import (
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// ThemeMode selects the palette. Auto reads the terminal's background, so the
// same binary is legible on macOS Terminal's light default and on a dark theme.
type ThemeMode string

const (
	ThemeAuto  ThemeMode = "auto"
	ThemeDark  ThemeMode = "dark"
	ThemeLight ThemeMode = "light"
)

// The palette pairs a light and a dark value for every role, resolved at render
// time from the detected (or forced) background. The first version hardcoded a
// dark-terminal palette, and typed values rendered white-on-white on a light
// terminal. Values start from GitHub Primer and were adjusted where a role fell
// short on a common terminal background; theme_test.go holds every text role to
// WCAG AA (4.5:1) against white, off-white and four dark terminal backgrounds,
// and Subtle — borders, empty bar track, placeholders — to 3:1.
var pal = struct {
	Text, Muted, Subtle, Accent, Pass, Block, Risk, Skip, Info, SelBg lipgloss.AdaptiveColor
}{
	Text:   lipgloss.AdaptiveColor{Light: "#1F2328", Dark: "#E6EDF3"},
	Muted:  lipgloss.AdaptiveColor{Light: "#57606A", Dark: "#9198A1"},
	Subtle: lipgloss.AdaptiveColor{Light: "#848D97", Dark: "#768390"},
	Accent: lipgloss.AdaptiveColor{Light: "#0969DA", Dark: "#58A6FF"},
	Pass:   lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#3FB950"},
	Block:  lipgloss.AdaptiveColor{Light: "#CF222E", Dark: "#FF7B72"},
	Risk:   lipgloss.AdaptiveColor{Light: "#9A6700", Dark: "#D29922"},
	Skip:   lipgloss.AdaptiveColor{Light: "#656D76", Dark: "#8B949E"},
	Info:   lipgloss.AdaptiveColor{Light: "#8250DF", Dark: "#BC8CFF"},
	SelBg:  lipgloss.AdaptiveColor{Light: "#DDF4FF", Dark: "#1C2B3F"},
}

// DisableColor renders every screen without colour, for --no-color. NO_COLOR
// needs no call: Lip Gloss reads it from the environment itself.
func DisableColor() { lipgloss.SetColorProfile(termenv.Ascii) }

// ApplyTheme fixes the palette before the program starts. Background detection
// queries the terminal, and doing that after Bubble Tea owns stdin can stall or
// swallow keystrokes, so auto mode resolves it here, once, up front.
func ApplyTheme(mode ThemeMode) {
	switch mode {
	case ThemeDark:
		lipgloss.SetHasDarkBackground(true)
	case ThemeLight:
		lipgloss.SetHasDarkBackground(false)
	default:
		lipgloss.SetHasDarkBackground(lipgloss.HasDarkBackground())
	}
}

var (
	sText   = lipgloss.NewStyle().Foreground(pal.Text)
	sMuted  = lipgloss.NewStyle().Foreground(pal.Muted)
	sAccent = lipgloss.NewStyle().Foreground(pal.Accent)
	sBold   = lipgloss.NewStyle().Foreground(pal.Text).Bold(true)
	sTitle  = lipgloss.NewStyle().Foreground(pal.Accent).Bold(true)
	sPass   = lipgloss.NewStyle().Foreground(pal.Pass)
	sBlock  = lipgloss.NewStyle().Foreground(pal.Block)
	sRisk   = lipgloss.NewStyle().Foreground(pal.Risk)
	sSkip   = lipgloss.NewStyle().Foreground(pal.Skip)
	sInfo   = lipgloss.NewStyle().Foreground(pal.Info)
)

// statusColor maps a result status to its role colour.
func statusColor(status string) lipgloss.AdaptiveColor {
	switch status {
	case "PASS":
		return pal.Pass
	case "BLOCK":
		return pal.Block
	case "RISK":
		return pal.Risk
	case "INFO":
		return pal.Info
	default:
		return pal.Skip
	}
}

// statusIcon pairs every colour with a glyph and the result's own word, so
// status survives NO_COLOR and colour blindness alike.
func statusIcon(status string) string {
	switch status {
	case "PASS":
		return "✓"
	case "BLOCK":
		return "✗"
	case "RISK":
		return "▲"
	case "INFO":
		return "i"
	default:
		return "○"
	}
}

// intakeTheme derives the form's styles from the same palette, so the first
// screen and the results screens are visibly one tool.
func intakeTheme() *huh.Theme {
	t := huh.ThemeBase()

	t.Focused.Base = t.Focused.Base.BorderForeground(pal.Accent)
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = lipgloss.NewStyle().Foreground(pal.Accent).Bold(true)
	t.Focused.NoteTitle = t.Focused.Title.MarginBottom(1)
	t.Focused.Description = lipgloss.NewStyle().Foreground(pal.Muted)
	t.Focused.ErrorIndicator = lipgloss.NewStyle().Foreground(pal.Block).SetString(" ✗")
	t.Focused.ErrorMessage = lipgloss.NewStyle().Foreground(pal.Block)
	t.Focused.SelectSelector = lipgloss.NewStyle().Foreground(pal.Accent).SetString("❯ ")
	t.Focused.NextIndicator = lipgloss.NewStyle().Foreground(pal.Accent).MarginLeft(1).SetString("→")
	t.Focused.PrevIndicator = lipgloss.NewStyle().Foreground(pal.Accent).MarginRight(1).SetString("←")
	t.Focused.Option = lipgloss.NewStyle().Foreground(pal.Text)
	t.Focused.SelectedOption = lipgloss.NewStyle().Foreground(pal.Accent).Bold(true)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(pal.Pass).SetString("✓ ")
	t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(pal.Muted).SetString("○ ")
	t.Focused.UnselectedOption = lipgloss.NewStyle().Foreground(pal.Text)
	t.Focused.TextInput.Cursor = lipgloss.NewStyle().Foreground(pal.Accent)
	t.Focused.TextInput.Placeholder = lipgloss.NewStyle().Foreground(pal.Subtle)
	t.Focused.TextInput.Prompt = lipgloss.NewStyle().Foreground(pal.Accent)
	t.Focused.TextInput.Text = lipgloss.NewStyle().Foreground(pal.Text)
	t.Focused.FocusedButton = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#0D1117"}).
		Background(pal.Accent).Bold(true).Padding(0, 2).MarginRight(1)
	t.Focused.BlurredButton = lipgloss.NewStyle().Foreground(pal.Muted).
		Background(pal.SelBg).Padding(0, 2).MarginRight(1)

	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.Title = lipgloss.NewStyle().Foreground(pal.Text)
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	t.Group.Title = lipgloss.NewStyle().Foreground(pal.Text).Bold(true).MarginBottom(0)
	t.Group.Description = lipgloss.NewStyle().Foreground(pal.Muted).MarginBottom(1)
	t.Help.ShortKey = lipgloss.NewStyle().Foreground(pal.Muted)
	t.Help.ShortDesc = lipgloss.NewStyle().Foreground(pal.Muted)
	t.Help.ShortSeparator = lipgloss.NewStyle().Foreground(pal.Subtle)
	return t
}
