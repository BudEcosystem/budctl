package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/BudEcosystem/budctl/internal/engine"
)

// card is the basic building block: a rounded box whose border carries the
// meaning (red for a blocker, amber for a risk) and whose first line titles it.
func card(title, body string, width int, border lipgloss.AdaptiveColor) string {
	if width < 24 {
		width = 24
	}
	inner := width - 4 // two border columns plus one space of padding each side
	var b strings.Builder
	if title != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(border).Bold(true).Width(inner).Render(title))
		if body != "" {
			b.WriteString("\n")
		}
	}
	b.WriteString(body)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 1).
		Width(width - 2).
		Render(b.String())
}

// statCard is one tile in the headline row: a large figure over its label.
func statCard(value, label string, color lipgloss.AdaptiveColor, width int) string {
	v := lipgloss.NewStyle().Foreground(color).Bold(true).Render(value)
	l := sMuted.Render(label)
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(color).
		Width(width - 2).
		Align(lipgloss.Center).
		Render(v + "\n" + l)
}

// wrapTo word-wraps plain text to a width. Styling is applied by the caller,
// after wrapping, so a colour escape never counts toward the line length.
func wrapTo(s string, width int) string {
	if width < 10 {
		width = 10
	}
	return lipgloss.NewStyle().Width(width).Render(s)
}

// gaugeBar draws one measurement against its need. A shortfall is red and says
// how much is missing; a sufficient figure is green. The bar fills to the need,
// so a quantity with headroom reads as a full bar rather than a sliver of a
// huge denominator.
func gaugeBar(g engine.Gauge, width int) string {
	labelW := 22
	if width < 60 {
		labelW = 14
	}
	barW := width - labelW - 30
	if barW < 10 {
		barW = 10
	}
	frac := 1.0
	if g.Need > 0 {
		frac = g.Have / g.Need
	}
	if frac > 1 {
		frac = 1
	}
	if frac < 0 {
		frac = 0
	}
	filled := int(frac*float64(barW) + 0.5)

	color := pal.Pass
	if g.Short() {
		color = pal.Block
	}
	bar := lipgloss.NewStyle().Foreground(color).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(pal.Subtle).Render(strings.Repeat("░", barW-filled))

	label := g.Label
	if len(label) > labelW {
		label = label[:labelW-1] + "…"
	}
	figure := fmt.Sprintf("%s / %s", formatQty(g.Have, g.Unit), formatQty(g.Need, g.Unit))
	return sText.Width(labelW).Render(label) + " " + bar + " " +
		lipgloss.NewStyle().Foreground(color).Render(figure)
}

func formatQty(v float64, unit string) string {
	if unit == "cores" {
		return fmt.Sprintf("%.1f cores", v)
	}
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f B", v)
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// badge renders a status as glyph plus word in its colour.
func badge(status string) string {
	return lipgloss.NewStyle().Foreground(statusColor(status)).Bold(true).
		Render(statusIcon(status) + " " + status)
}

// titleBar is the one-line header shared by every results screen.
func titleBar(left, right string, width int) string {
	l := sTitle.Render(left)
	r := sMuted.Render(right)
	gap := width - lipgloss.Width(l) - lipgloss.Width(r)
	if gap < 2 {
		return l + "  " + r
	}
	return l + strings.Repeat(" ", gap) + r
}

// dialog centres a small bordered prompt in a region.
func dialog(title, body string, width, height int) string {
	w := 56
	if width < w+4 {
		w = width - 4
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(pal.Accent).
		Padding(1, 2).
		Width(w).
		Render(sTitle.Render(title) + "\n\n" + body)
	if height < lipgloss.Height(box) {
		return box
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
