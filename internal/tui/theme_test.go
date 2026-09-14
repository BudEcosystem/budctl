package tui

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func luminance(hex string) float64 {
	hex = strings.TrimPrefix(hex, "#")
	ch := func(i int) float64 {
		v, _ := strconv.ParseUint(hex[i:i+2], 16, 8)
		c := float64(v) / 255
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(0) + 0.7152*ch(2) + 0.0722*ch(4)
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// The first palette was tuned for a dark terminal only, and typed values
// rendered white-on-white on a light one. This holds every role to a contrast
// floor on the backgrounds terminals actually ship with, in both modes.
func TestPaletteMeetsContrastOnRealTerminalBackgrounds(t *testing.T) {
	lights := []string{"#FFFFFF", "#F6F8FA"}
	darks := []string{"#000000", "#0D1117", "#1E1E1E", "#282C34"}

	roles := []struct {
		name  string
		color lipgloss.AdaptiveColor
		floor float64
	}{
		{"Text", pal.Text, 4.5}, {"Muted", pal.Muted, 4.5}, {"Accent", pal.Accent, 4.5},
		{"Pass", pal.Pass, 4.5}, {"Block", pal.Block, 4.5}, {"Risk", pal.Risk, 4.5},
		{"Skip", pal.Skip, 4.5}, {"Info", pal.Info, 4.5},
		// Subtle is borders, the empty bar track and placeholders — non-text UI,
		// held to WCAG's 3:1 for graphical objects.
		{"Subtle", pal.Subtle, 3.0},
	}
	for _, r := range roles {
		for _, bg := range lights {
			if c := contrast(r.color.Light, bg); c < r.floor {
				t.Errorf("%s light %s on %s: %.2f:1, below %.1f:1", r.name, r.color.Light, bg, c, r.floor)
			}
		}
		for _, bg := range darks {
			if c := contrast(r.color.Dark, bg); c < r.floor {
				t.Errorf("%s dark %s on %s: %.2f:1, below %.1f:1", r.name, r.color.Dark, bg, c, r.floor)
			}
		}
	}
}

// Forcing a mode must actually select that side of every colour. The value in
// the escape sequence is checked, not merely that some colour was emitted.
func TestForcedThemeSelectsTheMatchingPalette(t *testing.T) {
	rgb := func(hex string) string {
		hex = strings.TrimPrefix(hex, "#")
		r, _ := strconv.ParseUint(hex[0:2], 16, 8)
		g, _ := strconv.ParseUint(hex[2:4], 16, 8)
		b, _ := strconv.ParseUint(hex[4:6], 16, 8)
		return fmt.Sprintf("38;2;%d;%d;%d", r, g, b)
	}
	for _, tc := range []struct {
		dark bool
		want string
	}{{false, pal.Text.Light}, {true, pal.Text.Dark}} {
		withTrueColor(t, tc.dark)
		if out := sText.Render("x"); !strings.Contains(out, rgb(tc.want)) {
			t.Errorf("dark=%v: text rendered %q, want colour %s", tc.dark, out, tc.want)
		}
	}
}

// Typed values must not be the background colour in either mode — the exact
// failure the first palette had.
func TestTypedValuesAreVisibleInBothModes(t *testing.T) {
	th := intakeTheme()
	for _, dark := range []bool{false, true} {
		withTrueColor(t, dark)
		out := th.Focused.TextInput.Text.Render("bud.example.com")
		bg := "38;2;255;255;255"
		if dark {
			bg = "38;2;0;0;0"
		}
		if strings.Contains(out, bg) {
			t.Errorf("dark=%v: typed text uses the terminal background colour", dark)
		}
	}
}

// colourSGR matches a foreground or background colour escape, in any of the
// forms Lip Gloss and termenv emit (38;5 / 38;2 / combined with bold).
var colourSGR = regexp.MustCompile(`\x1b\[(?:[0-9]+;)*(?:38|48);`)

// --no-color must reach every screen. The progress bar is the trap: Bubbles
// detects its own colour profile through termenv rather than Lip Gloss, so it
// ignored the override the rest of the UI obeyed.
func TestNoColorReachesEveryScreenIncludingTheProgressBar(t *testing.T) {
	withTrueColor(t, true)
	m := finishedModel(testCtx(t), sampleReport(), 120, 40)
	if bar := newProgress().ViewAs(0.5); !colourSGR.MatchString(bar) {
		t.Fatalf("on a colour terminal the progress bar is uncoloured, so it is not following Lip Gloss's profile: %q", bar)
	}
	if !colourSGR.MatchString(m.View()) {
		t.Fatal("the summary is uncoloured on a colour terminal; this test would prove nothing")
	}

	DisableColor()
	m.layoutSummary()
	for name, out := range map[string]string{"progress bar": newProgress().ViewAs(0.5), "summary": m.View()} {
		if colourSGR.MatchString(out) {
			t.Errorf("--no-color still colours the %s: %q", name, out)
		}
	}
}
