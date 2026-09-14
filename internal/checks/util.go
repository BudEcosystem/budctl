package checks

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
)

var verRE = regexp.MustCompile(`v?(\d+)\.(\d+)(?:\.(\d+))?`)

// compareVersions returns -1, 0 or 1. It tolerates distribution suffixes such
// as "v1.35.7+k3s1" and "v1.30.8-eks-2d5f260".
func compareVersions(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersion(s string) [3]int {
	var out [3]int
	m := verRE.FindStringSubmatch(s)
	if m == nil {
		return out
	}
	for i := 0; i < 3; i++ {
		if i+1 < len(m) && m[i+1] != "" {
			out[i], _ = strconv.Atoi(m[i+1])
		}
	}
	return out
}

var memSuffix = map[string]float64{
	"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15,
	"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50,
}

var qtyRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)([A-Za-z]*)$`)

// ParseQuantity converts a Kubernetes quantity to a float. Memory returns
// bytes; CPU returns cores ("100m" -> 0.1).
func ParseQuantity(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	m := qtyRE.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	switch m[2] {
	case "m":
		return n / 1000
	case "n":
		return n / 1e9
	case "u":
		return n / 1e6
	}
	if mult, ok := memSuffix[m[2]]; ok {
		return n * mult
	}
	return n
}

// HumanBytes renders a byte count the way an operator reads a disk figure.
func HumanBytes(n float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0fB", n)
	}
	return fmt.Sprintf("%.1f%s", n, units[i])
}

func Gi(n int) float64 { return float64(n) * (1 << 30) }

// QuantityOf reads a nested quantity out of a manifest, e.g.
// QuantityOf(container, "resources", "requests", "cpu").
func QuantityOf(m map[string]any, path ...string) float64 {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0
		}
		cur = mm[p]
	}
	if s, ok := cur.(string); ok {
		return ParseQuantity(s)
	}
	if f, ok := cur.(float64); ok {
		return f
	}
	return 0
}

// Sorted returns a stable, de-duplicated copy — used so detail lines do not
// reorder between runs and make diffs noisy.
func Sorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Rendered returns the objects produced by config.render, or nil when no
// --values was supplied. Checks that read it must degrade to a stated SKIP
// rather than silently checking nothing.
func Rendered(c *engine.Ctx) []adapters.Object {
	if v, ok := c.Get(engine.KeyRenderedObjects); ok {
		if objs, ok := v.([]adapters.Object); ok {
			return objs
		}
	}
	return nil
}

// RenderedImages returns the image inventory from the render, or nil.
func RenderedImages(c *engine.Ctx) []string {
	if v, ok := c.Get(engine.KeyImages); ok {
		if imgs, ok := v.([]string); ok {
			return imgs
		}
	}
	return nil
}

// Plural is a small readability helper for summaries.
func Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// EffectiveValuesFiles is the single definition of "the values this install
// will actually use", in the order Helm will layer them.
//
// Order matches what `bud_pde` runs — the SOPS secrets file first, then the
// per-environment values on top — because that is the precedence the real
// install has, and a checker that merges them differently judges a
// configuration nobody will ever deploy.
//
// It exists because getting this wrong is silent: a group that merged only
// ValuesFiles saw the chart's own default for anything the secrets file
// overrides, and then reported a perfectly good environment as broken.
func EffectiveValuesFiles(c *engine.Ctx) []string {
	out, seen := []string{}, map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	add(c.Opts.SecretsFile)
	for _, p := range c.Opts.ValuesFiles {
		add(p)
	}
	return out
}
