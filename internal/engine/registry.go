package engine

import (
	"fmt"
	"sort"
)

// GroupOrder fixes the order groups are reported in. "platform" is first
// because every other group branches on what it detects (FRD-020 §5.0).
// GroupOrder fixes both the report order and the EXECUTION order, which is why
// "config" sits third rather than where it reads most naturally. config.render
// is what populates the rendered manifest, and registry/charts/storage all read
// it: with config last, registry.tags could never see the images it exists to
// check and reported "no chart render available" even when --values was given.
var GroupOrder = []string{
	"platform", "toolchain", "config", "cluster", "argocd", "registry", "charts",
	"nodes", "storage", "components", "domains", "egress", "gpu",
	"external-datastores",
}

var registry = map[string]*Check{}

// Register panics on a duplicate id: two checks answering to one name is a bug
// that must not survive to runtime, and every check is registered at init.
func Register(c *Check) {
	if c.ID == "" || c.Group == "" || c.Run == nil {
		panic(fmt.Sprintf("budctl: malformed check %+v", c))
	}
	if _, dup := registry[c.ID]; dup {
		panic("budctl: duplicate check id " + c.ID)
	}
	registry[c.ID] = c
}

func All() []*Check {
	out := make([]*Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		gi, gj := groupIndex(out[i].Group), groupIndex(out[j].Group)
		if gi != gj {
			return gi < gj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func groupIndex(g string) int {
	for i, name := range GroupOrder {
		if name == g {
			return i
		}
	}
	return len(GroupOrder)
}

// Groups returns the registered groups in report order.
func Groups() []string {
	seen, out := map[string]bool{}, []string{}
	for _, c := range All() {
		if !seen[c.Group] {
			seen[c.Group] = true
			out = append(out, c.Group)
		}
	}
	return out
}

func Lookup(id string) *Check { return registry[id] }
