// Package components is the single table of everything an installation
// deploys. Each entry says where its chart comes from, when it is enabled,
// which values it starts from and which it derives from the Spec, its
// generated credentials, and when ArgoCD syncs it. The values files, the
// ApplicationSet and the bootstrap sync order are all produced from this
// table, so adding or bumping a component is one edit here.
package components

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/install/spec"
	"gopkg.in/yaml.v3"
)

// base holds the shared layers every environment starts from, ported verbatim
// from the reference template (example-bud-foundry-config @ 9b4ac59).
//
//go:embed base
var base embed.FS

// Source is where ArgoCD fetches a component from: a Helm chart, or a chart
// path inside a Git repository.
type Source struct {
	RepoURL string
	Chart   string
	Version string

	GitRepoURL  string
	GitRevision string
	GitPath     string
}

type Component struct {
	Name      string
	Namespace string
	Source    Source
	// ChartValueFiles live inside the chart itself (e.g. example.minimal.yaml).
	// ArgoCD resolves them, so they are referenced, never merged by budctl.
	ChartValueFiles []string
	// Enabled reports whether the installation includes this component. Nil
	// means always.
	Enabled func(spec.Spec) bool
	// BaseFiles names the shared layers under base/<name>/, merged in order.
	BaseFiles func(spec.Spec) []string
	// Values derives the environment's own values from the Spec.
	Values func(spec.Spec) map[string]any
	// Secrets builds the values that are committed SOPS-encrypted.
	Secrets func(spec.Spec, spec.GeneratedSecrets) map[string]any
	// SyncWave orders the bootstrap's child syncs, lowest first.
	SyncWave int
}

func files(names ...string) func(spec.Spec) []string {
	return func(spec.Spec) []string { return names }
}

const (
	budCharts           = "registry.bud.studio/charts"
	openSandboxRepo     = "https://github.com/BudEcosystem/bud-runtime.git"
	openSandboxRevision = "adc5eb4518b820e3452512fcf30fe4cb2e1da524"
	minimalExample      = "example.minimal.yaml"
)

func injectsCA(s spec.Spec) bool { return s.TLS == spec.TLSSelfSigned || s.TLS == spec.TLSInternalCA }

// All is every component, in the order the ApplicationSet lists them.
var All = []Component{
	{
		Name: "argocd", Namespace: defaults.ArgoCDNamespace,
		Source:    Source{RepoURL: budCharts, Chart: "argocd", Version: defaults.ArgoCDChartVersion},
		BaseFiles: files("values.budruntime.yaml"),
		Values:    argocdValues, Secrets: argocdSecrets,
		SyncWave: 0,
	},
	{
		Name: "dapr", Namespace: "dapr-system",
		Source:    Source{RepoURL: "https://dapr.github.io/helm-charts", Chart: "dapr", Version: "1.17.5"},
		BaseFiles: files("values.yaml"),
		SyncWave:  3,
	},
	{
		Name: "kafka", Namespace: "kafka",
		Source:          Source{RepoURL: budCharts, Chart: "kafka", Version: "0.1.1"},
		ChartValueFiles: []string{minimalExample},
		BaseFiles:       files("values.budruntime.yaml"),
		Secrets:         kafkaSecrets,
		SyncWave:        4,
	},
	{
		Name: "mongodb", Namespace: "mongodb",
		Source:          Source{RepoURL: budCharts, Chart: "mongodb", Version: "0.1.1"},
		ChartValueFiles: []string{minimalExample},
		BaseFiles:       files("values.budruntime.yaml"),
		Secrets:         mongodbSecrets,
		SyncWave:        5,
	},
	{
		Name: "cert-manager", Namespace: "cert-manager",
		Source:  Source{RepoURL: budCharts, Chart: "cert-manager", Version: "0.1.3"},
		Enabled: func(s spec.Spec) bool { return s.TLS != spec.TLSExternal },
		BaseFiles: func(s spec.Spec) []string {
			if s.TLS == spec.TLSSelfSigned {
				return []string{"values.budruntime.yaml", "values.selfsigned-ca.yaml"}
			}
			return []string{"values.budruntime.yaml"}
		},
		Values: certManagerValues, Secrets: certManagerSecrets,
		SyncWave: 1,
	},
	{
		Name: "kyverno", Namespace: "kyverno",
		Source:    Source{RepoURL: budCharts, Chart: "kyverno", Version: "0.0.2"},
		Enabled:   injectsCA,
		BaseFiles: files("values.inject-ca.yaml", "values.budruntime.yaml"),
		SyncWave:  2,
	},
	{
		Name: "clickhouse", Namespace: "clickhouse",
		Source:          Source{RepoURL: budCharts, Chart: "clickhouse", Version: "0.1.1"},
		ChartValueFiles: []string{minimalExample},
		BaseFiles:       files("values.budruntime.yaml"),
		Secrets:         clickhouseSecrets,
		SyncWave:        6,
	},
	{
		Name: "postgres", Namespace: "postgres",
		Source:          Source{RepoURL: budCharts, Chart: "postgres", Version: "0.1.1"},
		ChartValueFiles: []string{minimalExample},
		BaseFiles:       files("values.budruntime.yaml", "values.minimal.budruntime.yaml"),
		Secrets:         postgresSecrets,
		SyncWave:        7,
	},
	{
		Name: "seaweedfs", Namespace: "seaweedfs",
		Source:          Source{RepoURL: budCharts, Chart: "seaweedfs", Version: "0.1.1"},
		ChartValueFiles: []string{minimalExample},
		BaseFiles:       files("values.budruntime.yaml"),
		Values:          seaweedValues, Secrets: seaweedSecrets,
		SyncWave: 8,
	},
	{
		Name: "valkey", Namespace: "valkey",
		Source:    Source{RepoURL: "registry-1.docker.io/cloudpirates", Chart: "valkey", Version: "0.21.4"},
		BaseFiles: files("values.yaml", "values.minimal.yaml", "values.budruntime.yaml"),
		Secrets:   valkeySecrets,
		SyncWave:  9,
	},
	{
		Name: "keycloak", Namespace: "keycloak",
		Source:    Source{RepoURL: budCharts, Chart: "keycloak", Version: "0.2.1"},
		BaseFiles: files("values.budruntime.yaml"),
		Values:    keycloakValues, Secrets: keycloakSecrets,
		SyncWave: 10,
	},
	{
		Name: "bud", Namespace: "bud",
		Source: Source{RepoURL: budCharts, Chart: "bud", Version: "1.2.8"},
		Values: budValues, Secrets: budSecrets,
		SyncWave: 12,
	},
	{
		Name: "opensandbox", Namespace: "opensandbox-system",
		Source:   Source{GitRepoURL: openSandboxRepo, GitRevision: openSandboxRevision, GitPath: "infra/charts/opensandbox"},
		Secrets:  openSandboxSecrets,
		SyncWave: 11,
	},
	{
		Name: "bud-studio", Namespace: "bud-studio",
		Source:  Source{RepoURL: budCharts, Chart: "budagent", Version: "0.3.6"},
		Enabled: func(s spec.Spec) bool { return s.BudStudio },
		Values:  budStudioValues, Secrets: budStudioSecrets,
		SyncWave: 13,
	},
}

// IsEnabled reports whether the installation described by s includes c: its
// condition holds, and the operator did not skip it.
func (c Component) IsEnabled(s spec.Spec) bool {
	for _, skipped := range s.SkipComponents {
		if skipped == c.Name {
			return false
		}
	}
	return c.Enabled == nil || c.Enabled(s)
}

// Base merges the component's shared layers for s, in order.
func (c Component) Base(s spec.Spec) (map[string]any, error) {
	out := map[string]any{}
	if c.BaseFiles == nil {
		return out, nil
	}
	for _, name := range c.BaseFiles(s) {
		body, err := base.ReadFile(path.Join("base", c.Name, name))
		if err != nil {
			return nil, fmt.Errorf("%s base layer %s: %w", c.Name, name, err)
		}
		layer := map[string]any{}
		if err := yaml.Unmarshal(body, &layer); err != nil {
			return nil, fmt.Errorf("%s base layer %s: %w", c.Name, name, err)
		}
		out = Merge(out, layer)
	}
	return out, nil
}

// Enabled returns the components the installation described by s includes,
// in table order.
func Enabled(s spec.Spec) []Component {
	var out []Component
	for _, c := range All {
		if c.IsEnabled(s) {
			out = append(out, c)
		}
	}
	return out
}

// BySyncWave returns cs ordered for the bootstrap's sequential child syncs.
func BySyncWave(cs []Component) []Component {
	out := append([]Component(nil), cs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].SyncWave < out[j].SyncWave })
	return out
}

// Lookup finds a component by name.
func Lookup(name string) (Component, bool) {
	for _, c := range All {
		if c.Name == name {
			return c, true
		}
	}
	return Component{}, false
}

// Names lists every component name, sorted, for error messages.
func Names() []string {
	out := make([]string, len(All))
	for i, c := range All {
		out[i] = c.Name
	}
	sort.Strings(out)
	return out
}

// Merge layers over onto base the way Helm layers values files: maps merge
// key by key, anything else (lists included) is replaced, and an explicit null
// is kept so it still removes the chart's default. Neither input is modified.
func Merge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range over {
		if nested, ok := value.(map[string]any); ok {
			if current, ok := out[key].(map[string]any); ok {
				out[key] = Merge(current, nested)
				continue
			}
		}
		out[key] = value
	}
	return out
}

// Layers returns every embedded shared layer by its path,
// values/<component>/<file>, with its content.
func Layers() (map[string][]byte, error) {
	out := map[string][]byte{}
	err := fs.WalkDir(base, "base", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := base.ReadFile(p)
		if err != nil {
			return err
		}
		out["values/"+strings.TrimPrefix(p, "base/")] = body
		return nil
	})
	return out, err
}
