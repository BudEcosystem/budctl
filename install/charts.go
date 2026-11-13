package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/install/gitops"
	"github.com/BudEcosystem/budctl/install/spec"
	"github.com/BudEcosystem/budctl/internal/helm"
	"github.com/BudEcosystem/budctl/internal/oci"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
)

// RenderedChart is one component's chart templated with its final values.
type RenderedChart struct {
	Component components.Component
	Manifest  string
	Objects   int
	Err       error
}

// RenderCharts templates every component's chart client-side, the way ArgoCD
// will: the chart's own value files first, then the values and secrets this
// bundle commits, in the same order. Nothing touches a cluster. kubeVersion
// may be empty for Helm's default. A component that cannot be fetched or
// rendered carries its error; the others still render.
func RenderCharts(ctx context.Context, s spec.Spec, b Bundle, kubeVersion string, step func(string)) []RenderedChart {
	if step == nil {
		step = func(string) {}
	}
	client := helm.New()
	cred := oci.Credential{Username: s.RegistryUser, Password: s.RegistryPassword}
	var out []RenderedChart
	for _, rc := range b.Components {
		c := rc.Component
		step("rendering " + c.Name)
		r := RenderedChart{Component: c}
		ch, err := fetchChart(ctx, client, c, cred)
		if err == nil {
			var values map[string]any
			values, err = chartValues(ch, c, rc)
			if err == nil {
				var res *helm.RenderResult
				res, err = client.Render(ch, values, c.Name, c.Namespace, kubeVersion)
				if err == nil {
					r.Manifest, r.Objects = res.Manifest, len(res.Objects)
				}
			}
		}
		r.Err = err
		out = append(out, r)
	}
	return out
}

func fetchChart(ctx context.Context, client *helm.Client, c components.Component, cred oci.Credential) (*chart.Chart, error) {
	src := c.Source
	if src.GitPath == "" {
		return client.PullChart(src.RepoURL, src.Chart, src.Version, cred)
	}
	dir, err := os.MkdirTemp("", "budctl-chart-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := gitops.CloneAt(ctx, src.GitRepoURL, src.GitRevision, filepath.Join(dir, "repo")); err != nil {
		return nil, err
	}
	return client.LoadChart(filepath.Join(dir, "repo", filepath.FromSlash(src.GitPath)))
}

// chartValues merges the files the ApplicationSet lists, in order: those
// inside the chart, then the committed values, then the committed secrets.
func chartValues(ch *chart.Chart, c components.Component, rc RenderedComponent) (map[string]any, error) {
	values := map[string]any{}
	for _, name := range c.ChartValueFiles {
		var body []byte
		for _, f := range ch.Files {
			if f.Name == name {
				body = f.Data
			}
		}
		if body == nil {
			return nil, fmt.Errorf("chart %s has no %s, which the ApplicationSet lists", c.Source.Chart, name)
		}
		layer := map[string]any{}
		if err := yaml.Unmarshal(body, &layer); err != nil {
			return nil, fmt.Errorf("%s in chart %s: %w", name, c.Source.Chart, err)
		}
		values = components.Merge(values, layer)
	}
	values = components.Merge(values, rc.Values)
	if rc.Secrets != nil {
		values = components.Merge(values, rc.Secrets)
	}
	// ArgoCD hands Helm files, and Helm parses them through JSON, so every
	// number is a float64. Charts compare against that; pass the same.
	body, err := yaml.Marshal(values)
	if err != nil {
		return nil, err
	}
	return chartutil.ReadValues(body)
}

// Summary is one line per component, for printing after a render.
func (r RenderedChart) Summary() string {
	if r.Err != nil {
		return fmt.Sprintf("%-13s FAILED  %s", r.Component.Name, strings.Join(strings.Fields(r.Err.Error()), " "))
	}
	return fmt.Sprintf("%-13s ok      %d objects", r.Component.Name, r.Objects)
}
