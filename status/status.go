// Package status reports how an installed environment is doing, as ArgoCD
// sees it: each component's Application, synced or not, healthy or not.
package status

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/install/appset"
	"github.com/BudEcosystem/budctl/k8s"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
)

// Application is one ArgoCD Application's state.
type Application struct {
	Name      string `json:"name"`
	Component string `json:"component,omitempty"`
	// Chart and Revision are what the Application deploys: the chart name and
	// version, or a Git path and revision.
	Chart    string `json:"chart,omitempty"`
	Revision string `json:"revision,omitempty"`
	Sync     string `json:"sync"`
	Health   string `json:"health"`
	// Operation is the phase of the last sync operation (Running, Succeeded,
	// Failed …) and Message its message.
	Operation string `json:"operation,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Ready reports whether ArgoCD considers the Application converged.
func (a Application) Ready() bool { return a.Sync == "Synced" && a.Health == "Healthy" }

// Environment is one installed environment: its ApplicationSet and the
// Applications generated from it.
type Environment struct {
	Name         string        `json:"name"`
	Applications []Application `json:"applications"`
}

// Report is the state of every environment in the cluster.
type Report struct {
	Root         *Application  `json:"root,omitempty"`
	Environments []Environment `json:"environments"`
}

// Ready reports whether every Application in the report is converged.
func (r Report) Ready() bool {
	if r.Root != nil && !r.Root.Ready() {
		return false
	}
	for _, e := range r.Environments {
		for _, a := range e.Applications {
			if !a.Ready() {
				return false
			}
		}
	}
	return true
}

// ErrNoArgoCD means the cluster has no ArgoCD Application API at all.
var ErrNoArgoCD = errors.New("ArgoCD is not installed in this cluster (no argoproj.io Applications API)")

// ErrNotInstalled means no environment matched.
var ErrNotInstalled = errors.New("no Bud environment is installed in this cluster")

// Collect reads the state of one environment, or of every environment when
// environment is empty.
func Collect(ctx context.Context, client *k8s.Client, environment string) (Report, error) {
	ns := defaults.ArgoCDNamespace
	sets, err := client.ListFresh(ctx, k8s.ApplicationSetGVR, ns)
	if err != nil {
		if meta.IsNoMatchError(err) || apierrors.IsNotFound(err) {
			return Report{}, ErrNoArgoCD
		}
		return Report{}, fmt.Errorf("list ApplicationSets: %w", err)
	}
	apps, err := client.ListFresh(ctx, k8s.ApplicationGVR, ns)
	if err != nil {
		return Report{}, fmt.Errorf("list Applications: %w", err)
	}

	var r Report
	for _, a := range apps {
		if a.Name() == appset.RootName {
			root := application(a, "")
			r.Root = &root
		}
	}
	for _, set := range sets {
		name := set.Name()
		if environment != "" && name != environment {
			continue
		}
		env := Environment{Name: name}
		for _, a := range apps {
			if ownedBy(a, name) {
				env.Applications = append(env.Applications, application(a, strings.TrimPrefix(a.Name(), name+"-")))
			}
		}
		sort.Slice(env.Applications, func(i, j int) bool { return env.Applications[i].Name < env.Applications[j].Name })
		r.Environments = append(r.Environments, env)
	}
	if len(r.Environments) == 0 {
		if environment != "" {
			return r, fmt.Errorf("environment %q is not installed in this cluster", environment)
		}
		return r, ErrNotInstalled
	}
	sort.Slice(r.Environments, func(i, j int) bool { return r.Environments[i].Name < r.Environments[j].Name })
	return r, nil
}

// Wait polls until every Application is converged or timeout passes, calling
// progress after each poll. It returns the last report either way; the error
// says whether it converged.
func Wait(ctx context.Context, client *k8s.Client, environment string, timeout, interval time.Duration, progress func(Report)) (Report, error) {
	deadline := time.Now().Add(timeout)
	for {
		r, err := Collect(ctx, client, environment)
		if err != nil {
			return r, err
		}
		if progress != nil {
			progress(r)
		}
		if r.Ready() {
			return r, nil
		}
		if time.Now().After(deadline) {
			return r, fmt.Errorf("not every Application was Synced and Healthy after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func ownedBy(o k8s.Object, set string) bool {
	refs, _ := o.Dig("metadata", "ownerReferences").([]any)
	for _, raw := range refs {
		ref, _ := raw.(map[string]any)
		if ref["kind"] == "ApplicationSet" && ref["name"] == set {
			return true
		}
	}
	return false
}

func application(o k8s.Object, component string) Application {
	a := Application{
		Name:      o.Name(),
		Component: component,
		Sync:      orUnknown(o.DigString("status", "sync", "status")),
		Health:    orUnknown(o.DigString("status", "health", "status")),
		Operation: o.DigString("status", "operationState", "phase"),
		Message:   o.DigString("status", "operationState", "message"),
	}
	// A comparison or sync error is why an Application is Unknown or stuck,
	// and ArgoCD reports it as a condition rather than an operation.
	if conditions, ok := o.Dig("status", "conditions").([]any); ok {
		for _, raw := range conditions {
			c, _ := raw.(map[string]any)
			kind, _ := c["type"].(string)
			message, _ := c["message"].(string)
			if strings.HasSuffix(kind, "Error") && message != "" {
				a.Operation, a.Message = kind, message
				break
			}
		}
	}
	// The ApplicationSet template gives each Application sources: the chart
	// first, the $values repository second. The root Application has one source.
	source, _ := o.Dig("spec", "source").(map[string]any)
	if sources, ok := o.Dig("spec", "sources").([]any); ok && len(sources) > 0 {
		source, _ = sources[0].(map[string]any)
	}
	if source != nil {
		chart, _ := source["chart"].(string)
		if chart == "" {
			chart, _ = source["path"].(string)
		}
		a.Chart = chart
		a.Revision, _ = source["targetRevision"].(string)
	}
	return a
}

func orUnknown(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}
