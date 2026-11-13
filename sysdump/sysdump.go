// Package sysdump collects what is needed to debug an installation into one
// zip: the ArgoCD Applications and ApplicationSets, and the pods, events and
// recent logs of every namespace the platform deploys into. Secrets are never
// collected.
package sysdump

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/k8s"
	"sigs.k8s.io/yaml"
)

type Options struct {
	// Namespaces to collect; empty means ArgoCD's and every component's.
	Namespaces []string
	// TailLines is how many log lines to keep per container.
	TailLines int64
	// Step reports progress; may be nil.
	Step func(string)
}

// Namespaces is every namespace an installation deploys into.
func Namespaces() []string {
	seen := map[string]bool{defaults.ArgoCDNamespace: true}
	out := []string{defaults.ArgoCDNamespace}
	for _, c := range components.All {
		if !seen[c.Namespace] {
			seen[c.Namespace] = true
			out = append(out, c.Namespace)
		}
	}
	sort.Strings(out)
	return out
}

// Collect writes the dump to w as a zip. A section that cannot be read is
// recorded as an error file in the zip rather than aborting the dump: a
// partial dump of a broken cluster is the point.
func Collect(ctx context.Context, client *k8s.Client, opts Options, w io.Writer) error {
	step := opts.Step
	if step == nil {
		step = func(string) {}
	}
	if len(opts.Namespaces) == 0 {
		opts.Namespaces = Namespaces()
	}
	if opts.TailLines <= 0 {
		opts.TailLines = 500
	}
	z := zip.NewWriter(w)
	add := func(name string, body []byte) error {
		f, err := z.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return err
		}
		_, err = f.Write(body)
		return err
	}
	addYAML := func(name string, v any, readErr error) error {
		if readErr != nil {
			return add(name+".error.txt", []byte(readErr.Error()+"\n"))
		}
		body, err := yaml.Marshal(v)
		if err != nil {
			return err
		}
		return add(name, body)
	}

	info := fmt.Sprintf("budctl %s (%s)\ncollected %s\ncontext %s\nserver %s\n", defaults.Version, defaults.Commit, time.Now().UTC().Format(time.RFC3339), client.Context, client.Host())
	if v, err := client.ServerVersion(); err == nil {
		info += "kubernetes " + v.GitVersion + "\n"
	}
	if err := add("budctl.txt", []byte(info)); err != nil {
		return err
	}

	step("ArgoCD Applications and ApplicationSets")
	apps, err := client.ListFresh(ctx, k8s.ApplicationGVR, defaults.ArgoCDNamespace)
	if err := addYAML("argocd/applications.yaml", apps, err); err != nil {
		return err
	}
	sets, err := client.ListFresh(ctx, k8s.ApplicationSetGVR, defaults.ArgoCDNamespace)
	if err := addYAML("argocd/applicationsets.yaml", sets, err); err != nil {
		return err
	}
	step("nodes")
	if err := addYAML("cluster/nodes.yaml", client.List(ctx, "nodes", ""), nil); err != nil {
		return err
	}

	for _, ns := range opts.Namespaces {
		step("namespace " + ns)
		pods := client.List(ctx, "pods", ns)
		if len(pods) == 0 && client.Get(ctx, "namespaces", "", ns) == nil {
			continue
		}
		if err := addYAML(ns+"/pods.yaml", pods, nil); err != nil {
			return err
		}
		if err := addYAML(ns+"/events.yaml", client.List(ctx, "events", ns), nil); err != nil {
			return err
		}
		for _, pod := range pods {
			for _, name := range containerNames(pod) {
				logs, err := client.PodLogTail(ctx, ns, pod.Name(), name, opts.TailLines)
				path := fmt.Sprintf("%s/logs/%s/%s.log", ns, pod.Name(), name)
				if err != nil {
					logs = []byte("could not read logs: " + err.Error() + "\n")
				}
				if err := add(path, logs); err != nil {
					return err
				}
			}
		}
	}
	return z.Close()
}

func containerNames(pod k8s.Object) []string {
	var out []string
	for _, field := range []string{"initContainers", "containers"} {
		list, _ := pod.Dig("spec", field).([]any)
		for _, raw := range list {
			c, _ := raw.(map[string]any)
			if name, _ := c["name"].(string); name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}
