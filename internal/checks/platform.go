package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
)

// The platform group runs first and every later group branches on what it
// records. OpenShift is a supported target — budcluster already renders
// route.openshift.io/v1 Routes and applies a privileged SCC — so assuming
// IngressClass and PodSecurity would make budctl wrong on a whole class of
// customer cluster (FRD-020 §5.0).

func init() {
	engine.Register(&engine.Check{
		ID: "platform.distribution", Group: "platform", Severity: engine.Info,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("platform.distribution")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable")
			}
			v, err := c.Kube.ServerVersion()
			if err != nil {
				return ch.Skip("could not read the server version: " + err.Error())
			}
			c.Platform.Version = v.GitVersion
			c.Platform.Distribution = detectDistribution(ctx, c, v.GitVersion)

			detail := []string{"server " + v.GitVersion, "api " + c.Kube.Host()}
			if c.Platform.IsOpenShift() {
				c.Platform.OpenShiftVersion = openShiftVersion(ctx, c)
				c.Platform.AppsDomain = appsDomain(ctx, c)
				if c.Platform.OpenShiftVersion != "" {
					detail = append(detail, "OpenShift "+c.Platform.OpenShiftVersion)
				}
				if c.Platform.AppsDomain != "" {
					detail = append(detail, "apps wildcard *."+c.Platform.AppsDomain)
				}
			}
			return ch.Infof("%s", c.Platform.Distribution).With(detail...)
		},
	})

	engine.Register(&engine.Check{
		ID: "platform.openshift-version", Group: "platform", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("platform.openshift-version")
			if !c.Platform.IsOpenShift() {
				return ch.Skip("not an OpenShift cluster")
			}
			got := c.Platform.OpenShiftVersion
			if got == "" {
				return ch.Skip("OpenShift detected but ClusterVersion is not readable")
			}
			if compareVersions(got, c.Profile.MinOpenShift) < 0 {
				return ch.Fail(
					fmt.Sprintf("OpenShift %s is below the supported %s", got, c.Profile.MinOpenShift),
					"upgrade the cluster before installing")
			}
			return ch.Pass(fmt.Sprintf("OpenShift %s ≥ %s", got, c.Profile.MinOpenShift))
		},
	})

	engine.Register(&engine.Check{
		ID: "platform.cluster-proxy", Group: "platform", Severity: engine.Info,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("platform.cluster-proxy")
			if !c.Platform.IsOpenShift() {
				return ch.Skip("cluster-wide proxy object is OpenShift-specific")
			}
			p := c.Kube.Get(ctx, "proxies.config.openshift.io", "", "cluster")
			if p == nil {
				return ch.Infof("no cluster-wide egress proxy configured")
			}
			httpProxy := p.DigString("spec", "httpProxy")
			httpsProxy := p.DigString("spec", "httpsProxy")
			noProxy := p.DigString("spec", "noProxy")
			if httpProxy == "" && httpsProxy == "" {
				return ch.Infof("cluster proxy object exists but sets no proxy")
			}
			c.Platform.ClusterProxy = firstNonEmpty(httpsProxy, httpProxy)
			return ch.Infof("cluster-wide egress proxy in effect: %s", c.Platform.ClusterProxy).
				With("every egress result must be read against this proxy, not against direct connectivity",
					"noProxy: "+noProxy)
		},
	})
}

func detectDistribution(ctx context.Context, c *engine.Ctx, gitVersion string) engine.Distribution {
	// OpenShift is identified by its own API groups, not by a version string:
	// the k8s version of an OpenShift cluster looks entirely ordinary.
	if c.Kube.HasAPIVersion(ctx, "route.openshift.io/v1") &&
		c.Kube.HasAPIVersion(ctx, "security.openshift.io/v1") {
		return engine.DistOpenShift
	}
	switch {
	case strings.Contains(gitVersion, "k3s"):
		return engine.DistK3s
	case strings.Contains(gitVersion, "eks"):
		return engine.DistEKS
	case strings.Contains(gitVersion, "gke"):
		return engine.DistGKE
	}
	// AKS does not mark the version string; its nodes carry the label.
	for _, n := range c.Kube.List(ctx, "nodes", "") {
		if _, ok := n.Labels()["kubernetes.azure.com/cluster"]; ok {
			return engine.DistAKS
		}
	}
	return engine.DistVanilla
}

func openShiftVersion(ctx context.Context, c *engine.Ctx) string {
	cv := c.Kube.Get(ctx, "clusterversions.config.openshift.io", "", "version")
	if cv == nil {
		return ""
	}
	// history is newest-first, and its newest entry is the version most recently
	// ATTEMPTED. During an upgrade — or after one that failed or was rolled
	// back — that entry is state "Partial" and names the target, while the
	// version actually serving is the newest "Completed" entry below it.
	// Trusting history[0] lets a 4.10 cluster that once reached for 4.12 report
	// 4.12 and pass a floor it does not meet, which is precisely the
	// false-assurance this tool exists to avoid.
	hist := cv.DigSlice("status", "history")
	for _, raw := range hist {
		h, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if state, _ := h["state"].(string); state != "Completed" {
			continue
		}
		if v, ok := h["version"].(string); ok && v != "" {
			return v
		}
	}
	// No completed entry: either a first install still in progress, or history
	// is absent. `desired` is the best remaining signal, and it is the target
	// rather than the running version — so it can only be optimistic, which the
	// caller reports as a version it could read rather than one it verified.
	if len(hist) > 0 {
		if h, ok := hist[0].(map[string]any); ok {
			if v, ok := h["version"].(string); ok && v != "" {
				return v
			}
		}
	}
	return cv.DigString("status", "desired", "version")
}

// appsDomain reads the wildcard the cluster already owns. It usually satisfies
// domains.resolve for every hostname at once, so the intake form offers it.
func appsDomain(ctx context.Context, c *engine.Ctx) string {
	ing := c.Kube.Get(ctx, "ingresses.config.openshift.io", "", "cluster")
	if ing != nil {
		if d := ing.DigString("spec", "domain"); d != "" {
			return d
		}
	}
	for _, ic := range c.Kube.List(ctx, "ingresscontrollers.operator.openshift.io", "openshift-ingress-operator") {
		if d := ic.DigString("status", "domain"); d != "" {
			return d
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

var _ = adapters.Object{}
