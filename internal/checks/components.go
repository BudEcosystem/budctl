package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
)

// The components group is deliberately tiny. FRD-020 §3.1 draws the line: the
// two ApplicationSets install twenty components — Dapr, cert-manager, OpenEBS,
// Kyverno, every database operator — so requiring any of them before the
// install is checking that the installer has already run. Three things are left
// that no chart in either ApplicationSet supplies, and only those three block:
//
//	dns            — a cluster property; every Dapr service-invocation hop needs it
//	ingress        — the documented prerequisite; not in any ApplicationSet
//	metrics-server — not in any ApplicationSet, and every HPA in the chart needs it
//
// Everything else is swept by components.appset-conflicts, which is declared
// INFO and raises a conflict as RISK. Absence is never a finding here: that is
// what TestAppsetComponentsNeverBlock enforces as a class.

func init() {
	engine.Register(&engine.Check{
		ID: "components.dns", Group: "components", Severity: engine.Block,
		// DependsOn platform: the DNS pods live in a different namespace on
		// OpenShift, so without it this check reads the wrong place.
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("components.dns")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: cluster DNS was not inspected")
			}

			// OpenShift runs CoreDNS in openshift-dns, but a cluster that was
			// upgraded into OpenShift, or one running an extra resolver, can
			// still have it in kube-system — so fall back rather than report a
			// bare cluster.
			candidates := []string{"kube-system"}
			if c.Platform.IsOpenShift() {
				candidates = []string{"openshift-dns", "kube-system"}
			}
			ns := candidates[0]
			var pods []adapters.Object
			for _, candidate := range candidates {
				if found := componentDNSPods(ctx, c, candidate); len(found) > 0 {
					ns, pods = candidate, found
					break
				}
			}

			if len(pods) == 0 {
				return ch.Fail(
					fmt.Sprintf("no CoreDNS or kube-dns pods in %s: nothing in the cluster can resolve a Service name, so every Dapr service-invocation hop, database connection and object-store call fails", strings.Join(candidates, " or ")),
					"install the distribution's DNS addon before installing Bud — no chart in either ApplicationSet provides cluster DNS. On kubeadm it arrives with the CNI manifest; on k3s and managed distributions it is present by default, so its absence means the addon was disabled or removed.",
				).WithEvidence(engine.Evidence{
					What:   "pods in " + strings.Join(candidates, ", ") + " labelled k8s-app=kube-dns / k8s-app=coredns, or named coredns / kube-dns / dns-default",
					Output: "no matching pods",
				})
			}

			lines := make([]string, 0, len(pods))
			unhealthy := []string{}
			reasons := map[string]bool{}
			for _, p := range pods {
				ok, line, reason := componentPodHealth(p)
				lines = append(lines, line)
				if !ok {
					unhealthy = append(unhealthy, p.Name())
					if reason != "" {
						reasons[reason] = true
					}
				}
			}
			ev := engine.Evidence{What: "kubectl -n " + ns + " get pods (cluster DNS)", Output: strings.Join(lines, "\n")}

			if len(unhealthy) > 0 {
				why := ""
				if len(reasons) > 0 {
					why = " (" + strings.Join(Sorted(componentSetKeys(reasons)), ", ") + ")"
				}
				return ch.Fail(
					fmt.Sprintf("%d of %d cluster-DNS %s in %s not ready%s: in-cluster name resolution is failing or one node outage away from it, and every Dapr call, database connection and object-store request resolves through them",
						len(unhealthy), len(pods), Plural(len(pods), "pod is", "pods are"), ns, why),
					"`kubectl -n "+ns+" describe pod "+unhealthy[0]+"` and `kubectl -n "+ns+" logs "+unhealthy[0]+"` — a CrashLooping CoreDNS is usually a bad Corefile, an unreachable upstream resolver in the node's /etc/resolv.conf, or a forwarding loop back into itself. Fix it before installing; nothing in the ApplicationSets can.",
				).With(lines...).WithEvidence(ev)
			}

			// The kubelet writes the DNS Service ClusterIP into every pod's
			// /etc/resolv.conf, so healthy pods with no Service in front of them
			// resolve nothing. Match on port 53 rather than on the name:
			// "kube-dns" is a compatibility name CoreDNS keeps, and a cluster is
			// free to publish DNS under any name.
			dnsSvc, clusterIP := componentDNSService(ctx, c, ns)
			if dnsSvc == "" {
				return ch.Fail(
					fmt.Sprintf("the DNS pods in %s are ready but no Service there publishes port 53: pods get a resolver address from the kubelet that answers nothing, so every in-cluster lookup times out", ns),
					"restore the cluster DNS Service (`kubectl -n "+ns+" get svc`); on a kubeadm cluster it is `kube-dns`, and its ClusterIP must match the kubelet's --cluster-dns flag",
				).With(lines...).WithEvidence(ev)
			}

			return ch.Pass(
				fmt.Sprintf("%d cluster-DNS %s ready in %s, published as %s/%s", len(pods), Plural(len(pods), "pod", "pods"), ns, ns, dnsSvc),
			).With(append(lines, fmt.Sprintf("service %s/%s ClusterIP %s", ns, dnsSvc, clusterIP))...).
				WithEvidence(ev).
				Bounds("pods being Ready is not a resolution test: budctl does not query the DNS service from inside the cluster, so a broken CNI datapath, a NetworkPolicy on the workload namespace, or an unreachable upstream forwarder can still make lookups fail.")
		},
	})

	engine.Register(&engine.Check{
		ID: "components.ingress", Group: "components", Severity: engine.Block,
		// DependsOn platform: OpenShift has no IngressClass to find — the
		// Ingress Operator owns the path — and reporting a vanilla-only
		// sub-check as PASS there (or the reverse) is the exact wrongness
		// FRD-020 §5.0 exists to prevent.
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("components.ingress")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the ingress path was not inspected")
			}
			if c.Platform.IsOpenShift() {
				return openShiftIngress(ctx, c, ch)
			}
			return vanillaIngress(ctx, c, ch)
		},
	})

	engine.Register(&engine.Check{
		ID: "components.metrics-server", Group: "components", Severity: engine.Block,
		// DependsOn platform for the remedy: on OpenShift metrics-server is not
		// something the operator installs, so that advice would send them down
		// the wrong path entirely.
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("components.metrics-server")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: the metrics API was not inspected")
			}

			remedy := "install metrics-server — no chart in either ApplicationSet does: " +
				"`kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml`, " +
				"adding `--kubelet-insecure-tls` to its args on clusters whose kubelets serve self-signed certificates"
			if c.Platform.IsOpenShift() {
				remedy = "OpenShift serves metrics.k8s.io from the cluster monitoring stack rather than a standalone metrics-server, so this is a broken monitoring stack and not a missing install: " +
					"`oc get clusteroperator monitoring` and `oc -n openshift-monitoring get pods` show why the aggregated API is gone"
			}

			as := c.Kube.Get(ctx, "apiservices.apiregistration.k8s.io", "", "v1beta1.metrics.k8s.io")
			if as == nil {
				return ch.Fail(
					"the v1beta1.metrics.k8s.io APIService does not exist: every HPA the chart creates reads `<unknown>/70%` and never scales, so the platform sits at its minimum replica count under any load",
					remedy,
				).WithEvidence(engine.Evidence{
					What:   "kubectl get apiservice v1beta1.metrics.k8s.io",
					Output: "NotFound",
				})
			}

			backing := "local (served by the API server itself)"
			if svcName := as.DigString("spec", "service", "name"); svcName != "" {
				backing = as.DigString("spec", "service", "namespace") + "/" + svcName
			}
			status, message := componentCondition(as.DigSlice("status", "conditions"), "Available")
			ev := engine.Evidence{
				What:   "kubectl get apiservice v1beta1.metrics.k8s.io -o jsonpath='{.status.conditions}'",
				Output: fmt.Sprintf("Available=%s %s", status, message),
			}
			if status != "True" {
				return ch.Fail(
					fmt.Sprintf("the v1beta1.metrics.k8s.io APIService exists but is not Available (%s): the aggregation layer cannot reach it, so every HPA in the chart reads `<unknown>/70%%` and never scales", message),
					remedy,
					"backing service: "+backing,
				).WithEvidence(ev)
			}

			return ch.Pass("metrics.k8s.io/v1beta1 is served and Available", "backing service: "+backing).
				WithEvidence(ev).
				Bounds("an Available APIService does not prove metrics flow for every node: a node whose kubelet the metrics backend cannot scrape still reports `<unknown>` to an HPA, and budctl does not query the metrics API itself.")
		},
	})

	engine.Register(&engine.Check{
		// INFO by declaration, which is what makes absence unable to move the
		// verdict no matter what this body decides. A conflict is raised with
		// FailAs(Risk) and never Block: FRD-020 §3.1 says a component in the
		// list is checked only if it is already present, and then only to warn.
		ID: "components.appset-conflicts", Group: "components", Severity: engine.Info,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("components.appset-conflicts")
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: installed components were not inventoried")
			}
			names := c.Profile.AppsetComponents
			if len(names) == 0 {
				return ch.Skip("the embedded profile lists no ApplicationSet components to sweep")
			}

			namespaces := map[string]bool{}
			for _, n := range c.Kube.List(ctx, "namespaces", "") {
				namespaces[n.Name()] = true
			}

			detail := make([]string, 0, len(names))
			evidence := make([]string, 0, len(names))
			installed, conflicting := []string{}, []string{}
			conflictLines := []string{}

			for _, name := range names {
				p := detectAppsetComponent(ctx, c, name, namespaces)
				if !p.installed {
					detail = append(detail, fmt.Sprintf("%s: absent — installed by the %s ApplicationSet, not a prerequisite", name, p.appset))
					evidence = append(evidence, fmt.Sprintf("%-15s absent", name))
					continue
				}
				installed = append(installed, name)
				line := fmt.Sprintf("%s: present (%s) — installed by the %s ApplicationSet", name, p.describe(), p.appset)
				evidence = append(evidence, fmt.Sprintf("%-15s present  %s  owner=%s  via=%s", name, p.versionOr("version unknown"), p.owner, p.via))
				if len(p.notes) > 0 {
					line += " — " + strings.Join(p.notes, "; ")
				}
				if len(p.conflicts) > 0 {
					conflicting = append(conflicting, name)
					for _, cf := range p.conflicts {
						conflictLines = append(conflictLines, name+": "+cf)
					}
					line += " — CONFLICT: " + strings.Join(p.conflicts, "; ")
				}
				detail = append(detail, line)
			}

			ev := engine.Evidence{
				What:   "namespace, CRD and workload inventory for the components installed by cluster-addons and prod-apps",
				Output: strings.Join(evidence, "\n"),
			}
			bounds := "absence is not checked for, only reported: none of these components is a prerequisite (FRD-020 §3.1). " +
				"Version comparison covers only the components whose ApplicationSet pin budctl carries; for the rest the installed version is reported with no compatibility claim. " +
				"Ownership is read from labels on the component's own workloads, not from Helm release state."

			switch {
			case len(conflicting) > 0:
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("%d of the %d ApplicationSet %s already installed in a way the first sync collides with (%s): ArgoCD will claim resources another release owns, and a later `helm uninstall` or operator upgrade then deletes objects ArgoCD believes it manages",
						len(conflicting), len(names), Plural(len(conflicting), "component is", "components are"), strings.Join(conflicting, ", ")),
					"decide per component before applying the ApplicationSets: either remove the existing install and let ArgoCD create it, or drop that element from the list generator in infra/appsets/cluster-addons.yaml so ArgoCD never claims it. Adopting in place works only if you also reconcile the pinned version and the values.",
					append(conflictLines, detail...)...,
				).WithEvidence(ev).Bounds(bounds)

			case len(installed) == 0:
				return ch.Infof("none of the %d ApplicationSet components is installed; cluster-addons and prod-apps install all of them, so their absence is not a readiness failure", len(names)).
					With(detail...).WithEvidence(ev).Bounds(bounds)

			default:
				return ch.Infof("%d of %d ApplicationSet components already installed and none conflicts with the sync: %s",
					len(installed), len(names), strings.Join(installed, ", ")).
					With(detail...).WithEvidence(ev).Bounds(bounds)
			}
		},
	})
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

// componentDNSPods finds the cluster's DNS pods by label first and by name
// second. The label is the portable signal — `k8s-app=kube-dns` is what both
// CoreDNS and the old kube-dns carry, and the OpenShift DNS operator sets its
// own — but a hand-rolled CoreDNS deployment often carries neither.
func componentDNSPods(ctx context.Context, c *engine.Ctx, ns string) []adapters.Object {
	out := []adapters.Object{}
	for _, p := range c.Kube.List(ctx, "pods", ns) {
		l := p.Labels()
		match := l["k8s-app"] == "kube-dns" || l["k8s-app"] == "coredns" ||
			l["dns.operator.openshift.io/daemonset-dns"] == "default"
		if !match {
			name := p.Name()
			for _, prefix := range []string{"coredns", "kube-dns", "dns-default"} {
				if strings.HasPrefix(name, prefix) {
					match = true
					break
				}
			}
		}
		// A Succeeded pod is a finished one-shot, not a failing resolver;
		// counting it as unhealthy would block on leftovers from a node drain.
		if match && p.DigString("status", "phase") != "Succeeded" {
			out = append(out, p)
		}
	}
	return out
}

// componentDNSService returns the name and ClusterIP of whatever Service in the
// namespace publishes port 53.
func componentDNSService(ctx context.Context, c *engine.Ctx, ns string) (string, string) {
	for _, s := range c.Kube.List(ctx, "services", ns) {
		for _, raw := range s.DigSlice("spec", "ports") {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if componentInt(m["port"]) == 53 {
				return s.Name(), s.DigString("spec", "clusterIP")
			}
		}
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------

func openShiftIngress(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	co := c.Kube.Get(ctx, "clusteroperators.config.openshift.io", "", "ingress")
	if co == nil {
		return ch.Skip("OpenShift detected but clusteroperators.config.openshift.io/ingress is not readable; the ingress path was NOT verified")
	}
	available, availMsg := componentCondition(co.DigSlice("status", "conditions"), "Available")
	degraded, degMsg := componentCondition(co.DigSlice("status", "conditions"), "Degraded")
	ev := engine.Evidence{
		What:   "oc get clusteroperator ingress -o jsonpath='{.status.conditions}'",
		Output: fmt.Sprintf("Available=%s %s\nDegraded=%s %s", available, availMsg, degraded, degMsg),
	}

	if available != "True" {
		return ch.Fail(
			fmt.Sprintf("the OpenShift Ingress Operator is not Available (%s): no router is being reconciled, so no Route the install creates is ever served and nothing it publishes is reachable", availMsg),
			"`oc get clusteroperator ingress -o yaml` and `oc -n openshift-ingress-operator logs deploy/ingress-operator` — the operator is a cluster component, not something the install can repair",
		).WithEvidence(ev)
	}
	if degraded == "True" {
		return ch.Fail(
			fmt.Sprintf("the OpenShift Ingress Operator reports Degraded (%s): Routes may still be admitted while the router does not serve them, so the install completes and no hostname answers", degMsg),
			"`oc -n openshift-ingress get pods` and `oc -n openshift-ingress-operator get ingresscontroller default -o yaml` — clear the Degraded condition before installing",
		).WithEvidence(ev)
	}

	ic := c.Kube.Get(ctx, "ingresscontrollers.operator.openshift.io", "openshift-ingress-operator", "default")
	if ic == nil {
		return ch.Fail(
			"the Ingress Operator is Available but there is no `default` IngressController: the cluster has no router, so every Route the install creates is admitted by nothing",
			"create the default IngressController in openshift-ingress-operator with the cluster's base domain, or restore it from the cluster's install config",
		).WithEvidence(ev)
	}
	icAvail, icMsg := componentCondition(ic.DigSlice("status", "conditions"), "Available")
	replicas := componentInt(ic.Dig("status", "availableReplicas"))
	domain := ic.DigString("status", "domain")
	ev.Output += fmt.Sprintf("\ningresscontroller/default Available=%s %s availableReplicas=%d domain=%s", icAvail, icMsg, replicas, domain)

	if icAvail != "True" || replicas == 0 {
		return ch.Fail(
			fmt.Sprintf("the default IngressController has %d available %s (Available=%s): no router pod is serving, so nothing the install publishes answers on 80 or 443",
				replicas, Plural(replicas, "replica", "replicas"), icAvail),
			"`oc -n openshift-ingress get pods` — the router pods are usually unschedulable because no node matches their placement, or blocked waiting on their LoadBalancer Service",
		).WithEvidence(ev)
	}

	// The domains group needs somewhere to compare each hostname's A record
	// against; on OpenShift the router's Service is that address.
	if svc := c.Kube.Get(ctx, "services", "openshift-ingress", "router-default"); svc != nil {
		if addrs := componentIngressAddresses(svc); len(addrs) > 0 {
			c.Set(engine.KeyIngressAddrs, addrs)
			ev.Output += "\nrouter-default external: " + strings.Join(addrs, ", ")
		}
	}

	return ch.Pass(
		fmt.Sprintf("the OpenShift Ingress Operator is Available and the default IngressController serves %d %s on *.%s", replicas, Plural(replicas, "replica", "replicas"), domain),
	).WithEvidence(ev).
		Bounds("Route admission is not evaluated: the IngressController's domain and any routeSelector decide whether a given hostname is admitted, and `domains.*` checks DNS and the inbound path rather than admission policy.")
}

func vanillaIngress(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	classes := c.Kube.List(ctx, "ingressclasses.networking.k8s.io", "")
	if len(classes) == 0 {
		return ch.Fail(
			"no IngressClass exists: every Ingress the install creates stays unclaimed, so not one hostname the chart publishes is ever reachable",
			"install an ingress controller before applying the ApplicationSets — neither of them provides one. Any controller is acceptable: "+
				"`helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace`, k3s's bundled Traefik, or the cloud provider's. "+
				"Then set global.ingress.className to its class, or mark the class default with the `ingressclass.kubernetes.io/is-default-class: \"true\"` annotation.",
		).WithEvidence(engine.Evidence{What: "kubectl get ingressclass", Output: "No resources found"})
	}

	index := componentEndpointIndex(ctx, c)
	states := make([]componentClassState, 0, len(classes))
	evLines := []string{}
	for _, cl := range classes {
		st := componentClassState{
			name:       cl.Name(),
			controller: cl.DigString("spec", "controller"),
			isDefault:  cl.Annotations()["ingressclass.kubernetes.io/is-default-class"] == "true",
		}
		tokens := ingressControllerTokens(st.name, st.controller)
		for _, e := range index {
			if !e.matches(tokens) {
				continue
			}
			st.matched = true
			st.ready += e.Ready
			st.notReady += e.NotReady
			st.where = append(st.where, fmt.Sprintf("%s/%s %d ready / %d not ready", e.Namespace, e.Service, e.Ready, e.NotReady))
			if st.ready > 0 && len(st.addrs) == 0 {
				if svc := c.Kube.Get(ctx, "services", e.Namespace, e.Service); svc != nil {
					st.addrs = componentIngressAddresses(svc)
				}
			}
		}
		evLines = append(evLines, st.evidence(tokens))
		states = append(states, st)
	}
	ev := engine.Evidence{
		What:   "each IngressClass, and the ready endpoints of the workload its spec.controller names",
		Output: strings.Join(evLines, "\n"),
	}

	// When --values was supplied, the chart's own Ingresses name the class that
	// has to work. A controller that is ready on some OTHER class does not make
	// the install reachable, so the requested class is the only one that counts.
	requested := componentRequestedIngressClasses(c)
	scope := states
	if len(requested) > 0 {
		byName := map[string]componentClassState{}
		for _, st := range states {
			byName[st.name] = st
		}
		scope = nil
		for _, want := range requested {
			st, ok := byName[want]
			if !ok {
				return ch.Fail(
					fmt.Sprintf("the chart's Ingresses request IngressClass %q, which does not exist in this cluster: those Ingresses are claimed by no controller and none of their hostnames answers", want),
					fmt.Sprintf("either set global.ingress.className in your values to a class that exists (%s), or install the controller that provides %q", strings.Join(componentClassNames(states), ", "), want),
				).WithEvidence(ev)
			}
			scope = append(scope, st)
		}
	}

	ready, controllerDown, unmatched := []string{}, []string{}, []string{}
	addrs := []string{}
	for _, st := range scope {
		switch {
		case st.matched && st.ready > 0:
			ready = append(ready, fmt.Sprintf("%s (%s) via %s", st.name, st.controller, strings.Join(st.where, ", ")))
			addrs = append(addrs, st.addrs...)
		case st.matched:
			controllerDown = append(controllerDown, fmt.Sprintf("%s (%s): %s", st.name, st.controller, strings.Join(st.where, ", ")))
		default:
			unmatched = append(unmatched, fmt.Sprintf("%s (%s)", st.name, st.controller))
		}
	}

	// Existence of the class alone must NOT pass. An IngressClass is a piece of
	// metadata; the thing that has to be alive is the controller behind it, and
	// "alive" means a pod in that Service's ready endpoint set — a pod that is
	// Running but out of the endpoints receives no traffic.
	if len(ready) == 0 && len(controllerDown) > 0 {
		return ch.Fail(
			fmt.Sprintf("an IngressClass exists but its controller has no ready endpoints (%s): the class is only metadata, so with nothing serving it every Ingress the install creates stays unclaimed and no hostname answers",
				strings.Join(controllerDown, "; ")),
			"`kubectl get pods -A | grep -i ingress` and describe the controller pod — it is usually unschedulable, stuck pulling its image, or failing its readiness probe. Nothing in the ApplicationSets repairs an ingress controller.",
		).WithEvidence(ev)
	}
	if len(ready) == 0 {
		return ch.Fail(
			fmt.Sprintf("no running controller could be matched to %s (%s): if nothing is serving %s, every Ingress the install creates stays unclaimed and no hostname the chart publishes answers",
				Plural(len(unmatched), "the IngressClass", "any of the IngressClasses"), strings.Join(unmatched, ", "), Plural(len(unmatched), "it", "them")),
			"check the controller is running (`kubectl get pods -A | grep -i ingress`). budctl ties a class to its controller by name, because spec.controller is a vendor identifier with no API link to a workload — "+
				"so a controller whose pods carry none of those names, or one that runs outside the cluster such as a cloud load-balancer controller, is not matched here, and `domains.inbound-80` / `domains.inbound-443` are what prove that path instead.",
		).WithEvidence(ev).With(componentPort80443Candidates(ctx, c, index)...)
	}

	if len(addrs) > 0 {
		c.Set(engine.KeyIngressAddrs, Sorted(addrs))
	}
	detail := append([]string{}, ready...)
	if len(controllerDown) > 0 {
		detail = append(detail, "other classes with no ready controller: "+strings.Join(controllerDown, "; "))
	}
	if !componentAnyDefault(states) && len(requested) == 0 {
		detail = append(detail, "no IngressClass is marked default; set global.ingress.className in values so the chart's Ingresses name one explicitly")
	}
	return ch.Pass(
		fmt.Sprintf("%s %s a controller with ready endpoints: %s",
			Plural(len(ready), "IngressClass", "IngressClasses"), Plural(len(ready), "has", "have"), strings.Join(ready, "; ")),
		detail...,
	).WithEvidence(ev).
		Bounds("a ready controller is not a reachability test: it proves a pod is serving inside the cluster, not that traffic arrives from outside (`domains.inbound-80` / `domains.inbound-443`) nor that this controller will admit the chart's hostnames. The class is tied to its controller by name, so the Service named above is worth a glance.")
}

type componentClassState struct {
	name       string
	controller string
	isDefault  bool
	matched    bool
	ready      int
	notReady   int
	where      []string
	addrs      []string
}

func (s componentClassState) evidence(tokens []string) string {
	def := ""
	if s.isDefault {
		def = " [default]"
	}
	if !s.matched {
		return fmt.Sprintf("ingressclass/%s%s controller=%s -> no workload matched (searched for %s)", s.name, def, s.controller, strings.Join(tokens, ", "))
	}
	return fmt.Sprintf("ingressclass/%s%s controller=%s -> %s", s.name, def, s.controller, strings.Join(s.where, ", "))
}

func componentClassNames(states []componentClassState) []string {
	out := make([]string, 0, len(states))
	for _, s := range states {
		out = append(out, s.name)
	}
	return Sorted(out)
}

func componentAnyDefault(states []componentClassState) bool {
	for _, s := range states {
		if s.isDefault {
			return true
		}
	}
	return false
}

// componentRequestedIngressClasses reads the classes the chart's own Ingresses
// ask for. Nil when --values was not supplied, in which case every class in the
// cluster is a candidate instead.
func componentRequestedIngressClasses(c *engine.Ctx) []string {
	objs := Rendered(c)
	if len(objs) == 0 {
		return nil
	}
	out := []string{}
	for _, o := range objs {
		if o.Kind() != "Ingress" {
			continue
		}
		name := o.DigString("spec", "ingressClassName")
		if name == "" {
			// Charts that still target pre-1.18 clusters name the class in the
			// deprecated annotation, and controllers honour it.
			name = o.Annotations()["kubernetes.io/ingress.class"]
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return Sorted(out)
}

// ingressControllerTokens turns an IngressClass into the names its controller's
// pods and Service are likely to carry. spec.controller is a vendor identifier
// ("k8s.io/ingress-nginx", "traefik.io/ingress-controller") and never references
// a workload, so there is no API link from a class to the thing serving it: the
// name is the only bridge. Tokens shorter than four characters are dropped
// because a three-letter substring ("aws", "alb") matches unrelated pods, and a
// false PASS here is worse than a false BLOCK.
func ingressControllerTokens(class, controller string) []string {
	generic := map[string]bool{
		"io": true, "org": true, "com": true, "net": true, "sh": true, "dev": true,
		"cloud": true, "k8s": true, "x-k8s": true, "kubernetes": true,
		"ingress": true, "controller": true, "ingress-controller": true, "ingressclass": true,
	}
	add := func(out []string, s string) []string {
		s = strings.ToLower(strings.TrimSpace(s))
		if len(s) < 4 || generic[s] {
			return out
		}
		return append(out, s)
	}
	out := add(nil, class)
	domain, path, _ := strings.Cut(controller, "/")
	for _, label := range strings.Split(domain, ".") {
		out = add(out, label)
	}
	for _, seg := range strings.Split(path, "/") {
		out = add(out, seg)
	}
	return Sorted(out)
}

// componentEndpoint is one Service's readiness, aggregated across its slices.
// Ready is the count the ingress check turns on: an IngressClass whose
// controller has endpoints but none of them ready is exactly the failure
// FRD-020 §5.8 says existence must not paper over.
type componentEndpoint struct {
	Namespace string
	Service   string
	Ready     int
	NotReady  int
	Targets   []string
}

func (e componentEndpoint) matches(tokens []string) bool {
	hay := strings.ToLower(e.Namespace + " " + e.Service + " " + strings.Join(e.Targets, " "))
	for _, t := range tokens {
		if strings.Contains(hay, t) {
			return true
		}
	}
	return false
}

// componentEndpointIndex prefers EndpointSlices and falls back to Endpoints.
// Endpoints is deprecated but is still the only source on older servers, and
// EndpointSlice is the only one that survives the deprecation — reading just one
// of the two would make this check wrong on half the clusters in the field.
func componentEndpointIndex(ctx context.Context, c *engine.Ctx) []componentEndpoint {
	agg := map[string]*componentEndpoint{}
	key := func(ns, svc string) *componentEndpoint {
		k := ns + "/" + svc
		if e, ok := agg[k]; ok {
			return e
		}
		e := &componentEndpoint{Namespace: ns, Service: svc}
		agg[k] = e
		return e
	}

	for _, s := range c.Kube.List(ctx, "endpointslices.discovery.k8s.io", "") {
		svc := s.Labels()["kubernetes.io/service-name"]
		if svc == "" {
			svc = s.Name()
		}
		e := key(s.Namespace(), svc)
		for _, raw := range s.DigSlice("endpoints") {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			// conditions.ready unset means "unknown", which the API contract
			// tells consumers to read as ready.
			ready := true
			if cond, ok := m["conditions"].(map[string]any); ok {
				if r, ok := cond["ready"].(bool); ok {
					ready = r
				}
			}
			if ready {
				e.Ready++
			} else {
				e.NotReady++
			}
			if tr, ok := m["targetRef"].(map[string]any); ok {
				if n, ok := tr["name"].(string); ok {
					e.Targets = append(e.Targets, n)
				}
			}
		}
	}

	if len(agg) == 0 {
		for _, o := range c.Kube.List(ctx, "endpoints", "") {
			e := key(o.Namespace(), o.Name())
			for _, raw := range o.DigSlice("subsets") {
				sub, ok := raw.(map[string]any)
				if !ok {
					continue
				}
				// In Endpoints, "addresses" IS the ready set; not-ready
				// addresses are kept in a separate list.
				for _, list := range []string{"addresses", "notReadyAddresses"} {
					items, _ := sub[list].([]any)
					for _, a := range items {
						am, ok := a.(map[string]any)
						if !ok {
							continue
						}
						if list == "addresses" {
							e.Ready++
						} else {
							e.NotReady++
						}
						if tr, ok := am["targetRef"].(map[string]any); ok {
							if n, ok := tr["name"].(string); ok {
								e.Targets = append(e.Targets, n)
							}
						}
					}
				}
			}
		}
	}

	out := make([]componentEndpoint, 0, len(agg))
	for _, e := range agg {
		out = append(out, *e)
	}
	return out
}

// componentPort80443Candidates lists Services that publish both 80 and 443 with
// ready endpoints. It is evidence, never a pass: it tells an operator staring at
// an unmatched IngressClass whether budctl missed their controller or whether
// there genuinely is none.
func componentPort80443Candidates(ctx context.Context, c *engine.Ctx, index []componentEndpoint) []string {
	ready := map[string]int{}
	for _, e := range index {
		ready[e.Namespace+"/"+e.Service] = e.Ready
	}
	out := []string{}
	for _, s := range c.Kube.List(ctx, "services", "") {
		has80, has443 := false, false
		for _, raw := range s.DigSlice("spec", "ports") {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			switch componentInt(m["port"]) {
			case 80:
				has80 = true
			case 443:
				has443 = true
			}
		}
		k := s.Namespace() + "/" + s.Name()
		if has80 && has443 && ready[k] > 0 {
			out = append(out, fmt.Sprintf("candidate: %s publishes 80 and 443 with %d ready %s", k, ready[k], Plural(ready[k], "endpoint", "endpoints")))
		}
	}
	return Sorted(out)
}

func componentIngressAddresses(svc adapters.Object) []string {
	out := []string{}
	for _, raw := range svc.DigSlice("status", "loadBalancer", "ingress") {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"ip", "hostname"} {
			if v, ok := m[field].(string); ok && v != "" {
				out = append(out, v)
			}
		}
	}
	for _, raw := range svc.DigSlice("spec", "externalIPs") {
		if v, ok := raw.(string); ok && v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// ApplicationSet component sweep
// ---------------------------------------------------------------------------

// appsetComponent is how budctl recognises one of the twenty components the
// ApplicationSets install. The table exists only to tell "already here" from
// "will be installed"; nothing in it is ever required.
type appsetComponent struct {
	appset string
	// namespaces the ApplicationSets target, plus the upstream chart's own
	// default where it differs — a component installed by hand often sits there.
	namespaces []string
	// apis are served only when the component is installed. An operator's CRDs
	// are a stronger signal than a namespace, which outlives an uninstall.
	apis []string
	// tokens pick the representative workload inside the namespace, so the
	// version is read off the component itself rather than off a sidecar.
	tokens []string
}

// appsetCatalog maps the component names in profiles/defaults.yaml to the
// namespaces and API groups in infra/appsets/{cluster-addons,prod-apps}.yaml.
var appsetCatalog = map[string]appsetComponent{
	"argocd":         {"cluster-addons", []string{"argocd"}, []string{"applications.argoproj.io", "applicationsets.argoproj.io"}, []string{"argocd-server", "argocd"}},
	"cert-manager":   {"cluster-addons", []string{"cert-manager"}, []string{"certificates.cert-manager.io", "clusterissuers.cert-manager.io"}, []string{"cert-manager"}},
	"clickhouse":     {"cluster-addons", []string{"clickhouse"}, []string{"clickhouseinstallations.clickhouse.altinity.com"}, []string{"clickhouse"}},
	"dapr":           {"cluster-addons", []string{"dapr-system"}, []string{"components.dapr.io", "configurations.dapr.io"}, []string{"dapr-operator", "dapr"}},
	"harbor":         {"prod-apps", []string{"harbor"}, nil, []string{"harbor-core", "harbor"}},
	"kafka":          {"cluster-addons", []string{"kafka"}, []string{"kafkas.kafka.strimzi.io"}, []string{"strimzi", "kafka"}},
	"keel":           {"cluster-addons", []string{"keel"}, nil, []string{"keel"}},
	"keycloak":       {"prod-apps", []string{"keycloak"}, []string{"keycloaks.k8s.keycloak.org"}, []string{"keycloak"}},
	"kyverno":        {"cluster-addons", []string{"kyverno"}, []string{"clusterpolicies.kyverno.io", "policies.kyverno.io"}, []string{"kyverno-admission", "kyverno"}},
	"mongodb":        {"cluster-addons", []string{"mongodb"}, []string{"perconaservermongodbs.psmdb.percona.com"}, []string{"psmdb", "mongodb"}},
	"openebs":        {"cluster-addons", []string{"openebs"}, []string{"diskpools.openebs.io"}, []string{"openebs"}},
	"opensandbox":    {"prod-apps", []string{"opensandbox-system", "opensandbox"}, nil, []string{"opensandbox"}},
	"otel":           {"cluster-addons", []string{"otel", "opentelemetry-operator-system"}, []string{"opentelemetrycollectors.opentelemetry.io", "instrumentations.opentelemetry.io"}, []string{"opentelemetry-operator", "otel"}},
	"postgres":       {"cluster-addons", []string{"postgres", "cnpg-system"}, []string{"clusters.postgresql.cnpg.io"}, []string{"cloudnative-pg", "cnpg"}},
	"seaweedfs":      {"cluster-addons", []string{"seaweedfs"}, []string{"seaweeds.seaweed.seaweedfs.com"}, []string{"seaweedfs"}},
	"signoz":         {"cluster-addons", []string{"signoz"}, nil, []string{"signoz"}},
	"valkey":         {"cluster-addons", []string{"valkey"}, []string{"valkeys.hyperspike.io"}, []string{"valkey-operator", "valkey"}},
	"valkey-cluster": {"cluster-addons", []string{"valkey-cluster"}, nil, []string{"valkey"}},
	"velero":         {"cluster-addons", []string{"velero"}, []string{"backups.velero.io", "restores.velero.io"}, []string{"velero"}},
	"bud":            {"prod-apps", []string{"bud", "bud-dev", "bud-prod", "bud-stage"}, nil, []string{"budapp", "bud"}},
}

// appsetPins are the versions the ApplicationSets pin, for the two components
// where the chart version IS the upstream application version and a mismatch is
// therefore a real statement rather than a units error. dapr comes from
// infra/appsets/cluster-addons.yaml (targetRevision 1.17.5); cert-manager from
// infra/charts/cert-manager/Chart.yaml (dependency 1.21.0).
//
// CONTRACT GAP: these belong in profiles/defaults.yaml beside appsetComponents,
// so they cannot drift from the ApplicationSets the way a copy in Go source
// will. intake.Profile has no field for them today, and a sweep that carries no
// expected version cannot report a version conflict at all.
var appsetPins = map[string]string{
	"dapr":         "1.17.5",
	"cert-manager": "1.21.0",
}

type componentPresence struct {
	name      string
	appset    string
	installed bool
	via       string
	namespace string
	version   string
	owner     string
	conflicts []string
	// notes record what could NOT be determined, so a quiet result is not read
	// as a clean one.
	notes []string
}

func (p componentPresence) versionOr(fallback string) string {
	if p.version == "" {
		return fallback
	}
	return p.version
}

func (p componentPresence) describe() string {
	parts := []string{p.versionOr("version unknown")}
	if p.namespace != "" {
		parts = append(parts, "ns "+p.namespace)
	}
	if p.owner == "unknown" {
		parts = append(parts, "ownership undetermined")
	} else {
		parts = append(parts, "managed by "+p.owner)
	}
	return strings.Join(parts, ", ")
}

func detectAppsetComponent(ctx context.Context, c *engine.Ctx, name string, namespaces map[string]bool) componentPresence {
	spec, known := appsetCatalog[name]
	if !known {
		// A component added to the profile but not to this table: fall back to
		// a namespace of the same name rather than silently report absence.
		spec = appsetComponent{appset: "cluster-addons", namespaces: []string{name}, tokens: []string{name}}
	}
	p := componentPresence{name: name, appset: spec.appset, owner: "unknown"}

	for _, api := range spec.apis {
		if c.Kube.HasResource(ctx, api) {
			p.installed = true
			p.via = "CRD " + api
			break
		}
	}

	// The workload carries the version and the ownership labels, so look for one
	// even when a CRD has already proved presence.
	for _, ns := range spec.namespaces {
		if !namespaces[ns] {
			continue
		}
		w := componentWorkload(ctx, c, ns, spec.tokens)
		if w == nil {
			continue
		}
		p.installed = true
		p.namespace = ns
		if p.via == "" {
			p.via = "workload " + ns + "/" + w.Name()
		}
		p.version = componentVersion(w)
		p.owner = componentOwner(w)
		break
	}
	if !p.installed {
		return p
	}

	// Anything ArgoCD does not already own is a resource the ApplicationSet's
	// first sync will take over: Helm's ownership metadata stays behind, the
	// Application renders permanently OutOfSync against the values in this repo,
	// and a later `helm uninstall` deletes objects ArgoCD believes it manages.
	//
	// Claimed only when a workload was actually read. Presence proved by a CRD
	// alone says nothing about who owns the install, and asserting a conflict
	// from an unknown owner would manufacture a RISK out of missing data.
	switch {
	case p.owner == "unknown":
		p.notes = append(p.notes, "owner not determined: no workload found in "+strings.Join(spec.namespaces, " or "))
	case !strings.HasPrefix(p.owner, "ArgoCD"):
		p.conflicts = append(p.conflicts,
			fmt.Sprintf("installed outside ArgoCD (%s), so the %s ApplicationSet will adopt resources another release owns", p.owner, p.appset))
	}

	if pin, ok := appsetPins[name]; ok && p.version != "" {
		got, want := parseVersion(p.version), parseVersion(pin)
		// An unparseable tag — a digest, "stable", a fork suffix — is reported
		// as unknown rather than compared: parseVersion yields 0.0.0 for it, and
		// comparing that against a pin invents a conflict out of nothing.
		if got != ([3]int{}) && (got[0] != want[0] || got[1] != want[1]) {
			direction := "upgrade"
			if compareVersions(p.version, pin) > 0 {
				direction = "DOWNGRADE"
			}
			p.conflicts = append(p.conflicts,
				fmt.Sprintf("runs %s while the %s ApplicationSet pins %s, so the first sync is an in-place %s of a component the whole platform sits on", p.version, p.appset, pin, direction))
		} else if got == ([3]int{}) {
			p.notes = append(p.notes, fmt.Sprintf("version %q is not comparable with the pinned %s", p.version, pin))
		}
	}
	return p
}

// componentWorkload returns the workload that best represents a component in a
// namespace: the first whose name matches a token, else any workload at all,
// because an unrecognised name is still evidence the namespace is occupied.
func componentWorkload(ctx context.Context, c *engine.Ctx, ns string, tokens []string) adapters.Object {
	all := []adapters.Object{}
	for _, kind := range []string{"deployments.apps", "statefulsets.apps", "daemonsets.apps"} {
		all = append(all, c.Kube.List(ctx, kind, ns)...)
	}
	for _, t := range tokens {
		for _, o := range all {
			if strings.Contains(strings.ToLower(o.Name()), strings.ToLower(t)) {
				return o
			}
		}
	}
	if len(all) > 0 {
		return all[0]
	}
	return nil
}

// componentVersion prefers the standard label and falls back to the image tag,
// which is what an operator would read off `kubectl get deploy -o wide`.
func componentVersion(o adapters.Object) string {
	if v := o.Labels()["app.kubernetes.io/version"]; v != "" {
		return v
	}
	for _, ct := range o.Containers() {
		img, _ := ct["image"].(string)
		if img == "" {
			continue
		}
		if _, _, ref := adapters.ImageRef(img); ref != "" && ref != "latest" {
			return ref
		}
	}
	return ""
}

// componentOwner reads ownership off labels on the object itself. It never
// touches Helm release state or Secrets: FRD-020 §3 puts release diffing out of
// scope, and the question here is only "would ArgoCD be taking this over".
func componentOwner(o adapters.Object) string {
	l, a := o.Labels(), o.Annotations()
	if v := l["argocd.argoproj.io/instance"]; v != "" {
		return "ArgoCD Application " + v
	}
	if v := a["argocd.argoproj.io/tracking-id"]; v != "" {
		return "ArgoCD Application " + strings.SplitN(v, ":", 2)[0]
	}
	if v := l["app.kubernetes.io/instance"]; v != "" && l["app.kubernetes.io/managed-by"] != "Helm" {
		// ArgoCD's default tracking method is this label; Helm sets it too, and
		// managed-by is what disambiguates the two.
		return "ArgoCD Application " + v
	}
	if by := l["app.kubernetes.io/managed-by"]; by != "" {
		if inst := l["app.kubernetes.io/instance"]; inst != "" {
			return by + " release " + inst
		}
		return by
	}
	return "no ArgoCD or Helm ownership labels"
}

// ---------------------------------------------------------------------------
// Shared readers
// ---------------------------------------------------------------------------

// componentCondition returns the status and message of one status condition.
func componentCondition(conditions []any, want string) (string, string) {
	for _, raw := range conditions {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t != want {
			continue
		}
		status, _ := m["status"].(string)
		msg, _ := m["message"].(string)
		if msg == "" {
			msg, _ = m["reason"].(string)
		}
		return status, msg
	}
	return "Unknown", "condition " + want + " is not reported"
}

// componentPodHealth summarises one pod the way `kubectl get pod` does, and
// returns the waiting/terminated reason separately because that reason —
// CrashLoopBackOff, ImagePullBackOff — is what decides the remedy.
func componentPodHealth(p adapters.Object) (bool, string, string) {
	phase := p.DigString("status", "phase")
	statuses := p.DigSlice("status", "containerStatuses")
	readyN, restarts, reason := 0, 0, ""
	for _, raw := range statuses {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if r, ok := m["ready"].(bool); ok && r {
			readyN++
		}
		if n := componentInt(m["restartCount"]); n > restarts {
			restarts = n
		}
		state, _ := m["state"].(map[string]any)
		for _, k := range []string{"waiting", "terminated"} {
			if s, ok := state[k].(map[string]any); ok {
				if r, _ := s["reason"].(string); r != "" && reason == "" {
					reason = r
				}
			}
		}
	}
	total := len(statuses)
	ready := phase == "Running" && total > 0 && readyN == total
	line := fmt.Sprintf("%s %d/%d %s", p.Name(), readyN, total, phase)
	if reason != "" {
		line += " " + reason
	}
	if restarts > 0 {
		line += fmt.Sprintf(" (restarts %d)", restarts)
	}
	if reason == "" && !ready {
		reason = phase
	}
	return ready, line, reason
}

// componentInt reads a number out of an unstructured object, which decodes
// whole numbers as int64 and everything else as float64.
func componentInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func componentSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
