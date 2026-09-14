package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// The components group is the boundary between "the cluster must supply this"
// and "the ApplicationSets install this". Both halves of that line are testable
// and both are dangerous when wrong: a missing blocker lets an install proceed
// into a cluster with no DNS, and a spurious blocker refuses to install onto a
// perfectly good cluster because Dapr is not there yet — which is the whole
// point of installing.

// ---------------------------------------------------------------------------
// Group-local helpers and builders
// ---------------------------------------------------------------------------

// componentsRun is run() plus access to the Ctx, because two of the ingress
// paths are only observable through what they publish for the domains group
// (engine.KeyIngressAddrs) or through what config.render put in front of them.
func componentsRun(t *testing.T, f *fakeCluster, id string, tweak ...func(*engine.Ctx)) (engine.Result, *engine.Ctx) {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	for _, fn := range tweak {
		fn(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c), c
}

// componentsRunWithoutCluster drives the unreachable-cluster path, which is the
// one branch of every check in this group that a seeded fake cannot express:
// the harness always attaches a Kube.
func componentsRunWithoutCluster(t *testing.T, id string) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := vanilla().ctx(t)
	c.Kube = nil
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

func componentsAssertSummaryHas(t *testing.T, r engine.Result, want string) {
	t.Helper()
	if !strings.Contains(r.Summary, want) {
		t.Fatalf("%s: summary does not mention %q\n  summary: %s", r.ID, want, r.Summary)
	}
}

func componentsAssertDetailHas(t *testing.T, r engine.Result, want string) {
	t.Helper()
	for _, d := range r.Detail {
		if strings.Contains(d, want) {
			return
		}
	}
	t.Fatalf("%s: no detail line mentions %q\n  detail: %s", r.ID, want, strings.Join(r.Detail, "\n"))
}

func componentsNamespace(name string) adapters.Object {
	return adapters.Object{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": name},
	}
}

// componentsDNSPod models what the kubelet actually reports. The check reads
// containerStatuses rather than the Ready condition, so a DNS fixture has to
// carry them or every pod reads as not-ready regardless of its condition.
func componentsDNSPod(ns, name string, opts ...func(adapters.Object)) adapters.Object {
	o := adapters.Object{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{
			"name": name, "namespace": ns,
			"labels": map[string]any{"k8s-app": "kube-dns"},
		},
		"spec": map[string]any{"containers": []any{map[string]any{"name": "coredns", "image": "coredns:1.11.1"}}},
		"status": map[string]any{
			"phase": "Running",
			"containerStatuses": []any{map[string]any{
				"name": "coredns", "ready": true, "restartCount": int64(0),
			}},
		},
	}
	for _, fn := range opts {
		fn(o)
	}
	return o
}

func componentsCrashLooping(o adapters.Object) {
	cs := o.DigSlice("status", "containerStatuses")[0].(map[string]any)
	cs["ready"] = false
	cs["restartCount"] = int64(147)
	cs["state"] = map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff"}}
}

// componentsUnlabelled strips the k8s-app label so only the name-prefix branch
// can find the pod — a hand-rolled CoreDNS Deployment carries no label.
func componentsUnlabelled(o adapters.Object) {
	delete(o["metadata"].(map[string]any), "labels")
}

// componentsSucceeded is a finished one-shot left behind by a node drain, not a
// failing resolver.
func componentsSucceeded(o adapters.Object) {
	st := o["status"].(map[string]any)
	st["phase"] = "Succeeded"
	st["containerStatuses"].([]any)[0].(map[string]any)["ready"] = false
}

// componentsOpenShiftDNSLabel is what the OpenShift DNS operator stamps on its
// daemonset pods instead of k8s-app.
func componentsOpenShiftDNSLabel(o adapters.Object) {
	o["metadata"].(map[string]any)["labels"] = map[string]any{
		"dns.operator.openshift.io/daemonset-dns": "default",
	}
}

func componentsService(ns, name, clusterIP string, ports []int, opts ...func(adapters.Object)) adapters.Object {
	p := make([]any, 0, len(ports))
	for _, port := range ports {
		p = append(p, map[string]any{"port": int64(port), "protocol": "TCP"})
	}
	o := adapters.Object{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     map[string]any{"clusterIP": clusterIP, "ports": p},
		"status":   map[string]any{},
	}
	for _, fn := range opts {
		fn(o)
	}
	return o
}

func componentsLoadBalancerIP(ip string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["status"].(map[string]any)["loadBalancer"] = map[string]any{
			"ingress": []any{map[string]any{"ip": ip}},
		}
	}
}

func componentsEndpointSlice(ns, svc string, ready, notReady int) adapters.Object {
	eps := []any{}
	for i := 0; i < ready; i++ {
		eps = append(eps, map[string]any{
			"conditions": map[string]any{"ready": true},
			"targetRef":  map[string]any{"name": svc + "-ready"},
		})
	}
	for i := 0; i < notReady; i++ {
		eps = append(eps, map[string]any{
			"conditions": map[string]any{"ready": false},
			"targetRef":  map[string]any{"name": svc + "-pending"},
		})
	}
	return adapters.Object{
		"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
		"metadata": map[string]any{
			"name": svc + "-abcde", "namespace": ns,
			"labels": map[string]any{"kubernetes.io/service-name": svc},
		},
		"endpoints": eps,
	}
}

// componentsLegacyEndpoints is the pre-EndpointSlice shape older API servers
// still serve. In Endpoints, "addresses" IS the ready set.
func componentsLegacyEndpoints(ns, name string, ready, notReady int) adapters.Object {
	addrs, notReadyAddrs := []any{}, []any{}
	for i := 0; i < ready; i++ {
		addrs = append(addrs, map[string]any{"ip": "10.1.0.1", "targetRef": map[string]any{"name": name + "-ready"}})
	}
	for i := 0; i < notReady; i++ {
		notReadyAddrs = append(notReadyAddrs, map[string]any{"ip": "10.1.0.2", "targetRef": map[string]any{"name": name + "-pending"}})
	}
	return adapters.Object{
		"apiVersion": "v1", "kind": "Endpoints",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"subsets": []any{map[string]any{
			"addresses": addrs, "notReadyAddresses": notReadyAddrs,
		}},
	}
}

func componentsDefaultIngressClass(name, controller string) adapters.Object {
	o := ingressClass(name, controller)
	o["metadata"].(map[string]any)["annotations"] = map[string]any{
		"ingressclass.kubernetes.io/is-default-class": "true",
	}
	return o
}

// componentsIngressObject is what config.render hands the ingress check: the
// chart's own Ingress, naming the class that actually has to work.
func componentsIngressObject(name, className string, useDeprecatedAnnotation bool) adapters.Object {
	meta := map[string]any{"name": name, "namespace": "bud"}
	spec := map[string]any{}
	if useDeprecatedAnnotation {
		meta["annotations"] = map[string]any{"kubernetes.io/ingress.class": className}
	} else {
		spec["ingressClassName"] = className
	}
	return adapters.Object{
		"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
		"metadata": meta, "spec": spec,
	}
}

func componentsClusterOperator(name string, available, degraded bool) adapters.Object {
	b := func(v bool) string {
		if v {
			return "True"
		}
		return "False"
	}
	return adapters.Object{
		"apiVersion": "config.openshift.io/v1", "kind": "ClusterOperator",
		"metadata": map[string]any{"name": name},
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "Available", "status": b(available), "message": "seeded"},
			map[string]any{"type": "Degraded", "status": b(degraded), "message": "canary route not admitted on any router"},
		}},
	}
}

func componentsIngressController(name, domain string, replicas int, available bool) adapters.Object {
	o := ingressController(name, domain, replicas)
	if !available {
		o["status"].(map[string]any)["conditions"] = []any{
			map[string]any{"type": "Available", "status": "False", "message": "0/2 router pods scheduled"},
			map[string]any{"type": "Degraded", "status": "True"},
		}
	}
	return o
}

func componentsAPIServiceNoConditions(name, svcNamespace, svcName string) adapters.Object {
	return adapters.Object{
		"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService",
		"metadata": map[string]any{"name": name},
		"spec": map[string]any{
			"service": map[string]any{"namespace": svcNamespace, "name": svcName},
		},
		"status": map[string]any{"conditions": []any{}},
	}
}

// componentsAppsetWorkload is one already-installed ApplicationSet component:
// the Deployment the sweep reads its version and ownership off.
func componentsAppsetWorkload(ns, name, version string, labels map[string]string) adapters.Object {
	l := map[string]any{}
	for k, v := range labels {
		l[k] = v
	}
	if version != "" {
		l["app.kubernetes.io/version"] = version
	}
	return adapters.Object{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": ns, "labels": l},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			// Tagged :latest so componentVersion falls back to nothing when no
			// version label is set — "version unknown" has to stay reachable.
			"containers": []any{map[string]any{"name": "c", "image": "example.io/" + name + ":latest"}},
		}}},
	}
}

func componentsWithAPIs(f *fakeCluster, apis ...string) *fakeCluster {
	for _, a := range apis {
		f.apiGroups[a] = true
	}
	return f
}

// componentsHealthyBase is a cluster that passes all three blocking checks, so
// a test that varies one thing is varying exactly that one thing.
func componentsHealthyBase() *fakeCluster {
	return vanilla().
		with("pods", "kube-system",
			componentsDNSPod("kube-system", "coredns-7db6d8ff4d-aaaaa"),
			componentsDNSPod("kube-system", "coredns-7db6d8ff4d-bbbbb")).
		with("services", "kube-system",
			componentsService("kube-system", "kube-dns", "10.96.0.10", []int{53})).
		with("ingressclasses.networking.k8s.io", "",
			componentsDefaultIngressClass("nginx", "k8s.io/ingress-nginx")).
		with("endpointslices.discovery.k8s.io", "",
			componentsEndpointSlice("ingress-nginx", "ingress-nginx-controller", 2, 0)).
		with("apiservices.apiregistration.k8s.io", "",
			apiService("v1beta1.metrics.k8s.io", true))
}

// ---------------------------------------------------------------------------
// THE BOUNDARY PROPERTY
// ---------------------------------------------------------------------------

// TestComponentsAppsetAbsenceNeverBlocks is the assertion the whole group
// exists to make. FRD-020 §3.1: the two ApplicationSets install these twenty
// components, so requiring any of them before the install is checking that the
// installer has already run. Asserted per component rather than once for a bare
// cluster, because the failure this guards against is a single component
// creeping back into the blocking set — which a bare-cluster test would only
// catch if it happened to that component last.
func TestComponentsAppsetAbsenceNeverBlocks(t *testing.T) {
	profile, err := intake.LoadProfile()
	if err != nil {
		t.Fatalf("embedded profile: %v", err)
	}
	if len(profile.AppsetComponents) < 20 {
		t.Fatalf("profile lists %d appset components, expected the 20 of FRD-020 §3.1", len(profile.AppsetComponents))
	}

	for _, absent := range profile.AppsetComponents {
		t.Run(absent+"-absent", func(t *testing.T) {
			f := componentsHealthyBase()
			namespaces := []adapters.Object{}
			for _, name := range profile.AppsetComponents {
				if name == absent {
					continue
				}
				spec, known := appsetCatalog[name]
				if !known {
					t.Fatalf("appsetCatalog has no entry for profile component %q", name)
				}
				ns := spec.namespaces[0]
				namespaces = append(namespaces, componentsNamespace(ns))
				// ArgoCD-owned at the pinned version, so the other nineteen
				// contribute no conflict of their own and the only variable in
				// this fixture is the absence.
				f.with("deployments.apps", ns, componentsAppsetWorkload(
					ns, spec.tokens[0], appsetPins[name],
					map[string]string{"argocd.argoproj.io/instance": name}))
			}
			f.with("namespaces", "", namespaces...)

			checked := 0
			for _, ch := range engine.All() {
				if ch.Group != "components" {
					continue
				}
				checked++
				r := run(t, f, ch.ID)
				if r.Status() == "BLOCK" {
					t.Fatalf("%s BLOCKED because %s is not installed, but %s is installed by the %s ApplicationSet\n  summary: %s",
						ch.ID, absent, absent, appsetCatalog[absent].appset, r.Summary)
				}
			}
			if checked < 4 {
				t.Fatalf("only %d components checks ran; the property is not covering the group", checked)
			}

			// A property that holds because the sweep never noticed anything is
			// worth nothing: prove the absence was actually seen and reported.
			r := run(t, f, "components.appset-conflicts")
			assertStatus(t, r, "INFO")
			componentsAssertDetailHas(t, r, absent+": absent")
		})
	}
}

// A bare cluster — nothing from either ApplicationSet installed — is the S1
// fixture, and the one an operator runs budctl on first. It must read as
// context, never as twenty blockers.
func TestComponentsBareClusterReportsAppsetComponentsAsInfo(t *testing.T) {
	f := componentsHealthyBase()
	for _, ch := range engine.All() {
		if ch.Group != "components" {
			continue
		}
		r := run(t, f, ch.ID)
		if r.Status() == "BLOCK" || r.Status() == "RISK" {
			t.Fatalf("%s reported %s on a cluster whose only omission is the twenty ApplicationSet components: %s",
				ch.ID, r.Status(), r.Summary)
		}
	}
	r := run(t, f, "components.appset-conflicts")
	assertStatus(t, r, "INFO")
	componentsAssertSummaryHas(t, r, "not a readiness failure")
}

// ---------------------------------------------------------------------------
// components.dns
// ---------------------------------------------------------------------------

// Nothing in either ApplicationSet provides cluster DNS, and without it every
// Dapr service-invocation hop fails. This is the one component whose absence is
// genuinely a blocker.
func TestComponentsDNSBlocksWhenNoDNSPodExists(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["pods|kube-system"] = nil
	r := run(t, f, "components.dns")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "kube-system")
}

// A CrashLooping CoreDNS is the TEST_CASES fixture. The waiting reason has to
// survive into the summary: CrashLoopBackOff and ImagePullBackOff have entirely
// different remedies, and "not ready" alone names neither.
func TestComponentsDNSBlocksWhenCoreDNSCrashLooping(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["pods|kube-system"] = []adapters.Object{
		componentsDNSPod("kube-system", "coredns-aaaaa", componentsCrashLooping),
		componentsDNSPod("kube-system", "coredns-bbbbb", componentsCrashLooping),
	}
	r := run(t, f, "components.dns")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "CrashLoopBackOff")
}

// One of two replicas down is graded exactly as hard as both down: there is no
// RISK path in this check. Recorded as the current contract so a future change
// to a proportional verdict is a deliberate edit and not a silent one.
func TestComponentsDNSBlocksOnPartialOutage(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["pods|kube-system"] = []adapters.Object{
		componentsDNSPod("kube-system", "coredns-aaaaa"),
		componentsDNSPod("kube-system", "coredns-bbbbb", componentsCrashLooping),
	}
	r := run(t, f, "components.dns")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "1 of 2")
}

// Healthy pods behind no Service is the quiet version of no DNS at all: the
// kubelet writes a resolver address into every pod that answers nothing.
func TestComponentsDNSBlocksWhenNoServicePublishesPort53(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["services|kube-system"] = []adapters.Object{
		// Port 9153 is CoreDNS's metrics port — present on a real cluster, and
		// not a resolver.
		componentsService("kube-system", "kube-dns-metrics", "10.96.0.11", []int{9153}),
	}
	r := run(t, f, "components.dns")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "port 53")
}

func TestComponentsDNSPassesWithReadyPodsAndAService(t *testing.T) {
	r := run(t, componentsHealthyBase(), "components.dns")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatalf("components.dns passed with no bound: Ready pods are not a resolution test")
	}
}

// The DNS Service is matched on port 53 rather than on its name, because
// "kube-dns" is only a compatibility name and a cluster may publish DNS under
// any name at all.
func TestComponentsDNSPassesWhenServiceIsNotNamedKubeDNS(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["services|kube-system"] = []adapters.Object{
		componentsService("kube-system", "rke2-coredns-rke2-coredns", "10.43.0.10", []int{53, 9153}),
	}
	assertStatus(t, run(t, f, "components.dns"), "PASS")
}

// A hand-rolled CoreDNS Deployment often carries neither k8s-app label. Failing
// to match it by name would report a bare cluster and block an install on a
// cluster whose DNS is fine.
func TestComponentsDNSPassesWhenPodsAreMatchedByNameNotLabel(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["pods|kube-system"] = []adapters.Object{
		componentsDNSPod("kube-system", "coredns-custom-xyz", componentsUnlabelled),
	}
	assertStatus(t, run(t, f, "components.dns"), "PASS")
}

// A Succeeded pod is a leftover from a node drain, not a failing resolver.
// Counting it as unhealthy would block an install on a cluster whose DNS is
// serving perfectly well.
func TestComponentsDNSIgnoresSucceededLeftovers(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["pods|kube-system"] = []adapters.Object{
		componentsDNSPod("kube-system", "coredns-live-aaaaa"),
		componentsDNSPod("kube-system", "coredns-drained-zzzzz", componentsSucceeded),
	}
	r := run(t, f, "components.dns")
	assertStatus(t, r, "PASS")
	componentsAssertSummaryHas(t, r, "1 cluster-DNS pod")
}

// OpenShift keeps CoreDNS in openshift-dns under a label of its own. Reading
// kube-system first there would report a cluster with no DNS at all.
func TestComponentsDNSOpenShiftReadsOpenShiftDNSNamespace(t *testing.T) {
	f := openShift().
		with("pods", "openshift-dns",
			componentsDNSPod("openshift-dns", "dns-default-aaaaa", componentsOpenShiftDNSLabel),
			componentsDNSPod("openshift-dns", "dns-default-bbbbb", componentsOpenShiftDNSLabel)).
		with("services", "openshift-dns",
			componentsService("openshift-dns", "dns-default", "172.30.0.10", []int{53, 9154}))
	r := run(t, f, "components.dns")
	assertStatus(t, r, "PASS")
	componentsAssertSummaryHas(t, r, "openshift-dns")
}

// A cluster upgraded into OpenShift, or one running an extra resolver, can
// still have DNS in kube-system. The fallback must find it rather than report a
// bare cluster.
func TestComponentsDNSOpenShiftFallsBackToKubeSystem(t *testing.T) {
	f := openShift().
		with("pods", "kube-system", componentsDNSPod("kube-system", "coredns-aaaaa")).
		with("services", "kube-system", componentsService("kube-system", "kube-dns", "172.30.0.10", []int{53}))
	r := run(t, f, "components.dns")
	assertStatus(t, r, "PASS")
	componentsAssertSummaryHas(t, r, "kube-system")
}

// On OpenShift the blocker has to name both places it looked, or the operator
// goes hunting in the wrong namespace.
func TestComponentsDNSOpenShiftBlockNamesBothNamespaces(t *testing.T) {
	r := run(t, openShift(), "components.dns")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "openshift-dns or kube-system")
}

// ---------------------------------------------------------------------------
// components.ingress — vanilla
// ---------------------------------------------------------------------------

// The PASS the whole vanilla branch turns on: a class whose controller has
// ready endpoints. The class is matched to its controller by name because
// spec.controller is a vendor identifier with no API link to a workload.
func TestComponentsIngressVanillaPassesWithReadyController(t *testing.T) {
	r := run(t, componentsHealthyBase(), "components.ingress")
	assertStatus(t, r, "PASS")
	componentsAssertSummaryHas(t, r, "ingress-nginx-controller")
	if r.DoesNotProve == "" {
		t.Fatalf("components.ingress passed with no bound: a ready controller is not a reachability test")
	}
}

// An IngressClass is metadata. A controller with endpoints but none of them
// ready serves nothing, and every Ingress the install creates stays unclaimed —
// FRD-020 §5.8: existence alone must not pass.
func TestComponentsIngressVanillaBlocksWhenControllerHasNoReadyEndpoints(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["endpointslices.discovery.k8s.io|"] = []adapters.Object{
		componentsEndpointSlice("ingress-nginx", "ingress-nginx-controller", 0, 3),
	}
	r := run(t, f, "components.ingress")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "no ready endpoints")
}

// EndpointSlice is the source on any current server; Endpoints is the only one
// on an older one. Reading just the first would call an ingress controller dead
// on half the clusters in the field.
func TestComponentsIngressVanillaPassesFromLegacyEndpoints(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["endpointslices.discovery.k8s.io|"] = nil
	f.with("endpoints", "", componentsLegacyEndpoints("ingress-nginx", "ingress-nginx-controller", 2, 0))
	assertStatus(t, run(t, f, "components.ingress"), "PASS")
}

// The legacy shape keeps not-ready addresses in a separate list, so a fixture
// where every address is not-ready must still block rather than count them.
func TestComponentsIngressVanillaBlocksFromLegacyEndpointsAllNotReady(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["endpointslices.discovery.k8s.io|"] = nil
	f.with("endpoints", "", componentsLegacyEndpoints("ingress-nginx", "ingress-nginx-controller", 0, 2))
	assertStatus(t, run(t, f, "components.ingress"), "BLOCK")
}

// A controller budctl cannot name-match (a cloud load-balancer controller, an
// in-house build) must block rather than pass on the class alone — but the
// evidence has to point at the thing it could not match, or the operator has no
// way to tell a missed controller from a missing one.
func TestComponentsIngressVanillaBlocksOnUnmatchedClassAndNamesCandidates(t *testing.T) {
	f := vanilla().
		with("ingressclasses.networking.k8s.io", "", ingressClass("traefik", "traefik.io/ingress-controller")).
		with("endpointslices.discovery.k8s.io", "", componentsEndpointSlice("extlb", "lb-router", 2, 0)).
		with("services", "", componentsService("extlb", "lb-router", "10.96.5.5", []int{80, 443}))
	r := run(t, f, "components.ingress")
	assertStatus(t, r, "BLOCK")
	componentsAssertDetailHas(t, r, "candidate: extlb/lb-router")
}

// When --values was supplied, the chart's own Ingresses name the class that has
// to work. A class that does not exist means those Ingresses are claimed by
// nobody, however healthy the rest of the cluster's ingress is.
func TestComponentsIngressVanillaBlocksWhenChartRequestsMissingClass(t *testing.T) {
	f := componentsHealthyBase()
	r, _ := componentsRun(t, f, "components.ingress", func(c *engine.Ctx) {
		c.Set(engine.KeyRenderedObjects, []adapters.Object{
			componentsIngressObject("bud-app", "bud-nginx", false),
		})
	})
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, `"bud-nginx"`)
	// The remedy has to list what DOES exist, or "pick a class that exists" is
	// advice the operator cannot act on.
	if !strings.Contains(r.Remedy, "nginx") {
		t.Fatalf("remedy does not name the classes that exist: %s", r.Remedy)
	}
}

// Charts still targeting pre-1.18 clusters name the class in the deprecated
// annotation, and controllers honour it — so budctl has to read it too.
func TestComponentsIngressVanillaReadsDeprecatedClassAnnotation(t *testing.T) {
	f := componentsHealthyBase()
	r, _ := componentsRun(t, f, "components.ingress", func(c *engine.Ctx) {
		c.Set(engine.KeyRenderedObjects, []adapters.Object{
			componentsIngressObject("bud-app", "absent-class", true),
		})
	})
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "absent-class")
}

// The scariest false PASS available here: a healthy controller on SOME class
// while the class the chart actually names has nothing serving it. Scoping to
// the requested class is what stops the run reading READY.
func TestComponentsIngressVanillaBlocksWhenRequestedClassIsTheDeadOne(t *testing.T) {
	f := componentsHealthyBase().
		with("ingressclasses.networking.k8s.io", "", ingressClass("traefik", "traefik.io/ingress-controller")).
		with("endpointslices.discovery.k8s.io", "", componentsEndpointSlice("traefik-system", "traefik", 0, 2))
	r, _ := componentsRun(t, f, "components.ingress", func(c *engine.Ctx) {
		c.Set(engine.KeyRenderedObjects, []adapters.Object{
			componentsIngressObject("bud-app", "traefik", false),
		})
	})
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "traefik")
}

// The domains group compares each hostname's A record against whatever the
// ingress path publishes. If the PASS forgets to record the address, every
// points-at-ingress result downstream silently degrades.
func TestComponentsIngressVanillaPublishesLoadBalancerAddress(t *testing.T) {
	f := componentsHealthyBase().
		with("services", "ingress-nginx", componentsService(
			"ingress-nginx", "ingress-nginx-controller", "10.96.9.9", []int{80, 443},
			componentsLoadBalancerIP("203.0.113.40")))
	r, c := componentsRun(t, f, "components.ingress")
	assertStatus(t, r, "PASS")
	v, ok := c.Get(engine.KeyIngressAddrs)
	if !ok {
		t.Fatalf("components.ingress passed without publishing an ingress address for the domains group")
	}
	if addrs, _ := v.([]string); len(addrs) == 0 || addrs[0] != "203.0.113.40" {
		t.Fatalf("published ingress addresses = %v, want the router's external IP", v)
	}
}

// KNOWN GAP, asserted as current behaviour so that fixing it is a visible,
// deliberate edit of this test rather than a silent change of verdict.
//
// A class is tied to its controller by name, and the haystack that name is
// searched in includes the NAMESPACE. So any ready Service sharing the
// controller's namespace — a metrics exporter, a dashboard, a sidecar — is
// counted as the controller itself. Here the router Service has 0 ready
// endpoints out of 3 and nothing serves the class, yet the check reports PASS
// and its own evidence says "0 ready / 3 not ready" one clause later. This is
// precisely the failure FRD-020 §5.8 says existence must not paper over, moved
// one level down from the class to its namespace.
func TestComponentsIngressVanillaPassesOnANeighbourServiceInTheControllerNamespace(t *testing.T) {
	f := vanilla().
		with("ingressclasses.networking.k8s.io", "", ingressClass("traefik", "traefik.io/ingress-controller")).
		with("endpointslices.discovery.k8s.io", "",
			componentsEndpointSlice("traefik-system", "traefik", 0, 3),
			componentsEndpointSlice("traefik-system", "metrics-exporter", 2, 0))
	r := run(t, f, "components.ingress")
	assertStatus(t, r, "PASS")
	// The verdict contradicts the evidence inside the same sentence.
	componentsAssertSummaryHas(t, r, "traefik-system/traefik 0 ready / 3 not ready")
}

// No default class is worth saying — the chart's Ingresses have to name one —
// but it is not a blocker when a controller is serving.
func TestComponentsIngressVanillaPassesWithNoDefaultClassButSaysSo(t *testing.T) {
	f := componentsHealthyBase()
	f.objects["ingressclasses.networking.k8s.io|"] = []adapters.Object{
		ingressClass("nginx", "k8s.io/ingress-nginx"),
	}
	r := run(t, f, "components.ingress")
	assertStatus(t, r, "PASS")
	componentsAssertDetailHas(t, r, "no IngressClass is marked default")
}

// ---------------------------------------------------------------------------
// components.ingress — OpenShift
// ---------------------------------------------------------------------------

// Degraded is the fixture TEST_CASES names, and the nastier one: Routes are
// still admitted while the router does not serve them, so the install completes
// and no hostname answers.
func TestComponentsIngressOpenShiftBlocksWhenOperatorDegradedButAvailable(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", componentsClusterOperator("ingress", true, true)).
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			ingressController("default", "apps.ocp.example.com", 2))
	r := run(t, f, "components.ingress")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "Degraded")
}

func TestComponentsIngressOpenShiftBlocksWhenNoDefaultIngressController(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", componentsClusterOperator("ingress", true, false))
	r := run(t, f, "components.ingress")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "default")
}

// An IngressController the operator considers Available with zero router pods
// serving is the OpenShift twin of a class with no ready endpoints.
func TestComponentsIngressOpenShiftBlocksWhenRouterHasZeroReplicas(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", componentsClusterOperator("ingress", true, false)).
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			ingressController("default", "apps.ocp.example.com", 0))
	r := run(t, f, "components.ingress")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "0 available")
}

func TestComponentsIngressOpenShiftBlocksWhenRouterNotAvailable(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", componentsClusterOperator("ingress", true, false)).
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			componentsIngressController("default", "apps.ocp.example.com", 2, false))
	assertStatus(t, run(t, f, "components.ingress"), "BLOCK")
}

// RBAC can deny clusteroperators. That must read as "the ingress path was NOT
// verified", never as a pass — D5.
func TestComponentsIngressOpenShiftSkipsWhenClusterOperatorUnreadable(t *testing.T) {
	assertSkipHasReason(t, run(t, openShift(), "components.ingress"))
}

// On OpenShift the router's Service is the address the domains group compares
// hostnames against.
func TestComponentsIngressOpenShiftPublishesRouterAddress(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", componentsClusterOperator("ingress", true, false)).
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			ingressController("default", "apps.ocp.example.com", 2)).
		with("services", "openshift-ingress", componentsService(
			"openshift-ingress", "router-default", "172.30.9.9", []int{80, 443},
			componentsLoadBalancerIP("203.0.113.77")))
	r, c := componentsRun(t, f, "components.ingress")
	assertStatus(t, r, "PASS")
	v, ok := c.Get(engine.KeyIngressAddrs)
	if !ok {
		t.Fatalf("OpenShift ingress passed without publishing router-default's address")
	}
	if addrs, _ := v.([]string); len(addrs) == 0 || addrs[0] != "203.0.113.77" {
		t.Fatalf("published ingress addresses = %v, want the router's external IP", v)
	}
}

// An OpenShift cluster must never be judged by IngressClass: seeding a dead one
// alongside a healthy operator must not change the verdict.
func TestComponentsIngressOpenShiftIgnoresIngressClasses(t *testing.T) {
	f := openShift().
		with("clusteroperators.config.openshift.io", "", componentsClusterOperator("ingress", true, false)).
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			ingressController("default", "apps.ocp.example.com", 2)).
		with("ingressclasses.networking.k8s.io", "", ingressClass("nginx", "k8s.io/ingress-nginx")).
		with("endpointslices.discovery.k8s.io", "", componentsEndpointSlice("ingress-nginx", "ingress-nginx-controller", 0, 4))
	assertStatus(t, run(t, f, "components.ingress"), "PASS")
}

// ---------------------------------------------------------------------------
// components.metrics-server
// ---------------------------------------------------------------------------

// Commonly absent on bare kubeadm, in no ApplicationSet, and every HPA in the
// chart reads <unknown>/70% without it.
func TestComponentsMetricsServerBlocksWhenAPIServiceAbsent(t *testing.T) {
	r := run(t, vanilla(), "components.metrics-server")
	assertStatus(t, r, "BLOCK")
	componentsAssertSummaryHas(t, r, "does not exist")
	if !strings.Contains(r.Remedy, "metrics-server") {
		t.Fatalf("remedy does not say how to install metrics-server: %s", r.Remedy)
	}
}

// An APIService that reports no Available condition at all is unknown, not
// healthy. Treating a missing condition as True is the classic way a check
// passes on a cluster it never actually inspected.
func TestComponentsMetricsServerBlocksWhenAvailableConditionMissing(t *testing.T) {
	f := vanilla().with("apiservices.apiregistration.k8s.io", "",
		componentsAPIServiceNoConditions("v1beta1.metrics.k8s.io", "kube-system", "metrics-server"))
	r := run(t, f, "components.metrics-server")
	assertStatus(t, r, "BLOCK")
	componentsAssertDetailHas(t, r, "backing service: kube-system/metrics-server")
}

// OpenShift serves metrics.k8s.io from the monitoring stack. Telling an
// OpenShift operator to `kubectl apply` upstream metrics-server sends them to
// install a second, conflicting aggregated API.
func TestComponentsMetricsServerOpenShiftRemedyPointsAtMonitoringStack(t *testing.T) {
	f := openShift().with("apiservices.apiregistration.k8s.io", "",
		apiService("v1beta1.metrics.k8s.io", false))
	r := run(t, f, "components.metrics-server")
	assertStatus(t, r, "BLOCK")
	if !strings.Contains(r.Remedy, "monitoring") {
		t.Fatalf("OpenShift remedy does not mention the monitoring stack: %s", r.Remedy)
	}
	if strings.Contains(r.Remedy, "kubernetes-sigs/metrics-server") {
		t.Fatalf("OpenShift remedy tells the operator to install upstream metrics-server: %s", r.Remedy)
	}
}

// A PASS must still say what it did not prove: an Available APIService is not
// evidence that every node's kubelet is being scraped.
func TestComponentsMetricsServerPassBoundsItsClaim(t *testing.T) {
	f := vanilla().with("apiservices.apiregistration.k8s.io", "",
		apiService("v1beta1.metrics.k8s.io", true))
	r := run(t, f, "components.metrics-server")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatalf("components.metrics-server passed with no bound on the claim")
	}
}

// ---------------------------------------------------------------------------
// components.appset-conflicts
// ---------------------------------------------------------------------------

// Installed outside ArgoCD is the ownership conflict: the first sync adopts
// resources a Helm release owns, and a later `helm uninstall` then deletes
// objects ArgoCD believes it manages. A RISK, never a BLOCK — the install
// works, the ownership is what is wrong.
func TestComponentsAppsetConflictsRiskOnHelmOwnedInstall(t *testing.T) {
	f := vanilla().
		with("namespaces", "", componentsNamespace("dapr-system")).
		with("deployments.apps", "dapr-system", componentsAppsetWorkload(
			"dapr-system", "dapr-operator", "1.17.5", map[string]string{
				"app.kubernetes.io/managed-by": "Helm",
				"app.kubernetes.io/instance":   "dapr",
			}))
	r := run(t, f, "components.appset-conflicts")
	assertStatus(t, r, "RISK")
	componentsAssertDetailHas(t, r, "installed outside ArgoCD")
}

// "existing Dapr at an incompatible version → RISK for conflict, not BLOCK for
// absence". The direction matters in the wording: syncing a pin older than what
// runs is an in-place DOWNGRADE of a component the whole platform sits on.
func TestComponentsAppsetConflictsRiskOnVersionDrift(t *testing.T) {
	cases := []struct {
		name      string
		component string
		namespace string
		workload  string
		version   string
		want      string
	}{
		{"dapr newer than the pin is a downgrade", "dapr", "dapr-system", "dapr-operator", "1.20.1", "DOWNGRADE"},
		{"dapr older than the pin is an upgrade", "dapr", "dapr-system", "dapr-operator", "1.14.9", "upgrade"},
		{"cert-manager minor drift", "cert-manager", "cert-manager", "cert-manager", "1.16.2", "upgrade"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := vanilla().
				with("namespaces", "", componentsNamespace(tc.namespace)).
				with("deployments.apps", tc.namespace, componentsAppsetWorkload(
					tc.namespace, tc.workload, tc.version,
					// ArgoCD-owned, so the ONLY thing wrong is the version.
					map[string]string{"argocd.argoproj.io/instance": tc.component}))
			r := run(t, f, "components.appset-conflicts")
			assertStatus(t, r, "RISK")
			componentsAssertDetailHas(t, r, tc.want)
		})
	}
}

// The same component at the pinned version under ArgoCD is not a conflict.
// Without this, the RISK above proves only that the check always risks.
func TestComponentsAppsetConflictsInfoWhenPinnedVersionMatches(t *testing.T) {
	f := vanilla().
		with("namespaces", "", componentsNamespace("dapr-system")).
		with("deployments.apps", "dapr-system", componentsAppsetWorkload(
			"dapr-system", "dapr-operator", "1.17.5",
			map[string]string{"argocd.argoproj.io/instance": "dapr"}))
	r := run(t, f, "components.appset-conflicts")
	assertStatus(t, r, "INFO")
	componentsAssertSummaryHas(t, r, "dapr")
}

// A patch-level difference is not a conflict: the pin comparison is major.minor
// deliberately, and flagging 1.17.4-vs-1.17.5 would train operators to ignore
// the finding that matters.
func TestComponentsAppsetConflictsIgnoresPatchDrift(t *testing.T) {
	f := vanilla().
		with("namespaces", "", componentsNamespace("dapr-system")).
		with("deployments.apps", "dapr-system", componentsAppsetWorkload(
			"dapr-system", "dapr-operator", "1.17.2",
			map[string]string{"argocd.argoproj.io/instance": "dapr"}))
	assertStatus(t, run(t, f, "components.appset-conflicts"), "INFO")
}

// An unparseable tag — a digest, "stable", a fork suffix — must be reported as
// not comparable rather than compared: parseVersion yields 0.0.0 for it, and
// comparing that against the pin invents a conflict out of nothing.
func TestComponentsAppsetConflictsReportsUncomparableVersionWithoutInventingAConflict(t *testing.T) {
	f := vanilla().
		with("namespaces", "", componentsNamespace("dapr-system")).
		with("deployments.apps", "dapr-system", componentsAppsetWorkload(
			"dapr-system", "dapr-operator", "stable",
			map[string]string{"argocd.argoproj.io/instance": "dapr"}))
	r := run(t, f, "components.appset-conflicts")
	assertStatus(t, r, "INFO")
	componentsAssertDetailHas(t, r, "not comparable")
}

// Presence proved by a CRD alone says nothing about who owns the install.
// Asserting a conflict from an unknown owner would manufacture a RISK out of
// missing data — so it has to be a note, and the note has to be visible.
func TestComponentsAppsetConflictsDoesNotRiskOnCRDOnlyPresence(t *testing.T) {
	f := componentsWithAPIs(vanilla(), "components.dapr.io", "configurations.dapr.io")
	r := run(t, f, "components.appset-conflicts")
	assertStatus(t, r, "INFO")
	componentsAssertDetailHas(t, r, "dapr: present")
	componentsAssertDetailHas(t, r, "owner not determined")
}

// A component in the profile that this table has never heard of must fall back
// to a namespace of its own name rather than silently report absence — the
// quiet failure mode when someone adds a component to defaults.yaml only.
func TestComponentsAppsetConflictsDetectsUncatalogedComponentByNamespace(t *testing.T) {
	f := vanilla().
		with("namespaces", "", componentsNamespace("budnewthing")).
		with("deployments.apps", "budnewthing", componentsAppsetWorkload(
			"budnewthing", "budnewthing", "2.0.0",
			map[string]string{"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": "budnewthing"}))
	r, _ := componentsRun(t, f, "components.appset-conflicts", func(c *engine.Ctx) {
		c.Profile.AppsetComponents = append([]string{"budnewthing"}, c.Profile.AppsetComponents...)
	})
	// Present, Helm-owned, uncataloged: reported as a conflict, never a blocker.
	assertStatus(t, r, "RISK")
	componentsAssertDetailHas(t, r, "budnewthing: present")
}

// An empty component list means the sweep looked at nothing. That is a skip
// with a reason, not an INFO that reads like a clean inventory.
func TestComponentsAppsetConflictsSkipsWhenProfileListsNothing(t *testing.T) {
	r, _ := componentsRun(t, vanilla(), "components.appset-conflicts", func(c *engine.Ctx) {
		c.Profile.AppsetComponents = nil
	})
	assertSkipHasReason(t, r)
}

// ---------------------------------------------------------------------------
// Unreachable cluster — every check in the group
// ---------------------------------------------------------------------------

// D5: "we did not look" and "we looked and it was fine" are different facts. A
// group whose every check silently passes when the cluster is unreachable would
// report READY on no evidence at all.
func TestComponentsAllChecksSkipWithAReasonWhenClusterUnreachable(t *testing.T) {
	for _, ch := range engine.All() {
		if ch.Group != "components" {
			continue
		}
		t.Run(ch.ID, func(t *testing.T) {
			assertSkipHasReason(t, componentsRunWithoutCluster(t, ch.ID))
		})
	}
}
