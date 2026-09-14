package checks

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// A single real cluster can only ever be one thing at a time: it is vanilla or
// OpenShift, its nodes are tainted or they are not, its image filesystem is
// full or it is not. Every check therefore has to be drivable against a
// synthetic cluster, or the OpenShift branches and the failure paths are
// asserted by hope rather than by test.

type fakeCluster struct {
	apiGroups map[string]bool
	objects   map[string][]adapters.Object
	stats     map[string]adapters.NodeStats
	answers   intake.Answers
	opts      engine.Options
	platform  *engine.PlatformInfo
	version   string
}

func vanilla() *fakeCluster {
	return &fakeCluster{
		apiGroups: map[string]bool{
			"apps/v1": true, "batch/v1": true, "networking.k8s.io/v1": true,
			"autoscaling/v2": true, "storage.k8s.io/v1": true,
			"discovery.k8s.io/v1": true, "rbac.authorization.k8s.io/v1": true,
			"apiextensions.k8s.io/v1": true, "v1": true,
			"nodes": true, "pods": true, "services": true, "namespaces": true,
		},
		objects:  map[string][]adapters.Object{},
		stats:    map[string]adapters.NodeStats{},
		answers:  testAnswers(),
		platform: &engine.PlatformInfo{Distribution: engine.DistVanilla, Version: "v1.30.0"},
		version:  "v1.30.0",
		opts:     engine.Options{NetTimeout: time.Second, EgressFrom: "workstation", ProbeImage: "curlimages/curl:8.10.1"},
	}
}

// openShift is vanilla plus the two API groups that identify OpenShift, which
// is exactly how platform.distribution decides — a version string never says.
func openShift() *fakeCluster {
	f := vanilla()
	f.apiGroups["route.openshift.io/v1"] = true
	f.apiGroups["security.openshift.io/v1"] = true
	f.apiGroups["config.openshift.io/v1"] = true
	f.apiGroups["operator.openshift.io/v1"] = true
	f.platform = &engine.PlatformInfo{
		Distribution: engine.DistOpenShift, Version: "v1.29.0",
		OpenShiftVersion: "4.16.7", AppsDomain: "apps.ocp.example.com",
	}
	f.version = "v1.29.0"
	return f
}

func testAnswers() intake.Answers {
	a := intake.Defaults()
	a.Domain = "bud.example.com"
	a.ModelStorageGi = 200
	return a
}

func (f *fakeCluster) with(fq, ns string, objs ...adapters.Object) *fakeCluster {
	f.objects[fq+"|"+ns] = append(f.objects[fq+"|"+ns], objs...)
	return f
}

func (f *fakeCluster) withStats(node string, s adapters.NodeStats) *fakeCluster {
	f.stats[node] = s
	return f
}

func (f *fakeCluster) withAnswers(fn func(*intake.Answers)) *fakeCluster {
	fn(&f.answers)
	return f
}

// withVersion sets what the fake API server reports, so version-gated checks
// can be driven without reaching a cluster.
func (f *fakeCluster) withVersion(v string) *fakeCluster {
	f.version = v
	f.platform.Version = v
	return f
}

func (f *fakeCluster) withOpts(fn func(*engine.Options)) *fakeCluster {
	fn(&f.opts)
	return f
}

func (f *fakeCluster) ctx(t *testing.T) *engine.Ctx {
	t.Helper()
	profile, err := intake.LoadProfile()
	if err != nil {
		t.Fatalf("embedded profile: %v", err)
	}
	clientset := k8sfake.NewSimpleClientset()
	// A discovery client is required: Kube.ServerVersion() reads it, and every
	// version-gated check calls that. Passing nil here used to take the whole
	// run down rather than degrade.
	disco, _ := clientset.Discovery().(*fakediscovery.FakeDiscovery)
	if disco != nil && f.version != "" {
		disco.FakedServerVersion = &version.Info{GitVersion: f.version}
	}
	k := adapters.NewFakeKube(clientset, nil, clientset.Discovery(), nil,
		func(_ context.Context, node string) adapters.NodeStats {
			if s, ok := f.stats[node]; ok {
				return s
			}
			return adapters.NodeStats{Node: node, Err: "no stats seeded"}
		})
	k.SetAPIGroups(f.apiGroups)
	for key, objs := range f.objects {
		fq, ns := splitKey(key)
		k.Seed(fq, ns, objs)
	}
	c := engine.NewCtx()
	c.Kube = k
	c.Net = adapters.NewNet(time.Second)
	c.OCI = adapters.NewOCI(c.Net)
	c.Helm = adapters.NewHelm()
	c.Answers = f.answers
	c.Profile = profile
	c.Opts = f.opts
	c.Platform = f.platform
	return c
}

func splitKey(key string) (string, string) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}

// run executes one check by id against the synthetic cluster.
func run(t *testing.T, f *fakeCluster, id string) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, f.ctx(t))
}

// drivenToFailure records every check some test has proved capable of failing.
// FRD-020 §4.1: a check that cannot fail is worse than no check, because it
// converts an unknown into a false assurance. TestMain turns this into a build
// gate rather than a convention.
var (
	coverageMu      sync.Mutex
	drivenToFailure = map[string]bool{}
)

func recordFailureCoverage(id, want string) {
	if want != "BLOCK" && want != "RISK" {
		return
	}
	coverageMu.Lock()
	drivenToFailure[id] = true
	coverageMu.Unlock()
}

// assertStatus fails with the check's own summary, so a broken expectation
// reads as a claim about the cluster rather than as "got PASS want BLOCK".
func assertStatus(t *testing.T, r engine.Result, want string) {
	t.Helper()
	recordFailureCoverage(r.ID, want)
	if got := r.Status(); got != want {
		t.Fatalf("%s: got %s, want %s\n  summary: %s\n  remedy: %s",
			r.ID, got, want, r.Summary, r.Remedy)
	}
}

// assertSkipHasReason enforces D5: a skip that says nothing is indistinguishable
// from a pass when someone scans the output.
func assertSkipHasReason(t *testing.T, r engine.Result) {
	t.Helper()
	assertStatus(t, r, "SKIP")
	if len(r.Summary) < 15 {
		t.Fatalf("%s: skipped with no usable reason: %q", r.ID, r.Summary)
	}
}

// Object builders — small, so a test reads as the cluster it describes.

func node(name string, opts ...func(adapters.Object)) adapters.Object {
	o := adapters.Object{
		"apiVersion": "v1", "kind": "Node",
		"metadata": map[string]any{"name": name, "labels": map[string]any{
			"kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux",
			// Every real node carries its hostname label, and CSI topology
			// segments are matched against it.
			"kubernetes.io/hostname": name,
		}},
		"spec": map[string]any{},
		"status": map[string]any{
			"conditions": []any{map[string]any{"type": "Ready", "status": "True"}},
			"allocatable": map[string]any{
				"cpu": "8", "memory": "32Gi", "pods": "110", "ephemeral-storage": "200Gi",
			},
			"capacity":  map[string]any{"cpu": "8", "memory": "32Gi", "pods": "110"},
			"nodeInfo":  map[string]any{"architecture": "amd64", "kubeletVersion": "v1.30.0"},
			"addresses": []any{map[string]any{"type": "InternalIP", "address": "10.0.0.1"}},
		},
	}
	for _, fn := range opts {
		fn(o)
	}
	return o
}

func notReady(o adapters.Object) {
	o["status"].(map[string]any)["conditions"] = []any{
		map[string]any{"type": "Ready", "status": "False"},
	}
}

func tainted(o adapters.Object) {
	o["spec"].(map[string]any)["taints"] = []any{
		map[string]any{"key": "node-role.kubernetes.io/control-plane", "effect": "NoSchedule"},
	}
}

func arm64(o adapters.Object) {
	o["status"].(map[string]any)["nodeInfo"].(map[string]any)["architecture"] = "arm64"
	o["metadata"].(map[string]any)["labels"].(map[string]any)["kubernetes.io/arch"] = "arm64"
}

func withGPU(count string) func(adapters.Object) {
	return func(o adapters.Object) {
		st := o["status"].(map[string]any)
		st["allocatable"].(map[string]any)["nvidia.com/gpu"] = count
		st["capacity"].(map[string]any)["nvidia.com/gpu"] = count
	}
}

// gpuCapacityOnly models the failure the check exists to catch: a node whose
// device plugin has died still advertises CAPACITY, so a check reading capacity
// reports a healthy GPU fleet that cannot schedule a single GPU pod.
func gpuCapacityOnly(count string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["status"].(map[string]any)["capacity"].(map[string]any)["nvidia.com/gpu"] = count
	}
}

func controlPlaneLabel(o adapters.Object) {
	o["metadata"].(map[string]any)["labels"].(map[string]any)["bud.studio/control-plane"] = "true"
}

func pod(ns, name string, ready bool) adapters.Object {
	status := "True"
	if !ready {
		status = "False"
	}
	return adapters.Object{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x:1"}}},
		"status": map[string]any{
			"phase":      "Running",
			"conditions": []any{map[string]any{"type": "Ready", "status": status}},
		},
	}
}

func apiService(name string, available bool) adapters.Object {
	status := "True"
	if !available {
		status = "False"
	}
	return adapters.Object{
		"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService",
		"metadata": map[string]any{"name": name},
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "Available", "status": status, "message": "seeded"},
		}},
	}
}

func storageClass(name, provisioner string, isDefault, expansion bool, params map[string]any) adapters.Object {
	ann := map[string]any{}
	if isDefault {
		ann["storageclass.kubernetes.io/is-default-class"] = "true"
	}
	o := adapters.Object{
		"apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
		"metadata":             map[string]any{"name": name, "annotations": ann},
		"provisioner":          provisioner,
		"allowVolumeExpansion": expansion,
	}
	if params != nil {
		o["parameters"] = params
	}
	return o
}

// ingressController models a serving router: the check requires available
// replicas, because an IngressController with none publishes nothing.
func ingressController(name, domain string, replicas int) adapters.Object {
	return adapters.Object{
		"apiVersion": "operator.openshift.io/v1", "kind": "IngressController",
		"metadata": map[string]any{"name": name, "namespace": "openshift-ingress-operator"},
		"spec":     map[string]any{"replicas": int64(replicas)},
		"status": map[string]any{
			"domain":            domain,
			"availableReplicas": int64(replicas),
			"conditions": []any{
				map[string]any{"type": "Available", "status": "True"},
				map[string]any{"type": "Degraded", "status": "False"},
			},
		},
	}
}

func clusterOperator(name string, available bool) adapters.Object {
	status := "True"
	if !available {
		status = "False"
	}
	return adapters.Object{
		"apiVersion": "config.openshift.io/v1", "kind": "ClusterOperator",
		"metadata": map[string]any{"name": name},
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "Available", "status": status, "message": "seeded"},
		}},
	}
}

func ingressClass(name, controller string) adapters.Object {
	return adapters.Object{
		"apiVersion": "networking.k8s.io/v1", "kind": "IngressClass",
		"metadata": map[string]any{"name": name},
		"spec":     map[string]any{"controller": controller},
	}
}

func gib(n float64) uint64 { return uint64(n * (1 << 30)) }

// probeOnly lists checks whose failure path requires a real cluster or real
// network — a probe pod that cannot be scheduled, a registry that must actually
// refuse credentials. They are exempt from the failure-coverage gate, and the
// exemption is written down HERE so that adding one is a visible decision
// rather than a silent gap.
var probeOnly = map[string]string{
	"charts.oci":                    "needs the real OCI chart registry",
	"charts.classic":                "needs real chart repositories",
	"charts.runtime":                "needs real chart repositories",
	"charts.aibrix":                 "needs GitHub release assets",
	"storage.provision":             "provisions a real PVC",
	"gpu.operator-functional":       "schedules a pod requesting a real GPU",
	"toolchain.clock":               "needs a real reference clock",
	"toolchain.exec-plugin":         "needs a kubeconfig with an exec stanza on disk",
	"domains.resolve":               "needs real DNS",
	"domains.inbound-80":            "needs real inbound reachability",
	"domains.inbound-443":           "needs real inbound reachability",
	"domains.tls":                   "needs a real TLS handshake",
	"domains.points-at-ingress":     "needs real DNS",
	"externaldatastores.postgres":   "needs a reachable external store",
	"externaldatastores.clickhouse": "needs a reachable external store",
	"externaldatastores.valkey":     "needs a reachable external store",
	"externaldatastores.kafka":      "needs a reachable external store",
	"externaldatastores.mongodb":    "needs a reachable external store",
	"externaldatastores.s3":         "needs a reachable external store",
	"externaldatastores.keycloak":   "needs a reachable external store",
	"config.render":                 "needs a chart on disk",
	"config.dry-run":                "needs a live API server",
}

func TestMain(m *testing.M) {
	code := m.Run()
	if code != 0 {
		os.Exit(code)
	}
	// The gate is a property of the WHOLE suite. Under `-run <filter>` only a
	// subset executed, so every unexercised check would look uncovered and a
	// developer iterating on one group would be told the build is broken.
	if f := flag.Lookup("test.run"); f != nil && f.Value.String() != "" {
		fmt.Fprintf(os.Stderr,
			"\nfailure-coverage gate skipped: -run %s selected a subset; run the full suite to enforce it\n",
			f.Value.String())
		os.Exit(0)
	}
	var missing []string
	for _, ch := range engine.All() {
		if ch.Severity == engine.Info {
			continue // an informational check has no failure state to drive
		}
		if drivenToFailure[ch.ID] {
			continue
		}
		if why, exempt := probeOnly[ch.ID]; exempt {
			_ = why
			continue
		}
		missing = append(missing, ch.ID)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fmt.Fprintf(os.Stderr,
			"\nFAILURE-COVERAGE GATE: %d check(s) have no test that drives them to BLOCK or RISK.\n"+
				"A check that cannot fail converts an unknown into a false assurance (FRD-020 §4.1).\n"+
				"Add a negative test, or record a reason in probeOnly:\n  %s\n",
			len(missing), strings.Join(missing, "\n  "))
		os.Exit(1)
	}
	os.Exit(0)
}
