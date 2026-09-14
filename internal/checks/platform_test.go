package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// platform is the only group that reads the server version, so it needs a Kube
// with a working discovery client. The shared harness builds its fake with a
// nil discovery (adapters.NewFakeKube(..., nil, ...)), which is fine for every
// other group but makes Kube.ServerVersion() dereference nil — see
// TestPlatformDistributionPanicsOnHarnessKube for the proof. These helpers
// build the same fake cluster with discovery wired, so platform.distribution
// can be driven for real rather than asserted by hope.

// platformBuildCtx mirrors fakeCluster.ctx but injects a discovery client and
// lets the caller decide whether the platform group has already run.
func platformBuildCtx(t *testing.T, f *fakeCluster, disco discovery.DiscoveryInterface, plat *engine.PlatformInfo) *engine.Ctx {
	t.Helper()
	profile, err := intake.LoadProfile()
	if err != nil {
		t.Fatalf("embedded profile: %v", err)
	}
	cs := k8sfake.NewSimpleClientset()
	// Dynamic stays nil: Kube.resolve refuses to map a GVR without it, so every
	// List falls back to the seeded cache exactly as in the shared harness.
	k := adapters.NewFakeKube(cs, nil, disco, nil,
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
	c.Platform = plat
	return c
}

func platformDiscovery(t *testing.T, gitVersion string) discovery.DiscoveryInterface {
	t.Helper()
	d, ok := k8sfake.NewSimpleClientset().Discovery().(*fakediscovery.FakeDiscovery)
	if !ok {
		t.Fatalf("client-go fake no longer exposes *fakediscovery.FakeDiscovery")
	}
	d.FakedServerVersion = &version.Info{GitVersion: gitVersion}
	return d
}

// platformFreshCtx is a cluster on which the platform group has NOT yet run:
// Distribution is unknown, exactly as engine.NewCtx leaves it before
// platform.distribution executes first (GroupOrder puts platform first).
// Detection tests must start here, or the fixture's pre-set Distribution would
// be doing the work the check is supposed to do.
func platformFreshCtx(t *testing.T, f *fakeCluster, gitVersion string) *engine.Ctx {
	t.Helper()
	return platformBuildCtx(t, f, platformDiscovery(t, gitVersion),
		&engine.PlatformInfo{Distribution: engine.DistUnknown})
}

// platformDetectedCtx is a cluster on which the platform group already ran —
// the state every DependsOn:["platform"] check actually sees.
func platformDetectedCtx(t *testing.T, f *fakeCluster) *engine.Ctx {
	t.Helper()
	p := *f.platform
	return platformBuildCtx(t, f, platformDiscovery(t, f.platform.Version), &p)
}

// platformRunOn runs one check against a ctx the test owns, so the test can
// inspect what the check recorded on PlatformInfo for later groups, and so a
// two-check pipeline (detect, then judge) shares one cluster.
func platformRunOn(t *testing.T, c *engine.Ctx, id string) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

func platformAssertDetail(t *testing.T, r engine.Result, want string) {
	t.Helper()
	for _, d := range r.Detail {
		if strings.Contains(d, want) {
			return
		}
	}
	t.Fatalf("%s: detail does not mention %q\n  summary: %s\n  detail: %v", r.ID, want, r.Summary, r.Detail)
}

// Fixture objects. Prefixed so they cannot collide with another group's file.

func platformClusterVersion(history []map[string]any, desired string) adapters.Object {
	status := map[string]any{}
	if history != nil {
		h := make([]any, 0, len(history))
		for _, e := range history {
			h = append(h, e)
		}
		status["history"] = h
	}
	if desired != "" {
		status["desired"] = map[string]any{"version": desired}
	}
	return adapters.Object{
		"apiVersion": "config.openshift.io/v1", "kind": "ClusterVersion",
		"metadata": map[string]any{"name": "version"},
		"status":   status,
	}
}

// platformProxy is the cluster-wide egress proxy object. OpenShift ships this
// object on every cluster, usually with an empty spec, which is why "exists"
// and "configured" have to be different answers.
func platformProxy(httpProxy, httpsProxy, noProxy string) adapters.Object {
	spec := map[string]any{}
	if httpProxy != "" {
		spec["httpProxy"] = httpProxy
	}
	if httpsProxy != "" {
		spec["httpsProxy"] = httpsProxy
	}
	if noProxy != "" {
		spec["noProxy"] = noProxy
	}
	return adapters.Object{
		"apiVersion": "config.openshift.io/v1", "kind": "Proxy",
		"metadata": map[string]any{"name": "cluster"},
		"spec":     spec,
	}
}

func platformIngressConfig(domain string) adapters.Object {
	return adapters.Object{
		"apiVersion": "config.openshift.io/v1", "kind": "Ingress",
		"metadata": map[string]any{"name": "cluster"},
		"spec":     map[string]any{"domain": domain},
	}
}

// platformAKSNodeLabel is how AKS identifies itself: its version string is
// ordinary, so only the node label gives it away.
func platformAKSNodeLabel(o adapters.Object) {
	o["metadata"].(map[string]any)["labels"].(map[string]any)["kubernetes.azure.com/cluster"] = "MC_rg_aks_eastus"
}

// platformErrDiscovery models the API server answering /version with an error —
// an aggregated-API outage or a proxy rejecting the path. The check must SKIP
// with a reason, never silently report "kubernetes".
type platformErrDiscovery struct {
	discovery.DiscoveryInterface
	err error
}

func (d platformErrDiscovery) ServerVersion() (*version.Info, error) { return nil, d.err }

// ---------------------------------------------------------------------------
// platform.distribution
// ---------------------------------------------------------------------------

// The whole OpenShift branch of budctl hangs off this one answer: get it wrong
// and components.ingress judges an IngressClass that will never exist, and
// cluster.admission-policy looks for PodSecurity labels on a cluster that uses
// SCCs. So detection is asserted per distribution, not once.
func TestPlatformDistributionDetectsEachDistribution(t *testing.T) {
	cases := []struct {
		name       string
		fixture    func() *fakeCluster
		gitVersion string
		want       engine.Distribution
	}{
		{
			name:       "a plain cluster is kubernetes",
			fixture:    vanilla,
			gitVersion: "v1.30.0",
			want:       engine.DistVanilla,
		},
		{
			// The requirement: OpenShift is identified by its API groups. Its
			// k8s version string is entirely ordinary, so a version-string test
			// would call this cluster vanilla.
			name:       "OpenShift is detected from its API groups despite an ordinary version",
			fixture:    openShift,
			gitVersion: "v1.29.8+632b078",
			want:       engine.DistOpenShift,
		},
		{
			name:       "k3s from the +k3s1 build suffix",
			fixture:    vanilla,
			gitVersion: "v1.30.2+k3s1",
			want:       engine.DistK3s,
		},
		{
			name:       "EKS from its version suffix",
			fixture:    vanilla,
			gitVersion: "v1.30.8-eks-2d5f260",
			want:       engine.DistEKS,
		},
		{
			name:       "GKE from its version suffix",
			fixture:    vanilla,
			gitVersion: "v1.29.7-gke.1104000",
			want:       engine.DistGKE,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := platformFreshCtx(t, tc.fixture(), tc.gitVersion)
			r := platformRunOn(t, c, "platform.distribution")
			assertStatus(t, r, "INFO")
			if c.Platform.Distribution != tc.want {
				t.Fatalf("detected %q, want %q (summary: %s)", c.Platform.Distribution, tc.want, r.Summary)
			}
			// Later groups read Version, not the result text.
			if c.Platform.Version != tc.gitVersion {
				t.Fatalf("recorded version %q, want %q", c.Platform.Version, tc.gitVersion)
			}
			platformAssertDetail(t, r, "server "+tc.gitVersion)
		})
	}
}

// AKS marks nothing in the version string; the giveaway is a node label. A
// detector that only reads the version would call every AKS cluster vanilla.
func TestPlatformDistributionDetectsAKSFromNodeLabel(t *testing.T) {
	f := vanilla().with("nodes", "", node("aks-sys-1", platformAKSNodeLabel))
	c := platformFreshCtx(t, f, "v1.30.4")
	platformRunOn(t, c, "platform.distribution")
	if c.Platform.Distribution != engine.DistAKS {
		t.Fatalf("detected %q, want aks", c.Platform.Distribution)
	}
}

// The inverse of the requirement, and the one that actually bites: a cluster
// whose version string mentions OpenShift but which serves none of the
// OpenShift APIs is NOT OpenShift. Detecting from the string would send every
// later group down the Route/SCC branch on a cluster that has neither.
func TestPlatformDistributionIgnoresAnOpenShiftLookingVersionString(t *testing.T) {
	c := platformFreshCtx(t, vanilla(), "v1.29.8+openshift-4.14.0")
	platformRunOn(t, c, "platform.distribution")
	if c.Platform.Distribution != engine.DistVanilla {
		t.Fatalf("detected %q from a version string alone, want kubernetes", c.Platform.Distribution)
	}
	if c.Platform.OpenShiftVersion != "" || c.Platform.AppsDomain != "" {
		t.Fatalf("non-OpenShift cluster carries OpenShift fields: version=%q apps=%q",
			c.Platform.OpenShiftVersion, c.Platform.AppsDomain)
	}
}

// Both groups are required. A vanilla cluster can end up serving one of them
// alone — route.openshift.io/v1 exists on clusters that installed the Route
// CRD for compatibility, and security.openshift.io shows up on OKD-flavoured
// installs — and either alone must not flip the whole tool to the OpenShift
// variant.
func TestPlatformDistributionNeedsBothOpenShiftAPIGroups(t *testing.T) {
	cases := []struct {
		name   string
		groups []string
		want   engine.Distribution
	}{
		{"route.openshift.io alone is not OpenShift", []string{"route.openshift.io/v1"}, engine.DistVanilla},
		{"security.openshift.io alone is not OpenShift", []string{"security.openshift.io/v1"}, engine.DistVanilla},
		{"both together are OpenShift", []string{"route.openshift.io/v1", "security.openshift.io/v1"}, engine.DistOpenShift},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := vanilla()
			for _, g := range tc.groups {
				f.apiGroups[g] = true
			}
			c := platformFreshCtx(t, f, "v1.29.8+632b078")
			platformRunOn(t, c, "platform.distribution")
			if c.Platform.Distribution != tc.want {
				t.Fatalf("detected %q, want %q", c.Platform.Distribution, tc.want)
			}
		})
	}
}

// On OpenShift the check also harvests the two facts later groups cannot get
// anywhere else: the ClusterVersion (which platform.openshift-version judges)
// and the *.apps wildcard (which domains.resolve is usually satisfied by).
func TestPlatformDistributionHarvestsOpenShiftFacts(t *testing.T) {
	f := openShift().
		with("clusterversions.config.openshift.io", "",
			platformClusterVersion([]map[string]any{{"version": "4.16.7", "state": "Completed"}}, "4.16.7")).
		with("ingresses.config.openshift.io", "", platformIngressConfig("apps.ocp.example.com"))
	c := platformFreshCtx(t, f, "v1.29.8+632b078")
	r := platformRunOn(t, c, "platform.distribution")
	if c.Platform.OpenShiftVersion != "4.16.7" {
		t.Fatalf("OpenShiftVersion = %q, want 4.16.7", c.Platform.OpenShiftVersion)
	}
	if c.Platform.AppsDomain != "apps.ocp.example.com" {
		t.Fatalf("AppsDomain = %q, want apps.ocp.example.com", c.Platform.AppsDomain)
	}
	platformAssertDetail(t, r, "OpenShift 4.16.7")
	platformAssertDetail(t, r, "apps wildcard *.apps.ocp.example.com")
}

// When the cluster-scoped Ingress config is unreadable, the wildcard still has
// to come from somewhere: the default IngressController publishes it.
func TestPlatformDistributionFallsBackToIngressControllerDomain(t *testing.T) {
	f := openShift().
		with("ingresscontrollers.operator.openshift.io", "openshift-ingress-operator",
			ingressController("default", "apps.fallback.example.com", 2))
	c := platformFreshCtx(t, f, "v1.29.8+632b078")
	platformRunOn(t, c, "platform.distribution")
	if c.Platform.AppsDomain != "apps.fallback.example.com" {
		t.Fatalf("AppsDomain = %q, want the IngressController's domain", c.Platform.AppsDomain)
	}
}

// D5: "we could not look" must never read as "kubernetes". A silently
// defaulted distribution would send an OpenShift cluster down the vanilla
// branch of every check below.
func TestPlatformDistributionSkipsWhenClusterUnreachable(t *testing.T) {
	c := platformFreshCtx(t, vanilla(), "v1.30.0")
	c.Kube = nil
	assertSkipHasReason(t, platformRunOn(t, c, "platform.distribution"))
}

func TestPlatformDistributionSkipsWhenServerVersionUnreadable(t *testing.T) {
	f := vanilla()
	disco := platformErrDiscovery{
		DiscoveryInterface: platformDiscovery(t, "v1.30.0"),
		err:                errors.New("Get \"https://api.example.com/version\": EOF"),
	}
	c := platformBuildCtx(t, f, disco, &engine.PlatformInfo{Distribution: engine.DistUnknown})
	r := platformRunOn(t, c, "platform.distribution")
	assertSkipHasReason(t, r)
	if c.Platform.Distribution != engine.DistUnknown {
		t.Fatalf("distribution was set to %q despite an unreadable version", c.Platform.Distribution)
	}
	if !strings.Contains(r.Summary, "EOF") {
		t.Fatalf("skip reason hides the underlying error: %q", r.Summary)
	}
}

// The shared harness builds its fake Kube with a nil discovery client, so any
// check calling ServerVersion() dereferences nil. That is why every test above
// builds its ctx with platformBuildCtx instead of run(). This records the fact
// where the next person will look for it, and keeps asserting the check behaves
// if the harness ever grows a discovery client.
func TestPlatformDistributionUnderTheSharedHarness(t *testing.T) {
	var r engine.Result
	panicked := func() (p bool) {
		defer func() {
			if recover() != nil {
				p = true
			}
		}()
		r = run(t, vanilla(), "platform.distribution")
		return false
	}()
	if panicked {
		t.Skip("harness Kube has a nil discovery client: Kube.ServerVersion() panics, " +
			"so platform.distribution cannot be driven through run(); see platformBuildCtx")
	}
	if s := r.Status(); s != "INFO" && s != "SKIP" {
		t.Fatalf("platform.distribution returned %s under the shared harness: %s", s, r.Summary)
	}
}

// ---------------------------------------------------------------------------
// platform.openshift-version
// ---------------------------------------------------------------------------

// The floor is a real one: budcluster's OpenShift path and the CSI/SCC
// manifests the chart applies assume 4.12 APIs. Below it the install fails
// after it has already started, which is the failure BLOCK exists to prevent.
// Every case here runs the real two-step pipeline — detect, then judge — so the
// version being judged is one the tool actually read off ClusterVersion.
func TestPlatformOpenShiftVersionJudgesTheClusterVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		want    string
	}{
		{"4.10 is below the floor", "4.10.60", "BLOCK"},
		{"4.11 is still below the floor", "4.11.59", "BLOCK"},
		{"4.12.0 is exactly the floor and passes", "4.12.0", "PASS"},
		{"4.16.7 is above the floor", "4.16.7", "PASS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := openShift().with("clusterversions.config.openshift.io", "",
				platformClusterVersion([]map[string]any{{"version": tc.version, "state": "Completed"}}, tc.version))
			c := platformFreshCtx(t, f, "v1.25.0+9d5a0d5")
			platformRunOn(t, c, "platform.distribution")
			r := platformRunOn(t, c, "platform.openshift-version")
			assertStatus(t, r, tc.want)
			if !strings.Contains(r.Summary, tc.version) {
				t.Fatalf("summary does not name the version it judged: %q", r.Summary)
			}
			if tc.want == "BLOCK" {
				// A blocker that does not name the floor, or whose remedy just
				// restates the failure, is not actionable at 2am.
				if !strings.Contains(r.Summary, "4.12") {
					t.Fatalf("BLOCK summary does not name the supported floor: %q", r.Summary)
				}
				if r.Remedy == "" || r.Remedy == r.Summary {
					t.Fatalf("BLOCK carries no distinct remedy: %q", r.Remedy)
				}
			}
		})
	}
}

func TestPlatformOpenShiftVersionSkipsOnVanilla(t *testing.T) {
	// Not "PASS because nothing was wrong": on a vanilla cluster there is no
	// OpenShift version, and reporting PASS would claim a check ran that did not.
	c := platformDetectedCtx(t, vanilla())
	assertSkipHasReason(t, platformRunOn(t, c, "platform.openshift-version"))
}

// OpenShift with no readable ClusterVersion (RBAC, or an aggregated API down)
// is an unknown, not a pass. This is the case that would otherwise let a 4.10
// cluster through.
func TestPlatformOpenShiftVersionSkipsWhenClusterVersionUnreadable(t *testing.T) {
	c := platformFreshCtx(t, openShift(), "v1.25.0+9d5a0d5")
	platformRunOn(t, c, "platform.distribution")
	if c.Platform.Distribution != engine.DistOpenShift {
		t.Fatalf("fixture did not detect OpenShift: %q", c.Platform.Distribution)
	}
	assertSkipHasReason(t, platformRunOn(t, c, "platform.openshift-version"))
}

// history is absent on a cluster that has never completed an upgrade record;
// desired.version is the fallback, and it must still be judged.
func TestPlatformOpenShiftVersionFallsBackToDesiredVersion(t *testing.T) {
	f := openShift().with("clusterversions.config.openshift.io", "",
		platformClusterVersion(nil, "4.10.60"))
	c := platformFreshCtx(t, f, "v1.23.12+8a6bfe4")
	platformRunOn(t, c, "platform.distribution")
	assertStatus(t, platformRunOn(t, c, "platform.openshift-version"), "BLOCK")
}

// IMPLEMENTATION GAP — false assurance, documented deliberately.
//
// openShiftVersion() takes status.history[0] without reading its `state`.
// history[0] is the most RECENT entry, which during (or after a failed or
// rolled-back) upgrade is a "Partial" entry naming the TARGET version, while
// the version actually running is the newest "Completed" entry below it. So a
// cluster still on 4.10.60 that someone once tried to move to 4.12.0 reports
// "OpenShift 4.12.0 ≥ 4.12" and PASSES the floor it does not meet — exactly the
// unknown-turned-into-assurance the check exists to prevent.
//
// This test asserts the CURRENT behaviour so the gap is visible and pinned. The
// fix is to prefer the newest entry with state == "Completed"; when that lands,
// this expectation flips to BLOCK.
func TestPlatformOpenShiftVersionJudgesTheRunningVersion(t *testing.T) {
	f := openShift().with("clusterversions.config.openshift.io", "",
		platformClusterVersion([]map[string]any{
			{"version": "4.12.0", "state": "Partial"},
			{"version": "4.10.60", "state": "Completed"},
		}, "4.12.0"))
	c := platformFreshCtx(t, f, "v1.23.12+8a6bfe4")
	platformRunOn(t, c, "platform.distribution")
	r := platformRunOn(t, c, "platform.openshift-version")
	// The cluster is RUNNING 4.10.60; 4.12.0 was only ever attempted. Reading
	// the attempted version would pass a floor the cluster does not meet.
	assertStatus(t, r, "BLOCK")
	if !strings.Contains(r.Summary, "4.10.60") {
		t.Fatalf("judged the attempted version, not the running one: %q", r.Summary)
	}
}

// A first install still in progress has a Partial entry and no Completed one.
// There is nothing better to report than the target, and the check must still
// produce a verdict rather than silently skipping.
func TestPlatformOpenShiftVersionFallsBackWhenNothingCompleted(t *testing.T) {
	f := openShift().with("clusterversions.config.openshift.io", "",
		platformClusterVersion([]map[string]any{
			{"version": "4.16.3", "state": "Partial"},
		}, "4.16.3"))
	c := platformFreshCtx(t, f, "v1.29.0")
	platformRunOn(t, c, "platform.distribution")
	assertStatus(t, platformRunOn(t, c, "platform.openshift-version"), "PASS")
}

// ---------------------------------------------------------------------------
// platform.cluster-proxy
// ---------------------------------------------------------------------------

func TestPlatformClusterProxySkipsOnVanilla(t *testing.T) {
	c := platformDetectedCtx(t, vanilla())
	assertSkipHasReason(t, platformRunOn(t, c, "platform.cluster-proxy"))
}

// The point of the check is the hand-off: registry.from-cluster, argocd and
// every egress result read Platform.ClusterProxy to decide whether a blocked
// host means "no route" or "the proxy refused". An INFO line nobody can read
// programmatically would be useless, so both the text and the recorded value
// are asserted.
func TestPlatformClusterProxyReportsAndRecordsTheProxy(t *testing.T) {
	cases := []struct {
		name       string
		httpProxy  string
		httpsProxy string
		want       string
	}{
		{"https wins when both are set", "http://p.corp:3128", "https://p.corp:3129", "https://p.corp:3129"},
		{"httpProxy alone is still a proxy in effect", "http://p.corp:3128", "", "http://p.corp:3128"},
		{"httpsProxy alone is still a proxy in effect", "", "https://p.corp:3129", "https://p.corp:3129"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := openShift().with("proxies.config.openshift.io", "",
				platformProxy(tc.httpProxy, tc.httpsProxy, ".svc,.cluster.local,10.0.0.0/8"))
			c := platformDetectedCtx(t, f)
			r := platformRunOn(t, c, "platform.cluster-proxy")
			assertStatus(t, r, "INFO")
			if !strings.Contains(r.Summary, tc.want) {
				t.Fatalf("summary does not carry the proxy value: %q", r.Summary)
			}
			if c.Platform.ClusterProxy != tc.want {
				t.Fatalf("recorded ClusterProxy = %q, want %q", c.Platform.ClusterProxy, tc.want)
			}
			platformAssertDetail(t, r, "noProxy: .svc,.cluster.local,10.0.0.0/8")
			platformAssertDetail(t, r, "every egress result must be read against this proxy")
		})
	}
}

// OpenShift ships a Proxy named "cluster" on every install, usually with an
// empty spec. Treating "the object exists" as "a proxy is in effect" would
// annotate every egress result on every OpenShift cluster with a proxy that
// does not exist, and would poison the probe command with an empty value.
func TestPlatformClusterProxyDistinguishesExistingFromConfigured(t *testing.T) {
	cases := []struct {
		name    string
		seed    bool
		obj     adapters.Object
		wantSub string
	}{
		{"no Proxy object at all", false, nil, "no cluster-wide egress proxy configured"},
		{"Proxy object with an empty spec", true, platformProxy("", "", ""), "sets no proxy"},
		{"Proxy object setting only noProxy", true, platformProxy("", "", ".svc"), "sets no proxy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := openShift()
			if tc.seed {
				f = f.with("proxies.config.openshift.io", "", tc.obj)
			}
			c := platformDetectedCtx(t, f)
			r := platformRunOn(t, c, "platform.cluster-proxy")
			assertStatus(t, r, "INFO")
			if !strings.Contains(r.Summary, tc.wantSub) {
				t.Fatalf("summary %q does not say %q", r.Summary, tc.wantSub)
			}
			if c.Platform.ClusterProxy != "" {
				t.Fatalf("recorded a proxy (%q) where none is configured", c.Platform.ClusterProxy)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

// Two of the three platform checks cannot BLOCK or RISK by construction: FRD
// §5.0 classes them INFO because their job is to SELECT the variant of every
// later check, not to judge the cluster. Their failure mode is therefore a
// WRONG ANSWER, not a missing verdict — which is what the detection tests above
// cover. This pins the classification so a silent downgrade of
// platform.openshift-version from BLOCK to INFO cannot pass unnoticed.
func TestPlatformCheckSeverities(t *testing.T) {
	want := map[string]engine.Severity{
		"platform.distribution":      engine.Info,
		"platform.cluster-proxy":     engine.Info,
		"platform.openshift-version": engine.Block,
	}
	for id, sev := range want {
		ch := engine.Lookup(id)
		if ch == nil {
			t.Fatalf("check %s is no longer registered", id)
		}
		if ch.Severity != sev {
			t.Fatalf("%s severity = %s, want %s", id, ch.Severity, sev)
		}
	}
}
