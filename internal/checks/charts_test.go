package checks

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// The charts group asks one question per hub: can the thing that resolves a
// chart reach the place the chart lives? Every answer comes from the network,
// so a test that used the real network would test the office firewall rather
// than the check. Instead the fixtures script the HTTP layer: each one is an
// egress policy written down — "everything is allowed except bitnami", "the
// allowlist names github.com and forgot the asset CDN" — and the assertion is
// what budctl says about that policy.
//
// This matters more here than elsewhere: a blocked chart repository produces no
// failing pod to look at. If these checks cannot fail, the failure they exist to
// pre-empt is a sync that creates nothing and explains nothing.

// --- scripted HTTP -----------------------------------------------------------

// chartsReply is one scripted answer. err models the DNS/TCP/TLS failures an
// egress policy produces; status models a live host that refuses the document.
type chartsReply struct {
	status   int
	location string // non-empty: answer with a redirect, as GitHub does for assets
	wwwAuth  string
	err      string
}

type chartsRule struct {
	when  func(url string) bool
	reply chartsReply
}

type chartsTransport struct {
	rules []chartsRule
	def   chartsReply
}

func (tr *chartsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL.String()
	rep := tr.def
	for _, r := range tr.rules {
		if r.when(u) {
			rep = r.reply
			break
		}
	}
	if rep.err != "" {
		return nil, errors.New(rep.err)
	}
	h := http.Header{}
	h.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	if rep.location != "" {
		h.Set("Location", rep.location)
	}
	if rep.wwwAuth != "" {
		h.Set("WWW-Authenticate", rep.wwwAuth)
	}
	return &http.Response{
		StatusCode: rep.status,
		Status:     http.StatusText(rep.status),
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:  h,
		Body:    io.NopCloser(strings.NewReader("")),
		Request: req,
	}, nil
}

// chartsAllOK is an unrestricted network. A fixture then breaks exactly one
// thing, so a finding names a cause instead of a fog.
func chartsAllOK(rules ...chartsRule) *chartsTransport {
	return &chartsTransport{rules: rules, def: chartsReply{status: 200}}
}

// chartsAllBlocked is default-deny egress with no allowlist at all.
func chartsAllBlocked(rules ...chartsRule) *chartsTransport {
	return &chartsTransport{rules: rules, def: chartsReply{err: "dial tcp 10.0.0.1:443: i/o timeout"}}
}

func chartsURLIs(u string) func(string) bool {
	return func(s string) bool { return s == u }
}

func chartsURLHas(sub string) func(string) bool {
	return func(s string) bool { return strings.Contains(s, sub) }
}

func chartsBlock(match string) chartsRule {
	return chartsRule{when: chartsURLHas(match), reply: chartsReply{err: "dial tcp 10.0.0.1:443: i/o timeout"}}
}

func chartsCode(match string, code int) chartsRule {
	return chartsRule{when: chartsURLHas(match), reply: chartsReply{status: code}}
}

// chartsRun drives one check against a scripted network. It reuses the shared
// harness for the cluster half and only replaces the HTTP transport, so the
// fixtures stay the same shape as every other group's.
func chartsRun(t *testing.T, f *fakeCluster, id string, tr http.RoundTripper, mutate func(*engine.Ctx)) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	if tr != nil {
		c.Net.Client.Transport = tr
	}
	if mutate != nil {
		mutate(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

// chartsMentions asserts the finding actually names the thing an operator has to
// act on. A BLOCK that does not say which repository died is a BLOCK nobody can
// action, which is the same failure as not checking.
func chartsMentions(t *testing.T, r engine.Result, want ...string) {
	t.Helper()
	var b strings.Builder
	b.WriteString(r.Summary + "\n" + r.Remedy + "\n" + r.DoesNotProve + "\n")
	b.WriteString(strings.Join(r.Detail, "\n") + "\n")
	for _, e := range r.Evidence {
		b.WriteString(e.What + "\n" + e.Output + "\n")
	}
	text := b.String()
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Fatalf("%s (%s): result never mentions %q\n%s", r.ID, r.Status(), w, text)
		}
	}
}

// chartsGPULabelled is the other way a cluster says it has GPUs: the NFD/GPU
// operator label, present even before the device plugin advertises a resource.
func chartsGPULabelled(o adapters.Object) {
	o["metadata"].(map[string]any)["labels"].(map[string]any)["nvidia.com/gpu.present"] = "true"
}

const (
	chartsRegistryRoot = "https://registry.bud.studio/v2/"
	chartsBudManifest  = "/v2/charts/bud/manifests/1.2.8"
	chartsAibrixAsset  = "releases/download/"
	chartsAibrixCDN    = "objects.githubusercontent.com"
)

// --- charts.oci --------------------------------------------------------------

// No adapter means the repository was never contacted. That has to read as
// "unverified", never as a quiet pass on the single input the whole install
// resolves from.
func TestChartsOCISkipsWithoutAnAdapter(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.oci", chartsAllOK(), func(c *engine.Ctx) { c.OCI = nil })
	assertSkipHasReason(t, r)
}

// The worst outcome in the group: nothing resolves, so no Application produces
// an object and there is nothing failing to diagnose.
func TestChartsOCIBlocksWhenTheRegistryDoesNotAnswer(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.oci", chartsAllBlocked(), nil)
	assertStatus(t, r, "BLOCK")
	chartsMentions(t, r, "registry.bud.studio", "no Application produces a single object")
}

// A live registry that does not carry the pinned umbrella version is a
// release-pinning failure, not an egress failure — different ticket, different
// team, so the check must separate them.
func TestChartsOCIBlocksWhenThePinnedUmbrellaChartIsAbsent(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.oci",
		chartsAllOK(chartsCode(chartsBudManifest, http.StatusNotFound)), nil)
	assertStatus(t, r, "BLOCK")
	chartsMentions(t, r, "bud:1.2.8", "the platform itself")
}

// An addon nobody selected must not block an install — but it must not vanish
// either, because selecting it later is when it bites.
func TestChartsOCIRisksWhenOnlyAnUnselectedAddonIsAbsent(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.oci",
		chartsAllOK(chartsCode("/charts/kyverno/manifests/", http.StatusNotFound)), nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r, "kyverno:0.0.4", "policy addon")
}

// Scope is answer-driven: the same missing chart is a blocker or a risk
// depending on what the operator said they are installing. Getting this
// backwards either blocks an install that would have worked or waves through one
// that will not.
func TestChartsOCIScopesChartsToTheIntakeAnswers(t *testing.T) {
	cases := []struct {
		name    string
		missing string
		answers func(a *intake.Answers)
		want    string
	}{
		{
			name:    "in-cluster data stores selected: the CNPG chart is on the critical path",
			missing: "/charts/postgres/manifests/",
			answers: func(a *intake.Answers) { a.InClusterData = true },
			want:    "BLOCK",
		},
		{
			name:    "external data stores: no postgres chart is installed, so its absence is not a blocker",
			missing: "/charts/postgres/manifests/",
			answers: func(a *intake.Answers) { a.InClusterData = false },
			want:    "RISK",
		},
		{
			name:    "ACME issuance: cert-manager issues every published hostname's certificate",
			missing: "/charts/cert-manager/manifests/",
			answers: func(a *intake.Answers) { a.TLS = "acme-http01" },
			want:    "BLOCK",
		},
		{
			name:    "operator-provided certificate: cert-manager is an addon, not a step",
			missing: "/charts/cert-manager/manifests/",
			answers: func(a *intake.Answers) { a.TLS = "provided" },
			want:    "RISK",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := vanilla().withAnswers(func(a *intake.Answers) { tc.answers(a) })
			r := chartsRun(t, f, "charts.oci",
				chartsAllOK(chartsCode(tc.missing, http.StatusNotFound)), nil)
			assertStatus(t, r, tc.want)
		})
	}
}

// ArgoCD presents the same credential at sync time, so a rejection here is a
// rejection then. Without a credential the same 401 means something else
// entirely (see the next test), and the two must not collapse.
func TestChartsOCIBlocksWhenTheSuppliedCredentialIsRejected(t *testing.T) {
	f := vanilla().withOpts(func(o *engine.Options) {
		o.RegistryCreds = map[string]adapters.Credential{
			"registry.bud.studio": {Username: "robot$budctl", Password: "nope"},
		}
	})
	r := chartsRun(t, f, "charts.oci",
		chartsAllOK(chartsCode("/manifests/", http.StatusUnauthorized)), nil)
	assertStatus(t, r, "BLOCK")
	chartsMentions(t, r, "cannot read", "--registry-credentials")
}

// Pre-credential, an authenticating registry is the whole question (D7) — but
// the pass must state that no version was resolved, or it reads as proof the
// charts exist.
func TestChartsOCIPassesUnresolvedWhenNoCredentialWasSupplied(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.oci",
		chartsAllOK(chartsCode("/manifests/", http.StatusUnauthorized)), nil)
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatalf("charts.oci passed on a registry that resolved nothing without bounding the claim: %s", r.Summary)
	}
	chartsMentions(t, r, "no chart version was resolved", "--registry-credentials")
}

// The root answers but the manifest requests do not: a proxy that terminates
// TLS, or an intermittent path. The remedy is "re-run when egress is stable",
// which is neither of the other two remedies.
func TestChartsOCIBlocksWhenManifestRequestsCannotBeReached(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.oci",
		chartsAllOK(
			chartsRule{when: chartsURLIs(chartsRegistryRoot), reply: chartsReply{status: 200}},
			chartsBlock("/manifests/"),
		), nil)
	assertStatus(t, r, "BLOCK")
	chartsMentions(t, r, "could not be reached", "bud:1.2.8")
}

// The pass case, which is what makes every failure above meaningful.
func TestChartsOCIPassesWhenEveryPinnedChartResolves(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.oci", chartsAllOK(), nil)
	assertStatus(t, r, "PASS")
	chartsMentions(t, r, "bud:1.2.8", "keycloak:0.2.1")
	if r.DoesNotProve == "" {
		t.Fatal("charts.oci passed without bounding the claim to manifests rather than archives")
	}
}

// --chart-dir exists because checking a version nobody is installing produces a
// confident verdict about a release that is not in play. This asserts the
// override actually reaches the request, not just the report.
func TestChartsOCIChecksTheChartDirVersionRatherThanTheEmbeddedPin(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"),
		[]byte("apiVersion: v2\nname: bud\nversion: 9.9.9\n"), 0o600); err != nil {
		t.Fatalf("write chart: %v", err)
	}
	f := vanilla().withOpts(func(o *engine.Options) { o.ChartDir = dir })

	// The embedded pin resolves; the version the operator is holding does not.
	r := chartsRun(t, f, "charts.oci",
		chartsAllOK(chartsCode("/charts/bud/manifests/9.9.9", http.StatusNotFound)), nil)
	assertStatus(t, r, "BLOCK")
	chartsMentions(t, r, "bud:9.9.9", "--chart-dir")
}

// --- charts.classic ----------------------------------------------------------

func TestChartsClassicSkipsWithoutANetworkAdapter(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.classic", chartsAllOK(), func(c *engine.Ctx) { c.Net = nil })
	assertSkipHasReason(t, r)
}

// An empty inventory would otherwise render as "all 0 repositories serve
// index.yaml" — a PASS that checked nothing.
func TestChartsClassicSkipsWhenTheInventoryNamesNoRepositories(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.classic", chartsAllOK(),
		func(c *engine.Ctx) { c.Profile.Egress = nil })
	assertSkipHasReason(t, r)
}

// One repo down blocks the install, and the finding has to name the chart that
// needs it: "bitnami unreachable" and "the common library subchart is absent"
// are not the same problem to the person holding the ticket.
func TestChartsClassicBlocksWhenAnInstallTimeRepoIsUnreachable(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.classic",
		chartsAllOK(chartsBlock("charts.bitnami.com")), nil)
	assertStatus(t, r, "BLOCK")
	chartsMentions(t, r, "bitnami charts", "common library subchart")
}

// index.yaml is a document, not a registry endpoint: the "401 proves the host is
// alive" rule from the registry group must not leak in here, or a proxy serving
// 403 to everything reads as a healthy hub.
func TestChartsClassicBlocksOnAForbiddenIndexRatherThanTreatingItAsReachable(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.classic",
		chartsAllOK(chartsCode("dapr.github.io", http.StatusForbidden)), nil)
	assertStatus(t, r, "BLOCK")
	chartsMentions(t, r, "dapr charts", "HTTP 403")
}

// An optional hub cannot block an install it is not part of, but it still costs
// the feature behind it.
func TestChartsClassicRisksWhenOnlyAnOptionalRepoIsUnreachable(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.classic",
		chartsAllOK(chartsBlock("charts.signoz.io")), nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r, "SigNoz charts")
}

// The same dead host is a blocker or a risk depending on whether the operator
// asked for in-cluster data stores. Reporting a repo nobody will contact as a
// blocker is how a report trains people to ignore it.
func TestChartsClassicScopesDataStoreReposToTheIntakeAnswer(t *testing.T) {
	cases := []struct {
		name          string
		inClusterData bool
		want          string
	}{
		{"in-cluster data stores: no CNPG operator means no database for any service", true, "BLOCK"},
		{"external data stores: the CNPG operator is never installed", false, "RISK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := vanilla().withAnswers(func(a *intake.Answers) { a.InClusterData = tc.inClusterData })
			r := chartsRun(t, f, "charts.classic",
				chartsAllOK(chartsBlock("cloudnative-pg.github.io")), nil)
			assertStatus(t, r, tc.want)
			chartsMentions(t, r, "CloudNativePG charts")
		})
	}
}

func TestChartsClassicPassesWhenEveryRepoServesAnIndex(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.classic", chartsAllOK(), nil)
	assertStatus(t, r, "PASS")
	// The fetch came from the workstation; claiming it proves the repo-server's
	// path would be the exact false assurance the bounds exist to prevent.
	if !strings.Contains(r.DoesNotProve, "repo-server") {
		t.Fatalf("charts.classic pass does not bound the vantage point: %q", r.DoesNotProve)
	}
}

// --- charts.runtime ----------------------------------------------------------

func TestChartsRuntimeSkipsWithoutANetworkAdapter(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.runtime", chartsAllOK(), func(c *engine.Ctx) { c.Net = nil })
	assertSkipHasReason(t, r)
}

func TestChartsRuntimeSkipsWhenTheInventoryNamesNoOnboardingRepos(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.runtime", chartsAllOK(),
		func(c *engine.Ctx) { c.Profile.Egress = nil })
	assertSkipHasReason(t, r)
}

// NFD is installed on every cluster budcluster onboards, GPU or not. An install
// that succeeds today and an onboarding that fails next week is still a bad day.
func TestChartsRuntimeRisksWhenTheNFDRepoIsUnreachable(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.runtime",
		chartsAllOK(chartsBlock("node-feature-discovery")), nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r, "NFD charts", "cluster onboarding")
}

// The GPU hubs are only contacted where GPUs are found. On a CPU-only cluster
// they must not appear as a finding — but they must still be reported as seen
// and deliberately out of scope, not silently dropped.
func TestChartsRuntimeKeepsGPUReposOutOfScopeOnACPUOnlyCluster(t *testing.T) {
	f := vanilla().with("nodes", "", node("cpu-1")).
		withAnswers(func(a *intake.Answers) { a.GPU = false })
	r := chartsRun(t, f, "charts.runtime",
		chartsAllOK(chartsBlock("project-hami.github.io"), chartsBlock("helm.ngc.nvidia.com")), nil)
	assertStatus(t, r, "PASS")
	chartsMentions(t, r, "out of scope", "HAMi charts", "NVIDIA NGC charts")
}

func TestChartsRuntimeRisksWhenGPUReposAreUnreachableOnAGPUCluster(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.GPU = true })
	r := chartsRun(t, f, "charts.runtime",
		chartsAllOK(chartsBlock("project-hami.github.io")), nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r, "HAMi charts", "intake says this is a GPU cluster")
}

// The GPU operator labels a node before any resource is advertised, so the
// label alone puts the GPU hubs in scope. Without this the window between
// labelling and the device plugin coming up reads as a CPU-only cluster.
func TestChartsRuntimeUsesTheGPUPresentLabelWhenNoResourceIsAdvertisedYet(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-2", chartsGPULabelled)).
		withAnswers(func(a *intake.Answers) { a.GPU = false })
	r := chartsRun(t, f, "charts.runtime",
		chartsAllOK(chartsBlock("project-hami.github.io")), nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r, "HAMi charts", "gpu-2", "nvidia.com/gpu.present")
}

// The cluster's own hardware overrides the intake answer: an operator who said
// "no GPU" on a fleet with GPU nodes still gets HAMi installed at onboarding, so
// the hub is in scope whatever they typed.
func TestChartsRuntimeUsesNodeEvidenceWhenIntakeSaysNoGPU(t *testing.T) {
	f := vanilla().
		with("nodes", "", node("gpu-1", withGPU("4"))).
		withAnswers(func(a *intake.Answers) { a.GPU = false })
	r := chartsRun(t, f, "charts.runtime",
		chartsAllOK(chartsBlock("helm.ngc.nvidia.com")), nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r, "NVIDIA NGC charts", "gpu-1")
}

func TestChartsRuntimePassesWhenEveryOnboardingRepoAnswers(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.runtime", chartsAllOK(), nil)
	assertStatus(t, r, "PASS")
	chartsMentions(t, r, "NFD charts")
}

// --- charts.aibrix -----------------------------------------------------------

func TestChartsAibrixSkipsWithoutANetworkAdapter(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.aibrix", chartsAllOK(), func(c *engine.Ctx) { c.Net = nil })
	assertSkipHasReason(t, r)
}

// Without the Aibrix manifests there is no data plane at onboarding, so model
// deployments have no gateway — an install-time green with a runtime cliff.
func TestChartsAibrixRisksWhenTheReleaseManifestsAreBlocked(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.aibrix", chartsAllBlocked(), nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r, "aibrix-dependency", "aibrix-core", "no gateway")
}

// The failure this check exists for: the allowlist names github.com, a manual
// `curl -I` shows the 302 and looks fine, and the actual download dies on the
// CDN host nobody listed.
func TestChartsAibrixCatchesTheGitHubOnlyAllowlist(t *testing.T) {
	tr := chartsAllOK(
		chartsBlock(chartsAibrixCDN),
		chartsRule{
			when: chartsURLHas(chartsAibrixAsset),
			reply: chartsReply{
				status:   http.StatusFound,
				location: "https://" + chartsAibrixCDN + "/github-production-release-asset/aibrix.yaml",
			},
		},
	)
	r := chartsRun(t, vanilla(), "charts.aibrix", tr, nil)
	assertStatus(t, r, "RISK")
	chartsMentions(t, r,
		chartsAibrixCDN,
		"the usual shape of a github.com-only allowlist",
		"allowlist BOTH github.com")
}

func TestChartsAibrixPassesWhenBothManifestsAndTheCDNAnswer(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.aibrix", chartsAllOK(), nil)
	assertStatus(t, r, "PASS")
	chartsMentions(t, r, chartsAibrixCDN)
	if r.DoesNotProve == "" {
		t.Fatal("charts.aibrix passed on a workstation fetch without bounding it to this vantage point")
	}
}

// A manifest that resolved while the CDN root refused is worth saying out loud:
// the redirect may have come from a cache, and the next onboarding will not.
func TestChartsAibrixPassStillNotesAnUnreachableCDN(t *testing.T) {
	r := chartsRun(t, vanilla(), "charts.aibrix",
		chartsAllOK(chartsBlock(chartsAibrixCDN)), nil)
	assertStatus(t, r, "PASS")
	chartsMentions(t, r, "did not answer directly")
}
