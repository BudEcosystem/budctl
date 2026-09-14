package checks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// The egress group is the one group whose subject is, by construction, off the
// machine running the tests: a pod dialling thirty hosts. Asserting it by
// letting the checks dial for real would make the suite a test of this
// workstation's internet connection — green on a laptop, red in CI, and never
// an assertion about budctl. So every test here supplies the vantage report
// that the pod or the workstation sweep would have produced, through the same
// memoisation the checks use to share one probe pod between seven checks, and
// then asserts the VERDICT budctl draws from it. Nothing below opens a socket.

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// Catalogue entries the tests name explicitly. If defaults.yaml renames or
// drops one of these, egressTestVantage fails loudly rather than quietly
// building an all-reachable fixture that asserts nothing.
const (
	egressTestDockerHub   = "https://registry-1.docker.io/v2/"
	egressTestBudRegistry = "https://registry.bud.studio/v2/"
	egressTestDaprCharts  = "https://dapr.github.io/helm-charts/index.yaml"
	egressTestHFAPI       = "https://huggingface.co/api/models/gpt2"
	egressTestKyverno     = "https://reg.kyverno.io/v2/"
	egressTestAltinity    = "https://docs.altinity.com/clickhouse-operator/index.yaml"
	egressTestACME        = "https://acme-v02.api.letsencrypt.org/directory"
	egressTestSSH         = "github.com:22"
)

// egressCluster is the fixture every test starts from. The harness default is
// --egress-from workstation, which would send the real sweep down a real
// socket; the cluster vantage is also budctl's own default and the one the FRD
// argues for, so it is what these tests assert against.
func egressCluster() *fakeCluster {
	return vanilla().withOpts(func(o *engine.Options) { o.EgressFrom = "cluster" })
}

func egressOpenShiftCluster() *fakeCluster {
	return openShift().withOpts(func(o *engine.Options) { o.EgressFrom = "cluster" })
}

func egressFrom(mode string) func(*engine.Options) {
	return func(o *engine.Options) { o.EgressFrom = mode }
}

// egressRun is run() with a seam for pre-loading Ctx. The checks memoise each
// vantage report on Ctx, so a report placed there before the check runs is the
// report the check reads — which is how a pod that never existed answers for
// thirty endpoints deterministically.
func egressRun(t *testing.T, f *fakeCluster, id string, seed ...func(*engine.Ctx)) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	for _, s := range seed {
		s(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

func egressTestProfile(t *testing.T) intake.Profile {
	t.Helper()
	p, err := intake.LoadProfile()
	if err != nil {
		t.Fatalf("embedded profile: %v", err)
	}
	return p
}

// egressTestVantage builds a vantage point from the RAW text a probe pod would
// have printed, and parses it with the same parser the real run uses. Feeding
// pre-computed verdicts in instead would make the fixture agree with the
// implementation by construction: the "000"/407 mapping, the field order and
// the CLOCK lines would all be asserted by the test against itself.
//
// Every catalogue endpoint answers 200 unless overridden. Starting from
// all-reachable and subtracting is deliberate: a fixture listing only the
// broken host would leave the other twenty-nine "untested", which is a
// different verdict entirely.
func egressTestVantage(t *testing.T, name string, overrides map[string]string) *egressVantage {
	t.Helper()
	p := egressTestProfile(t)
	var b strings.Builder
	known := map[string]bool{}
	for _, tgt := range p.Egress {
		if tgt.URL == "" {
			continue
		}
		known[tgt.URL] = true
		code := "200"
		if c, ok := overrides[tgt.URL]; ok {
			code = c
		}
		fmt.Fprintf(&b, "%s|%s|%s|%s\n", code, tgt.When, egressSanitizeField(tgt.Label), tgt.URL)
	}
	for _, tgt := range p.EgressTCP {
		key := fmt.Sprintf("%s:%d", tgt.Host, tgt.Port)
		known[key] = true
		code := "open"
		if c, ok := overrides[key]; ok {
			code = c
		}
		fmt.Fprintf(&b, "%s|%s|%s|%s\n", code, tgt.When, egressSanitizeField(tgt.Label), key)
	}
	for target := range overrides {
		if !known[target] {
			t.Fatalf("fixture names %q, which is not in the embedded catalogue: the test would assert an all-reachable cluster", target)
		}
	}
	return egressTestParsedVantage(name, b.String())
}

func egressTestParsedVantage(name, raw string) *egressVantage {
	v := &egressVantage{Name: name, Results: map[string]egressEndpoint{}, Raw: strings.TrimSpace(raw)}
	parseEgressLines(v.Raw, v)
	v.Ran = len(v.Results) > 0 || v.PodStart > 0
	return v
}

// egressTestDrop removes endpoints from a vantage, modelling a probe pod that
// was cut off before every background subshell reported.
func egressTestDrop(v *egressVantage, targets ...string) *egressVantage {
	for _, t := range targets {
		delete(v.Results, t)
	}
	return v
}

func egressSeedCluster(v *egressVantage) func(*engine.Ctx) {
	return func(c *engine.Ctx) { c.Set(keyEgressCluster, v) }
}

func egressSeedWorkstation(v *egressVantage) func(*engine.Ctx) {
	return func(c *engine.Ctx) { c.Set(keyEgressWorkstation, v) }
}

// egressWithProbeRunner gives Ctx a non-nil probe runner. egress.clock-nodes
// refuses to read a node clock without one, and the seeded report means the
// runner is never actually asked to create a pod.
func egressWithProbeRunner(c *engine.Ctx) {
	c.Probes = probes.NewRunner(c.Kube, "budctl-egress-test", "test", false)
}

func egressTargetsFor(t *testing.T, when string) []intake.EgressTarget {
	t.Helper()
	return egressTargetsWhen(egressTestProfile(t).Egress, when)
}

func egressAssertContains(t *testing.T, what, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("%s does not mention %q:\n  %s", what, needle, haystack)
	}
}

func egressAssertDetail(t *testing.T, r engine.Result, needle string) {
	t.Helper()
	for _, d := range r.Detail {
		if strings.Contains(d, needle) {
			return
		}
	}
	t.Fatalf("%s: no detail line mentions %q:\n  %s", r.ID, needle, strings.Join(r.Detail, "\n  "))
}

// egressAssertNoVerdictEffect guards the INFO contract: a finding the operator
// should see must not silently become a blocker or a risk.
func egressAssertNoVerdictEffect(t *testing.T, r engine.Result) {
	t.Helper()
	if r.IsBlocker() || r.IsRisk() {
		t.Fatalf("%s moved the verdict (%s/%s), but its severity must never do that", r.ID, r.State, r.Severity)
	}
}

// ---------------------------------------------------------------------------
// the catalogue itself
// ---------------------------------------------------------------------------

// Every check in this group opens by skipping when its slice of the catalogue
// is empty. An edit to defaults.yaml that empties a bucket would therefore turn
// three checks into permanent skips, and every fixture below into a tautology.
func TestEgressCatalogueFillsEveryBucket(t *testing.T) {
	p := egressTestProfile(t)
	for _, when := range []string{"install", "runtime", "optional", "acme"} {
		if len(egressTargetsWhen(p.Egress, when)) == 0 {
			t.Fatalf("the embedded catalogue lists no %q endpoints, so egress.%s can only ever SKIP", when, when)
		}
	}
	if len(p.EgressTCP) == 0 {
		t.Fatal("the catalogue lists no raw TCP endpoints, so egress.ssh can only ever SKIP")
	}
}

// The two codes that look like answers and are not. A registry's 401 and a
// moved chart index's 404 prove DNS, routing, TLS and a live server, so they
// are passes (D7); "000" is curl reporting that nothing came back at all, and
// 407 is a proxy refusing us — which is the exact state in which every image
// pull fails, and the one most likely to be mistaken for a response.
func TestEgressReachabilityTreatsOnlyNonAnswersAsUnreachable(t *testing.T) {
	for code, want := range map[string]bool{
		"200": true, "401": true, "404": true, "500": true, "open": true,
		"000": false, "407": false, "closed": false, "": false,
	} {
		if got := egressCodeOK(code); got != want {
			t.Errorf("egressCodeOK(%q) = %v, want %v", code, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// egress.install
// ---------------------------------------------------------------------------

// The load-bearing failure of the whole tool: a node that cannot reach a
// registry produces an ApplicationSet that stalls in ImagePullBackOff with
// nothing wrong upstream.
func TestEgressInstallBlocksWhenRequiredEndpointUnreachable(t *testing.T) {
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestDockerHub: "000"})
	r := egressRun(t, egressCluster(), "egress.install", egressSeedCluster(v))

	assertStatus(t, r, "BLOCK")
	egressAssertContains(t, "summary", r.Summary, "Docker Hub")
	egressAssertContains(t, "summary", r.Summary, "unreachable from the cluster")
	egressAssertContains(t, "remedy", r.Remedy, "registry-1.docker.io")
	// The consequence from the catalogue, not just the hostname: the operator
	// has to know what stops working.
	egressAssertDetail(t, r, "Aibrix, HAMi, ClickHouse")
}

// 407 is the one HTTP status that is not an answer: a proxy refusing us is the
// exact state in which every image pull fails. Treating "we got a response" as
// reachability would report a fully blocked cluster as green.
func TestEgressInstallBlocksOnProxy407(t *testing.T) {
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestBudRegistry: "407"})
	r := egressRun(t, egressCluster(), "egress.install", egressSeedCluster(v))

	assertStatus(t, r, "BLOCK")
	egressAssertDetail(t, r, "HTTP 407")
	egressAssertContains(t, "summary", r.Summary, "Bud private registry")
}

// D7: the question is whether DNS, routing, TLS and a live server exist — not
// whether we are authorised. A registry's 401 and a moved index's 404 are
// passes, and a check that demanded 200 would block every correctly configured
// cluster on earth.
func TestEgressInstallPassesOnAuthAndNotFoundStatuses(t *testing.T) {
	v := egressTestVantage(t, egressVantageCluster, map[string]string{
		egressTestBudRegistry: "401",
		egressTestDaprCharts:  "404",
	})
	r := egressRun(t, egressCluster(), "egress.install", egressSeedCluster(v))

	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("a passing reachability sweep must state that an answer is not a pulled layer")
	}
	if len(r.Evidence) != len(egressTargetsFor(t, "install")) {
		t.Fatalf("evidence covers %d endpoints, the install set has %d — the status codes are the only way to audit a proxy block page",
			len(r.Evidence), len(egressTargetsFor(t, "install")))
	}
}

// D5: endpoints that never answered were not dialled. Reporting the ones that
// did answer as a PASS would claim a sweep that did not happen.
func TestEgressInstallSkipsWhenSweepIsPartial(t *testing.T) {
	v := egressTestDrop(egressTestVantage(t, egressVantageCluster, nil),
		egressTestDockerHub, egressTestBudRegistry)
	r := egressRun(t, egressCluster(), "egress.install", egressSeedCluster(v))

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "never dialled")
}

// FRD §6: an unpullable probe image is not a tool error, it is the strongest
// possible egress answer for the install set — the node just failed to fetch an
// image from a public registry, which is what the whole sync is about to do.
func TestEgressInstallBlocksWhenProbeImageCannotBePulled(t *testing.T) {
	v := &egressVantage{
		Name: egressVantageCluster, Results: map[string]egressEndpoint{},
		ImagePull: "the probe image curlimages/curl:8.10.1 could not be pulled: ErrImagePull: back-off pulling image",
	}
	v.Why = v.ImagePull
	r := egressRun(t, egressCluster(), "egress.install", egressSeedCluster(v))

	assertStatus(t, r, "BLOCK")
	egressAssertContains(t, "summary", r.Summary, "could not pull")
	if len(r.Evidence) == 0 {
		t.Fatal("the pod events are the whole basis of this verdict and must be in the evidence")
	}
}

// The same unpullable image says nothing about a runtime feature's endpoint, so
// there it is a skip — with the pull failure as the reason, never a silent one.
func TestEgressRuntimeSkipsWhenProbeImageCannotBePulled(t *testing.T) {
	v := &egressVantage{
		Name: egressVantageCluster, Results: map[string]egressEndpoint{},
		ImagePull: "the probe image curlimages/curl:8.10.1 could not be pulled: ErrImagePull",
	}
	v.Why = v.ImagePull
	assertSkipHasReason(t, egressRun(t, egressCluster(), "egress.runtime", egressSeedCluster(v)))
}

// A host the laptop reaches and the node does not is a failure, not a pass —
// and the disagreement is itself the diagnosis, because it localises the block
// to the node network rather than to DNS or an upstream outage.
func TestEgressInstallFollowsPodWhenWorkstationDisagrees(t *testing.T) {
	f := egressCluster().withOpts(egressFrom("both"))
	cl := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestDockerHub: "000"})
	ws := egressTestVantage(t, egressVantageWorkstation, nil)

	r := egressRun(t, f, "egress.install", egressSeedCluster(cl), egressSeedWorkstation(ws))

	assertStatus(t, r, "BLOCK")
	egressAssertDetail(t, r, "second vantage point this workstation")
	egressAssertDetail(t, r, "reachable from this workstation — the difference is the node network")
}

// DEFECT, pinned rather than fixed (reported with this file, not repaired here:
// the brief is to expose implementation problems, not to edit egress.go).
//
// Under --egress-from both, a node that could not pull the probe image produces
// egress.install PASS — "all 7 install-time endpoints answered from this
// workstation" — because the ImagePull branch is guarded by (ws == nil ||
// !ws.Ran) and the workstation sweep then carries the verdict. The identical
// cluster is a BLOCK under the default --egress-from cluster. That is the exact
// false assurance §5.10 exists to prevent: the node has just demonstrated it
// cannot pull an image from a public registry, which is what every chart in the
// ApplicationSet is about to ask it to do, and the check goes green off the
// operator's laptop. D5 would make this a SKIP at the very least; FRD §6 argues
// for the BLOCK. This test asserts today's behaviour so the fix shows up here
// as a flip, and asserts the one thing that is unambiguously required either
// way: the pull failure is never silently dropped.
func TestEgressInstallGoesGreenOnAnUnpullableProbeImageUnderBothVantages(t *testing.T) {
	f := egressCluster().withOpts(egressFrom("both"))
	cl := &egressVantage{
		Name: egressVantageCluster, Results: map[string]egressEndpoint{},
		ImagePull: "the probe image curlimages/curl:8.10.1 could not be pulled: ErrImagePull",
	}
	cl.Why = cl.ImagePull
	ws := egressTestVantage(t, egressVantageWorkstation, nil)

	r := egressRun(t, f, "egress.install", egressSeedCluster(cl), egressSeedWorkstation(ws))

	if r.Status() != "PASS" {
		t.Fatalf("the pinned defect appears to be fixed: egress.install is now %s (%s) — "+
			"delete this test and keep the one that asserts the new verdict", r.Status(), r.Summary)
	}
	egressAssertContains(t, "summary", r.Summary, egressVantageWorkstation)
	egressAssertDetail(t, r, "cluster vantage point produced nothing")
	egressAssertDetail(t, r, "could not be pulled")
}

// --no-probe removes the cluster vantage. The runner short-circuits probe
// checks before the body runs; the body must reach the same verdict on its own,
// because "we did not look" is not "we looked and it was fine".
func TestEgressSkipsWithReasonWhenThereIsNoProbeRunner(t *testing.T) {
	for _, id := range []string{"egress.install", "egress.runtime", "egress.optional", "egress.acme", "egress.ssh"} {
		t.Run(id, func(t *testing.T) {
			f := egressCluster().withOpts(func(o *engine.Options) { o.NoProbe = true })
			r := egressRun(t, f, id)
			assertSkipHasReason(t, r)
			egressAssertContains(t, "skip reason", r.Summary, "not confirmed working")
		})
	}
}

// ---------------------------------------------------------------------------
// egress.runtime
// ---------------------------------------------------------------------------

// Hugging Face unreachable is the canonical runtime failure: the install
// completes and every model add fails afterwards.
func TestEgressRuntimeRisksWhenHuggingFaceUnreachable(t *testing.T) {
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestHFAPI: "000"})
	r := egressRun(t, egressCluster(), "egress.runtime", egressSeedCluster(v))

	assertStatus(t, r, "RISK")
	egressAssertContains(t, "summary", r.Summary, "Hugging Face API")
	egressAssertDetail(t, r, "every model added from Hugging Face")
	if r.IsBlocker() {
		t.Fatal("a runtime endpoint must not block the install: the sync still completes")
	}
}

func TestEgressRuntimePassesWhenEveryFeatureEndpointAnswers(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.runtime",
		egressSeedCluster(egressTestVantage(t, egressVantageCluster, nil)))
	assertStatus(t, r, "PASS")
}

// ---------------------------------------------------------------------------
// egress.optional
// ---------------------------------------------------------------------------

// An optional endpoint cannot be driven to BLOCK or RISK by design — §5.10 caps
// it at INFO. What must be provable is that it still REPORTS: an addon that
// will not work is reported as a finding, with its consequence, while leaving
// the verdict alone.
func TestEgressOptionalReportsUnreachableAddonWithoutMovingTheVerdict(t *testing.T) {
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestKyverno: "000"})
	r := egressRun(t, egressCluster(), "egress.optional", egressSeedCluster(v))

	assertStatus(t, r, "INFO")
	if r.State != engine.StateFail {
		t.Fatalf("an unreachable optional endpoint must be recorded as a finding, got state %q", r.State)
	}
	egressAssertNoVerdictEffect(t, r)
	egressAssertContains(t, "summary", r.Summary, "Kyverno registry")
	egressAssertDetail(t, r, "the Kyverno addon cannot pull its five images")
}

func TestEgressOptionalPassesWhenAddonEndpointsAnswer(t *testing.T) {
	assertStatus(t, egressRun(t, egressCluster(), "egress.optional",
		egressSeedCluster(egressTestVantage(t, egressVantageCluster, nil))), "PASS")
}

// ---------------------------------------------------------------------------
// egress.acme
// ---------------------------------------------------------------------------

// The shape of a real cluster Bud synced onto: Let's Encrypt reset the
// connection and the upstream ClickHouse chart repo was blocked. Neither is
// fetched by the sync, so the install set passes; the directory is egress.acme's
// to report and the Altinity repo only egress.optional's.
func TestEgressInstallPassesWhenOnlyACMEAndBundledChartReposAreBlocked(t *testing.T) {
	v := egressTestVantage(t, egressVantageCluster, map[string]string{
		egressTestACME:     "000",
		egressTestAltinity: "000",
	})
	assertStatus(t, egressRun(t, egressCluster(), "egress.install", egressSeedCluster(v)), "PASS")

	opt := egressRun(t, egressCluster(), "egress.optional", egressSeedCluster(v))
	assertStatus(t, opt, "INFO")
	egressAssertNoVerdictEffect(t, opt)
	egressAssertDetail(t, opt, "bundled in the published OCI chart")
}

// Under an ACME answer an unreachable directory blocks: no certificate is ever
// issued. The summary has to say that, and not that the sync stops at a chart.
func TestEgressACMEBlocksWhenTheDirectoryIsUnreachableUnderAnACMEAnswer(t *testing.T) {
	for _, method := range []intake.TLSMethod{intake.TLSACMEHTTP01, intake.TLSACMEDNS01} {
		t.Run(string(method), func(t *testing.T) {
			f := egressCluster().withAnswers(func(a *intake.Answers) { a.TLS = method })
			v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestACME: "000"})
			r := egressRun(t, f, "egress.acme", egressSeedCluster(v))

			assertStatus(t, r, "BLOCK")
			egressAssertContains(t, "summary", r.Summary, "Let's Encrypt ACME")
			egressAssertContains(t, "summary", r.Summary, "no certificate is issued")
			if strings.Contains(r.Summary, "image or chart") {
				t.Fatalf("an ACME directory is neither an image nor a chart: %s", r.Summary)
			}
			egressAssertContains(t, "remedy", r.Remedy, "acme-v02.api.letsencrypt.org")
			egressAssertContains(t, "remedy", r.Remedy, "'provided'")
		})
	}
}

// A provided certificate or plain HTTP never calls the directory, so the same
// blocked host is not this install's problem: a skip that says why.
func TestEgressACMESkipsWhenTLSIsNotObtainedThroughACME(t *testing.T) {
	for _, method := range []intake.TLSMethod{intake.TLSProvided, intake.TLSNone} {
		t.Run(string(method), func(t *testing.T) {
			f := egressCluster().withAnswers(func(a *intake.Answers) { a.TLS = method })
			v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestACME: "000"})
			r := egressRun(t, f, "egress.acme", egressSeedCluster(v))

			assertSkipHasReason(t, r)
			egressAssertContains(t, "skip reason", r.Summary, "never calls an ACME directory")
		})
	}
}

func TestEgressACMEPassesWhenTheDirectoryAnswers(t *testing.T) {
	assertStatus(t, egressRun(t, egressCluster(), "egress.acme",
		egressSeedCluster(egressTestVantage(t, egressVantageCluster, nil))), "PASS")
}

// ---------------------------------------------------------------------------
// egress.ssh
// ---------------------------------------------------------------------------

// Port 22, not 443. An allowlist written as "HTTPS to the internet" passes
// every other check in this group and still stops every ssh:// Application from
// syncing — quietly, as OutOfSync rather than as a network error.
func TestEgressSSHBlocksWhenRepoIsSSHAndPort22Refused(t *testing.T) {
	f := egressCluster().withAnswers(func(a *intake.Answers) {
		a.UseArgoCD = true
		a.ConfigRepo = "ssh://git@github.com/BudEcosystem/example-bud-foundry-config.git"
	})
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestSSH: "closed"})
	r := egressRun(t, f, "egress.ssh", egressSeedCluster(v))

	assertStatus(t, r, "BLOCK")
	egressAssertContains(t, "summary", r.Summary, egressTestSSH)
	egressAssertContains(t, "remedy", r.Remedy, "22")
	egressAssertContains(t, "remedy", r.Remedy, "443")
	egressAssertDetail(t, r, "ssh://git@github.com/BudEcosystem/example-bud-foundry-config.git")
}

// scp-style "git@host:path" is the same SSH path with none of the ssh:// text,
// and it is what most operators actually paste. Matching only the scheme would
// downgrade a real blocker to a risk.
func TestEgressSSHBlocksOnScpStyleRepoURL(t *testing.T) {
	f := egressCluster().withAnswers(func(a *intake.Answers) {
		a.ConfigRepo = "git@github.com:BudEcosystem/example-bud-foundry-config.git"
	})
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestSSH: "closed"})
	assertStatus(t, egressRun(t, f, "egress.ssh", egressSeedCluster(v)), "BLOCK")
}

// With no repoURL stated, budctl does not know whether ArgoCD will need port
// 22 — so the closed port is a decision for the operator, not a blocker, and
// the detail has to say why it was demoted.
func TestEgressSSHRisksWhenRepoURLIsUnstated(t *testing.T) {
	f := egressCluster().withAnswers(func(a *intake.Answers) { a.ConfigRepo = "" })
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestSSH: "closed"})
	r := egressRun(t, f, "egress.ssh", egressSeedCluster(v))

	assertStatus(t, r, "RISK")
	egressAssertDetail(t, r, "risk rather than a blocker")
}

// An https:// repoURL never touches port 22, so a closed one is not this
// install's problem. It must skip with that stated, not pass — the port really
// is closed, it just does not matter here.
func TestEgressSSHSkipsForHTTPSRepoURL(t *testing.T) {
	f := egressCluster().withAnswers(func(a *intake.Answers) {
		a.ConfigRepo = "https://github.com/BudEcosystem/example-bud-foundry-config.git"
	})
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestSSH: "closed"})
	r := egressRun(t, f, "egress.ssh", egressSeedCluster(v))

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "port 22 is not on its path")
}

func TestEgressSSHSkipsWhenArgoCDIsNotPartOfTheInstall(t *testing.T) {
	f := egressCluster().withAnswers(func(a *intake.Answers) { a.UseArgoCD = false })
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestSSH: "closed"})
	r := egressRun(t, f, "egress.ssh", egressSeedCluster(v))

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "ArgoCD is not part of this install")
}

func TestEgressSSHPassesWhenPort22Accepts(t *testing.T) {
	f := egressCluster().withAnswers(func(a *intake.Answers) {
		a.ConfigRepo = "ssh://git@github.com/BudEcosystem/example-bud-foundry-config.git"
	})
	r := egressRun(t, f, "egress.ssh", egressSeedCluster(egressTestVantage(t, egressVantageCluster, nil)))

	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("an accepted TCP connection is not an accepted deploy key, and the result must say so")
	}
}

// A pod that answered for the URL sweep but whose tcpprobe line never arrived
// has told us nothing about port 22. That is a skip, not a pass.
func TestEgressSSHSkipsWhenNoTCPAnswerWasRecorded(t *testing.T) {
	v := egressTestDrop(egressTestVantage(t, egressVantageCluster, nil), egressTestSSH)
	r := egressRun(t, egressCluster(), "egress.ssh", egressSeedCluster(v))

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "no TCP target produced an answer")
}

// ---------------------------------------------------------------------------
// egress.proxy
// ---------------------------------------------------------------------------

// egressClearProxyEnv keeps the machine running the tests out of the fixture:
// a developer with HTTPS_PROXY exported would otherwise change what this check
// reports.
func egressClearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"} {
		t.Setenv(k, "")
	}
}

// egressTestProxyPod is a kube-system workload carrying proxy environment
// variables — the only trace of a node-level proxy that the Kubernetes API
// exposes at all.
func egressTestProxyPod(name, proxy string) adapters.Object {
	return adapters.Object{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": "kube-system"},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "c", "image": "x:1",
			"env": []any{
				map[string]any{"name": "HTTPS_PROXY", "value": proxy},
				map[string]any{"name": "NO_PROXY", "value": ".svc,.cluster.local"},
			},
		}}},
		"status": map[string]any{"phase": "Running"},
	}
}

func TestEgressProxyReportsOpenShiftClusterProxy(t *testing.T) {
	egressClearProxyEnv(t)
	f := egressOpenShiftCluster()
	f.platform.ClusterProxy = "http://proxy.corp.example.com:3128"
	f.with("proxies.config.openshift.io", "", adapters.Object{
		"apiVersion": "config.openshift.io/v1", "kind": "Proxy",
		"metadata": map[string]any{"name": "cluster"},
		"spec": map[string]any{
			"httpProxy":  "http://proxy.corp.example.com:3128",
			"httpsProxy": "http://proxy.corp.example.com:3128",
		},
		"status": map[string]any{"noProxy": ".cluster.local,.svc,10.0.0.0/8"},
	})

	r := run(t, f, "egress.proxy")

	assertStatus(t, r, "INFO")
	egressAssertContains(t, "summary", r.Summary, "http://proxy.corp.example.com:3128")
	egressAssertDetail(t, r, ".cluster.local,.svc,10.0.0.0/8")
	if len(r.Evidence) == 0 {
		t.Fatal("the cluster Proxy object is the basis of this report and belongs in the evidence")
	}
}

// On vanilla there is no Proxy object to read, and the check must say so
// plainly rather than implying the results were proxied.
func TestEgressProxyReportsAbsenceOnVanilla(t *testing.T) {
	egressClearProxyEnv(t)
	r := run(t, egressCluster(), "egress.proxy")

	assertStatus(t, r, "INFO")
	egressAssertContains(t, "summary", r.Summary, "no egress proxy detected")
	// The honest bound: a proxy configured only in the runtime's systemd
	// drop-in is invisible here, and a reader must not take this for proof.
	egressAssertDetail(t, r, "systemd drop-in")
}

// No Proxy object on vanilla does not mean no proxy. Workloads carrying
// HTTP_PROXY are the one hint the API offers, and reporting "no proxy" over the
// top of them would misexplain every egress failure in the group.
func TestEgressProxyReportsNodeEnvironmentHintsOnVanilla(t *testing.T) {
	egressClearProxyEnv(t)
	f := egressCluster().with("pods", "kube-system",
		egressTestProxyPod("kube-proxy-abcde", "http://proxy.corp.example.com:3128"))

	r := run(t, f, "egress.proxy")

	assertStatus(t, r, "INFO")
	egressAssertContains(t, "summary", r.Summary, "proxy environment variables found on kube-system workloads")
	egressAssertDetail(t, r, "pod/kube-proxy-abcde: HTTPS_PROXY=http://proxy.corp.example.com:3128")
}

// k3s's helm controller sets NO_PROXY on every helm-install pod, proxy or not.
// Reading that alone as a hint explained a direct-connection cluster's egress
// failures as a proxy's.
func TestEgressProxyIgnoresNoProxyWithoutAProxyBesideIt(t *testing.T) {
	egressClearProxyEnv(t)
	f := egressCluster().with("pods", "kube-system", adapters.Object{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "helm-install-traefik-tqqgj", "namespace": "kube-system"},
		"spec": map[string]any{"containers": []any{map[string]any{
			"name": "helm", "image": "rancher/klipper-helm:v0.13.3",
			"env": []any{map[string]any{"name": "NO_PROXY", "value": ".svc,.cluster.local,10.42.0.0/16,10.43.0.0/16"}},
		}}},
		"status": map[string]any{"phase": "Running"},
	})

	r := run(t, f, "egress.proxy")

	assertStatus(t, r, "INFO")
	egressAssertContains(t, "summary", r.Summary, "no egress proxy detected")
}

// §5.9's promise that "every egress result records it": with a cluster-wide
// proxy in play, a node firewall rule is the wrong remedy, and a failure that
// sent the operator to one would waste the outage.
func TestEgressInstallRemedyNamesTheClusterProxyWhenOneExists(t *testing.T) {
	f := egressOpenShiftCluster()
	f.platform.ClusterProxy = "http://proxy.corp.example.com:3128"
	v := egressTestVantage(t, egressVantageCluster, map[string]string{egressTestDockerHub: "000"})

	r := egressRun(t, f, "egress.install", egressSeedCluster(v))

	assertStatus(t, r, "BLOCK")
	egressAssertContains(t, "remedy", r.Remedy, "cluster-wide proxy http://proxy.corp.example.com:3128")
	egressAssertContains(t, "remedy", r.Remedy, "a node firewall rule will not help")
	egressAssertDetail(t, r, "read against the cluster-wide egress proxy")
}

// ---------------------------------------------------------------------------
// egress.clock-nodes
// ---------------------------------------------------------------------------

// egressTestClockVantage brackets one in-pod timestamp the way a real run does:
// the workstation observed the pod somewhere inside [now, now+window], and the
// pod's own clock read now+podOffset when it printed its CLOCK line. The line
// is written and parsed in the pod's own format, so a change to either end of
// that contract shows up here.
func egressTestClockVantage(podOffset, window, work time.Duration) *egressVantage {
	now := time.Now()
	podStart := now.Add(podOffset).Unix()
	raw := fmt.Sprintf("CLOCK|start|%d\n", podStart)
	if work > 0 {
		raw += fmt.Sprintf("CLOCK|end|%d\n", podStart+int64(work.Seconds()))
	}
	v := egressTestParsedVantage(egressVantageCluster, raw)
	v.WindowStart, v.WindowEnd = now, now.Add(window)
	return v
}

// Nothing in the Bud chart configures NTP, and beyond two minutes of drift
// Keycloak rejects freshly minted tokens, budevent's 300s HMAC window closes
// and S3 SigV4 refuses to sign. That is a blocker, not a warning.
func TestEgressClockBlocksWhenNodeIsFarBehind(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.clock-nodes",
		egressWithProbeRunner, egressSeedCluster(egressTestClockVantage(-300*time.Second, 2*time.Second, time.Second)))

	assertStatus(t, r, "BLOCK")
	egressAssertContains(t, "summary", r.Summary, "behind")
	egressAssertContains(t, "summary", r.Summary, "Keycloak rejects freshly minted tokens")
	egressAssertContains(t, "remedy", r.Remedy, "NTP")
}

// A node running ahead breaks the same three things, and the report has to name
// the direction correctly or the operator debugs the wrong end.
func TestEgressClockBlocksWhenNodeIsFarAhead(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.clock-nodes",
		egressWithProbeRunner, egressSeedCluster(egressTestClockVantage(300*time.Second, 2*time.Second, time.Second)))

	assertStatus(t, r, "BLOCK")
	egressAssertContains(t, "summary", r.Summary, "ahead of")
}

// Between the warn and fail thresholds the install still works; the tokens are
// merely close to the edge.
func TestEgressClockRisksAtModerateDrift(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.clock-nodes",
		egressWithProbeRunner, egressSeedCluster(egressTestClockVantage(-60*time.Second, 2*time.Second, time.Second)))

	assertStatus(t, r, "RISK")
}

// The pod's date ran at an unknown instant between creating the pod and seeing
// it finish. A timestamp inside that bracket proves nothing more than the
// bracket's width, which is what the PASS must claim — and no more.
func TestEgressClockPassesWhenSampleFallsInsideTheBracket(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.clock-nodes",
		egressWithProbeRunner, egressSeedCluster(egressTestClockVantage(0, 2*time.Second, time.Second)))

	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("one pod runs on one node; a PASS that does not say so would be read as a fleet-wide claim")
	}
}

// A cold node that spends four minutes pulling the probe image makes the
// bracket wider than the blocking threshold. Calling that a PASS would claim a
// measurement that was never made — so it reports INFO instead.
func TestEgressClockReportsInfoWhenTheSamplingWindowIsWiderThanTheThreshold(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.clock-nodes",
		egressWithProbeRunner, egressSeedCluster(egressTestClockVantage(100*time.Second, 200*time.Second, 0)))

	assertStatus(t, r, "INFO")
	egressAssertContains(t, "summary", r.Summary, "did not bound the skew")
	egressAssertNoVerdictEffect(t, r)
}

// A node's clock can only be read from a pod on that node, so --no-probe leaves
// this unanswered — and unanswered must not read as fine.
func TestEgressClockSkipsWithoutAProbeRunner(t *testing.T) {
	r := egressRun(t, egressCluster().withOpts(func(o *engine.Options) { o.NoProbe = true }), "egress.clock-nodes")

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "only be read from a pod")
}

// The pod ran and answered for the URLs, but its CLOCK line never arrived: the
// endpoints are reported and the clock is not.
func TestEgressClockSkipsWhenThePodPrintedNoClockLine(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.clock-nodes",
		egressWithProbeRunner, egressSeedCluster(egressTestVantage(t, egressVantageCluster, nil)))

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "node clock not sampled")
}

// Under --egress-from both, a Date header from a real server is the only
// independent opinion budctl gets about its own reference clock, and the report
// is worth much less without it.
func TestEgressClockCitesTheServerDateHeaderUnderBothVantages(t *testing.T) {
	f := egressCluster().withOpts(egressFrom("both"))
	ws := egressTestVantage(t, egressVantageWorkstation, nil)
	ws.ServerTime = time.Now().Add(-3 * time.Second)
	ws.ServerHost = "registry-1.docker.io"

	r := egressRun(t, f, "egress.clock-nodes", egressWithProbeRunner,
		egressSeedCluster(egressTestClockVantage(0, 2*time.Second, time.Second)),
		egressSeedWorkstation(ws))

	assertStatus(t, r, "PASS")
	egressAssertDetail(t, r, "Date header served by registry-1.docker.io")
}

// ---------------------------------------------------------------------------
// egress.hf-throughput
// ---------------------------------------------------------------------------

// egressTestRoundTripper replaces the HTTP transport so the Hugging Face sample
// is arithmetic instead of a measurement of whatever link the test machine has.
type egressTestRoundTripper struct {
	body []byte
	code int
	err  error
}

func (rt egressTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.err != nil {
		return nil, rt.err
	}
	return &http.Response{
		StatusCode:    rt.code,
		Status:        fmt.Sprintf("%d test", rt.code),
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(rt.body)),
		ContentLength: int64(len(rt.body)),
		Request:       req,
	}, nil
}

// egressHFSample fixes both halves of the rate: how many bytes came back, and
// how long the run's clock says it took.
func egressHFSample(rt egressTestRoundTripper, elapsed time.Duration) func(*engine.Ctx) {
	return func(c *engine.Ctx) {
		c.Net.Client.Transport = rt
		base := time.Now()
		calls := 0
		c.Clock = func() time.Time {
			calls++
			if calls == 1 {
				return base
			}
			return base.Add(elapsed)
		}
	}
}

// egressHFCluster is the fixture for the sampled path: --egress-from
// workstation, because that is the branch whose transport a unit test can own.
func egressHFCluster() *fakeCluster {
	return vanilla().withOpts(func(o *engine.Options) {
		o.EgressFrom = "workstation"
		o.HFThroughput = true
	})
}

// The opt-in gate. NG4: budctl never downloads a model, so without the flag the
// rate is simply not known — and a skip has to say which of the two facts about
// Hugging Face this run established.
func TestEgressHFThroughputSkipsWhenFlagIsAbsent(t *testing.T) {
	r := egressRun(t, egressCluster(), "egress.hf-throughput")

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "--hf-throughput was not given")
	egressAssertContains(t, "skip reason", r.Summary, "sustained download rate was not")
}

// A 70B pull at 150 KB/s is a failed deployment even though DNS resolves, which
// is the entire reason this check exists separately from egress.runtime.
func TestEgressHFThroughputRisksBelowTheFloor(t *testing.T) {
	r := egressRun(t, egressHFCluster(), "egress.hf-throughput",
		egressHFSample(egressTestRoundTripper{body: make([]byte, 1_500_000), code: 206}, 10*time.Second))

	assertStatus(t, r, "RISK")
	egressAssertContains(t, "summary", r.Summary, "0.15 MB/s")
	egressAssertContains(t, "summary", r.Summary, "below the 5.0 MB/s floor")
	// The arithmetic the operator actually needs: hours, for the storage they
	// stated at intake.
	egressAssertDetail(t, r, "takes")
}

func TestEgressHFThroughputPassesAboveTheFloor(t *testing.T) {
	r := egressRun(t, egressHFCluster(), "egress.hf-throughput",
		egressHFSample(egressTestRoundTripper{body: make([]byte, 8<<20), code: 206}, time.Second))

	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("one few-megabyte sample from one CDN edge is not sustained throughput, and the result must bound itself")
	}
}

// A transfer that produced no bytes measured no rate. Reporting the resulting
// 0.00 MB/s as a RISK would blame the link for what was really an unreachable
// host — egress.runtime already carries that finding.
func TestEgressHFThroughputSkipsWhenNoBytesCameBack(t *testing.T) {
	t.Run("connection failed", func(t *testing.T) {
		r := egressRun(t, egressHFCluster(), "egress.hf-throughput",
			egressHFSample(egressTestRoundTripper{err: errors.New("dial tcp: connection refused")}, time.Second))
		assertSkipHasReason(t, r)
		egressAssertContains(t, "skip reason", r.Summary, "egress.runtime carries the reachability finding")
	})
	t.Run("empty body", func(t *testing.T) {
		r := egressRun(t, egressHFCluster(), "egress.hf-throughput",
			egressHFSample(egressTestRoundTripper{body: nil, code: 200}, time.Second))
		assertSkipHasReason(t, r)
		egressAssertContains(t, "skip reason", r.Summary, "returned no bytes")
	})
}

// With no probe runner and no network adapter there is nowhere to sample from,
// and the check must say that rather than reporting a floor failure.
func TestEgressHFThroughputSkipsWithNoVantagePoint(t *testing.T) {
	f := egressCluster().withOpts(func(o *engine.Options) { o.HFThroughput = true })
	r := egressRun(t, f, "egress.hf-throughput", func(c *engine.Ctx) { c.Net = nil })

	assertSkipHasReason(t, r)
	egressAssertContains(t, "skip reason", r.Summary, "no vantage point available")
}
