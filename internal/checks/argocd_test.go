package checks

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/probes"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// The argocd group is the one group whose ABSENCE must not be a failure: ArgoCD
// is itself an element of the cluster-addons ApplicationSet, so requiring it
// here would require that the installer had already run (FRD-020 §5.3). These
// tests exist mostly to prove the two halves of that: that argocd.installed
// can never turn into a blocker, and that the inputs ArgoCD will need — the
// chart repo and the config repo — still block when they are broken.

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// argocdTestCluster is a vanilla cluster with the group switched ON. The
// harness default leaves Options.ArgoCDEnabled false, which every check in this
// group reads as --no-argocd, so a test that forgets this asserts nothing.
func argocdTestCluster() *fakeCluster {
	return vanilla().withOpts(func(o *engine.Options) { o.ArgoCDEnabled = true })
}

// argocdTestDeploy builds an ArgoCD Deployment. availableReplicas is the field
// argocd.healthy reads for a Deployment; a StatefulSet uses a different one,
// which argocdTestStatefulSet exists to cover.
func argocdTestDeploy(ns, name string, available, desired int, opts ...func(adapters.Object)) adapters.Object {
	o := adapters.Object{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{
			"name": name, "namespace": ns,
			"labels": map[string]any{"app.kubernetes.io/part-of": "argocd"},
		},
		"spec": map[string]any{
			"replicas": int64(desired),
			"template": map[string]any{"spec": map[string]any{
				"containers": []any{map[string]any{
					"name": "c", "image": "quay.io/argoproj/argocd:v2.11.3",
				}},
			}},
		},
		"status": map[string]any{"availableReplicas": int64(available)},
	}
	for _, fn := range opts {
		fn(o)
	}
	return o
}

func argocdTestStatefulSet(ns, name string, ready, desired int, opts ...func(adapters.Object)) adapters.Object {
	o := argocdTestDeploy(ns, name, 0, desired, opts...)
	o["kind"] = "StatefulSet"
	o["status"] = map[string]any{"readyReplicas": int64(ready)}
	return o
}

func argocdTestVersionLabel(v string) func(adapters.Object) {
	return func(o adapters.Object) {
		o["metadata"].(map[string]any)["labels"].(map[string]any)["app.kubernetes.io/version"] = v
	}
}

func argocdTestImage(image string) func(adapters.Object) {
	return func(o adapters.Object) {
		ps := o.PodSpec()
		ps["containers"] = []any{map[string]any{"name": "c", "image": image}}
	}
}

func argocdTestServiceAccount(sa string) func(adapters.Object) {
	return func(o adapters.Object) { o.PodSpec()["serviceAccountName"] = sa }
}

func argocdTestInitContainer(name string) func(adapters.Object) {
	return func(o adapters.Object) {
		ps := o.PodSpec()
		ps["initContainers"] = []any{map[string]any{"name": name, "image": "alpine:3.20"}}
	}
}

// argocdTestInstall seeds a healthy three-workload ArgoCD in namespace argocd,
// the shape every "present" check branches on.
func argocdTestInstall(f *fakeCluster, opts ...func(adapters.Object)) *fakeCluster {
	return f.with("statefulsets.apps", "argocd",
		argocdTestStatefulSet("argocd", "argocd-application-controller", 1, 1,
			argocdTestServiceAccount("argocd-application-controller")),
	).with("deployments.apps", "argocd",
		argocdTestDeploy("argocd", "argocd-repo-server", 1, 1, opts...),
		argocdTestDeploy("argocd", "argocd-applicationset-controller", 1, 1),
	)
}

// argocdTestSecret carries its fields in stringData, the plaintext form; the
// data/base64 form is exercised separately because a Secret read back from the
// API only ever has the encoded one.
func argocdTestSecret(ns, name, secretType string, fields map[string]string) adapters.Object {
	sd := map[string]any{}
	for k, v := range fields {
		sd[k] = v
	}
	labels := map[string]any{}
	if secretType != "" {
		labels["argocd.argoproj.io/secret-type"] = secretType
	}
	return adapters.Object{
		"apiVersion": "v1", "kind": "Secret",
		"metadata":   map[string]any{"name": name, "namespace": ns, "labels": labels},
		"stringData": sd,
	}
}

func argocdTestSecretB64(ns, name, secretType string, fields map[string]string) adapters.Object {
	o := argocdTestSecret(ns, name, secretType, nil)
	data := map[string]any{}
	for k, v := range fields {
		data[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	delete(o, "stringData")
	o["data"] = data
	return o
}

// argocdTestChartDir writes the chart budctl was pointed at. chart-repo-reachable
// resolves the manifest only when --chart-dir supplies a version to resolve.
func argocdTestChartDir(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	body := "apiVersion: v2\nname: bud\nversion: " + version + "\n"
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write Chart.yaml: %v", err)
	}
	return dir
}

// ---------------------------------------------------------------------------
// drivers: HTTP and probe pods, without a network or a cluster
// ---------------------------------------------------------------------------

type argocdStubTransport struct {
	fn func(*http.Request) (*http.Response, error)
}

func (s argocdStubTransport) RoundTrip(r *http.Request) (*http.Response, error) { return s.fn(r) }

func argocdReply(code int) *http.Response {
	return &http.Response{
		StatusCode: code, Status: http.StatusText(code),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")),
	}
}

// argocdRunHTTP runs one check with every HTTP call answered by fn. The chart
// registry host is a compile-time constant, so this is the only way to drive
// the registry branches at all — and driving them off a live registry would
// make the result depend on the network the suite happens to run on.
func argocdRunHTTP(t *testing.T, f *fakeCluster, id string, fn func(*http.Request) (*http.Response, error)) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	c.Net.Client.Transport = argocdStubTransport{fn: fn}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

// argocdRunProbe runs a [probe] check against a fake cluster whose probe pod
// reports the given status, so the pod-outcome branches are reachable without a
// real cluster. Without this, every probe branch is asserted by hope.
func argocdRunProbe(t *testing.T, f *fakeCluster, id string, status corev1.PodStatus) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	cs, ok := c.Kube.Clientset.(*k8sfake.Clientset)
	if !ok {
		t.Fatalf("harness clientset is %T, not a fake", c.Kube.Clientset)
	}
	cs.PrependReactor("get", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		name := ""
		if ga, ok := a.(k8stesting.GetAction); ok {
			name = ga.GetName()
		}
		return true, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: a.GetNamespace()},
			// A pod with a node assigned is a SCHEDULED pod: the runner reads
			// spec.nodeName, and without it every outcome reads as "never
			// scheduled" regardless of what the container did.
			Spec:   corev1.PodSpec{NodeName: "probe-node"},
			Status: status,
		}, nil
	})
	c.Probes = probes.NewRunner(c.Kube, "budctl-readiness-test", "test", false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

// argocdRunSAR runs a check with ArgoCD's SubjectAccessReviews answered by
// allow. The fake clientset cannot do this on its own: it persists each review
// under its (empty) name, so the SECOND CanServiceAccount call comes back
// "already exists" and the check skips on an error no real cluster produces.
func argocdRunSAR(t *testing.T, f *fakeCluster, id string, allow func(group, resource string) bool) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	cs, ok := c.Kube.Clientset.(*k8sfake.Clientset)
	if !ok {
		t.Fatalf("harness clientset is %T, not a fake", c.Kube.Clientset)
	}
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		rev, ok := a.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		if !ok {
			return true, nil, nil
		}
		out := rev.DeepCopy()
		if ra := out.Spec.ResourceAttributes; ra != nil {
			out.Status.Allowed = allow(ra.Group, ra.Resource)
		}
		return true, out, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

// argocdAssertMentions keeps the claim, not just the status, under test: a
// remedy that does not name port 22 is the failure this group exists to catch.
func argocdAssertMentions(t *testing.T, r engine.Result, want ...string) {
	t.Helper()
	parts := append([]string{r.Summary, r.Remedy, r.DoesNotProve}, r.Detail...)
	for _, ev := range r.Evidence {
		parts = append(parts, ev.What, ev.Output)
	}
	hay := strings.Join(parts, "\n")
	for _, w := range want {
		if !strings.Contains(hay, w) {
			t.Fatalf("%s: result never mentions %q\n  summary: %s\n  remedy: %s\n  detail: %v",
				r.ID, w, r.Summary, r.Remedy, r.Detail)
		}
	}
}

var argocdAllChecks = []string{
	"argocd.installed", "argocd.chart-repo-reachable", "argocd.config-repo-reachable",
	"argocd.healthy", "argocd.version", "argocd.chart-repo-credential",
	"argocd.rbac", "argocd.repo-server-egress",
}

// ---------------------------------------------------------------------------
// argocd.installed — the property the whole group is built around
// ---------------------------------------------------------------------------

// THE point of FRD-020 §5.3: ArgoCD is installed AFTER readiness passes, so a
// cluster without it is not unready. If this ever becomes a blocker, every
// genuine first run reports NOT READY for the expected state of the world.
func TestArgoCDInstalledIsInfoAndNeverBlocksWhenAbsent(t *testing.T) {
	r := run(t, argocdTestCluster(), "argocd.installed")
	assertStatus(t, r, "INFO")
	if r.IsBlocker() || r.IsRisk() {
		t.Fatalf("argocd.installed counted against the verdict: severity=%s state=%s", r.Severity, r.State)
	}
	if v := engine.Summarize([]engine.Result{r}).Verdict; v != engine.Ready {
		t.Fatalf("an absent ArgoCD moved the verdict to %s", v)
	}
	// The operator must be told what still ran, or "not installed" reads as
	// "nothing about ArgoCD was checked".
	argocdAssertMentions(t, r, "argocd.chart-repo-reachable", "argocd.config-repo-reachable")
}

func TestArgoCDInstalledReportsAnExistingInstall(t *testing.T) {
	r := run(t, argocdTestInstall(argocdTestCluster()), "argocd.installed")
	assertStatus(t, r, "INFO")
	argocdAssertMentions(t, r, "namespace argocd", "2.11.3")
}

// ArgoCD is very often in "gitops" or "openshift-gitops". Reporting that as
// "not installed" would silently skip healthy/version/rbac/credential — five
// checks that all read as a clean run when they skip.
func TestArgoCDInstalledFindsANonDefaultNamespace(t *testing.T) {
	f := argocdTestCluster().with("deployments.apps", "",
		argocdTestDeploy("gitops", "argocd-repo-server", 1, 1),
		argocdTestDeploy("gitops", "argocd-applicationset-controller", 1, 1))
	r := run(t, f, "argocd.installed")
	assertStatus(t, r, "INFO")
	argocdAssertMentions(t, r, "namespace gitops")
}

// --no-argocd is a direct-Helm install: the question does not apply rather than
// having a good answer, and every check must say so out loud.
func TestArgoCDWholeGroupSkipsWithAReasonWhenDisabled(t *testing.T) {
	for _, id := range argocdAllChecks {
		t.Run(id, func(t *testing.T) {
			f := argocdTestInstall(vanilla()).
				withOpts(func(o *engine.Options) { o.ArgoCDEnabled = false }).
				withAnswers(func(a *intake.Answers) { a.ConfigRepo = "https://git.example.com/org/repo.git" })
			r := run(t, f, id)
			assertSkipHasReason(t, r)
			argocdAssertMentions(t, r, "--no-argocd")
		})
	}
}

// Documents a real asymmetry rather than endorsing it: --no-argocd is the ONLY
// off switch. An operator who answered "no ArgoCD" in the intake (or re-ran
// from a saved answers file) still gets the group, and its two BLOCK-level
// input checks, because Options.ArgoCDEnabled is never derived from the answer
// — while egress.go and charts.go do read Answers.UseArgoCD. If this test ever
// fails with a SKIP, the asymmetry was fixed and the test should go.
func TestArgoCDAnswersUseArgoCDFalseDoesNotDisableTheGroup(t *testing.T) {
	f := argocdTestCluster().withAnswers(func(a *intake.Answers) { a.UseArgoCD = false })
	r := run(t, f, "argocd.installed")
	if r.Status() == "SKIP" {
		t.Fatalf("answers.useArgoCd now disables the group; delete this test and the note above it")
	}
	assertStatus(t, r, "INFO")
}

// ---------------------------------------------------------------------------
// argocd.chart-repo-reachable — required input, BLOCK even with ArgoCD absent
// ---------------------------------------------------------------------------

func TestArgoCDChartRepoBlocksWhenRegistryDoesNotAnswer(t *testing.T) {
	r := argocdRunHTTP(t, argocdTestCluster(), "argocd.chart-repo-reachable",
		func(*http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "no such host", Name: argocdChartRegistry, IsNotFound: true}
		})
	assertStatus(t, r, "BLOCK")
	argocdAssertMentions(t, r, argocdChartRegistry, "allowlist")
}

// A captive portal or an intercepting proxy answers 200/403 on every path. The
// registry API must answer /v2/ with 200 or 401; anything else is not a registry.
func TestArgoCDChartRepoBlocksWhenSomethingElseAnswers(t *testing.T) {
	r := argocdRunHTTP(t, argocdTestCluster(), "argocd.chart-repo-reachable",
		func(*http.Request) (*http.Response, error) { return argocdReply(503), nil })
	assertStatus(t, r, "BLOCK")
	argocdAssertMentions(t, r, "503")
}

func TestArgoCDChartRepoBlocksWhenTheChartVersionIsNotPublished(t *testing.T) {
	f := argocdTestCluster().withOpts(func(o *engine.Options) {
		o.ChartDir = argocdTestChartDir(t, "1.2.3")
	})
	r := argocdRunHTTP(t, f, "argocd.chart-repo-reachable", func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v2/" {
			return argocdReply(401), nil
		}
		return argocdReply(404), nil // the tag the ApplicationSet pins does not exist
	})
	assertStatus(t, r, "BLOCK")
	argocdAssertMentions(t, r, "1.2.3", "targetRevision")
}

// A credential that is supplied and rejected is a blocker: ArgoCD's repository
// Secret will be rejected the same way. Without credentials the same 401 is a
// PASS (the test below) — the two must not be conflated.
func TestArgoCDChartRepoBlocksWhenSuppliedCredentialsAreRejected(t *testing.T) {
	f := argocdTestCluster().
		withOpts(func(o *engine.Options) { o.ChartDir = argocdTestChartDir(t, "1.2.3") }).
		withAnswers(func(a *intake.Answers) { a.RegistryUser = "robot$bud"; a.RegistryPass = "wrong" })
	r := argocdRunHTTP(t, f, "argocd.chart-repo-reachable", func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v2/" {
			return argocdReply(200), nil
		}
		return argocdReply(401), nil
	})
	assertStatus(t, r, "BLOCK")
	argocdAssertMentions(t, r, "credentials are rejected")
}

// FRD-020 D7: before the robot account is issued, a 401 is the EXPECTED answer
// and proves DNS, routing, TLS and a live registry. Failing here would fail
// every genuine first run.
func TestArgoCDChartRepoPassesOnAnonymous401(t *testing.T) {
	f := argocdTestCluster().withOpts(func(o *engine.Options) {
		o.ChartDir = argocdTestChartDir(t, "1.2.3")
	})
	r := argocdRunHTTP(t, f, "argocd.chart-repo-reachable", func(*http.Request) (*http.Response, error) {
		return argocdReply(401), nil
	})
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("a 401 pass must be bounded: it did not verify the chart exists")
	}
}

func TestArgoCDChartRepoPassesWhenTheManifestResolves(t *testing.T) {
	f := argocdTestCluster().withOpts(func(o *engine.Options) {
		o.ChartDir = argocdTestChartDir(t, "1.2.3")
	})
	r := argocdRunHTTP(t, f, "argocd.chart-repo-reachable", func(*http.Request) (*http.Response, error) {
		return argocdReply(200), nil
	})
	assertStatus(t, r, "PASS")
	argocdAssertMentions(t, r, "1.2.3")
}

// No --chart-dir means no version to resolve against. Inventing one would
// manufacture a false BLOCK, so the pass has to state what it did not check.
func TestArgoCDChartRepoPassesReachabilityWithoutAChartDir(t *testing.T) {
	r := argocdRunHTTP(t, argocdTestCluster(), "argocd.chart-repo-reachable",
		func(*http.Request) (*http.Response, error) { return argocdReply(401), nil })
	assertStatus(t, r, "PASS")
	argocdAssertMentions(t, r, "no --chart-dir")
	if r.DoesNotProve == "" {
		t.Fatal("reachability without a resolved chart version must be bounded")
	}
}

// The input is required whether or not ArgoCD exists, so with the group on this
// check must always produce an answer — never a quiet SKIP.
func TestArgoCDChartRepoNeverSkipsWhileTheGroupIsOn(t *testing.T) {
	for name, code := range map[string]int{"401": 401, "200": 200, "404": 404, "500": 500} {
		t.Run(name, func(t *testing.T) {
			r := argocdRunHTTP(t, argocdTestCluster(), "argocd.chart-repo-reachable",
				func(*http.Request) (*http.Response, error) { return argocdReply(code), nil })
			if r.Status() == "SKIP" || r.Status() == "INFO" {
				t.Fatalf("a BLOCK-level input check went quiet: %s — %s", r.Status(), r.Summary)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// argocd.config-repo-reachable
// ---------------------------------------------------------------------------

// An unstated config repo is a MISSING PREREQUISITE, not a question budctl
// declined to ask: the ApplicationSets read their values and secrets from it, so
// without one ArgoCD would sync an empty configuration. Skipping here would let
// a cluster pass readiness and then fail the moment it is installed.
func TestArgoCDConfigRepoBlocksWhenUnset(t *testing.T) {
	r := run(t, argocdTestCluster(), "argocd.config-repo-reachable")
	assertStatus(t, r, "BLOCK")
	if r.Remedy == "" {
		t.Fatal("no remedy: the operator is told what is wrong but not what to supply")
	}
	// The remedy has to name both auth shapes, because which one they need
	// decides whether they open 443 or 22.
	for _, want := range []string{"https://", "ssh://"} {
		if !strings.Contains(r.Remedy, want) {
			t.Errorf("remedy does not mention %q: %q", want, r.Remedy)
		}
	}
}

// The headline SSH case: git over SSH is port 22, and a 443-only egress policy
// blocks it silently. A remedy that does not say so sends the operator hunting
// through DNS instead of through the firewall rules.
func TestArgoCDConfigRepoBlocksWhenSSHPort22Refused(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: guaranteed unroutable, so this is a refusal
	// or a timeout on every machine rather than a live host somewhere.
	f := argocdTestCluster().withAnswers(func(a *intake.Answers) {
		a.ConfigRepo = "ssh://git@192.0.2.1/bud/config.git"
	})
	r := run(t, f, "argocd.config-repo-reachable")
	assertStatus(t, r, "BLOCK")
	argocdAssertMentions(t, r, "192.0.2.1:22", "NOT 443")
}

func TestArgoCDConfigRepoPassesWhenTheSSHPortAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	f := argocdTestCluster().withAnswers(func(a *intake.Answers) {
		a.ConfigRepo = "ssh://git@127.0.0.1:" + itoaTest(addr.Port) + "/bud/config.git"
	})
	r := run(t, f, "argocd.config-repo-reachable")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("an open port is not an authorised deploy key; the pass must be bounded")
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	out := []byte{}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

func TestArgoCDConfigRepoHTTPOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		err    bool
		want   string
		claims []string
	}{
		// A repo that serves git-upload-pack is the whole question.
		{name: "200 serves git-upload-pack", code: 200, want: "PASS"},
		// 401/403 hide a private repo behind the same answer as a missing one:
		// a pass, but a bounded one.
		{name: "401 demands credentials", code: 401, want: "PASS"},
		{name: "403 demands credentials", code: 403, want: "PASS"},
		// 404 is the typo'd repoURL — every $values source then resolves to
		// nothing and the Applications render empty.
		{name: "404 no repository there", code: 404, want: "BLOCK", claims: []string{"404", "configRepo"}},
		{name: "500 gateway in the way", code: 500, want: "BLOCK", claims: []string{"500"}},
		{name: "no answer at all", err: true, want: "BLOCK", claims: []string{"DNS"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := argocdTestCluster().withAnswers(func(a *intake.Answers) {
				a.ConfigRepo = "https://git.example.com/bud/config.git"
			})
			r := argocdRunHTTP(t, f, "argocd.config-repo-reachable", func(req *http.Request) (*http.Response, error) {
				if !strings.Contains(req.URL.RequestURI(), "/info/refs?service=git-upload-pack") {
					t.Errorf("probed %s, not the git discovery endpoint the repo-server asks for", req.URL)
				}
				if tc.err {
					return nil, &net.DNSError{Err: "no such host", Name: "git.example.com", IsNotFound: true}
				}
				return argocdReply(tc.code), nil
			})
			assertStatus(t, r, tc.want)
			argocdAssertMentions(t, r, tc.claims...)
			if tc.want == "PASS" && r.DoesNotProve == "" {
				t.Fatal("the endpoint answering is not the branch, the path or the credential")
			}
		})
	}
}

// A repoURL ArgoCD cannot parse generates no Applications at all, which looks
// like the installer doing nothing rather than like an error.
func TestArgoCDConfigRepoBlocksOnAnUnusableRepoURL(t *testing.T) {
	for _, repo := range []string{"github.com/bud/config", "/srv/git/config.git", "bud-config"} {
		t.Run(repo, func(t *testing.T) {
			f := argocdTestCluster().withAnswers(func(a *intake.Answers) { a.ConfigRepo = repo })
			r := run(t, f, "argocd.config-repo-reachable")
			assertStatus(t, r, "BLOCK")
			argocdAssertMentions(t, r, "transport")
		})
	}
}

// The scp-like form is the one most likely to be typed by hand, and it is SSH
// on port 22 even though it carries no scheme — classifying it as "unknown"
// would skip the port-22 question entirely.
func TestArgoCDRepoTransportClassification(t *testing.T) {
	cases := []struct {
		repo      string
		host      string
		port      int
		transport string
	}{
		{"ssh://git@github.com/bud/config.git", "github.com", 22, "ssh"},
		{"ssh://git@ssh.github.com:443/bud/config.git", "ssh.github.com", 443, "ssh"},
		{"git@github.com:bud/config.git", "github.com", 22, "ssh"},
		{"https://github.com/bud/config.git", "github.com", 0, "http"},
		{"http://git.internal/bud/config", "git.internal", 0, "http"},
		{"github.com/bud/config", "", 0, ""},
		{"", "", 0, ""},
	}
	for _, tc := range cases {
		host, port, transport := argocdRepoTransport(tc.repo)
		if host != tc.host || port != tc.port || transport != tc.transport {
			t.Errorf("%q -> (%q,%d,%q), want (%q,%d,%q)", tc.repo, host, port, transport, tc.host, tc.port, tc.transport)
		}
	}
}

// ---------------------------------------------------------------------------
// argocd.healthy
// ---------------------------------------------------------------------------

// RISK, never BLOCK: a broken existing ArgoCD is something the operator repairs
// during the install. Calling the cluster unfit for it would be wrong.
func TestArgoCDHealthyIsRiskNotBlock(t *testing.T) {
	cases := []struct {
		name   string
		build  func() *fakeCluster
		claims []string
	}{
		{
			// The FRD case: a repo-server with no available replica renders no
			// manifests, so every sync fails at "failed to generate manifests".
			name: "repo-server has 0 available replicas",
			build: func() *fakeCluster {
				return argocdTestCluster().
					with("statefulsets.apps", "argocd", argocdTestStatefulSet("argocd", "argocd-application-controller", 1, 1)).
					with("deployments.apps", "argocd",
						argocdTestDeploy("argocd", "argocd-repo-server", 0, 2),
						argocdTestDeploy("argocd", "argocd-applicationset-controller", 1, 1))
			},
			claims: []string{"argocd-repo-server has 0/2 available", "generate manifests"},
		},
		{
			// A whole missing component is the quietest failure of the three:
			// without the applicationset-controller the install appears to do
			// nothing at all.
			name: "applicationset-controller missing entirely",
			build: func() *fakeCluster {
				return argocdTestCluster().
					with("statefulsets.apps", "argocd", argocdTestStatefulSet("argocd", "argocd-application-controller", 1, 1)).
					with("deployments.apps", "argocd", argocdTestDeploy("argocd", "argocd-repo-server", 1, 1))
			},
			claims: []string{"no applicationset-controller workload exists"},
		},
		{
			// The application-controller is a StatefulSet: read
			// availableReplicas here and a dead controller reports healthy.
			name: "application-controller StatefulSet has 0 ready",
			build: func() *fakeCluster {
				return argocdTestCluster().
					with("statefulsets.apps", "argocd", argocdTestStatefulSet("argocd", "argocd-application-controller", 0, 1)).
					with("deployments.apps", "argocd",
						argocdTestDeploy("argocd", "argocd-repo-server", 1, 1),
						argocdTestDeploy("argocd", "argocd-applicationset-controller", 1, 1))
			},
			claims: []string{"argocd-application-controller has 0/1 available", "nothing reconciles"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, tc.build(), "argocd.healthy")
			assertStatus(t, r, "RISK")
			if r.IsBlocker() {
				t.Fatal("a broken existing ArgoCD must not make the cluster NOT READY")
			}
			argocdAssertMentions(t, r, tc.claims...)
		})
	}
}

func TestArgoCDHealthyPassesWhenAllThreeAreAvailable(t *testing.T) {
	r := run(t, argocdTestInstall(argocdTestCluster()), "argocd.healthy")
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("available replicas are not a working sync; the pass must be bounded")
	}
}

func TestArgoCDHealthySkipsWhenNotInstalled(t *testing.T) {
	r := run(t, argocdTestCluster(), "argocd.healthy")
	assertSkipHasReason(t, r)
	argocdAssertMentions(t, r, "not installed")
}

// ---------------------------------------------------------------------------
// argocd.version
// ---------------------------------------------------------------------------

func TestArgoCDVersionRiskBelowTheMultiSourceFloor(t *testing.T) {
	f := argocdTestCluster().with("statefulsets.apps", "argocd",
		argocdTestStatefulSet("argocd", "argocd-application-controller", 1, 1,
			argocdTestVersionLabel("v2.5.3")))
	r := run(t, f, "argocd.version")
	assertStatus(t, r, "RISK")
	argocdAssertMentions(t, r, "2.5.3", "$values")
}

// A hand-applied install.yaml often sets no version label at all, and the image
// tag is then the only evidence. Skipping there would hide an ancient ArgoCD.
func TestArgoCDVersionRiskFromTheImageTagFallback(t *testing.T) {
	f := argocdTestCluster().with("deployments.apps", "argocd",
		argocdTestDeploy("argocd", "argocd-repo-server", 1, 1,
			argocdTestImage("quay.io/argoproj/argocd:v2.4.8")))
	r := run(t, f, "argocd.version")
	assertStatus(t, r, "RISK")
	argocdAssertMentions(t, r, "2.4.8", "image quay.io/argoproj/argocd:v2.4.8")
}

func TestArgoCDVersionPassesAtAndAboveTheFloor(t *testing.T) {
	for _, v := range []string{"2.6.0", "2.11.3", "3.0.1"} {
		t.Run(v, func(t *testing.T) {
			f := argocdTestCluster().with("deployments.apps", "argocd",
				argocdTestDeploy("argocd", "argocd-repo-server", 1, 1, argocdTestVersionLabel(v)))
			assertStatus(t, run(t, f, "argocd.version"), "PASS")
		})
	}
}

// An unread version is not a supported version. This must never pass, or a
// digest-pinned install reads as verified.
func TestArgoCDVersionSkipsWhenUndetectable(t *testing.T) {
	f := argocdTestCluster().with("deployments.apps", "argocd",
		argocdTestDeploy("argocd", "argocd-repo-server", 1, 1,
			argocdTestImage("quay.io/argoproj/argocd@sha256:"+strings.Repeat("a", 64))))
	r := run(t, f, "argocd.version")
	assertSkipHasReason(t, r)
	argocdAssertMentions(t, r, "could not be read")
}

func TestArgoCDVersionSkipsWhenNotInstalled(t *testing.T) {
	assertSkipHasReason(t, run(t, argocdTestCluster(), "argocd.version"))
}

// ---------------------------------------------------------------------------
// argocd.chart-repo-credential
// ---------------------------------------------------------------------------

func TestArgoCDChartRepoCredentialRiskWhenNoSecretCoversTheRegistry(t *testing.T) {
	cases := []struct {
		name    string
		secrets []adapters.Object
		claims  []string
	}{
		{
			// Secrets exist, none of them a repository Secret: the first pull
			// fails 401 and every Application stalls on its first sync.
			name: "only unrelated secrets",
			secrets: []adapters.Object{
				argocdTestSecret("argocd", "argocd-initial-admin-secret", "", map[string]string{"password": "x"}),
				argocdTestSecret("argocd", "argocd-secret", "", nil),
			},
			claims: []string{argocdChartRegistry, "401"},
		},
		{
			// A repository Secret for the git repo is not a credential for the
			// chart registry — a very easy thing to mistake for coverage.
			name: "repository secret for a different host",
			secrets: []adapters.Object{
				argocdTestSecret("argocd", "bud-config-repo", "repository", map[string]string{
					"type": "git", "url": "https://github.com/bud/config.git",
				}),
			},
			claims: []string{argocdChartRegistry},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := argocdTestInstall(argocdTestCluster()).with("secrets", "argocd", tc.secrets...)
			r := run(t, f, "argocd.chart-repo-credential")
			assertStatus(t, r, "RISK")
			argocdAssertMentions(t, r, tc.claims...)
		})
	}
}

// enableOCI is the single field that decides whether ArgoCD speaks the OCI API
// or asks a registry for index.yaml — and asking yields a confusing 404, not an
// error naming the setting.
func TestArgoCDChartRepoCredentialRiskOnMisshapedSecret(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]string
		claim  string
	}{
		{"enableOCI absent", map[string]string{"type": "helm", "url": argocdChartRegistry + "/charts"}, "enableOCI"},
		{"enableOCI false", map[string]string{"type": "helm", "enableOCI": "false", "url": argocdChartRegistry + "/charts"}, "index.yaml"},
		{"type git not helm", map[string]string{"type": "git", "enableOCI": "true", "url": argocdChartRegistry + "/charts"}, "clone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := argocdTestInstall(argocdTestCluster()).with("secrets", "argocd",
				argocdTestSecret("argocd", "bud-charts-repo", "repository", tc.fields))
			r := run(t, f, "argocd.chart-repo-credential")
			assertStatus(t, r, "RISK")
			argocdAssertMentions(t, r, tc.claim)
		})
	}
}

func TestArgoCDChartRepoCredentialPassesForAnOCIHelmSecret(t *testing.T) {
	f := argocdTestInstall(argocdTestCluster()).with("secrets", "argocd",
		argocdTestSecret("argocd", "bud-charts-repo", "repository", map[string]string{
			"type": "helm", "enableOCI": "true", "url": argocdChartRegistry + "/charts",
			"username": "robot$bud", "password": "hunter2",
		}))
	r := run(t, f, "argocd.chart-repo-credential")
	assertStatus(t, r, "PASS")
	if strings.Contains(strings.Join(append(r.Detail, r.Summary), " "), "hunter2") {
		t.Fatal("the check leaked the repository password into its output")
	}
}

// A Secret read back from the API carries base64 in data, never stringData.
// Reading only stringData would report every real cluster as misconfigured.
func TestArgoCDChartRepoCredentialReadsBase64SecretData(t *testing.T) {
	f := argocdTestInstall(argocdTestCluster()).with("secrets", "argocd",
		argocdTestSecretB64("argocd", "bud-charts-repo", "repo-creds", map[string]string{
			"type": "helm", "enableOCI": "true", "url": "oci://" + argocdChartRegistry + "/charts",
		}))
	assertStatus(t, run(t, f, "argocd.chart-repo-credential"), "PASS")
}

// A denied LIST comes back as an empty slice, which would otherwise read as
// "no repository Secret exists" — a RISK invented out of missing permission.
func TestArgoCDChartRepoCredentialSkipsWhenSecretsAreUnreadable(t *testing.T) {
	r := run(t, argocdTestInstall(argocdTestCluster()), "argocd.chart-repo-credential")
	assertSkipHasReason(t, r)
	argocdAssertMentions(t, r, "may not list Secrets")
}

func TestArgoCDChartRepoCredentialSkipsWhenNotInstalled(t *testing.T) {
	assertSkipHasReason(t, run(t, argocdTestCluster(), "argocd.chart-repo-credential"))
}

// ---------------------------------------------------------------------------
// argocd.rbac
// ---------------------------------------------------------------------------

// The identity the sync actually runs as. A denial here stops cluster-addons
// half-applied, but it is still RISK: the operator can bind the role during the
// install (TEST_CASES: "ArgoCD present, its SA cannot create CRDs" -> RISK).
func TestArgoCDRBACIsRiskWhenTheControllerCannotCreateClusterObjects(t *testing.T) {
	deny := func(string, string) bool { return false }
	r := argocdRunSAR(t, argocdTestInstall(argocdTestCluster()), "argocd.rbac", deny)
	assertStatus(t, r, "RISK")
	if r.IsBlocker() {
		t.Fatal("ArgoCD's own RBAC must not make the cluster NOT READY")
	}
	argocdAssertMentions(t, r,
		"argocd-application-controller",
		"namespaces", "customresourcedefinitions", "clusterroles", "clusterrolebindings")
}

// The realistic denial is partial — a namespaced Role that covers everything
// except cluster-scoped kinds. The sync then fails at the first CRD, half
// applied, which is why one denial is enough to report.
func TestArgoCDRBACIsRiskOnASinglePartialDenial(t *testing.T) {
	f := argocdTestInstall(argocdTestCluster())
	r := argocdRunSAR(t, f, "argocd.rbac", func(group, resource string) bool {
		return resource != "customresourcedefinitions"
	})
	assertStatus(t, r, "RISK")
	argocdAssertMentions(t, r, "customresourcedefinitions", "Dapr, CloudNativePG, Strimzi")
}

func TestArgoCDRBACPassesWhenEveryClusterScopedCreateIsAllowed(t *testing.T) {
	allow := func(string, string) bool { return true }
	r := argocdRunSAR(t, argocdTestInstall(argocdTestCluster()), "argocd.rbac", allow)
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("an SAR answer for this cluster does not cover a remote destination cluster")
	}
}

// A SubjectAccessReview for a guessed identity answers a different question, so
// an unresolvable ServiceAccount must SKIP rather than test "default".
func TestArgoCDRBACSkipsWhenTheServiceAccountIsUnresolvable(t *testing.T) {
	cases := map[string]func(adapters.Object){
		"no serviceAccountName in the pod template": func(adapters.Object) {},
		"the default ServiceAccount":                argocdTestServiceAccount("default"),
	}
	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			f := argocdTestCluster().with("statefulsets.apps", "argocd",
				argocdTestStatefulSet("argocd", "argocd-application-controller", 1, 1, opt))
			r := run(t, f, "argocd.rbac")
			assertSkipHasReason(t, r)
			argocdAssertMentions(t, r, "ServiceAccount")
		})
	}
}

// ArgoCD present but with no application-controller at all: argocd.healthy
// reports that, and rbac must not silently test some other workload's identity.
func TestArgoCDRBACSkipsWhenTheControllerWorkloadIsMissing(t *testing.T) {
	f := argocdTestCluster().with("deployments.apps", "argocd",
		argocdTestDeploy("argocd", "argocd-repo-server", 1, 1))
	assertSkipHasReason(t, run(t, f, "argocd.rbac"))
}

func TestArgoCDRBACSkipsWhenNotInstalled(t *testing.T) {
	r := run(t, argocdTestCluster(), "argocd.rbac")
	assertSkipHasReason(t, r)
	argocdAssertMentions(t, r, "cluster.installer-rbac")
}

// ---------------------------------------------------------------------------
// argocd.repo-server-egress  [probe]
// ---------------------------------------------------------------------------

// A stock ArgoCD carries its tooling in the image: there is no per-restart
// egress to test, and claiming to have tested it would be a false assurance.
func TestArgoCDRepoServerEgressSkipsWithoutTheDownloadToolsInitContainer(t *testing.T) {
	r := run(t, argocdTestInstall(argocdTestCluster()), "argocd.repo-server-egress")
	assertSkipHasReason(t, r)
	argocdAssertMentions(t, r, "download-tools")
}

// --no-probe must say what was NOT verified: the repo-server refetches six
// tools on every restart, so this is a live dependency, not a one-off.
func TestArgoCDRepoServerEgressSkipsWhenProbesAreOff(t *testing.T) {
	f := argocdTestInstall(argocdTestCluster(), argocdTestInitContainer("download-tools")).
		withOpts(func(o *engine.Options) { o.NoProbe = true })
	r := run(t, f, "argocd.repo-server-egress")
	assertSkipHasReason(t, r)
	argocdAssertMentions(t, r, "NOT verified", "every restart")
}

// FRD-020 §6: an unpullable probe image IS the egress answer, because the
// download-tools initContainer pulls alpine over the same path.
func TestArgoCDRepoServerEgressIsRiskWhenTheProbeImageCannotStart(t *testing.T) {
	f := argocdTestInstall(argocdTestCluster(), argocdTestInitContainer("download-tools"))
	r := argocdRunProbe(t, f, "argocd.repo-server-egress", corev1.PodStatus{
		Phase: corev1.PodFailed,
		ContainerStatuses: []corev1.ContainerStatus{{
			Name: "probe",
			State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
				Reason: "ImagePullBackOff", Message: "Back-off pulling image",
			}},
		}},
	})
	assertStatus(t, r, "RISK")
	argocdAssertMentions(t, r, "ImagePullBackOff", "every restart")
}

// A probe that ran but produced nothing readable is not a pass: with no output
// there is no evidence about any host, and reporting reachability would be a
// fabricated result.
func TestArgoCDRepoServerEgressSkipsWhenTheProbeOutputIsUnreadable(t *testing.T) {
	f := argocdTestInstall(argocdTestCluster(), argocdTestInitContainer("download-tools"))
	r := argocdRunProbe(t, f, "argocd.repo-server-egress", corev1.PodStatus{
		Phase: corev1.PodSucceeded,
		ContainerStatuses: []corev1.ContainerStatus{{
			Name:  "probe",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}},
		}},
	})
	assertSkipHasReason(t, r)
	argocdAssertMentions(t, r, "no readable output")
}

func TestArgoCDRepoServerEgressSkipsWhenNotInstalled(t *testing.T) {
	assertSkipHasReason(t, run(t, argocdTestCluster(), "argocd.repo-server-egress"))
}

// The initContainer wgets the file itself, so a 403 from a CDN is as fatal as a
// timeout — classifying it as reachable would pass a repo-server that cannot
// start. github.com release assets redirect, hence 302 counting as reachable.
func TestArgoCDParseEgressTreatsNon2xxAsUnreachable(t *testing.T) {
	logs := strings.Join([]string{
		"https://github.com 200",
		"https://github.com/moparisthebest/static-curl/releases/latest/download/curl-amd64 302",
		"https://dl.k8s.io/release/stable.txt 403",
		"https://objects.githubusercontent.com/x error: timed out",
		"noise that is not a url",
	}, "\n")
	ok, bad := argocdParseEgress(logs)
	if len(ok) != 2 {
		t.Fatalf("reachable = %v, want the 200 and the 302", ok)
	}
	if len(bad) != 2 {
		t.Fatalf("unreachable = %v, want the 403 and the timeout", bad)
	}
	hosts := argocdHostsOf(bad)
	if strings.Join(hosts, ",") != "dl.k8s.io,objects.githubusercontent.com" {
		t.Fatalf("hosts = %v; the remedy is an allowlist entry per host", hosts)
	}
}
