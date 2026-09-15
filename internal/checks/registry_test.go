package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// The registry group is where a false green is cheapest to produce: nothing
// here can be answered from the cluster alone, so every path ends in either a
// network answer or a SKIP. Two properties are therefore worth more than the
// rest, and most of this file exists to hold them down:
//
//   - a 401 from /v2/ is a PASS and a silent host is a BLOCK (FRD-020 §5.4);
//   - no credentials is a SKIP WITH A REASON, never a pass (FRD-020 D7).
//
// Every HTTP answer below is produced in process by a stubbed RoundTripper:
// adapters.Net exposes its *http.Client, so the whole group is drivable without
// a network, a resolver or a recorded transcript. Nothing here opens a socket
// to a registry, and the single test that opens a socket at all binds loopback.
//
// Consequently none of registry.reachable / .tls / .auth / .tags /
// .from-cluster belongs in the harness's probeOnly exemption list: each is
// driven to a real BLOCK below.

// ---------------------------------------------------------------------------
// A registry that answers exactly what the test says, and nothing else
// ---------------------------------------------------------------------------

// registryRoundTrip is the seam the OCI adapter leaves open: Net.Client is
// exported, so a test can state what each host answers.
type registryRoundTrip func(*http.Request) (*http.Response, error)

func (f registryRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// registryStubNet replaces both Net and OCI on a live ctx. Net is replaced too
// because OCI is built over it, and a check that reached the real one would be
// testing the internet rather than the check.
func registryStubNet(c *engine.Ctx, answer func(*http.Request) (*http.Response, error)) {
	n := &adapters.Net{Timeout: time.Second, Client: &http.Client{Transport: registryRoundTrip(answer)}}
	c.Net = n
	c.OCI = adapters.NewOCI(n)
}

func registryReply(req *http.Request, status int, header map[string]string) (*http.Response, error) {
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	return &http.Response{
		Status:     fmt.Sprintf("%d", status),
		StatusCode: status,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

// registryNoAnswer is what a blocked egress policy looks like from Go: the
// transport never gets a response at all.
func registryNoAnswer() (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// registryAPIHostFor duplicates — deliberately, rather than calling regAPIHost —
// the one host rewrite the implementation performs. Building the fixture out of
// the code under test would make the docker.io mapping unfalsifiable.
func registryAPIHostFor(host string) string {
	if host == "docker.io" {
		return "registry-1.docker.io"
	}
	return host
}

// registryAnswers gives every host `def`, except the hosts named in `byHost`.
// A status of 0 means "this host does not answer at all".
func registryAnswers(def int, byHost map[string]int) func(*http.Request) (*http.Response, error) {
	rewritten := map[string]int{}
	for h, code := range byHost {
		rewritten[registryAPIHostFor(h)] = code
	}
	return func(req *http.Request) (*http.Response, error) {
		code, ok := rewritten[req.URL.Host]
		if !ok {
			code = def
		}
		if code == 0 {
			return registryNoAnswer()
		}
		return registryReply(req, code, nil)
	}
}

// registryRecorder wraps an answerer and remembers every URL requested, so a
// test can assert WHICH reference was probed — the HAMi tag derivation is only
// meaningful if the request itself is checked.
type registryRecorder struct {
	mu   sync.Mutex
	urls []string
	next func(*http.Request) (*http.Response, error)
}

func (r *registryRecorder) answer(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.urls = append(r.urls, req.URL.String())
	r.mu.Unlock()
	return r.next(req)
}

func (r *registryRecorder) sawContaining(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.urls {
		if strings.Contains(u, sub) {
			return true
		}
	}
	return false
}

func (r *registryRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.urls...)
}

// ---------------------------------------------------------------------------
// Running one check against a ctx the test has finished arranging
// ---------------------------------------------------------------------------

// registryRun is run() with a hook: the registry group reads things the fake
// cluster cannot carry — the rendered image list, credentials, a stubbed
// registry — and those have to be set on the ctx after the harness builds it.
func registryRun(t *testing.T, f *fakeCluster, id string, tweak func(*engine.Ctx)) engine.Result {
	t.Helper()
	return registryRunWithin(t, f, id, 20*time.Second, tweak)
}

func registryRunWithin(t *testing.T, f *fakeCluster, id string, d time.Duration, tweak func(*engine.Ctx)) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	if tweak != nil {
		tweak(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return ch.Run(ctx, c)
}

// registryText flattens everything an operator would actually read, so an
// assertion about "the finding names the host" cannot pass because the host
// appears only in a field nobody renders.
func registryText(r engine.Result) string {
	parts := []string{r.Summary, r.Remedy, r.DoesNotProve}
	parts = append(parts, r.Detail...)
	for _, e := range r.Evidence {
		parts = append(parts, e.What, e.Output)
	}
	return strings.Join(parts, "\n")
}

func registryAssertMentions(t *testing.T, r engine.Result, want ...string) {
	t.Helper()
	got := registryText(r)
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("%s [%s]: result never mentions %q\n---\n%s", r.ID, r.Status(), w, got)
		}
	}
}

// registryImages seeds the render the way config.render would.
func registryImages(imgs ...string) func(*engine.Ctx) {
	return func(c *engine.Ctx) { c.Set(engine.KeyImages, imgs) }
}

func registryCreds(host, user, pass string) func(*engine.Ctx) {
	return func(c *engine.Ctx) {
		c.Opts.RegistryCreds = map[string]adapters.Credential{host: {Username: user, Password: pass}}
	}
}

// registryChain applies several arrangements to one ctx.
func registryChain(fns ...func(*engine.Ctx)) func(*engine.Ctx) {
	return func(c *engine.Ctx) {
		for _, fn := range fns {
			if fn != nil {
				fn(c)
			}
		}
	}
}

// registryRenderedWorkload is one rendered Deployment carrying its chart label,
// which is what lets registry.upstream-defaults name the chart that moved
// rather than only the host.
func registryRenderedWorkload(name, chart string, images ...string) adapters.Object {
	containers := []any{}
	for i, img := range images {
		containers = append(containers, map[string]any{"name": fmt.Sprintf("c%d", i), "image": img})
	}
	return adapters.Object{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{
			"name": name, "namespace": "bud",
			"labels": map[string]any{"helm.sh/chart": chart},
		},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": containers,
		}}},
	}
}

// registryValuesObject is a host named from VALUES rather than from an image
// field — Harbor's trivy.dbRepository is the live example, and the whole reason
// the dormant/promoted distinction exists.
func registryValuesObject(name, key, value string) adapters.Object {
	return adapters.Object{
		"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": name, "namespace": "bud"},
		"data":     map[string]any{key: value},
	}
}

// registryGPULabelNode is a GPU node whose device plugin is NOT installed yet:
// no allocatable nvidia.com/*, only the NFD label. That is exactly the cluster
// budcluster is about to onboard — and the one HAMi gets installed on.
func registryGPULabelNode(name string) adapters.Object {
	o := node(name)
	o["metadata"].(map[string]any)["labels"].(map[string]any)["nvidia.com/gpu.present"] = "true"
	return o
}

// ---------------------------------------------------------------------------
// registry.pinned-tags — the one check that needs no network at all
// ---------------------------------------------------------------------------

// A mutable tag means the cluster cannot be reproduced: two nodes pulling the
// same reference a week apart run different code. Each tag is exercised on its
// own, because the failure is per-reference and a check that only looked at the
// first image would still satisfy a single-case test.
func TestRegistryPinnedTagsRisksOnEveryMutableReference(t *testing.T) {
	cases := []struct {
		name  string
		image string
		// also is the wording the finding must carry. An untagged reference is
		// a different fault from a mutable tag — the operator has to add a tag,
		// not change one — so the two must not collapse into one message.
		also string
	}{
		{name: "latest is the canonical moving target", image: "registry.bud.studio/bud/budapp:latest"},
		{name: "nightly is the one FRD-020 names", image: "registry.bud.studio/bud/budadmin:nightly"},
		{name: "edge moves on every upstream merge", image: "ghcr.io/dapr/daprd:edge"},
		{name: "dev is a build stream, not a release", image: "quay.io/keycloak/keycloak:dev"},
		{name: "main tracks a branch", image: "docker.io/budstudio/aibrix:main"},
		{name: "master tracks a branch under its older name", image: "docker.io/budstudio/aibrix:master"},
		{name: "stable reads immutable and is not", image: "registry.k8s.io/kube-state-metrics:stable"},
		{name: "no tag at all resolves as :latest at runtime",
			image: "docker.io/library/redis", also: "no tag"},
		{name: "a registry port must not be mistaken for a tag",
			image: "registry.internal:5000/bud/budapp", also: "no tag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := registryRun(t, vanilla(), "registry.pinned-tags",
				registryImages("registry.bud.studio/bud/budcluster:1.4.2", tc.image))
			assertStatus(t, r, "RISK")
			registryAssertMentions(t, r, tc.image)
			if tc.also != "" {
				registryAssertMentions(t, r, tc.also)
			}
		})
	}
}

// The pass case exists so the failures above cannot be passing by accident: a
// check that flagged everything would satisfy the table and be useless.
func TestRegistryPinnedTagsPassesWhenEveryReferenceIsPinned(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.pinned-tags", registryImages(
		"registry.bud.studio/bud/budapp:0.9.14",
		"registry.internal:5000/bud/budadmin:0.9.14",
		// A digest is the strongest pin there is, and must not be read as
		// "no tag" by the colon-scanning rule.
		"docker.io/library/redis@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"ghcr.io/cloudnative-pg/cloudnative-pg:1.24.1",
	))
	assertStatus(t, r, "PASS")
}

// Without --values there is no render, and the honest answer is "not looked
// at". A PASS here would tell the operator their tags are pinned when nothing
// was read.
func TestRegistryPinnedTagsSkipsWithoutARender(t *testing.T) {
	assertSkipHasReason(t, registryRun(t, vanilla(), "registry.pinned-tags", nil))
}

// ---------------------------------------------------------------------------
// registry.reachable
// ---------------------------------------------------------------------------

// A 401 is the answer an un-credentialled first run gets from a private
// registry, and FRD-020 §5.4 makes it a PASS on purpose: it proves DNS,
// routing, TLS and a live registry. If this ever regresses to BLOCK, every
// genuine first run fails on a registry that is working.
func TestRegistryReachablePassesOn401(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.reachable", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
	})
	assertStatus(t, r, "PASS")
	registryAssertMentions(t, r, "registry.bud.studio", "HTTP 401")
}

// The inventory's whole reason to exist: four of its hosts appear nowhere in
// this repository, so a grep-built check would never probe them. Each one must
// be able to fail the run on its own.
func TestRegistryReachableBlocksPerRequiredHost(t *testing.T) {
	hosts := []string{
		"registry.bud.studio",
		"docker.io",
		"quay.io",
		"ghcr.io",
		"registry.k8s.io",
		// Not in this repo: ArgoCD's bundled Redis, via an upstream default.
		"ecr-public.aws.com",
		// Not in this repo: Kyverno's chart-level defaultRegistry.
		"reg.kyverno.io",
	}
	for _, h := range hosts {
		t.Run(h, func(t *testing.T) {
			r := registryRun(t, vanilla(), "registry.reachable", func(c *engine.Ctx) {
				registryStubNet(c, registryAnswers(http.StatusOK, map[string]int{h: 0}))
			})
			assertStatus(t, r, "BLOCK")
			registryAssertMentions(t, r, h, "connection refused")
		})
	}
}

// A timeout and a refusal are the same finding — the host does not answer —
// and neither may be softened into a risk just because the error text differs.
func TestRegistryReachableBlocksOnTimeout(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.reachable", func(c *engine.Ctx) {
		registryStubNet(c, func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "registry.bud.studio" {
				return nil, context.DeadlineExceeded
			}
			return registryReply(req, http.StatusOK, nil)
		})
	})
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r, "registry.bud.studio")
}

// A host tied to a feature nobody enabled must not stop an install that will
// never pull from it — but it must not disappear either, because enabling that
// feature next month needs it.
func TestRegistryReachableRisksWhenOnlyInactiveFeatureHostsFail(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) {
		a.GPU = false
		a.OpenSandbox = false
	})
	r := registryRun(t, f, "registry.reachable", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusOK, map[string]int{
			"nvcr.io": 0,
			"sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com": 0,
		}))
	})
	assertStatus(t, r, "RISK")
	registryAssertMentions(t, r, "nvcr.io", "gpu")
}

// The same host, the same failure, a different install: once the operator says
// GPU, the GPU registries stop being optional. A check that read only the
// requirement column would call this a risk on a cluster that cannot onboard.
func TestRegistryReachableBlocksWhenTheFeatureIsInPlay(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.GPU = true })
	r := registryRun(t, f, "registry.reachable", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusOK, map[string]int{"nvcr.io": 0}))
	})
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r, "nvcr.io")
}

// GPU nodes already in the cluster are as good as the answer: budcluster
// installs HAMi and the GPU operator on detection, without asking.
func TestRegistryReachableBlocksWhenGPUNodesArePresentEvenIfUnanswered(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("g1", withGPU("4")))
	r := registryRun(t, f, "registry.reachable", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusOK, map[string]int{
			"nvcr.io": 0,
		}))
	})
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r, "nvcr.io")
}

// mirror.gcr.io is dormant only while Harbor's trivy stays off. The promotion
// has to be driven by the render, not by a hardcoded flag list, or a values
// change reintroduces a silent dependency.
func TestRegistryReachableIgnoresDormantHostUntilTheRenderNamesIt(t *testing.T) {
	stub := func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusOK, map[string]int{"mirror.gcr.io": 0}))
	}

	// Dormant: the host is unreachable and that is not a finding, because
	// nothing in this install pulls from it.
	quiet := registryRun(t, vanilla(), "registry.reachable", stub)
	assertStatus(t, quiet, "PASS")
	registryAssertMentions(t, quiet, "mirror.gcr.io: not probed")

	// Promoted: trivy.enabled flipped, so the render now names the host.
	loud := registryRun(t, vanilla(), "registry.reachable", registryChain(stub, func(c *engine.Ctx) {
		c.Set(engine.KeyRenderedObjects, []adapters.Object{
			registryValuesObject("harbor-trivy", "dbRepository", "mirror.gcr.io/aquasecurity/trivy-db"),
		})
	}))
	assertStatus(t, loud, "BLOCK")
	registryAssertMentions(t, loud, "mirror.gcr.io", "no longer dormant")
}

// docker.io's API lives on registry-1.docker.io. Probing the name from the
// image reference instead would report Docker Hub unreachable on every cluster.
func TestRegistryReachableProbesDockerHubsRealAPIHost(t *testing.T) {
	rec := &registryRecorder{next: registryAnswers(http.StatusOK, nil)}
	r := registryRun(t, vanilla(), "registry.reachable", func(c *engine.Ctx) {
		registryStubNet(c, rec.answer)
	})
	assertStatus(t, r, "PASS")
	if !rec.sawContaining("https://registry-1.docker.io/v2/") {
		t.Fatalf("docker.io was never probed at its API host; requests were:\n%s",
			strings.Join(rec.seen(), "\n"))
	}
}

func TestRegistryReachableSkipsWithoutANetworkAdapter(t *testing.T) {
	assertSkipHasReason(t, registryRun(t, vanilla(), "registry.reachable", func(c *engine.Ctx) {
		c.OCI = nil
	}))
}

// ---------------------------------------------------------------------------
// registry.tls
// ---------------------------------------------------------------------------

// registryMITMListener stands up a TLS endpoint on loopback serving a
// certificate this workstation does not trust — a corporate interception proxy
// reduced to its one observable property. It returns the host:port to point the
// check at.
//
// It binds an ephemeral port, not 443. Binding 443 needs root, so off root the
// listener never came up and the test skipped — which is how registry.tls came
// to have no failing test anywhere CI runs, while passing on a workstation that
// happened to be root. A check reached only under root is a check nobody runs.
func registryMITMListener(t *testing.T, issuerCN string, notAfter time.Time) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot bind a loopback port: %v", err)
	}

	// A real interception proxy presents a leaf signed by ITS OWN CA, and the
	// issuer name on that leaf is how an operator recognises it. The fixture
	// therefore has to be a genuine two-certificate chain: a self-signed leaf
	// names itself as its own issuer and would prove nothing.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}

	cert := tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
				_ = c.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = tlsLn.Close()
		<-done
	})
	return ln.Addr().String()
}

// registryOnlyHost narrows the inventory to one host, so a TLS finding is about
// the certificate this test served rather than about whatever the rest of the
// inventory does.
func registryOnlyHost(host string) func(*engine.Ctx) {
	return func(c *engine.Ctx) {
		c.Profile.Registries = []intake.RegistryEntry{{
			Host: host, Requirement: "required", PulledBy: "the test's only registry",
		}}
	}
}

// An unexpected issuer is TLS interception, and it must surface here as its own
// blocker: left to the install it appears as an x509 error inside a pull, which
// sends the operator looking at the registry instead of at their proxy.
func TestRegistryTLSBlocksOnAnUntrustedInterceptingCA(t *testing.T) {
	addr := registryMITMListener(t, "Acme Corporate Inspection CA", time.Now().AddDate(1, 0, 0))
	r := registryRun(t, vanilla(), "registry.tls", registryChain(
		// Carries the port, which is also how a self-hosted Harbor on :8443 is
		// written — so this covers regTLSTarget's split as well.
		registryOnlyHost(addr),
		func(c *engine.Ctx) { c.Net = &adapters.Net{Timeout: 3 * time.Second} },
	))
	assertStatus(t, r, "BLOCK")
	// The x509 cause is carried through rather than flattened to "did not
	// verify": an intercepting CA and an expired certificate are different
	// problems, and the operator should not have to dial the host to find out
	// which one this is.
	registryAssertMentions(t, r, "Acme Corporate Inspection CA", "signed by unknown authority")
}

// A host that never completes a handshake is registry.reachable's finding, not
// a certificate finding. Reporting it twice sends the operator after the wrong
// cause, so this must be a stated SKIP.
func TestRegistryTLSSkipsWhenNoHandshakeCompletes(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.tls", registryChain(
		// A loopback address with nothing listening refuses instantly and needs
		// no resolver, so this path is reached without touching a network.
		registryOnlyHost("127.0.0.2"),
		func(c *engine.Ctx) { c.Net = &adapters.Net{Timeout: 2 * time.Second} },
	))
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "registry.reachable")
}

func TestRegistryTLSSkipsWithoutANetworkAdapter(t *testing.T) {
	assertSkipHasReason(t, registryRun(t, vanilla(), "registry.tls", func(c *engine.Ctx) {
		c.Net = nil
	}))
}

// ---------------------------------------------------------------------------
// registry.from-cluster  [probe]
// ---------------------------------------------------------------------------

// registryProbeCluster makes the fake cluster answer for one probe pod: the
// status the kubelet would report, and the logs the pod would have written.
// client-go's fake honours a reactor on the "log" subresource, which is what
// makes the pod-side branch testable at all.
func registryProbeCluster(c *engine.Ctx, status corev1.PodStatus, nodeName, logs string) {
	cs, ok := c.Kube.Clientset.(*k8sfake.Clientset)
	if !ok {
		panic("registryProbeCluster: harness clientset is not a fake")
	}
	cs.PrependReactor("get", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "log" {
			return true, &runtime.Unknown{Raw: []byte(logs)}, nil
		}
		get, ok := a.(k8stesting.GetAction)
		if !ok {
			return false, nil, nil
		}
		return true, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: get.GetName(), Namespace: get.GetNamespace()},
			Spec:       corev1.PodSpec{NodeName: nodeName},
			Status:     status,
		}, nil
	})
	c.Probes = probes.NewRunner(c.Kube, "budctl-readiness-test", "test", false)
}

// registryEgressLogs is what regEgressScript prints: one host|code line each.
func registryEgressLogs(codes map[string]string, order ...string) string {
	var b strings.Builder
	for _, h := range order {
		b.WriteString(h + "|" + codes[h] + "\n")
	}
	return b.String()
}

// The required hosts as the inventory orders them, for probe log fixtures.
var registryRequiredHosts = []string{
	"registry.bud.studio", "docker.io", "quay.io", "ghcr.io",
	"registry.k8s.io", "ecr-public.aws.com", "reg.kyverno.io",
}

func registryAllReached(code string) map[string]string {
	out := map[string]string{}
	for _, h := range registryRequiredHosts {
		out[h] = code
	}
	return out
}

// The finding this check exists for: the workstation reaches the registry and
// the node does not. The pull happens on the node, so the workstation's success
// is not evidence of anything, and the summary has to say which vantage point
// failed or the operator debugs the wrong network.
func TestRegistryFromClusterBlocksWhenOnlyTheNodeIsBlocked(t *testing.T) {
	codes := registryAllReached("401")
	codes["registry.bud.studio"] = "000" // curl writes 000 when it never connected
	r := registryRun(t, vanilla(), "registry.from-cluster", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
		registryProbeCluster(c, corev1.PodStatus{
			Phase: corev1.PodSucceeded,
			ContainerStatuses: []corev1.ContainerStatus{{
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}},
			}},
		}, "node-1", registryEgressLogs(codes, registryRequiredHosts...))
	})
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r,
		"registry.bud.studio",
		"no answer (DNS, routing or TLS)",
		"from this workstation", // the two vantage points must be contrasted
	)
}

// If the probe image itself cannot be pulled, that IS the registry answer — the
// first real image pull this cluster attempted — and reporting it as a tool
// error would hide a blocked node network behind "budctl failed".
func TestRegistryFromClusterBlocksWhenTheProbeImageCannotBePulled(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.from-cluster", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
		registryProbeCluster(c, corev1.PodStatus{
			Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{{
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{
					Reason:  "ImagePullBackOff",
					Message: "Back-off pulling image \"curlimages/curl:8.10.1\"",
				}},
			}},
		}, "node-1", "")
	})
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r, "curlimages/curl:8.10.1", "docker.io")
}

// A probe that answered for some hosts and stayed silent about others has not
// verified those others. That is a risk, not a pass — and the remedy has to
// give the operator the by-hand equivalent.
func TestRegistryFromClusterRisksWhenTheProbeIsSilentAboutAHost(t *testing.T) {
	partial := []string{"registry.bud.studio", "docker.io"}
	r := registryRun(t, vanilla(), "registry.from-cluster", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
		registryProbeCluster(c, corev1.PodStatus{Phase: corev1.PodSucceeded},
			"node-1", registryEgressLogs(registryAllReached("200"), partial...))
	})
	assertStatus(t, r, "RISK")
	registryAssertMentions(t, r, "quay.io", "reported nothing")
}

func TestRegistryFromClusterPassesWhenEveryRequiredHostAnswersFromThePod(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.from-cluster", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
		registryProbeCluster(c, corev1.PodStatus{Phase: corev1.PodSucceeded},
			"node-1", registryEgressLogs(registryAllReached("401"), registryRequiredHosts...))
	})
	assertStatus(t, r, "PASS")
}

// The probe script carries the same docker.io rewrite as the workstation
// probe, and it has to keep the two spellings apart: curl must be pointed at
// registry-1.docker.io (docker.io/v2/ is not the registry API), while the line
// it prints must be keyed by the INVENTORY host, because that is the name
// regParseEgress looks the result up under. Getting either half wrong makes
// Docker Hub silently unreportable from inside the cluster.
func TestRegistryEgressScriptCurlsTheAPIHostButReportsTheInventoryHost(t *testing.T) {
	script := regEgressScript([]string{"docker.io", "quay.io"}, "")
	if !strings.Contains(script, "https://registry-1.docker.io/v2/") {
		t.Fatalf("probe script does not curl Docker Hub's API host:\n%s", script)
	}
	if strings.Contains(script, "https://docker.io/v2/") {
		t.Fatalf("probe script curls docker.io, which is not the registry API:\n%s", script)
	}
	if !strings.Contains(script, `echo "docker.io|`) {
		t.Fatalf("probe script keys its output by something other than the inventory host:\n%s", script)
	}
	// The proxy is exported only when there is one: exporting an empty
	// https_proxy would break the probe on every cluster that has none.
	if strings.Contains(script, "https_proxy") {
		t.Fatalf("no cluster proxy was configured, but the script sets one:\n%s", script)
	}
	withProxy := regEgressScript([]string{"quay.io"}, "http://proxy.corp:3128")
	if !strings.Contains(withProxy, "export https_proxy=http://proxy.corp:3128") {
		t.Fatalf("the cluster-wide proxy was not applied to the probe:\n%s", withProxy)
	}
}

// A pod that never got a node proves nothing about egress. Reporting the
// scheduling failure as an egress failure would send the operator to their
// firewall over a full cluster.
func TestRegistryFromClusterSkipsWhenTheProbePodNeverSchedules(t *testing.T) {
	r := registryRunWithin(t, vanilla(), "registry.from-cluster", 2*time.Second, func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
		registryProbeCluster(c, corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{{
				Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
				Reason: "Unschedulable", Message: "0/3 nodes are available: 3 Insufficient cpu",
			}},
		}, "", "")
	})
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "Unschedulable")
}

// --no-probe must never read as "the nodes can reach the registries".
func TestRegistryFromClusterSkipsUnderNoProbe(t *testing.T) {
	f := vanilla().withOpts(func(o *engine.Options) { o.NoProbe = true })
	r := registryRun(t, f, "registry.from-cluster", func(c *engine.Ctx) {
		registryProbeCluster(c, corev1.PodStatus{Phase: corev1.PodSucceeded}, "node-1", "")
	})
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "NOT verified")
}

// ---------------------------------------------------------------------------
// registry.auth — FRD-020 D7
// ---------------------------------------------------------------------------

// The robot account is issued AFTER readiness passes, so no credentials is the
// expected first-run state. It must SKIP with a reason: a PASS here would tell
// an operator their credentials work when none were ever supplied.
func TestRegistryAuthSkipsWithAReasonWhenNoCredentialsAreSupplied(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.auth", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusOK, nil))
	})
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "NOT verified")
}

// Supplied and rejected is the blocker: every first-party pull 401s and the
// platform pods never start.
func TestRegistryAuthBlocksWhenCredentialsAreRejected(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.auth", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "wrong"),
		func(c *engine.Ctx) {
			registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
		},
	))
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r, "robot$bud", "registry.bud.studio")
}

func TestRegistryAuthPassesWhenTheManifestResolves(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.auth", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		registryImages("registry.bud.studio/bud/budapp:0.9.14"),
		func(c *engine.Ctx) { registryStubNet(c, registryAnswers(http.StatusOK, nil)) },
	))
	assertStatus(t, r, "PASS")
}

// A 404 is a PASS here on purpose: the registry authenticated the request and
// only then said "no such tag". Treating it as a failure would reject every
// correct credential on an install with no render to name a real repository.
func TestRegistryAuthTreats404AsCredentialsAccepted(t *testing.T) {
	rec := &registryRecorder{next: registryAnswers(http.StatusNotFound, nil)}
	r := registryRun(t, vanilla(), "registry.auth", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		func(c *engine.Ctx) { registryStubNet(c, rec.answer) },
	))
	assertStatus(t, r, "PASS")
	// No render, so it must ask for something that cannot exist rather than
	// inventing a repository that might.
	if !rec.sawContaining("budctl/readiness-probe") {
		t.Fatalf("no render, but the check did not use its synthetic repository; requests were:\n%s",
			strings.Join(rec.seen(), "\n"))
	}
}

// With a render, the credentials must be tested against something the install
// will really pull — a project-scoped robot account can be valid for the render
// repository and blind to a synthetic one.
func TestRegistryAuthAuthenticatesAgainstARenderedRepository(t *testing.T) {
	rec := &registryRecorder{next: registryAnswers(http.StatusOK, nil)}
	r := registryRun(t, vanilla(), "registry.auth", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		registryImages("registry.bud.studio/bud/budapp:0.9.14"),
		func(c *engine.Ctx) { registryStubNet(c, rec.answer) },
	))
	assertStatus(t, r, "PASS")
	if !rec.sawContaining("/v2/bud/budapp/manifests/0.9.14") {
		t.Fatalf("the render named a repository but it was not the one authenticated against:\n%s",
			strings.Join(rec.seen(), "\n"))
	}
}

// Credentials that could not be tested are not credentials that work.
func TestRegistryAuthSkipsWhenTheRegistryCannotBeReached(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.auth", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		func(c *engine.Ctx) { registryStubNet(c, registryAnswers(0, nil)) },
	))
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "registry.reachable")
}

// ---------------------------------------------------------------------------
// registry.tags
// ---------------------------------------------------------------------------

// A tag that does not exist is an ImagePullBackOff the operator will meet at
// 2am, and the finding is only actionable if it names the exact reference the
// render resolved.
func TestRegistryTagsBlocksOnAMissingTagAndNamesIt(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.tags", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		registryImages(
			"registry.bud.studio/bud/budapp:0.9.14",
			"registry.bud.studio/bud/budcluster:0.9.14-typo",
		),
		func(c *engine.Ctx) {
			registryStubNet(c, func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Path, "0.9.14-typo") {
					return registryReply(req, http.StatusNotFound, nil)
				}
				return registryReply(req, http.StatusOK, nil)
			})
		},
	))
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r, "registry.bud.studio/bud/budcluster:0.9.14-typo")
}

// Credentials are optional for the group, which means this check must state
// that it did not run rather than quietly resolving only the public images.
func TestRegistryTagsSkipsWithAReasonWhenNoCredentialsAreSupplied(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.tags", registryChain(
		registryImages("registry.bud.studio/bud/budapp:0.9.14"),
		func(c *engine.Ctx) { registryStubNet(c, registryAnswers(http.StatusOK, nil)) },
	))
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "NOT verified")
}

func TestRegistryTagsSkipsWithoutARender(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.tags", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		func(c *engine.Ctx) { registryStubNet(c, registryAnswers(http.StatusOK, nil)) },
	))
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "--values")
}

// An image whose tag could not be resolved is unverified, not verified-good —
// and the two reasons it can be unresolvable have different owners, so each has
// to point at the check that actually explains it.
func TestRegistryTagsRisksWhenAReferenceCannotBeResolved(t *testing.T) {
	cases := []struct {
		name   string
		answer func(*http.Request) (*http.Response, error)
		points string
	}{
		{
			name:   "the host does not answer at all",
			answer: func(*http.Request) (*http.Response, error) { return registryNoAnswer() },
			points: "registry.reachable",
		},
		{
			// 401 on one image with credentials in play is a credential
			// problem, not a missing tag: calling it BLOCK would send the
			// operator to fix a values file that is correct.
			name: "the registry refuses the request",
			answer: func(req *http.Request) (*http.Response, error) {
				return registryReply(req, http.StatusUnauthorized, nil)
			},
			points: "registry.auth",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := registryRun(t, vanilla(), "registry.tags", registryChain(
				registryCreds("registry.bud.studio", "robot$bud", "right"),
				registryImages("registry.bud.studio/bud/budapp:0.9.14", "quay.io/keycloak/keycloak:26.0"),
				func(c *engine.Ctx) {
					registryStubNet(c, func(req *http.Request) (*http.Response, error) {
						if req.URL.Host == "quay.io" {
							return tc.answer(req)
						}
						return registryReply(req, http.StatusOK, nil)
					})
				},
			))
			assertStatus(t, r, "RISK")
			registryAssertMentions(t, r, "quay.io/keycloak/keycloak:26.0", tc.points)
		})
	}
}

// Docker Hub answers 401 with a bearer challenge even for public images, and
// the anonymous token exchange that follows is what makes the pull work. If it
// regressed, every public image in the render would report "unauthorized".
func TestRegistryTagsCompletesTheAnonymousTokenExchange(t *testing.T) {
	const token = "anonymous-pull-token"
	r := registryRun(t, vanilla(), "registry.tags", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		registryImages("docker.io/library/redis:7.4"),
		func(c *engine.Ctx) {
			registryStubNet(c, func(req *http.Request) (*http.Response, error) {
				switch {
				case req.URL.Host == "auth.docker.io":
					resp, _ := registryReply(req, http.StatusOK, map[string]string{
						"Content-Type": "application/json",
					})
					resp.Body = io.NopCloser(strings.NewReader(`{"token":"` + token + `"}`))
					return resp, nil
				case req.Header.Get("Authorization") == "Bearer "+token:
					return registryReply(req, http.StatusOK, nil)
				default:
					return registryReply(req, http.StatusUnauthorized, map[string]string{
						"WWW-Authenticate": `Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`,
					})
				}
			})
		},
	))
	assertStatus(t, r, "PASS")
}

// A multi-arch tag answers with an image INDEX, not a manifest. A request that
// did not offer to accept an index would be answered 404 by a registry serving
// one, and every multi-arch image in the render would read as missing.
func TestRegistryTagsResolvesAMultiArchIndex(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.tags", registryChain(
		registryCreds("registry.bud.studio", "robot$bud", "right"),
		registryImages("registry.bud.studio/bud/budapp:0.9.14"),
		func(c *engine.Ctx) {
			registryStubNet(c, func(req *http.Request) (*http.Response, error) {
				if !strings.Contains(req.Header.Get("Accept"), "image.index") {
					return registryReply(req, http.StatusNotFound, nil)
				}
				return registryReply(req, http.StatusOK, map[string]string{
					"Content-Type":          "application/vnd.oci.image.index.v1+json",
					"Docker-Content-Digest": "sha256:" + strings.Repeat("a", 64),
				})
			})
		},
	))
	assertStatus(t, r, "PASS")
}

// ---------------------------------------------------------------------------
// registry.upstream-defaults
// ---------------------------------------------------------------------------

// The inventory goes stale silently: an upstream chart bumps and starts pulling
// from a host nobody allowlisted. The finding has to name the chart, because
// the host alone does not tell anyone what to pin.
func TestRegistryUpstreamDefaultsRisksOnAHostTheInventoryDoesNotKnow(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.upstream-defaults", func(c *engine.Ctx) {
		c.Set(engine.KeyRenderedObjects, []adapters.Object{
			registryRenderedWorkload("budapp", "bud-0.9.14", "registry.bud.studio/bud/budapp:0.9.14"),
			registryRenderedWorkload("signoz-collector", "signoz-0.63.0",
				"docker.redpanda.example.io/redpandadata/redpanda:v24.2.7"),
		})
	})
	assertStatus(t, r, "RISK")
	registryAssertMentions(t, r, "docker.redpanda.example.io", "signoz-0.63.0", "defaults.yaml")
}

// The image inventory can carry references the object walk misses — a values
// key rather than a container image — and those hosts need an allowlist entry
// just as much.
func TestRegistryUpstreamDefaultsSeesHostsOnlyTheImageListCarries(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.upstream-defaults", registryChain(
		registryImages("some-new-mirror.example.com/ops/thing:1.0"),
		func(c *engine.Ctx) {
			c.Set(engine.KeyRenderedObjects, []adapters.Object{
				registryRenderedWorkload("budapp", "bud-0.9.14", "registry.bud.studio/bud/budapp:0.9.14"),
			})
		},
	))
	assertStatus(t, r, "RISK")
	registryAssertMentions(t, r, "some-new-mirror.example.com")
}

func TestRegistryUpstreamDefaultsPassesWhenEveryHostIsKnown(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.upstream-defaults", func(c *engine.Ctx) {
		c.Set(engine.KeyRenderedObjects, []adapters.Object{
			registryRenderedWorkload("budapp", "bud-0.9.14", "registry.bud.studio/bud/budapp:0.9.14"),
			// A bare Docker Hub reference must resolve to docker.io rather than
			// to a host the inventory has never heard of.
			registryRenderedWorkload("redis", "argo-cd-7.7.5", "redis:7.4-alpine"),
			registryRenderedWorkload("dapr", "dapr-1.14.4", "ghcr.io/dapr/daprd:1.14.4"),
		})
	})
	assertStatus(t, r, "PASS")
}

// Grepping the repository for registries is exactly the method §5.4.2 forbids,
// so with no render this check has nothing honest to say.
func TestRegistryUpstreamDefaultsSkipsWithoutARender(t *testing.T) {
	assertSkipHasReason(t, registryRun(t, vanilla(), "registry.upstream-defaults", nil))
}

// ---------------------------------------------------------------------------
// registry.hami-scheduler
// ---------------------------------------------------------------------------

// HAMi's Helm task is atomic, so this one unpullable image does not leave a
// diagnosable ImagePullBackOff — it rolls the whole release back and GPU
// onboarding fails with nothing to look at.
func TestRegistryHAMiSchedulerBlocksWhenRegistryK8sIsUnreachable(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("g1", withGPU("4")))
	r := registryRun(t, f, "registry.hami-scheduler", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusOK, map[string]int{regHAMiRegistry: 0}))
	})
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r,
		"registry.k8s.io/kube-scheduler",
		// A mirror must override BOTH fields and warn about the trap: the
		// obvious one-line fix keeps the chart's google_containers/ prefix.
		"repository: kube-scheduler",
		"global.imageRegistry alone is NOT sufficient",
	)
}

// budcluster overrides HAMi's Alibaba CN-region default, so the check must
// probe the upstream image a GPU node will actually pull — probing the old
// mirror would block every cluster whose egress policy rightly excludes it.
func TestRegistryHAMiSchedulerNeverProbesTheAlibabaMirror(t *testing.T) {
	f := vanilla().with("nodes", "", node("g1", withGPU("2")))
	rec := &registryRecorder{next: registryAnswers(http.StatusOK, nil)}
	r := registryRun(t, f, "registry.hami-scheduler", func(c *engine.Ctx) {
		c.Platform.Version = "v1.36.3+k3s1"
		registryStubNet(c, rec.answer)
	})
	assertStatus(t, r, "PASS")
	if !rec.sawContaining("https://registry.k8s.io/v2/kube-scheduler/manifests/v1.36.3") {
		t.Fatalf("expected a HEAD of the upstream kube-scheduler image, got:\n%s", strings.Join(rec.seen(), "\n"))
	}
	if rec.sawContaining("aliyuncs.com") {
		t.Fatalf("the check still dialled the Alibaba mirror:\n%s", strings.Join(rec.seen(), "\n"))
	}
	for _, e := range egressTestProfile(t).Registries {
		if e.Host == "registry.cn-hangzhou.aliyuncs.com" {
			t.Fatal("the registry inventory still lists registry.cn-hangzhou.aliyuncs.com, so registry.reachable and registry.from-cluster would still probe it")
		}
	}
}

// A GPU node whose device plugin is not installed yet advertises no
// nvidia.com/* allocatable at all — and it is precisely the cluster budcluster
// is about to onboard HAMi onto.
func TestRegistryHAMiSchedulerSeesAGPUNodeWithNoDevicePluginYet(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), registryGPULabelNode("g1"))
	r := registryRun(t, f, "registry.hami-scheduler", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusOK, map[string]int{regHAMiRegistry: 0}))
	})
	assertStatus(t, r, "BLOCK")
	registryAssertMentions(t, r, "g1")
}

// The chart derives the tag from the cluster's own version with the
// distribution suffix stripped. A hardcoded tag would probe an image this
// cluster never pulls and report a green result about the wrong thing.
func TestRegistryHAMiSchedulerDerivesTheTagFromTheClusterVersion(t *testing.T) {
	cases := []struct{ version, tag string }{
		{"v1.34.2+k3s1", "v1.34.2"},
		{"v1.30.8-eks-2d5f260", "v1.30.8"},
		{"1.29.4", "v1.29.4"},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			f := vanilla().with("nodes", "", node("g1", withGPU("2")))
			rec := &registryRecorder{next: registryAnswers(http.StatusOK, nil)}
			r := registryRun(t, f, "registry.hami-scheduler", func(c *engine.Ctx) {
				c.Platform.Version = tc.version
				registryStubNet(c, rec.answer)
			})
			assertStatus(t, r, "PASS")
			want := "https://" + regHAMiRegistry + "/v2/" + regHAMiRepo + "/manifests/" + tc.tag
			if !rec.sawContaining(want) {
				t.Fatalf("expected a HEAD of %s, got:\n%s", want, strings.Join(rec.seen(), "\n"))
			}
		})
	}
}

// registry.k8s.io publishes every release, so a 404 means this cluster reports a
// version upstream never shipped — either way the pull fails, and the operator
// needs a mirror carrying the tag.
func TestRegistryHAMiSchedulerRisksWhenTheDerivedTagIsMissing(t *testing.T) {
	f := vanilla().with("nodes", "", node("g1", withGPU("2")))
	r := registryRun(t, f, "registry.hami-scheduler", func(c *engine.Ctx) {
		c.Platform.Version = "v1.99.0+k3s1"
		registryStubNet(c, registryAnswers(http.StatusNotFound, nil))
	})
	assertStatus(t, r, "RISK")
	registryAssertMentions(t, r, "v1.99.0", "global.imageRegistry alone is NOT sufficient")
}

// Anonymous access refused is not proof the pull fails — the node may carry a
// pull secret — so it is a risk rather than a blocker, and must not be silently
// upgraded to a pass either.
func TestRegistryHAMiSchedulerRisksWhenAnonymousAccessIsRefused(t *testing.T) {
	f := vanilla().with("nodes", "", node("g1", withGPU("2")))
	r := registryRun(t, f, "registry.hami-scheduler", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(http.StatusUnauthorized, nil))
	})
	assertStatus(t, r, "RISK")
	registryAssertMentions(t, r, regHAMiRepo)
}

// No GPU nodes means budcluster never installs HAMi, so this image is never
// pulled. It must SKIP with that reason stated — not pass, which would read as
// "the scheduler image is reachable".
func TestRegistryHAMiSchedulerSkipsWithoutGPUNodes(t *testing.T) {
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	r := registryRun(t, f, "registry.hami-scheduler", func(c *engine.Ctx) {
		registryStubNet(c, registryAnswers(0, nil)) // nothing answers; still a SKIP
	})
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "no NVIDIA GPU nodes")
}

// Without a cluster, neither the GPU question nor the version the tag is
// derived from can be answered.
func TestRegistryHAMiSchedulerSkipsWhenTheClusterIsUnreachable(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.hami-scheduler", func(c *engine.Ctx) {
		c.Kube = nil
		registryStubNet(c, registryAnswers(http.StatusOK, nil))
	})
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "cluster unreachable")
}

// GPU nodes are known but the server version is not: probing a hardcoded tag
// here would check an image the cluster never pulls, so the honest answer is a
// stated skip.
func TestRegistryHAMiSchedulerSkipsWhenTheVersionIsUnreadable(t *testing.T) {
	r := registryRun(t, vanilla(), "registry.hami-scheduler", func(c *engine.Ctx) {
		c.Kube = nil
		c.Set(engine.KeyGPUNodes, []string{"g1"})
		c.Platform.Version = ""
		registryStubNet(c, registryAnswers(http.StatusOK, nil))
	})
	assertSkipHasReason(t, r)
	registryAssertMentions(t, r, "derived")
}
