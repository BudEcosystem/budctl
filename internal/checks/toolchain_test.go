package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/intake"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"

	"github.com/BudEcosystem/budctl/internal/engine"
)

// The toolchain group is the only group that interrogates the OPERATOR'S
// MACHINE rather than the cluster: the kubeconfig on disk, PATH, the age
// identity, the wall clock. That makes every test here hostage to the developer
// running it — a workstation that happens to hold ~/.config/sops/age/keys.txt
// would turn the age-identity BLOCK case green locally and red in CI. So every
// test starts by pointing HOME, KUBECONFIG, PATH and the SOPS_* variables at a
// temp directory it owns.

// ---------------------------------------------------------------- test harness

// toolchainTestRun is run() with one seam added: the ability to mutate the
// engine.Ctx before the check sees it. toolchain.kubeconfig's whole BLOCK path
// is "c.Kube is nil", and toolchain.clock needs a reference clock that is not
// the internet; neither is reachable through fakeCluster alone.
func toolchainTestRun(t *testing.T, f *fakeCluster, id string, mutate func(*engine.Ctx)) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	if mutate != nil {
		mutate(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

// toolchainTestIsolate severs every ambient input this group reads. Without it
// these tests assert the developer's laptop, not the code.
func toolchainTestIsolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("seed home: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("SOPS_AGE_KEY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	// A path that deliberately does not exist: client-go skips unreadable files
	// in the KUBECONFIG precedence list, so this yields an empty kubeconfig
	// rather than the operator's real one.
	t.Setenv("KUBECONFIG", filepath.Join(dir, "no-such-kubeconfig"))
	return dir
}

func toolchainTestWriteKubeconfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	t.Setenv("KUBECONFIG", p)
	return p
}

func toolchainTestWriteFile(t *testing.T, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := os.Chmod(p, mode); err != nil { // defeat umask, which the mode test depends on
		t.Fatalf("chmod %s: %v", name, err)
	}
	return p
}

// toolchainTestText flattens a result so a test can assert that something was
// said — or, for the exec env case, that a secret was NOT said.
func toolchainTestText(r engine.Result) string {
	var b strings.Builder
	b.WriteString(r.Summary + "\n" + r.Remedy + "\n" + r.DoesNotProve + "\n")
	for _, d := range r.Detail {
		b.WriteString(d + "\n")
	}
	for _, e := range r.Evidence {
		b.WriteString(e.What + "\n" + e.Output + "\n")
	}
	return b.String()
}

func toolchainTestContains(t *testing.T, r engine.Result, want string) {
	t.Helper()
	if !strings.Contains(toolchainTestText(r), want) {
		t.Fatalf("%s: result never mentions %q\n  summary: %s\n  remedy: %s\n  detail: %v",
			r.ID, want, r.Summary, r.Remedy, r.Detail)
	}
}

// toolchainTestDiscovery stands in for a live API server. Embedding the
// interface (nil) means only ServerVersion is implemented, which is the only
// method toolchain.kubeconfig calls — and the harness's fake Kube carries a nil
// Discovery, so without this the check cannot be exercised at all.
type toolchainTestDiscovery struct {
	discovery.DiscoveryInterface
	info *version.Info
	err  error
}

func (d toolchainTestDiscovery) ServerVersion() (*version.Info, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.info, nil
}

func toolchainTestAPI(host string, info *version.Info, err error) func(*engine.Ctx) {
	return func(c *engine.Ctx) {
		c.Kube.Config = &rest.Config{Host: host}
		c.Kube.Discovery = toolchainTestDiscovery{info: info, err: err}
	}
}

// -------------------------------------------------------- toolchain.kubeconfig

// The check exists for exactly this state: nothing resolved, so every
// cluster-side check downstream is skipped and the run knows nothing. Reporting
// that as anything but a blocker would hand the operator a clean-looking report
// about a cluster budctl never contacted.
func TestToolchainKubeconfigBlocksWhenNoKubeconfigResolved(t *testing.T) {
	toolchainTestIsolate(t)
	r := toolchainTestRun(t, vanilla(), "toolchain.kubeconfig", func(c *engine.Ctx) {
		c.Kube = nil
	})
	assertStatus(t, r, "BLOCK")
	// A failure that does not name where it looked leaves the operator guessing
	// whether KUBECONFIG was honoured at all.
	toolchainTestContains(t, r, "no-such-kubeconfig")
	toolchainTestContains(t, r, "--kubeconfig")
}

// The loader's own error is the only thing that distinguishes "no such file"
// from "context not found" from "unparseable exec stanza". Dropping it makes
// all three read identically.
func TestToolchainKubeconfigSurfacesLoaderError(t *testing.T) {
	toolchainTestIsolate(t)
	r := toolchainTestRun(t, vanilla(), "toolchain.kubeconfig", func(c *engine.Ctx) {
		c.Kube = nil
		c.Set("kube.error", `context "prod" does not exist`)
	})
	assertStatus(t, r, "BLOCK")
	toolchainTestContains(t, r, `context "prod" does not exist`)
}

// A kubeconfig that parses but reaches nothing is just as fatal as no
// kubeconfig, and the remedy has to differ per cause — "check your kubeconfig"
// is a restatement, not a fix.
func TestToolchainKubeconfigBlocksWhenAPIDoesNotAnswer(t *testing.T) {
	const host = "https://api.ocp.example.com:6443"
	cases := []struct {
		name      string
		apiErr    string
		wantRemed string
	}{
		{
			name:      "connection refused points at the network path, not the credential",
			apiErr:    "Get \"" + host + "/version\": dial tcp 10.0.0.1:6443: connect: connection refused",
			wantRemed: "nothing is listening",
		},
		{
			name:      "x509 points at the CA bundle and TLS interception",
			apiErr:    "Get \"" + host + "/version\": x509: certificate signed by unknown authority",
			wantRemed: "certificate-authority-data",
		},
		{
			name:      "no such host points at DNS and the VPN",
			apiErr:    "Get \"" + host + "/version\": dial tcp: lookup api.ocp.example.com: no such host",
			wantRemed: "does not resolve",
		},
		{
			name:      "401 points at re-authentication, not at routing",
			apiErr:    "the server has asked for the client to provide credentials (Unauthorized)",
			wantRemed: "rejected this credential",
		},
		{
			// An OpenShift kubeconfig is written by `oc login` and carries an
			// OAuth token that expires (24h by default) — the common 401 there.
			name:      "401 names oc login for OpenShift's expiring tokens",
			apiErr:    "the server has asked for the client to provide credentials (Unauthorized)",
			wantRemed: "oc login",
		},
		{
			name:      "a failed exec plugin is named as the cause",
			apiErr:    "getting credentials: exec: executable aws not found",
			wantRemed: "credential plugin failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toolchainTestIsolate(t)
			r := toolchainTestRun(t, vanilla(), "toolchain.kubeconfig",
				toolchainTestAPI(host, nil, fmt.Errorf("%s", tc.apiErr)))
			assertStatus(t, r, "BLOCK")
			toolchainTestContains(t, r, host)
			toolchainTestContains(t, r, tc.wantRemed)
		})
	}
}

// The PASS case is what proves the BLOCK cases above are not passing by
// accident — the same code path, one live answer apart.
func TestToolchainKubeconfigPassesWhenAPIAnswers(t *testing.T) {
	toolchainTestIsolate(t)
	r := toolchainTestRun(t, vanilla(), "toolchain.kubeconfig",
		toolchainTestAPI("https://api.example.com:6443",
			&version.Info{GitVersion: "v1.30.4", Major: "1", Minor: "30"}, nil))
	assertStatus(t, r, "PASS")
	toolchainTestContains(t, r, "v1.30.4")
	// G3: a reachable API server is not permission to install, and the bound
	// has to travel with the pass or it will be read as one.
	if r.DoesNotProve == "" {
		t.Fatalf("toolchain.kubeconfig passed with no stated bound: %s", r.Summary)
	}
}

// ------------------------------------------------------- toolchain.exec-plugin

const toolchainTestExecKubeconfig = `apiVersion: v1
kind: Config
current-context: fake
clusters:
- name: c1
  cluster:
    server: https://api.example.com:6443
contexts:
- name: fake
  context:
    cluster: c1
    user: u1
users:
- name: u1
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: %s
      args: ["eks", "get-token", "--cluster-name", "bud"]
      env:
      - name: AWS_PROFILE
        value: %s
%s`

// The binary an exec stanza names is the one dependency a static budctl cannot
// absorb. Missing, every API call fails before it leaves the machine — and the
// error client-go produces reads like a credential problem, which is why this
// has to be reported as a missing binary by name.
func TestToolchainExecPluginBlocksWhenBinaryMissingFromPATH(t *testing.T) {
	dir := toolchainTestIsolate(t)
	empty := filepath.Join(dir, "empty-path")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("PATH", empty) // so a real `aws` on the developer's box cannot rescue this
	toolchainTestWriteKubeconfig(t, fmt.Sprintf(toolchainTestExecKubeconfig,
		"aws-iam-authenticator", "prod", ""))

	r := run(t, vanilla(), "toolchain.exec-plugin")
	assertStatus(t, r, "BLOCK")
	toolchainTestContains(t, r, "aws-iam-authenticator")
	toolchainTestContains(t, r, "install the AWS CLI") // a command, not "install the plugin"
}

// The kubeconfig's own installHint exists to be shown at exactly this moment;
// a generic remedy would discard the only cluster-specific instruction there is.
func TestToolchainExecPluginPrefersKubeconfigInstallHint(t *testing.T) {
	dir := toolchainTestIsolate(t)
	empty := filepath.Join(dir, "empty-path")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("PATH", empty)
	hint := "      installHint: run `make creds` in the platform repo\n"
	toolchainTestWriteKubeconfig(t, fmt.Sprintf(toolchainTestExecKubeconfig,
		"corp-kube-auth", "prod", hint))

	r := run(t, vanilla(), "toolchain.exec-plugin")
	assertStatus(t, r, "BLOCK")
	toolchainTestContains(t, r, "make creds")
}

// A path-qualified plugin that exists but is not executable is the everyday failure of
// a plugin copied out of a tarball or off a USB stick; "not on PATH" would be a
// lie about it, so the check must say what it actually found.
func TestToolchainExecPluginBlocksWhenPluginPathNotExecutable(t *testing.T) {
	toolchainTestIsolate(t)
	plugin := toolchainTestWriteFile(t, "corp-kube-auth", "#!/bin/sh\nexit 0\n", 0o644)
	toolchainTestWriteKubeconfig(t, fmt.Sprintf(toolchainTestExecKubeconfig, plugin, "prod", ""))

	r := run(t, vanilla(), "toolchain.exec-plugin")
	assertStatus(t, r, "BLOCK")
	toolchainTestContains(t, r, "not executable")
}

// PASS, and the security property that goes with it: an exec stanza routinely
// carries AWS_PROFILE next to a role ARN or a token, and this result is read
// aloud in support threads. Names may travel; values may not.
func TestToolchainExecPluginPassesAndWithholdsEnvValues(t *testing.T) {
	toolchainTestIsolate(t)
	const secret = "sekrit-profile-value"
	plugin := toolchainTestWriteFile(t, "aws", "#!/bin/sh\nexit 0\n", 0o755)
	toolchainTestWriteKubeconfig(t, fmt.Sprintf(toolchainTestExecKubeconfig, plugin, secret, ""))

	r := run(t, vanilla(), "toolchain.exec-plugin")
	assertStatus(t, r, "PASS")
	toolchainTestContains(t, r, "AWS_PROFILE")
	if strings.Contains(toolchainTestText(r), secret) {
		t.Fatalf("toolchain.exec-plugin leaked an exec env VALUE into its result: %v", r.Detail)
	}
	if r.DoesNotProve == "" {
		t.Fatalf("exec-plugin passed without stating that the plugin was never executed: %s", r.Summary)
	}
}

// Resolution through PATH is the common shape (a bare `aws`), and it must
// behave the same as a path-qualified command.
func TestToolchainExecPluginResolvesBareCommandThroughPATH(t *testing.T) {
	dir := toolchainTestIsolate(t)
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(bin, "gke-gcloud-auth-plugin")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatalf("chmod plugin: %v", err)
	}
	t.Setenv("PATH", bin)
	toolchainTestWriteKubeconfig(t, fmt.Sprintf(toolchainTestExecKubeconfig,
		"gke-gcloud-auth-plugin", "prod", ""))

	r := run(t, vanilla(), "toolchain.exec-plugin")
	assertStatus(t, r, "PASS")
	toolchainTestContains(t, r, p)
}

// D5: a static token or client certificate means this check looked at NOTHING.
// Reporting that as PASS would put a green line next to a question never asked.
func TestToolchainExecPluginSkipsForStaticCredential(t *testing.T) {
	toolchainTestIsolate(t)
	toolchainTestWriteKubeconfig(t, `apiVersion: v1
kind: Config
current-context: fake
clusters:
- name: c1
  cluster:
    server: https://api.example.com:6443
contexts:
- name: fake
  context:
    cluster: c1
    user: u1
users:
- name: u1
  user:
    token: static-service-account-token
`)
	assertSkipHasReason(t, run(t, vanilla(), "toolchain.exec-plugin"))
}

// --context can name a context this machine's kubeconfig does not carry. That
// is a fact about the run, not a credential-plugin verdict.
func TestToolchainExecPluginSkipsWhenSelectedContextAbsent(t *testing.T) {
	toolchainTestIsolate(t)
	toolchainTestWriteKubeconfig(t, `apiVersion: v1
kind: Config
current-context: other
clusters:
- name: c1
  cluster:
    server: https://api.example.com:6443
contexts:
- name: other
  context:
    cluster: c1
    user: u1
users:
- name: u1
  user:
    token: t
`)
	// The harness's Kube reports context "fake", which is what --context would
	// have selected; the file only knows "other".
	r := run(t, vanilla(), "toolchain.exec-plugin")
	assertSkipHasReason(t, r)
	toolchainTestContains(t, r, "fake")
}

// No kubeconfig at all: nothing to inspect, and nothing to claim either way.
func TestToolchainExecPluginSkipsWhenNoCurrentContext(t *testing.T) {
	toolchainTestIsolate(t)
	r := toolchainTestRun(t, vanilla(), "toolchain.exec-plugin", func(c *engine.Ctx) {
		c.Kube = nil // no resolved context to fall back on either
	})
	assertSkipHasReason(t, r)
}

// -------------------------------------------------------------- toolchain.clock

// toolchainTestRef is one HTTPS reference clock: what it claims the time is,
// or that it does not answer at all.
type toolchainTestRef struct {
	host string
	when string // "install" is the only scope the check is allowed to consult
	date time.Time
	dead bool
}

type toolchainTestClockRT struct{ refs map[string]toolchainTestRef }

func (rt toolchainTestClockRT) RoundTrip(req *http.Request) (*http.Response, error) {
	ref, ok := rt.refs[req.URL.Host]
	if !ok || ref.dead {
		return nil, fmt.Errorf("dial tcp: %s: connect: connection refused", req.URL.Host)
	}
	h := http.Header{}
	h.Set("Date", ref.date.UTC().Format(http.TimeFormat))
	return &http.Response{
		StatusCode: http.StatusUnauthorized, // registries answer /v2/ with 401; still a Date
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req,
	}, nil
}

// toolchainTestClock replaces the internet with a set of reference hosts whose
// clocks the test states outright. Without this the check would need real
// egress, and a network-dependent readiness test is the thing this suite exists
// to avoid.
func toolchainTestClock(now time.Time, refs ...toolchainTestRef) func(*engine.Ctx) {
	return func(c *engine.Ctx) {
		c.Clock = func() time.Time { return now }
		byHost := map[string]toolchainTestRef{}
		targets := []intake.EgressTarget{}
		for _, ref := range refs {
			byHost[ref.host] = ref
			when := ref.when
			if when == "" {
				when = "install"
			}
			targets = append(targets, intake.EgressTarget{
				URL: "https://" + ref.host + "/v2/", Label: ref.host, When: when,
			})
		}
		c.Profile.Egress = targets
		// The registry fallback would otherwise reach the real internet.
		c.Profile.Registries = nil
		c.OCI = nil
		c.Net.Client = &http.Client{Transport: toolchainTestClockRT{refs: byHost}, Timeout: time.Second}
	}
}

// 400s of skew is past the 120s hard band: OIDC and registry tokens carry
// exp/nbf windows of 60-300s, so this machine cannot authenticate anywhere and
// the errors it gets back read as rejected credentials.
func TestToolchainClockRisksWhenWorkstationIsAhead(t *testing.T) {
	toolchainTestIsolate(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r := toolchainTestRun(t, vanilla(), "toolchain.clock", toolchainTestClock(now,
		toolchainTestRef{host: "clock-a.example", date: now.Add(-400 * time.Second)},
		toolchainTestRef{host: "clock-b.example", date: now.Add(-402 * time.Second)},
	))
	assertStatus(t, r, "RISK")
	toolchainTestContains(t, r, "ahead of")
	toolchainTestContains(t, r, "hard band")
	toolchainTestContains(t, r, "set-ntp") // a runnable command, not "fix your clock"
}

// The direction has to be right or the operator chases the wrong machine.
func TestToolchainClockRisksWhenWorkstationIsBehind(t *testing.T) {
	toolchainTestIsolate(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r := toolchainTestRun(t, vanilla(), "toolchain.clock", toolchainTestClock(now,
		toolchainTestRef{host: "clock-a.example", date: now.Add(400 * time.Second)},
		toolchainTestRef{host: "clock-b.example", date: now.Add(398 * time.Second)},
	))
	assertStatus(t, r, "RISK")
	toolchainTestContains(t, r, "behind")
}

// One reference host with a broken clock of its own must not be enough to
// declare the operator's machine wrong: the check fails only when EVERY
// reference agrees. This is the case that separates a real skew from a bad NTP
// server on somebody else's CDN edge.
func TestToolchainClockPassesWhenOnlyOneReferenceDisagrees(t *testing.T) {
	toolchainTestIsolate(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r := toolchainTestRun(t, vanilla(), "toolchain.clock", toolchainTestClock(now,
		toolchainTestRef{host: "clock-a.example", date: now.Add(-9000 * time.Second)},
		toolchainTestRef{host: "clock-b.example", date: now},
	))
	assertStatus(t, r, "PASS")
}

func TestToolchainClockPassesWhenInTolerance(t *testing.T) {
	toolchainTestIsolate(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r := toolchainTestRun(t, vanilla(), "toolchain.clock", toolchainTestClock(now,
		toolchainTestRef{host: "clock-a.example", date: now.Add(-2 * time.Second)},
		toolchainTestRef{host: "clock-b.example", date: now.Add(1 * time.Second)},
	))
	assertStatus(t, r, "PASS")
	// G3 again: the workstation clock is not the one Keycloak token exp and S3
	// SigV4 depend on, and a pass that does not say so overstates itself.
	if !strings.Contains(r.DoesNotProve, "egress.clock-nodes") {
		t.Fatalf("clock pass does not hand the node-clock question to egress.clock-nodes: %q", r.DoesNotProve)
	}
}

// Only install-scoped HTTPS targets are a reference. A runtime-only host with a
// wild clock must be ignored — if it were consulted, this cluster would be
// reported as 2.5h out.
func TestToolchainClockIgnoresNonInstallTargets(t *testing.T) {
	toolchainTestIsolate(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r := toolchainTestRun(t, vanilla(), "toolchain.clock", toolchainTestClock(now,
		toolchainTestRef{host: "runtime-only.example", when: "runtime", date: now.Add(-9000 * time.Second)},
		toolchainTestRef{host: "clock-a.example", date: now},
	))
	assertStatus(t, r, "PASS")
	if strings.Contains(toolchainTestText(r), "runtime-only.example") {
		t.Fatalf("toolchain.clock consulted a runtime-scoped egress target: %v", r.Detail)
	}
}

// Air-gapped or egress-filtered: nothing answered, so the clock was compared to
// nothing. That is a SKIP naming the hosts tried, never a PASS — this is also
// the path a real `budctl` run takes with no internet, and the only one a unit
// test can reach for a check whose reference is the internet.
func TestToolchainClockSkipsWhenNoReferenceAnswers(t *testing.T) {
	toolchainTestIsolate(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	r := toolchainTestRun(t, vanilla(), "toolchain.clock", toolchainTestClock(now,
		toolchainTestRef{host: "clock-a.example", dead: true},
		toolchainTestRef{host: "clock-b.example", dead: true},
	))
	assertSkipHasReason(t, r)
	toolchainTestContains(t, r, "clock-a.example")
}

// No reference host configured at all is a different fact again, and it must
// still name itself rather than silently reporting nothing.
func TestToolchainClockSkipsWhenProfileHasNoReferenceHost(t *testing.T) {
	toolchainTestIsolate(t)
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	assertSkipHasReason(t, toolchainTestRun(t, vanilla(), "toolchain.clock", toolchainTestClock(now)))
}

func TestToolchainClockSkipsWithoutNetworkAdapter(t *testing.T) {
	toolchainTestIsolate(t)
	r := toolchainTestRun(t, vanilla(), "toolchain.clock", func(c *engine.Ctx) { c.Net = nil })
	assertSkipHasReason(t, r)
}

// ------------------------------------------------------- toolchain.age-identity

const toolchainTestSopsFile = `keycloak:
    adminPassword: ENC[AES256_GCM,data:Zm9vYmFy,iv:abc,tag:def,type:str]
sops:
    age:
        - recipient: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2026-01-01T00:00:00Z"
    version: 3.8.1
`

const toolchainTestAgeKey = "# created: 2026-01-01T00:00:00Z\n" +
	"# public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n" +
	"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n"

// Conditional by construction: with no --secrets there is nothing to decrypt,
// and blocking on a key nothing would use would be a failure the operator
// cannot act on. It is still a SKIP, not a PASS.
func TestToolchainAgeIdentitySkipsWithoutSecretsFile(t *testing.T) {
	toolchainTestIsolate(t)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = "" })
	assertSkipHasReason(t, run(t, f, "toolchain.age-identity"))
}

// --secrets naming a file this machine cannot read means every encrypted value
// the install depends on is unverifiable — the operator is about to install
// from values nobody has read.
func TestToolchainAgeIdentityBlocksWhenSecretsFileMissing(t *testing.T) {
	dir := toolchainTestIsolate(t)
	missing := filepath.Join(dir, "secrets.bud.yaml")
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = missing })
	r := run(t, f, "toolchain.age-identity")
	assertStatus(t, r, "BLOCK")
	toolchainTestContains(t, r, missing)
}

// The BLOCK this check exists for: a SOPS file is named, and this machine holds
// no identity capable of reading it.
func TestToolchainAgeIdentityBlocksWhenNoIdentityAnywhere(t *testing.T) {
	toolchainTestIsolate(t)
	secrets := toolchainTestWriteFile(t, "secrets.bud.yaml", toolchainTestSopsFile, 0o600)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = secrets })

	r := run(t, f, "toolchain.age-identity")
	assertStatus(t, r, "BLOCK")
	// Printing the recipients is what lets an operator see at a glance that they
	// hold the wrong key rather than no key.
	toolchainTestContains(t, r, "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
	toolchainTestContains(t, r, "keys.txt")
	// A private key must never be echoed, but the fact of the variables must be.
	toolchainTestContains(t, r, "SOPS_AGE_KEY unset")
}

// The trap: a keys.txt that exists and is empty, or holds only the comment
// header age-keygen writes. "The file exists" is not "an identity exists", and
// a check that stats the path would pass here.
func TestToolchainAgeIdentityBlocksOnCommentOnlyKeyFile(t *testing.T) {
	toolchainTestIsolate(t)
	keys := toolchainTestWriteFile(t, "keys.txt",
		"# created: 2026-01-01T00:00:00Z\n# public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n", 0o600)
	t.Setenv("SOPS_AGE_KEY_FILE", keys)
	secrets := toolchainTestWriteFile(t, "secrets.bud.yaml", toolchainTestSopsFile, 0o600)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = secrets })

	r := run(t, f, "toolchain.age-identity")
	assertStatus(t, r, "BLOCK")
	toolchainTestContains(t, r, "contains no AGE-SECRET-KEY-1 line")
}

// SOPS_AGE_KEY set to something that is not a key at all (a public key pasted
// by mistake is the usual shape) fails at render time otherwise.
func TestToolchainAgeIdentityBlocksWhenEnvKeyHoldsNoSecret(t *testing.T) {
	toolchainTestIsolate(t)
	t.Setenv("SOPS_AGE_KEY", "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
	secrets := toolchainTestWriteFile(t, "secrets.bud.yaml", toolchainTestSopsFile, 0o600)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = secrets })

	r := run(t, f, "toolchain.age-identity")
	assertStatus(t, r, "BLOCK")
	toolchainTestContains(t, r, "SOPS_AGE_KEY is set but holds no")
}

// A plaintext values file needs no identity. Saying so is honest; blocking on a
// key nothing would use is not — and it is a SKIP because nothing was verified.
func TestToolchainAgeIdentitySkipsForPlaintextSecretsFile(t *testing.T) {
	toolchainTestIsolate(t)
	plain := toolchainTestWriteFile(t, "values.yaml", "keycloak:\n  adminPassword: hunter2\n", 0o600)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = plain })
	assertSkipHasReason(t, run(t, f, "toolchain.age-identity"))
}

func TestToolchainAgeIdentityPassesFromEnvironmentKey(t *testing.T) {
	toolchainTestIsolate(t)
	t.Setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	secrets := toolchainTestWriteFile(t, "secrets.bud.yaml", toolchainTestSopsFile, 0o600)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = secrets })

	r := run(t, f, "toolchain.age-identity")
	assertStatus(t, r, "PASS")
	// Holding an identity is not holding the RIGHT identity; the pass has to say
	// so, because budctl never attempts a decrypt here.
	if r.DoesNotProve == "" {
		t.Fatalf("age-identity passed without bounding the claim: %s", r.Summary)
	}
	if strings.Contains(toolchainTestText(r), "AGE-SECRET-KEY-1QQQ") {
		t.Fatalf("age-identity echoed the private key into its result: %v", r.Detail)
	}
}

// The key file is found where sops itself looks, and a world-readable private
// key on a shared workstation is said out loud — as a note, because it does not
// stop the decrypt.
func TestToolchainAgeIdentityPassesFromHomeAndNotesLooseMode(t *testing.T) {
	dir := toolchainTestIsolate(t)
	ageDir := filepath.Join(dir, "home", ".config", "sops", "age")
	if err := os.MkdirAll(ageDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	keys := filepath.Join(ageDir, "keys.txt")
	if err := os.WriteFile(keys, []byte(toolchainTestAgeKey), 0o644); err != nil {
		t.Fatalf("write keys.txt: %v", err)
	}
	if err := os.Chmod(keys, 0o644); err != nil {
		t.Fatalf("chmod keys.txt: %v", err)
	}
	secrets := toolchainTestWriteFile(t, "secrets.bud.yaml", toolchainTestSopsFile, 0o600)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = secrets })

	r := run(t, f, "toolchain.age-identity")
	assertStatus(t, r, "PASS")
	toolchainTestContains(t, r, keys)
	toolchainTestContains(t, r, "group/world readable")
}

// A plugin in interactive mode blocks on an SSO prompt. Passing silently would
// send an operator to run `budctl check` from CI, where it hangs until the job
// times out with nothing to show for it.
func TestToolchainExecPluginWarnsAboutInteractivePlugins(t *testing.T) {
	toolchainTestIsolate(t)
	plugin := toolchainTestWriteFile(t, "kubelogin", "#!/bin/sh\nexit 0\n", 0o755)
	toolchainTestWriteKubeconfig(t, fmt.Sprintf(toolchainTestExecKubeconfig, plugin, "prod", "")+
		"      interactiveMode: Always\n")

	r := run(t, vanilla(), "toolchain.exec-plugin")
	assertStatus(t, r, "PASS")
	toolchainTestContains(t, r, "interactiveMode=Always")
}

// budctl must never EXECUTE the credential plugin: one in interactive mode
// would block on an SSO prompt, and a readiness check that hangs is worse than
// one that fails. LookPath proves the binary exists; toolchain.kubeconfig is
// what actually exercises it, through client-go, against the API server.
func TestToolchainExecPluginNeverExecutesThePlugin(t *testing.T) {
	dir := toolchainTestIsolate(t)
	marker := filepath.Join(dir, "plugin-ran")
	plugin := filepath.Join(dir, "corp-kube-auth")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	if err := os.WriteFile(plugin, []byte(script), 0o755); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	if err := os.Chmod(plugin, 0o755); err != nil {
		t.Fatalf("chmod plugin: %v", err)
	}
	toolchainTestWriteKubeconfig(t, fmt.Sprintf(toolchainTestExecKubeconfig, plugin, "prod", ""))

	assertStatus(t, run(t, vanilla(), "toolchain.exec-plugin"), "PASS")
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("toolchain.exec-plugin executed the credential plugin; an interactive plugin would hang the run here")
	}
}

// CHARACTERIZATION TEST — this pins behaviour that is WRONG, reported rather
// than fixed (this file may not edit toolchain.go).
//
// toolchainAgeKeyPaths() documents itself as "where sops itself looks, IN
// ORDER", but it returns Sorted(...), which alphabetises. sops reads
// SOPS_AGE_KEY_FILE before the user config dir; budctl picks whichever path
// sorts first. With a stale personal ~/.config/sops/age/keys.txt and
// SOPS_AGE_KEY_FILE pointing at the team key — the exact setup an operator
// reaches for when their own key is not a recipient — budctl reports a PASS
// naming the personal file, the render then fails on a key mismatch, and the
// operator is holding a report that pointed them at the wrong file.
//
// When the precedence is fixed, this test SHOULD fail: change it to expect the
// SOPS_AGE_KEY_FILE path.
func TestToolchainAgeIdentitySearchOrderIgnoresSopsPrecedence(t *testing.T) {
	dir := toolchainTestIsolate(t)
	ageDir := filepath.Join(dir, "home", ".config", "sops", "age")
	if err := os.MkdirAll(ageDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	homeKeys := filepath.Join(ageDir, "keys.txt")
	if err := os.WriteFile(homeKeys, []byte(toolchainTestAgeKey), 0o600); err != nil {
		t.Fatalf("write home keys: %v", err)
	}
	// Sorts after the home path, so alphabetical order and sops order disagree.
	envKeys := filepath.Join(dir, "zteam-keys.txt")
	if err := os.WriteFile(envKeys, []byte(toolchainTestAgeKey), 0o600); err != nil {
		t.Fatalf("write team keys: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY_FILE", envKeys)
	secrets := toolchainTestWriteFile(t, "secrets.bud.yaml", toolchainTestSopsFile, 0o600)
	f := vanilla().withOpts(func(o *engine.Options) { o.SecretsFile = secrets })

	r := run(t, f, "toolchain.age-identity")
	assertStatus(t, r, "PASS")
	if !strings.Contains(r.Summary, homeKeys) {
		t.Fatalf("age key precedence changed — if SOPS_AGE_KEY_FILE now wins, this test has been fixed and should assert %s: %s", envKeys, r.Summary)
	}
	t.Logf("KNOWN DEFECT: sops would decrypt with %s, budctl reports %s", envKeys, homeKeys)
}
