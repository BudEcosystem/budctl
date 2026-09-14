package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/internal/engine"
	"k8s.io/client-go/rest"
)

// The config group is the only group that judges the operator's intent rather
// than the cluster, so every fixture here is a file on disk. Two properties are
// load-bearing and are asserted throughout:
//
//   - without --values the whole group must SKIP *with a reason*: silence here
//     would read as "your values are fine" when nothing was ever looked at;
//   - the merged tree, not the operator's file, is what the install sees. A
//     collision or a placeholder that only exists once the chart's own defaults
//     are layered underneath is the failure mode these checks exist for, and it
//     is invisible in any single file.

// configTestIDs is every id the group registers. The skip table below runs all
// of them, so a check added without a skip reason fails immediately.
var configTestIDs = []string{
	"config.render",
	"config.dry-run",
	"config.required-values",
	"config.fail-closed",
	"config.public-defaults",
	"config.placeholders",
	"config.valkey-indexes",
}

// configTestValues writes one values file and returns its path.
func configTestValues(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write values: %v", err)
	}
	return p
}

// configTestChart writes a chart small enough to render in a unit test but real
// enough to exercise the render path end to end: it carries a `fail` guard of
// the shape the umbrella chart uses for the budevent AES key, and one workload
// so the image inventory config.render publishes is non-empty.
//
// extraValues is layered into the chart's OWN values.yaml, which is what makes
// the "partial override against a chart default" fixtures possible. It must not
// redeclare daprExtra (YAML rejects the duplicate key).
func configTestChart(t *testing.T, extraValues string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	write("Chart.yaml", "apiVersion: v2\nname: bud\nversion: 0.1.0\n")
	write("values.yaml", "daprExtra:\n  crypto:\n    budeventCryptoKey: \"\"\n"+extraValues)
	write("templates/bud.yaml", `
{{- $key := .Values.daprExtra.crypto.budeventCryptoKey | default "" }}
{{- if eq (len $key) 0 }}
{{- fail "daprExtra.crypto.budeventCryptoKey is required (exactly 32 bytes, AES-256); set it in the SOPS-encrypted secrets file" }}
{{- end }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-crypto
  namespace: {{ .Release.Namespace }}
data:
  key: {{ $key | quote }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-budapp
  namespace: {{ .Release.Namespace }}
spec:
  template:
    spec:
      containers:
        - name: budapp
          image: registry.bud.studio/budapp:1.2.3
`)
	return dir
}

// configTestCluster is the only cluster shape this group needs: the checks read
// files, not the API server.
func configTestCluster(valuesFiles ...string) *fakeCluster {
	return vanilla().withOpts(func(o *engine.Options) { o.ValuesFiles = valuesFiles })
}

// configTestText flattens everything the operator would actually read, so an
// assertion can state "the report names both colliding consumers" rather than
// caring which field carried it.
func configTestText(r engine.Result) string {
	parts := []string{r.Summary, r.Remedy, r.DoesNotProve}
	parts = append(parts, r.Detail...)
	for _, e := range r.Evidence {
		parts = append(parts, e.What, e.Output)
	}
	return strings.Join(parts, "\n")
}

func configTestMentions(t *testing.T, r engine.Result, needles ...string) {
	t.Helper()
	got := configTestText(r)
	for _, n := range needles {
		if !strings.Contains(got, n) {
			t.Fatalf("%s [%s]: report never names %q\n---\n%s", r.ID, r.Status(), n, got)
		}
	}
}

// configTestRunCtx runs one check against a hand-built context, for the two
// cases the shared harness cannot express: no cluster at all, and a cluster
// whose API server does not answer.
func configTestRunCtx(t *testing.T, c *engine.Ctx, id string) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

// ---------------------------------------------------------------- inactive

// Without --values there is nothing to judge, and the group must say so. A
// silent PASS here would be the worst outcome in the tool: an operator reading
// a green config section would believe their values had been checked.
func TestConfigGroupSkipsWithReasonWhenNoValuesSupplied(t *testing.T) {
	for _, id := range configTestIDs {
		t.Run(id, func(t *testing.T) {
			r := run(t, vanilla(), id)
			assertSkipHasReason(t, r)
			configTestMentions(t, r, "--values")
		})
	}
}

// A values file that cannot be parsed is not a values file that is fine. Every
// content check must refuse to judge rather than report the empty tree it got.
func TestConfigContentChecksSkipWhenValuesCannotBeParsed(t *testing.T) {
	vals := configTestValues(t, "appApiToken: [unclosed\n  : :\n")
	f := configTestCluster(vals)
	for _, id := range []string{"config.required-values", "config.fail-closed", "config.public-defaults", "config.placeholders", "config.valkey-indexes"} {
		t.Run(id, func(t *testing.T) {
			assertSkipHasReason(t, run(t, f, id))
		})
	}
}

// ---------------------------------------------------------------- config.render

// The chart's guards fire at render time, which under GitOps means at sync time
// in a cluster nobody is watching. This is the fixture from TEST_CASES:
// a missing budeventCryptoKey must stop the run here, not in an ArgoCD event.
func TestConfigRenderBlocksWhenChartGuardFires(t *testing.T) {
	chart := configTestChart(t, "")
	vals := configTestValues(t, "domain: bud.example.com\n")
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })

	r := run(t, f, "config.render")
	assertStatus(t, r, "BLOCK")
	// The chart's own message is the only actionable part of a Helm error, so
	// it has to survive into the report.
	configTestMentions(t, r, "budeventCryptoKey is required", "helm template bud")
}

// The failing case above must not be passing by accident: the same chart, the
// same run, one value supplied.
func TestConfigRenderPassesWhenTheGuardIsSatisfied(t *testing.T) {
	chart := configTestChart(t, "")
	vals := configTestValues(t, "daprExtra:\n  crypto:\n    budeventCryptoKey: \"0123456789abcdef0123456789abcdef\"\n")
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })

	r := run(t, f, "config.render")
	assertStatus(t, r, "PASS")
	// Release and namespace are not cosmetic: every fullname-derived reference
	// between services is derived from them, so rendering under anything else
	// would validate a manifest that is never applied.
	configTestMentions(t, r, "release bud in namespace bud")
	if r.DoesNotProve == "" {
		t.Fatalf("config.render passed without bounding the claim: client-side templating is not an API-server accept")
	}
}

// DEFECT (implementation, not test): cfgGuardText matches only text/template's
// raw "error calling fail: " / "error calling required: " wrapper. Helm 3
// rewrites both through cleanUpExecError into "execution error at
// (chart/templates/x.yaml:4:4): <msg>", so the guard branch never runs: the
// summary loses the chart's instruction and the remedy stops pointing at the
// SOPS secrets file. The message survives only because the raw error is kept as
// evidence. This test pins the current behaviour so the fix is visible as a
// change here.
func TestConfigRenderDropsTheChartsOwnGuardMessageFromTheSummary(t *testing.T) {
	helmFailError := "execution error at (bud/templates/bud.yaml:4:4): daprExtra.crypto.budeventCryptoKey is required (exactly 32 bytes, AES-256)"
	if got := cfgGuardText(helmFailError); got != "" {
		t.Fatalf("cfgGuardText now understands Helm's cleaned error (%q) — update config.render's expectations too", got)
	}
	helmRequiredError := "execution error at (bud/templates/bud.yaml:6:8): microservices.rsaKeys.privateKey is required"
	if got := cfgGuardText(helmRequiredError); got != "" {
		t.Fatalf("cfgGuardText now understands Helm's cleaned `required` error (%q)", got)
	}

	chart := configTestChart(t, "")
	vals := configTestValues(t, "domain: bud.example.com\n")
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })
	r := run(t, f, "config.render")
	assertStatus(t, r, "BLOCK")
	if strings.Contains(r.Remedy, "secrets.<env>.yaml") {
		t.Fatalf("the guard branch now fires — good; this test documented that it did not")
	}
}

// Nothing downstream can be judged from values that do not parse, and that is a
// blocker rather than a skip: the file the operator is about to hand ArgoCD is
// broken on its face.
func TestConfigRenderBlocksOnUnparseableValues(t *testing.T) {
	chart := configTestChart(t, "")
	vals := configTestValues(t, "appApiToken: [unclosed\n  : :\n")
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })

	r := run(t, f, "config.render")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "cannot be parsed")
}

// DEFECT (implementation): a genuinely SOPS-encrypted secrets file that budctl
// cannot decrypt — no age identity on this host, the normal case for anyone but
// the file's recipients — is reported as a BLOCK claiming the values are
// broken, which flips the whole run to NOT READY on a fact never established.
// D5 says an unlooked-at thing is a SKIP. Note also that the `len(vs.Cipher)>0`
// SKIP branch in config.render/config.dry-run, and the "still SOPS ciphertext"
// paths in config.required-values and config.public-defaults, are unreachable
// through a file: adapters.SOPS routes anything containing "ENC[" into a real
// decrypt, so ciphertext either becomes plaintext or becomes this error, and
// never reaches the value tree as an ENC[...] string.
func TestConfigRenderBlocksWhenAnEncryptedSecretsFileCannotBeDecrypted(t *testing.T) {
	chart := configTestChart(t, "")
	secrets := configTestValues(t, "appApiToken: ENC[AES256_GCM,data:abc,type:str]\nsops:\n    version: 3.8.1\n")
	f := vanilla().withOpts(func(o *engine.Options) {
		o.ChartDir = chart
		o.ValuesFiles = []string{secrets}
	})

	r := run(t, f, "config.render")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "age identity")

	// config.dry-run gets this one right: it defers to config.render instead of
	// reporting a second blocker for the same file.
	assertSkipHasReason(t, run(t, f, "config.dry-run"))
}

func TestConfigRenderSkipsWithReasonWithoutChart(t *testing.T) {
	vals := configTestValues(t, "domain: bud.example.com\n")
	r := run(t, configTestCluster(vals), "config.render")
	assertSkipHasReason(t, r)
	configTestMentions(t, r, "--chart")
}

// ---------------------------------------------------------------- config.dry-run

func TestConfigDryRunSkipsWithReasonWithoutChart(t *testing.T) {
	vals := configTestValues(t, "domain: bud.example.com\n")
	r := run(t, configTestCluster(vals), "config.dry-run")
	assertSkipHasReason(t, r)
	configTestMentions(t, r, "--chart")
}

// A server-side dry run is validated by the API server. With no cluster there
// is no one to ask, and the check must say that rather than assume.
func TestConfigDryRunSkipsWithReasonWhenClusterUnreachable(t *testing.T) {
	chart := configTestChart(t, "")
	vals := configTestValues(t, "daprExtra:\n  crypto:\n    budeventCryptoKey: \"0123456789abcdef0123456789abcdef\"\n")
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })

	c := f.ctx(t)
	c.Kube = nil
	r := configTestRunCtx(t, c, "config.dry-run")
	assertSkipHasReason(t, r)
}

func TestConfigDryRunSkipsWhenTheChartCannotBeLoaded(t *testing.T) {
	vals := configTestValues(t, "domain: bud.example.com\n")
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = t.TempDir() }) // no Chart.yaml
	assertSkipHasReason(t, run(t, f, "config.dry-run"))
}

// DEFECT (implementation): an API server that never answered is reported as one
// that *rejected the manifest* — "the sync will fail at apply time even though
// the template is valid" — which is a claim about a cluster budctl never
// reached. cfgDryRunFailure has no unreachable/timeout class, so the connection
// error falls through to the default BLOCK. Per D5 this belongs in the same
// family as the RBAC-refused case just above it, which correctly SKIPs.
//
// This is also the only way to drive config.dry-run to a failure without a live
// API server, so it doubles as the group's proof that the check can fail at all.
func TestConfigDryRunReportsAnUnreachableAPIServerAsAManifestRejection(t *testing.T) {
	chart := configTestChart(t, "")
	vals := configTestValues(t, "daprExtra:\n  crypto:\n    budeventCryptoKey: \"0123456789abcdef0123456789abcdef\"\n")
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })

	c := f.ctx(t)
	// Discovery is what Helm asks for the cluster's capabilities; the shared
	// harness leaves it nil because no other check needs it.
	c.Kube.Discovery = c.Kube.Clientset.Discovery()
	c.Kube.Config = &rest.Config{Host: "https://127.0.0.1:1"} // nothing listens here

	r := configTestRunCtx(t, c, "config.dry-run")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "cluster unreachable")
	if !strings.Contains(r.Summary, "The API server rejects") && !strings.Contains(r.Summary, "the API server rejects") {
		t.Fatalf("config.dry-run no longer misattributes an unreachable cluster — update this test: %s", r.Summary)
	}
}

// cfgDryRunFailure decides, for every dry-run error, whether budctl owns the
// finding or is merely unable to answer. Getting it wrong in either direction
// is a lie: a refused dry run reported as a blocker, or a real admission denial
// reported as a skip.
func TestConfigDryRunFailureClassification(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want cfgDryRunClass
	}{
		{"namespace absent is not a manifest problem",
			`create: failed to create: namespaces "bud" not found`, cfgDryNoNamespace},
		{"RBAC refusal is not a rejection of the manifest",
			`configmaps is forbidden: User "dev" cannot create resource "configmaps"`, cfgDryForbidden},
		{"an unowned object already in the cluster will break the sync at apply time",
			`rendered manifests contain a resource that already exists: Secret "bud-registry" in namespace "bud" cannot be imported into the current release: invalid ownership metadata`, cfgDryConflict},
		{"a policy webhook denial is a real blocker the API server owns",
			`admission webhook "validation.gatekeeper.sh" denied the request: container has no resource limits`, cfgDryWebhook},
		{"a parse-time template error belongs to config.render",
			`template: bud/templates/bud.yaml:4: function "fial" not defined`, cfgDryTemplate},
		{"an API server message that merely mentions a pod template is not a template error",
			`Deployment in version "v1" cannot be handled: spec.template.spec.containers[0].image: Required value`, cfgDryOther},
		// DEFECT: Helm rewrites `fail`/`required` into "execution error at
		// (...)", which matches neither cfgGuardText nor the "template:"
		// prefix. A chart guard firing during a server-side dry run is
		// therefore reported as an API-server rejection instead of deferring
		// to config.render.
		{"a chart guard during dry-run is misclassified as an API server rejection",
			`execution error at (bud/templates/bud.yaml:4:4): daprExtra.crypto.budeventCryptoKey is required`, cfgDryOther},
		// DEFECT: no class for "never reached the cluster".
		{"an unreachable cluster is misclassified as an API server rejection",
			`Kubernetes cluster unreachable: Get "https://10.0.0.1:6443/version": dial tcp 10.0.0.1:6443: i/o timeout`, cfgDryOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfgDryRunFailure(tc.raw); got != tc.want {
				t.Fatalf("cfgDryRunFailure(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------- config.required-values

// The budevent AES key and the RSA keypair have no safe default. The keypair in
// particular has NO chart guard at all: blank renders an empty Secret, every
// service starts, and the first credential decryption fails hours later in a
// service log. That silence is the whole reason this check exists.
func TestConfigRequiredValuesBlocksWhenCredentialsAreMissing(t *testing.T) {
	vals := configTestValues(t, "domain: bud.example.com\n")
	r := run(t, configTestCluster(vals), "config.required-values")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r,
		"daprExtra.crypto.budeventCryptoKey",
		"microservices.rsaKeys.privateKey",
		"microservices.rsaKeys.publicKey",
		"microservices.rsaKeys.privateKeyPassword",
	)
	// Re-minting the budevent key per render orphans every stored connector
	// credential, so the remedy must not read as "just generate one each time".
	configTestMentions(t, r, "must NOT be re-minted")
}

// A key of the wrong length fails the chart's own 32-byte guard at render time.
// Reporting it as present would be worse than not checking: the operator would
// go looking somewhere else.
func TestConfigRequiredValuesBlocksOnAWrongLengthCryptoKey(t *testing.T) {
	vals := configTestValues(t, `
daprExtra:
  crypto:
    budeventCryptoKey: "0123456789abcdef0123456789abcde"
microservices:
  rsaKeys:
    privateKey: "rsa-private-key-fixture"
    publicKey: "rsa-public-key-fixture"
    privateKeyPassword: "s3cret"
`)
	r := run(t, configTestCluster(vals), "config.required-values")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "31 bytes, not 32")
}

// The token is required only while the feature is on, and the chart says so in
// as many words — so the check must read the flag rather than the key.
func TestConfigRequiredValuesBlocksWhenDefaultClusterRegistrationHasNoToken(t *testing.T) {
	vals := configTestValues(t, `
daprExtra:
  crypto:
    budeventCryptoKey: "0123456789abcdef0123456789abcdef"
microservices:
  rsaKeys:
    privateKey: "rsa-private-key-fixture"
    publicKey: "rsa-public-key-fixture"
    privateKeyPassword: "s3cret"
  budcluster:
    registerDefaultCluster:
      enabled: true
      token: ""
`)
	r := run(t, configTestCluster(vals), "config.required-values")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "registerDefaultCluster.token")
}

func TestConfigRequiredValuesPassesWhenEverythingIsSupplied(t *testing.T) {
	vals := configTestValues(t, `
daprExtra:
  crypto:
    budeventCryptoKey: "0123456789abcdef0123456789abcdef"
microservices:
  rsaKeys:
    privateKey: "rsa-private-key-fixture"
    publicKey: "rsa-public-key-fixture"
    privateKeyPassword: "s3cret"
  budcluster:
    registerDefaultCluster:
      enabled: false
`)
	r := run(t, configTestCluster(vals), "config.required-values")
	assertStatus(t, r, "PASS")
	configTestMentions(t, r, "registerDefaultCluster is disabled")
}

// budevent off means its vault key is not required. A check that demanded it
// anyway would block an install that would have worked.
func TestConfigRequiredValuesDoesNotDemandTheCryptoKeyWhenBudeventIsOff(t *testing.T) {
	vals := configTestValues(t, `
microservices:
  budevent:
    enabled: false
  rsaKeys:
    privateKey: "rsa-private-key-fixture"
    publicKey: "rsa-public-key-fixture"
    privateKeyPassword: "s3cret"
  budcluster:
    registerDefaultCluster:
      enabled: false
`)
	r := run(t, configTestCluster(vals), "config.required-values")
	assertStatus(t, r, "PASS")
	if strings.Contains(configTestText(r), "budeventCryptoKey") {
		t.Fatalf("the budevent key was demanded with budevent disabled: %s", configTestText(r))
	}
}

// ---------------------------------------------------------------- config.fail-closed

// Blank is the chart's deliberate default and the install still reports
// success — which is exactly why a blank one must be named. This is the
// TEST_CASES fixture: live workflow progress is silently off.
func TestConfigFailClosedRisksWhenRealtimeGrantSecretIsBlank(t *testing.T) {
	vals := configTestValues(t, `
realtimeGrantSecret: ""
widgetInternalToken: "widget-token"
resolveInternalToken: "resolve-token"
`)
	r := run(t, configTestCluster(vals), "config.fail-closed")
	assertStatus(t, r, "RISK")
	// Naming the secret is not enough; the report has to say what stops working.
	configTestMentions(t, r, "realtimeGrantSecret", "live workflow progress")
	// The two that ARE set must be reported as such, or the operator cannot
	// tell a deliberate blank from an unexamined one.
	configTestMentions(t, r, "provisioned: ")
}

// A key present but holding only whitespace is blank as far as every consumer
// is concerned; reading it as "set" would hide the same outage.
func TestConfigFailClosedTreatsWhitespaceAsBlank(t *testing.T) {
	vals := configTestValues(t, "realtimeGrantSecret: \"   \"\nwidgetInternalToken: \"w\"\nresolveInternalToken: \"r\"\n")
	assertStatus(t, run(t, configTestCluster(vals), "config.fail-closed"), "RISK")
}

// All three blank is the chart's own default, so this must be a RISK rather
// than a PASS — otherwise a stock install reads as fully provisioned.
func TestConfigFailClosedRisksWhenAllThreeAreBlank(t *testing.T) {
	vals := configTestValues(t, "domain: bud.example.com\n")
	r := run(t, configTestCluster(vals), "config.fail-closed")
	assertStatus(t, r, "RISK")
	configTestMentions(t, r, "realtimeGrantSecret", "widgetInternalToken", "resolveInternalToken",
		"none of the three is provisioned")
}

func TestConfigFailClosedPassesWhenAllThreeAreProvisioned(t *testing.T) {
	vals := configTestValues(t, `
realtimeGrantSecret: "3d1f9a"
widgetInternalToken: "widget-token"
resolveInternalToken: "resolve-token"
`)
	r := run(t, configTestCluster(vals), "config.fail-closed")
	assertStatus(t, r, "PASS")
	// A non-empty token is not proof it matches the consumer's copy, and the
	// pass must not be read as more than it verified.
	if r.DoesNotProve == "" {
		t.Fatalf("config.fail-closed passed without bounding the claim")
	}
}

// ---------------------------------------------------------------- config.public-defaults

// The TEST_CASES fixture: this exact string is in a public git repository, so
// anyone with the URL holds budapp's /internal/* credential minter.
func TestConfigPublicDefaultsRisksWhenAppApiTokenIsThePublishedValue(t *testing.T) {
	vals := configTestValues(t, "appApiToken: \"PRAJKQIzAsDNvHIrYALkTiwm5t6VNmnW\"\n")
	r := run(t, configTestCluster(vals), "config.public-defaults")
	assertStatus(t, r, "RISK")
	configTestMentions(t, r, "appApiToken", "credential minter", "byte-identical")
	// The credential is already public, but a report gets pasted into tickets:
	// it must not be reproduced in full.
	if strings.Contains(configTestText(r), "PRAJKQIzAsDNvHIrYALkTiwm5t6VNmnW") {
		t.Fatalf("the full credential was reproduced in the report:\n%s", configTestText(r))
	}
}

// The dangerous ones are buried several levels down in microservices.global.env,
// where a check reading only top-level keys would never look.
func TestConfigPublicDefaultsRisksOnNestedCredentials(t *testing.T) {
	vals := configTestValues(t, `
microservices:
  global:
    env:
      SUPER_USER_PASSWORD: "root@example.com"
      PASSWORD_SALT: "pL4eVOkzsLEKc25T69UCvjXvK0BxgghwzSpEE9wBbUMNezEODv0s7tWcrhEeQyCh"
`)
	r := run(t, configTestCluster(vals), "config.public-defaults")
	assertStatus(t, r, "RISK")
	configTestMentions(t, r,
		"microservices.global.env.SUPER_USER_PASSWORD",
		"microservices.global.env.PASSWORD_SALT",
		"rainbow table")
}

func TestConfigPublicDefaultsPassesOnceRotated(t *testing.T) {
	vals := configTestValues(t, `
appApiToken: "rotated-not-the-published-one"
microservices:
  global:
    env:
      SUPER_USER_PASSWORD: "rotated"
`)
	r := run(t, configTestCluster(vals), "config.public-defaults")
	assertStatus(t, r, "PASS")
	// An overridden credential is not necessarily a strong or unique one.
	if r.DoesNotProve == "" {
		t.Fatalf("config.public-defaults passed without bounding the claim")
	}
}

// ArgoCD layers the SOPS secrets file FIRST and the --values files on top
// (infra/appsets/*.yaml). Judging them in the other order would report a
// credential the install never sees.
func TestConfigPublicDefaultsHonoursTheArgoCDLayerOrder(t *testing.T) {
	published := "appApiToken: \"PRAJKQIzAsDNvHIrYALkTiwm5t6VNmnW\"\n"
	rotated := "appApiToken: \"rotated-per-environment\"\n"

	t.Run("an environment file overriding the secrets file wins", func(t *testing.T) {
		secrets := configTestValues(t, published)
		vals := configTestValues(t, rotated)
		f := vanilla().withOpts(func(o *engine.Options) {
			o.SecretsFile = secrets
			o.ValuesFiles = []string{vals}
		})
		assertStatus(t, run(t, f, "config.public-defaults"), "PASS")
	})

	t.Run("an environment file that reinstates the published value is caught", func(t *testing.T) {
		secrets := configTestValues(t, rotated)
		vals := configTestValues(t, published)
		f := vanilla().withOpts(func(o *engine.Options) {
			o.SecretsFile = secrets
			o.ValuesFiles = []string{vals}
		})
		assertStatus(t, run(t, f, "config.public-defaults"), "RISK")
	})
}

// ---------------------------------------------------------------- config.placeholders

// The TEST_CASES fixture. A placeholder registry login is a blocker on its own:
// the pull secret renders, every first-party image 401s, and each pod sits in
// ImagePullBackOff reporting nothing about credentials.
func TestConfigPlaceholdersBlocksOnARegistryCredential(t *testing.T) {
	vals := configTestValues(t, `
registries:
  registry.bud.studio:
    username: getmefrombud
    password: getmefrombud
`)
	r := run(t, configTestCluster(vals), "config.placeholders")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "registries.registry.bud.studio.password", "ImagePullBackOff")
}

// The realistic shape: the operator's file overrides the username and forgets
// the password, so the placeholder survives only in the merged tree. A check
// reading the operator's file alone would pass this.
func TestConfigPlaceholdersFindsAChartDefaultLeftUnoverridden(t *testing.T) {
	chart := configTestChart(t, `
registries:
  registry.bud.studio:
    username: getmefrombud
    password: getmefrombud
`)
	vals := configTestValues(t, `
registries:
  registry.bud.studio:
    username: bud-customer-42
`)
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })

	r := run(t, f, "config.placeholders")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "registries.registry.bud.studio.password")
	if strings.Contains(configTestText(r), "registries.registry.bud.studio.username") {
		t.Fatalf("an overridden key was still reported as a placeholder:\n%s", configTestText(r))
	}
}

// A placeholder outside the registry map does not stop the install; it
// misconfigures one feature, which is a different verdict and a different
// remedy. Both marker spellings this repository ships are exercised, including
// the suffixed one an enumerated list of exact strings would miss.
func TestConfigPlaceholdersRisksOnNonRegistryValues(t *testing.T) {
	vals := configTestValues(t, `
microservices:
  global:
    env:
      NOVU_API_KEY: "<change_me>"
      SOME_SECRET: "CHANGE_ME_4HCzQp"
`)
	r := run(t, configTestCluster(vals), "config.placeholders")
	assertStatus(t, r, "RISK")
	configTestMentions(t, r,
		"microservices.global.env.NOVU_API_KEY",
		"microservices.global.env.SOME_SECRET")
}

func TestConfigPlaceholdersPassesWhenNoneRemain(t *testing.T) {
	vals := configTestValues(t, `
registries:
  registry.bud.studio:
    username: bud-customer-42
    password: "s3cret"
`)
	r := run(t, configTestCluster(vals), "config.placeholders")
	assertStatus(t, r, "PASS")
	// A stand-in the operator invented is indistinguishable from a credential,
	// and the pass must say so.
	if r.DoesNotProve == "" {
		t.Fatalf("config.placeholders passed without bounding the claim")
	}
}

// ---------------------------------------------------------------- config.valkey-indexes

// The TEST_CASES fixture, and a real bug found in values.ditto.yaml: two
// logical uses on index 11 share one keyspace and evict each other's keys.
func TestConfigValkeyIndexesBlocksWhenTwoUsesShareOneIndex(t *testing.T) {
	vals := configTestValues(t, `
externalServices:
  valkey:
    databases:
      config_store: 11
      state_store: 4
      budcodeinterpreter: 11
`)
	r := run(t, configTestCluster(vals), "config.valkey-indexes")
	assertStatus(t, r, "BLOCK")
	// Naming only the index would leave the operator diffing the file by hand.
	configTestMentions(t, r, "index 11", "budcodeinterpreter", "config_store")
}

// The collision that matters is never visible in one file: values.ditto.yaml
// renumbers config_store to 11 and leaves budcodeinterpreter at the chart
// default of 11. Reading the operator's file alone reports a clean run.
func TestConfigValkeyIndexesBlocksOnAPartialOverrideAgainstChartDefaults(t *testing.T) {
	chart := configTestChart(t, `
externalServices:
  valkey:
    databases:
      config_store: 3
      state_store: 4
      novu: 5
      budgateway: 6
      mcpgateway: 7
      budprompt: 8
      global: 9
      onyx: 10
      budcodeinterpreter: 11
`)
	vals := configTestValues(t, `
externalServices:
  valkey:
    databases:
      config_store: 11
`)
	f := configTestCluster(vals).withOpts(func(o *engine.Options) { o.ChartDir = chart })

	r := run(t, f, "config.valkey-indexes")
	assertStatus(t, r, "BLOCK")
	configTestMentions(t, r, "index 11", "budcodeinterpreter", "config_store")

	// Without the chart the same override is invisible — the check can only see
	// one entry — so the pass must disclose that blind spot rather than read as
	// a clean bill of health.
	bare := run(t, configTestCluster(vals), "config.valkey-indexes")
	assertStatus(t, bare, "PASS")
	if bare.DoesNotProve == "" {
		t.Fatalf("a values-only run passed without disclosing that chart defaults were never compared")
	}
}

// Quoting an index in YAML must not hide a collision: the merged tree is what
// the install uses, and "11" and 11 select the same database.
func TestConfigValkeyIndexesSeesThroughQuotedIndexes(t *testing.T) {
	vals := configTestValues(t, `
externalServices:
  valkey:
    databases:
      config_store: "11"
      budcodeinterpreter: 11
`)
	assertStatus(t, run(t, configTestCluster(vals), "config.valkey-indexes"), "BLOCK")
}

// Valkey ships 16 databases; SELECT 16 is refused at connect time. A risk
// rather than a blocker, because a managed Valkey may be configured with more.
func TestConfigValkeyIndexesRisksOnAnIndexOutsideTheDefaultRange(t *testing.T) {
	vals := configTestValues(t, `
externalServices:
  valkey:
    databases:
      config_store: 3
      budprompt: 16
`)
	r := run(t, configTestCluster(vals), "config.valkey-indexes")
	assertStatus(t, r, "RISK")
	configTestMentions(t, r, "budprompt = 16", "0-15")
}

func TestConfigValkeyIndexesPassesWhenEveryUseIsDistinct(t *testing.T) {
	vals := configTestValues(t, `
externalServices:
  valkey:
    databases:
      config_store: 3
      state_store: 4
      budcodeinterpreter: 11
`)
	r := run(t, configTestCluster(vals), "config.valkey-indexes")
	assertStatus(t, r, "PASS")
	configTestMentions(t, r, "3=config_store", "11=budcodeinterpreter")
}

// A value that is not an index at all must be reported as not compared, never
// folded into the pass as if it had been.
func TestConfigValkeyIndexesReportsUncomparableEntries(t *testing.T) {
	vals := configTestValues(t, `
externalServices:
  valkey:
    databases:
      config_store: 3
      budprompt: auto
`)
	r := run(t, configTestCluster(vals), "config.valkey-indexes")
	assertStatus(t, r, "PASS")
	configTestMentions(t, r, "not comparable", "budprompt")
}

// No database block means no assignments to compare — which is a skip, not a
// clean bill of health for a Valkey nobody looked at.
func TestConfigValkeyIndexesSkipsWithReasonWhenDatabasesAbsent(t *testing.T) {
	vals := configTestValues(t, "externalServices:\n  valkey:\n    host: valkey-master.valkey\n")
	r := run(t, configTestCluster(vals), "config.valkey-indexes")
	assertSkipHasReason(t, r)
	configTestMentions(t, r, "externalServices.valkey.databases")
}
