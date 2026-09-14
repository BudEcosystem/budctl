package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// external-datastores is the one group whose correct answer is usually SKIP, and
// that is exactly what makes it dangerous: a group that skips by default can rot
// into a group that skips ALWAYS without anyone noticing, and a group that is
// wired to the wrong side of the boundary starts blocking installs because the
// addons it was never meant to judge are not there yet. The tests below pin both
// edges of FRD-020 §5.13 — when the group must stay silent, and when it must
// speak — and they drive every one of the seven check ids to a real finding.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// edsTestInClusterValues mirrors the shape infra/charts/bud/values.yaml ships:
// every endpoint names the addon the cluster-addons ApplicationSet installs.
// Used two ways — as "the operator changed nothing" (must skip) and as "the
// operator declared managed stores but left these endpoints alone" (must block).
const edsTestInClusterValues = `
externalServices:
  postgresql:
    host: pooler-rw.postgres
    port: 5432
    databases:
      budask:
        name: budask
        username: bud
      budapp:
        name: budapp
        username: bud
  clickhouse:
    host: clickhouse-clickhouse.clickhouse
    port: 9000
    databases:
      budmetrics: metrics
      budgateway: bud_gateway
  valkey:
    host: valkey-master.valkey
    port: 6379
    databases:
      config_store: 3
      state_store: 4
      budcodeinterpreter: 11
  kafka:
    endpoint: kafka-kafka-brokers.kafka:9092
    topics:
      pubsub: bud_pubsub
  mongodb:
    endpoint: mongodb-rs0.mongodb:27017
    databases:
      novu: bud_novu
  s3:
    endpoint: seaweed-s3.seaweedfs:8333
    secure: false
    buckets:
      modelRegistry: bud-models-registry
      novu: bud-novu
  oidc:
    url: http://keycloak.keycloak/realms/bud-keycloak
    clients:
      mcpgateway:
        id: mcp-gateway
`

func edsTestValuesFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write values file: %v", err)
	}
	return p
}

// edsTestExternal is the answered-managed-stores cluster: the operator said the
// data stores are theirs, and handed budctl the values that say where.
func edsTestExternal(t *testing.T, values string) *fakeCluster {
	t.Helper()
	path := edsTestValuesFile(t, values)
	return vanilla().
		withAnswers(func(a *intake.Answers) { a.InClusterData = false }).
		withOpts(func(o *engine.Options) { o.ValuesFiles = []string{path} })
}

// edsTestIDs reads the group's ids from the registry rather than hard-coding
// them, so a store added to the inventory is covered by the boundary tests the
// day it is registered instead of the day someone remembers to list it.
func edsTestIDs(t *testing.T) []string {
	t.Helper()
	out := []string{}
	for _, ch := range engine.All() {
		if ch.Group == "external-datastores" {
			out = append(out, ch.ID)
		}
	}
	if len(out) == 0 {
		t.Fatal("no checks registered in group external-datastores")
	}
	return out
}

// edsTestService seeds a real Service, which is the one signal that settles a
// `<name>.<namespace>` endpoint whose namespace is not a known addon.
func edsTestService(ns, name string) adapters.Object {
	return adapters.Object{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"clusterIP": "10.43.7.11",
			"ports":     []any{map[string]any{"port": int64(5432)}},
		},
	}
}

func edsTestAssertDetail(t *testing.T, r engine.Result, want string) {
	t.Helper()
	for _, d := range r.Detail {
		if strings.Contains(d, want) {
			return
		}
	}
	t.Fatalf("%s [%s]: no detail line contains %q\n  summary: %s\n  detail: %s",
		r.ID, r.Status(), want, r.Summary, strings.Join(r.Detail, "\n          "))
}

func edsTestAssertNotFailure(t *testing.T, r engine.Result) {
	t.Helper()
	if r.State == engine.StateFail {
		t.Fatalf("%s reported %s where nothing is a prerequisite: %s\n  remedy: %s",
			r.ID, r.Status(), r.Summary, r.Remedy)
	}
}

// ---------------------------------------------------------------------------
// The boundary rule (FRD-020 §5.13): in-cluster addons are not prerequisites
// ---------------------------------------------------------------------------

// The governing rule of the whole tool. When the customer takes the bundled
// addons, every check here is checking that the installer already ran, so the
// answer is SKIP — and the skip has to SAY that, because a bare "skipped" in the
// output is read as "fine" by every operator who scans it.
func TestExternalDatastoresWholeGroupSkipsWhenAddonsInstallInCluster(t *testing.T) {
	f := vanilla() // intake.Defaults(): InClusterData is true
	for _, id := range edsTestIDs(t) {
		r := run(t, f, id)
		assertSkipHasReason(t, r)
		if !strings.Contains(r.Summary, "ApplicationSet") {
			t.Fatalf("%s skipped without naming the ApplicationSet that installs it: %s", id, r.Summary)
		}
	}
}

// The same cluster is EMPTY: no PostgreSQL, no ClickHouse, no Kafka, no Service
// of any kind. That is the normal pre-install state, and it must never produce a
// finding — the addons' absence is what the installer is for.
func TestExternalDatastoresNeverFailsBecauseTheAddonsAreAbsent(t *testing.T) {
	for _, id := range edsTestIDs(t) {
		edsTestAssertNotFailure(t, run(t, vanilla(), id))
	}
}

// An operator who supplies their own values but keeps the bundled addons must
// still get silence. The endpoints here all name addon Services, so nothing in
// them is a prerequisite even though --values was given.
func TestExternalDatastoresSkipsWhenSuppliedValuesStillNameTheAddons(t *testing.T) {
	path := edsTestValuesFile(t, edsTestInClusterValues)
	f := vanilla().withOpts(func(o *engine.Options) { o.ValuesFiles = []string{path} })
	for _, id := range edsTestIDs(t) {
		r := run(t, f, id)
		assertSkipHasReason(t, r)
		edsTestAssertNotFailure(t, r)
		// The skip must be the BOUNDARY decision — "the installer creates this" —
		// and not "we could not probe it". Those are different facts, and only one
		// of them means no action is needed.
		if !strings.Contains(r.Summary, "ApplicationSet") {
			t.Fatalf("%s skipped for a reason other than the addon boundary: %s", id, r.Summary)
		}
	}
}

// The boundary is not the intake answer alone: §5.13 also runs the group when
// the operator's own values point a single endpoint off-cluster. One managed
// PostgreSQL must wake up the PostgreSQL check WITHOUT turning its six in-cluster
// siblings into blockers — the mixed inventory is where a wrongly-scoped group
// would start failing installs.
func TestExternalDatastoresMixedInventoryOnlyWakesTheOffClusterStore(t *testing.T) {
	values := strings.Replace(edsTestInClusterValues,
		"host: pooler-rw.postgres", "host: pg.managed.invalid", 1)
	path := edsTestValuesFile(t, values)
	f := vanilla().withOpts(func(o *engine.Options) { o.ValuesFiles = []string{path} })

	pg := run(t, f, "externaldatastores.postgres")
	assertSkipHasReason(t, pg) // no probe runner in a unit test; see the report
	edsTestAssertDetail(t, pg, "pg.managed.invalid:5432")
	edsTestAssertDetail(t, pg, "this workstation") // it attempted resolution

	for _, id := range edsTestIDs(t) {
		if id == "externaldatastores.postgres" {
			continue
		}
		r := run(t, f, id)
		assertSkipHasReason(t, r)
		edsTestAssertNotFailure(t, r)
		if !strings.Contains(r.Summary, "ApplicationSet") {
			t.Fatalf("%s: an in-cluster store skipped without saying the installer creates it: %s", id, r.Summary)
		}
	}
}

// ---------------------------------------------------------------------------
// The failure the group exists to catch
// ---------------------------------------------------------------------------

// The operator turned the addons OFF and left the endpoints pointing at them.
// Nothing will ever create those Services, so every one of these is a finding
// that is knowable before a single packet is sent. This is the case that drives
// all seven ids to BLOCK/RISK.
func TestExternalDatastoresFailWhenEndpointsStillNameTheDisabledAddons(t *testing.T) {
	f := edsTestExternal(t, edsTestInClusterValues)

	cases := []struct {
		id       string
		want     string
		endpoint string
		// needs is one of the databases/buckets/topics the chart creates none of;
		// it must be carried whether the check passes or fails.
		needs string
	}{
		{"externaldatastores.postgres", "BLOCK", "pooler-rw.postgres:5432", "budask (owner bud)"},
		{"externaldatastores.clickhouse", "BLOCK", "clickhouse-clickhouse.clickhouse:9000", "bud_gateway"},
		{"externaldatastores.valkey", "BLOCK", "valkey-master.valkey:6379", "3 (config_store)"},
		{"externaldatastores.kafka", "BLOCK", "kafka-kafka-brokers.kafka:9092", "bud_pubsub"},
		// MongoDB backs Novu and nothing else: notifications go absent, the
		// install still completes. §4 calls that a RISK, not a blocker.
		{"externaldatastores.mongodb", "RISK", "mongodb-rs0.mongodb:27017", "bud_novu"},
		{"externaldatastores.s3", "BLOCK", "seaweed-s3.seaweedfs:8333", "bud-models-registry"},
		{"externaldatastores.keycloak", "BLOCK", "keycloak.keycloak:80", "realm bud-keycloak"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r := run(t, f, tc.id)
			assertStatus(t, r, tc.want)
			if !strings.Contains(r.Summary, tc.endpoint) {
				t.Fatalf("%s: the finding does not name the endpoint %s: %s", tc.id, tc.endpoint, r.Summary)
			}
			if r.Remedy == "" {
				t.Fatalf("%s failed with no remedy — an operator cannot act on it", tc.id)
			}
			edsTestAssertDetail(t, r, tc.needs)
			edsTestAssertDetail(t, r, "the umbrella chart creates none")
		})
	}
}

// The same fixture, one answer different. If the BLOCKs above were an accident of
// the fixture rather than of the answer, this would fail — it is the control for
// the case above.
func TestExternalDatastoresSameEndpointsAreSilentWhenAddonsStayInCluster(t *testing.T) {
	path := edsTestValuesFile(t, edsTestInClusterValues)
	f := vanilla().withOpts(func(o *engine.Options) { o.ValuesFiles = []string{path} })
	for _, id := range edsTestIDs(t) {
		r := run(t, f, id)
		assertSkipHasReason(t, r)
		if !strings.Contains(r.Summary, "ApplicationSet") {
			t.Fatalf("%s: flipping one intake answer changed the reason to %q", id, r.Summary)
		}
	}
}

// `auth.<domain>` is the bundled Keycloak's OWN ingress. Declaring managed
// identity and then pointing the issuer back at the Keycloak that will no longer
// be installed is the quietest way to lock everyone out of the platform, and the
// hostname alone gives it away.
func TestExternalDatastoresKeycloakBlocksWhenIssuerIsTheBundledIngress(t *testing.T) {
	f := edsTestExternal(t, `
externalServices:
  oidc:
    url: http://auth.bud.example.com/realms/bud-keycloak
`)
	r := run(t, f, "externaldatastores.keycloak")
	assertStatus(t, r, "BLOCK")
	edsTestAssertDetail(t, r, "a hostname this chart publishes itself")
	if !strings.Contains(r.Summary, "auth.bud.example.com") {
		t.Fatalf("keycloak finding does not name the issuer host: %s", r.Summary)
	}
}

// A `<name>.<namespace>` endpoint in a namespace budctl has never heard of is
// only in-cluster if the Service is really there. Seeding it must flip the
// verdict — this is the rule that stops a genuinely external `db.corp` from being
// misread as a Service.
func TestExternalDatastoresBlocksWhenEndpointResolvesToASeededService(t *testing.T) {
	values := `
externalServices:
  postgresql:
    host: pg.dataops
    port: 5432
`
	withService := edsTestExternal(t, values).
		with("services", "dataops", edsTestService("dataops", "pg"))
	r := run(t, withService, "externaldatastores.postgres")
	assertStatus(t, r, "BLOCK")
	edsTestAssertDetail(t, r, "resolves to the in-cluster Service pg.dataops")

	// Control: the identical values against a cluster with no such Service are
	// treated as an off-cluster endpoint, so the check moves on to reachability
	// instead of declaring a misroute.
	withoutService := edsTestExternal(t, values)
	edsTestAssertNotFailure(t, run(t, withoutService, "externaldatastores.postgres"))
}

// An override that sets a port and forgets the host leaves nothing to probe. It
// must not be read as "reachable"; the detail has to say the host is missing.
func TestExternalDatastoresBlocksWhenTheHostIsMissingEntirely(t *testing.T) {
	f := edsTestExternal(t, `
externalServices:
  postgresql:
    port: 5433
`)
	r := run(t, f, "externaldatastores.postgres")
	assertStatus(t, r, "BLOCK")
	edsTestAssertDetail(t, r, "no host configured")
}

// The bundled Keycloak publishes its own ingress, and the chart's DEFAULT
// `externalServices.oidc.url` (auth.bud.lan) is that ingress. Every per-env
// values file carries an `oidc` block, so the moment --values is supplied this
// section counts as operator-supplied — and when the answered domain is not the
// one baked into the default, the hostname no longer matches
// intake.Answers.Hostnames() and the bundled Keycloak is classified as a managed
// IdP. Nothing here may become a finding on that basis: the addon's absence is
// what the installer is for. (See the report — with probes enabled this is the
// one path in the group where an absent addon can produce a blocker.)
func TestExternalDatastoresBundledKeycloakDefaultIssuerIsNeverAFinding(t *testing.T) {
	path := edsTestValuesFile(t, `
externalServices:
  oidc:
    url: http://auth.bud.lan/realms/bud-keycloak
    clients:
      mcpgateway:
        id: mcp-gateway
`)
	f := vanilla(). // in-cluster addons answered; domain is bud.example.com
			withOpts(func(o *engine.Options) { o.ValuesFiles = []string{path} })
	edsTestAssertNotFailure(t, run(t, f, "externaldatastores.keycloak"))
}

// ---------------------------------------------------------------------------
// Skips that must carry their reason (D5)
// ---------------------------------------------------------------------------

// Managed stores declared, no --values supplied: budctl does not know which host
// to probe. Passing would assert something nobody measured, and blocking would
// invent a failure — the only honest answer is a skip that names the missing
// input.
func TestExternalDatastoresSkipsWhenExternalIsDeclaredButNoValuesSayWhere(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.InClusterData = false })
	for _, id := range edsTestIDs(t) {
		r := run(t, f, id)
		assertSkipHasReason(t, r)
		edsTestAssertNotFailure(t, r)
		if !strings.Contains(r.Summary, "values") {
			t.Fatalf("%s: skip does not name the missing --values: %s", id, r.Summary)
		}
	}
}

// A managed endpoint on a private network is the normal case, and the workstation
// is the wrong vantage point to judge it from. With no probe runner the answer is
// a skip that says so — never a pass, and never a blocker manufactured out of a
// laptop's DNS.
func TestExternalDatastoresUnreachableHostSkipsRatherThanPassing(t *testing.T) {
	f := edsTestExternal(t, `
externalServices:
  postgresql:
    host: pg.managed.invalid
    port: 5432
    databases:
      budapp:
        name: budapp
        username: bud
`)
	r := run(t, f, "externaldatastores.postgres")
	assertSkipHasReason(t, r)
	if r.State == engine.StatePass {
		t.Fatalf("an unreachable managed endpoint passed without anything trying it: %s", r.Summary)
	}
	// The reason must be the vantage point, not a vague "skipped".
	if !strings.Contains(r.Summary, "pod") {
		t.Fatalf("skip does not explain that only a pod settles reachability: %s", r.Summary)
	}
	edsTestAssertDetail(t, r, "this workstation")
	// The inventory is carried on the skip path too: it is what the operator has
	// to go and create either way.
	edsTestAssertDetail(t, r, "budapp (owner bud)")
}

// An Atlas-style `mongodb+srv://` seed host carries an SRV record and no A
// record BY DESIGN. A TCP probe against it fails every time, so reporting that
// failure would be a blocker invented by the tool rather than found in the
// cluster.
func TestExternalDatastoresMongoSRVSkipsInsteadOfInventingAFailure(t *testing.T) {
	f := edsTestExternal(t, `
externalServices:
  mongodb:
    endpoint: mongodb+srv://bud_novu:secret@cluster0.abc12.mongodb.net/novu?retryWrites=true
    databases:
      novu: bud_novu
`)
	r := run(t, f, "externaldatastores.mongodb")
	assertSkipHasReason(t, r)
	edsTestAssertNotFailure(t, r)
	if !strings.Contains(r.Summary, "SRV") {
		t.Fatalf("SRV endpoint skipped for an unstated reason: %s", r.Summary)
	}
	edsTestAssertDetail(t, r, "_mongodb._tcp.cluster0.abc12.mongodb.net")
}

// A --values path that cannot be read must surface, not vanish. Silently
// checking the chart defaults instead would judge the wrong input while
// reporting a clean run.
func TestExternalDatastoresReportsAValuesFileItCouldNotRead(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there.yaml")
	f := vanilla().
		withAnswers(func(a *intake.Answers) { a.InClusterData = false }).
		withOpts(func(o *engine.Options) { o.ValuesFiles = []string{missing} })
	r := run(t, f, "externaldatastores.postgres")
	assertSkipHasReason(t, r)
	edsTestAssertDetail(t, r, "values could not be merged")
}

// ---------------------------------------------------------------------------
// The classification behind the pod probe
//
// The probe itself needs a live pod, so the BLOCK it produces cannot be reached
// from a unit test. Its two decisions can be, and they are the whole difference
// between "the port refused" and "the server does not speak HTTP" — which is the
// EXPECTED answer for PostgreSQL, Valkey, Kafka and MongoDB and must never be
// read as a failure.
// ---------------------------------------------------------------------------

func TestExternalDatastoresClassifiesCurlExitCodes(t *testing.T) {
	cases := []struct {
		rc       int
		open     bool
		contains string
	}{
		{0, true, "answered"},
		{6, false, "did not resolve"},
		{7, false, "refused"},
		{28, false, "timed out"},
		{35, true, "TLS handshake failed"},
		{60, true, "not trusted"},
		// A wire-protocol server answering curl with garbage is a REACHABILITY
		// pass. Treating it as a failure would block every PostgreSQL install.
		{52, true, "does not speak HTTP"},
	}
	for _, tc := range cases {
		open, what := edsClassify(tc.rc)
		if open != tc.open || !strings.Contains(what, tc.contains) {
			t.Errorf("edsClassify(%d) = (%v, %q), want open=%v containing %q",
				tc.rc, open, what, tc.open, tc.contains)
		}
	}
}

func TestExternalDatastoresParsesProbeOutput(t *testing.T) {
	logs := strings.Join([]string{
		"curl: (7) Failed to connect to pg.managed.invalid port 5432",
		"PROBE id=0 rc=7 curl: (7) Failed to connect",
		"PROBE id=1 rc=0 code=200 t=0.031s",
		"unrelated noise",
	}, "\n")
	lines := edsParse(logs)
	if len(lines) != 2 {
		t.Fatalf("parsed %d probe lines, want 2: %#v", len(lines), lines)
	}
	if lines[0].rc != 7 || lines[1].rc != 0 {
		t.Fatalf("exit codes mis-parsed: %#v", lines)
	}
	if !strings.Contains(lines[1].info, "code=200") {
		t.Fatalf("probe info dropped: %#v", lines[1])
	}
	// A target with no line must stay absent, so the check reports "was not
	// attempted" rather than silently scoring it as open.
	if _, ok := lines[2]; ok {
		t.Fatal("edsParse invented a result for a target that produced no line")
	}
}
