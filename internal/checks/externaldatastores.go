package checks

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// The external-datastores group is the one group that is expected to be SKIP on
// most runs. PostgreSQL, ClickHouse, Valkey, Kafka, MongoDB, SeaweedFS and
// Keycloak are all in the cluster-addons ApplicationSet (FRD-020 §3.1), so when
// the customer takes the in-cluster addons there is nothing here that is a
// prerequisite: checking would be checking that the installer already ran.
//
// It runs when the customer brought managed stores instead — either because the
// intake answer says so (`--external-datastores`), or because their own
// `--values` point an `externalServices.*` endpoint at a host that is not an
// in-cluster Service. The gate on "their own values" matters: the chart SHIPS
// pointing at the addons it installs (`pooler-rw.postgres`,
// `clickhouse-clickhouse.clickhouse`, …), so an endpoint the operator never
// overrode is in-cluster by definition, whatever its shape.
//
// What each check can prove is deliberately narrow. A TCP connection from a pod
// is the whole claim: credentials, database existence and schema privileges are
// not verified, because that is the install's job and NG5 excludes it. What the
// checks DO carry, pass or fail, is the list of databases, buckets and topics
// that must pre-exist — the umbrella chart creates none of them, and that is the
// most common way an otherwise-correct external-store install stalls.

const (
	edsInventoryKey = "external-datastores.inventory"

	// The reason every check reports when the addons install in-cluster. Quoted
	// verbatim rather than paraphrased per check, so a scan of the output shows
	// one decision rather than seven.
	edsAddonReason = "installed by the cluster-addons ApplicationSet; checking it would be checking that the installer already ran"

	// A managed endpoint routinely lives on a private network that answers a
	// node and not a laptop, so a workstation result — in either direction —
	// settles nothing. Only the pod probe is evidence.
	edsVantage = "a managed endpoint on a private network answers a node and refuses a laptop, so only a pod's attempt settles this"
)

func init() {
	for _, spec := range []struct {
		id, key string
		sev     engine.Severity
	}{
		{"externaldatastores.postgres", "postgres", engine.Block},
		{"externaldatastores.clickhouse", "clickhouse", engine.Block},
		{"externaldatastores.valkey", "valkey", engine.Block},
		{"externaldatastores.kafka", "kafka", engine.Block},
		// MongoDB backs Novu and nothing else. By the §4 definition that is a
		// named capability going absent — notifications and the in-app inbox —
		// rather than an install that cannot complete, so it is a RISK while its
		// six siblings are blockers.
		{"externaldatastores.mongodb", "mongodb", engine.Risk},
		{"externaldatastores.s3", "s3", engine.Block},
		{"externaldatastores.keycloak", "keycloak", engine.Block},
	} {
		id, key := spec.id, spec.key
		engine.Register(&engine.Check{
			ID: id, Group: "external-datastores", Severity: spec.sev,
			// Probe: the only measurement that counts is made from a pod, which
			// means creating one. Declaring it here is what puts the pod on the
			// TUI's "what will be created" confirmation screen (§6).
			Probe:     true,
			DependsOn: []string{"platform"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				ch := engine.Lookup(id)
				return edsCheck(ctx, c, ch, key)
			},
		})
	}
}

// edsCheck is the body every store shares. The per-store differences are data
// (port, scheme, what must pre-exist, what breaks when it is gone) and live in
// the inventory, not in seven near-identical function bodies.
func edsCheck(ctx context.Context, c *engine.Ctx, ch *engine.Check, key string) engine.Result {
	inv := edsInventory(ctx, c)
	if !inv.applies {
		return ch.Skip(edsAddonReason)
	}
	s := inv.stores[key]
	if s == nil {
		return ch.Skip("no externalServices." + key + " section in the values, and no chart default to read it from")
	}
	if !s.external {
		return ch.Skip(s.label + " stays in-cluster — " + s.why + "; " + edsAddonReason)
	}

	detail := s.detail()
	if inv.valuesErr != "" {
		detail = append(detail, "values could not be merged: "+inv.valuesErr)
	}

	// Declared external, but budctl was never told where. Skipping is the honest
	// answer: there is no endpoint to probe, and passing would assert something
	// nobody measured.
	if s.unknown {
		return ch.Skip(fmt.Sprintf(
			"the answers say %s is managed externally, but no --values sets externalServices.%s, so budctl does not know which host to probe",
			s.label, s.valuesPath)).
			With(detail...)
	}

	// Declared external, yet the endpoint still names a Service the install will
	// no longer create. This one is knowable without touching the network.
	if s.misrouted {
		return ch.Fail(
			fmt.Sprintf("%s is configured as %s — a cluster-internal Service that nothing will create once the in-cluster %s addon is off, so %s",
				s.label, s.endpoint(), s.label, s.consequence),
			fmt.Sprintf("set externalServices.%s to the managed endpoint's real hostname and port in your values file", s.valuesPath)).
			With(detail...)
	}

	if s.srv {
		return ch.Skip(fmt.Sprintf(
			"%s is configured as an SRV URI (%s), whose hostname carries no A record by design — a TCP probe against it would fail for a reason that says nothing about reachability",
			s.label, s.endpoint())).
			With(detail...)
	}

	if c.Net != nil {
		if addrs, err := c.Net.Resolve(ctx, s.host); err == nil && len(addrs) > 0 {
			detail = append(detail, "resolves from this workstation to "+strings.Join(Sorted(addrs), ", "))
		} else if err != nil {
			// Not a finding on its own: split-horizon DNS is the normal shape of
			// a private managed endpoint.
			detail = append(detail, "does not resolve from this workstation ("+err.Error()+") — expected for a private endpoint, and settled by the pod probe below")
		}
	}
	detail = append(detail, s.tlsDetail(ctx, c)...)

	if c.Kube == nil {
		return ch.Skip("cluster unreachable, so no pod could try the connection; " + edsVantage).With(detail...)
	}
	if c.Probes == nil {
		return ch.Skip("probes are disabled, so no pod tried the connection; " + edsVantage).With(detail...)
	}

	lines, outcome, err := edsProbe(ctx, c, s)
	switch {
	case !outcome.Scheduled:
		return ch.Skip(fmt.Sprintf("the probe pod was never scheduled (%s), so nothing tried the connection", edsOr(outcome.Reason, edsOr(outcome.Phase, "no reason reported")))).
			With(detail...).
			WithEvidence(engine.Evidence{What: "probe pod events", Output: strings.Join(outcome.Events, "\n")})
	case !outcome.Started:
		// §6: an unpullable probe image is a registry/egress finding, reported
		// by those groups. It is not evidence about this datastore.
		return ch.Skip(fmt.Sprintf("the probe pod never started (%s) — the probe image %s did not run, which the registry and egress groups report on",
			edsOr(outcome.Reason, "no reason reported"), edsProbeImage(c))).
			With(detail...).
			WithEvidence(engine.Evidence{What: "probe pod events", Output: strings.Join(outcome.Events, "\n")})
	case len(lines) == 0:
		return ch.Skip("the probe pod ran but produced no readable result" + edsSuffix(err)).
			With(detail...).
			WithEvidence(engine.Evidence{What: "probe pod output", Output: edsTruncate(outcome.Logs)})
	}

	ev := []engine.Evidence{{
		What:   fmt.Sprintf("curl from pod %s/%s", c.Probes.Namespace(), s.podName()),
		Output: edsTruncate(outcome.Logs),
	}}

	var blocked, degraded []string
	for i, t := range s.targets {
		line, ok := lines[i]
		if !ok {
			degraded = append(degraded, t.label+" ("+t.url+") was not attempted")
			continue
		}
		open, what := edsClassify(line.rc)
		detail = append(detail, fmt.Sprintf("%s %s → %s%s", t.label, t.url, what, edsSuffix2(line.info)))
		switch {
		case !open && t.required:
			blocked = append(blocked, fmt.Sprintf("%s (%s): %s", t.label, t.url, what))
		case !open:
			degraded = append(degraded, fmt.Sprintf("%s (%s): %s", t.label, t.url, what))
		case line.rc == 60 || line.rc == 35:
			// The port is open; the TLS chain is not acceptable to the probe
			// image's public CA bundle. That is a RISK and not a blocker,
			// because a private CA the Bud images are given at build or mount
			// time would still work — but nothing in this repository injects
			// one, so an operator using a private CA must be told now.
			degraded = append(degraded, fmt.Sprintf("%s (%s): %s", t.label, t.url, what))
		}
	}

	if len(blocked) > 0 {
		return ch.Fail(
			fmt.Sprintf("external %s at %s does not accept a connection from a pod in this cluster, so %s",
				s.label, s.endpoint(), s.consequence),
			s.remedy()).
			With(append(blocked, detail...)...).
			WithEvidence(ev...)
	}

	degraded = append(degraded, s.soft...)
	if len(degraded) > 0 {
		return ch.FailAs(engine.Risk,
			fmt.Sprintf("external %s at %s is reachable, but %s", s.label, s.endpoint(), degraded[0]),
			s.remedy()).
			With(append(degraded[1:], detail...)...).
			WithEvidence(ev...)
	}

	return ch.Pass(fmt.Sprintf("external %s at %s accepts a connection from a pod in this cluster", s.label, s.endpoint())).
		With(detail...).
		WithEvidence(ev...).
		Bounds(fmt.Sprintf("only that a connection opened from inside the cluster — not that the credentials are accepted, that the %s listed above exist, or that the account may write to them. The umbrella chart creates none of them (FRD-020 §5.13)", s.needsLabel))
}

// ---------------------------------------------------------------------------
// Inventory: what is external, and where it is
// ---------------------------------------------------------------------------

type edsTarget struct {
	url   string
	label string
	// required distinguishes the port the platform actually speaks from a
	// secondary interface whose loss degrades rather than blocks.
	required bool
}

type edsProbeLine struct {
	rc   int
	info string
}

type edsStore struct {
	key        string
	label      string
	valuesPath string // externalServices.<valuesPath>, quoted in remedies
	host       string
	port       int
	// tlsPort is the port to inspect a certificate on when it is not the port
	// the platform speaks — ClickHouse serves the native protocol on 9440 and
	// HTTPS on 8443, and quoting the wrong one in a remedy sends the operator
	// to open the wrong firewall rule.
	tlsPort int
	scheme  string // set for the HTTP-speaking stores; "" for wire protocols

	// fromValues records whether the operator's own --values set this section.
	// The chart ships pointing at the addons it installs, so a section nobody
	// overrode is in-cluster whatever its hostname looks like.
	fromValues bool

	external  bool
	why       string // why it was judged in-cluster or off-cluster
	unknown   bool   // declared external, endpoint never supplied
	misrouted bool   // declared external, endpoint still a cluster Service

	// srv marks an endpoint whose hostname deliberately carries no A record,
	// so a TCP probe against it would report a failure that means nothing.
	srv bool

	consequence string   // what breaks when it cannot be reached
	needsLabel  string   // "databases" | "buckets" | "topics" | …
	needs       []string // what must pre-exist, because the chart creates none
	notes       []string // requirements that are not a list of objects
	soft        []string // findings that degrade rather than block
	targets     []edsTarget
}

func (s *edsStore) endpoint() string {
	if s.port == 0 {
		return s.host
	}
	return net.JoinHostPort(s.host, strconv.Itoa(s.port))
}

func (s *edsStore) podName() string { return "budctl-eds-" + s.key }

// ports are every port this store is actually probed on, so a remedy names the
// rule the operator has to open rather than only the first one.
func (s *edsStore) ports() []string {
	out := []string{}
	for _, t := range s.targets {
		if u, err := url.Parse(t.url); err == nil {
			if _, p := edsHostPort(u.Host, s.port); p > 0 {
				out = append(out, strconv.Itoa(p))
			}
		}
	}
	if len(out) == 0 {
		out = append(out, strconv.Itoa(s.port))
	}
	return out
}

func (s *edsStore) detail() []string {
	out := []string{"endpoint " + s.endpoint() + " (" + s.why + ")"}
	if len(s.needs) > 0 {
		out = append(out, fmt.Sprintf("%s that must already exist — the umbrella chart creates none: %s",
			s.needsLabel, strings.Join(Sorted(s.needs), ", ")))
	}
	return append(out, s.notes...)
}

func (s *edsStore) remedy() string {
	base := fmt.Sprintf("allow TCP %s from the cluster's pod and node CIDRs to %s (security group, firewall rule or private-endpoint binding) and make the name resolve in cluster DNS",
		strings.Join(Sorted(s.ports()), " and "), s.host)
	if len(s.needs) > 0 {
		base += fmt.Sprintf("; then create the %s listed above — the umbrella chart creates none", s.needsLabel)
	}
	return base
}

// tlsDetail records the certificate an HTTPS-speaking store serves. It is read
// from the workstation, which is a weaker vantage point than the pod, so it is
// reported as detail and never as the finding itself.
func (s *edsStore) tlsDetail(ctx context.Context, c *engine.Ctx) []string {
	if s.scheme != "https" || c.Net == nil {
		return nil
	}
	port := s.port
	if s.tlsPort > 0 {
		port = s.tlsPort
	}
	issuer, expiry, sans, err := c.Net.TLSInspect(ctx, s.host, port)
	if err != nil && issuer == "" {
		return []string{"TLS could not be inspected from this workstation: " + err.Error()}
	}
	line := fmt.Sprintf("TLS issuer %q, expires %s", issuer, expiry.Format(time.RFC3339))
	if err != nil {
		line += " — " + err.Error() + " from this workstation"
	}
	out := []string{line}
	if !expiry.IsZero() {
		if left := time.Until(expiry); left < 0 {
			s.soft = append(s.soft, fmt.Sprintf("its TLS certificate expired %s ago, so every client will refuse the connection", left.Abs().Round(time.Hour)))
		} else if left < 30*24*time.Hour {
			s.soft = append(s.soft, fmt.Sprintf("its TLS certificate expires in %d days and nothing in this stack renews it", int(left.Hours()/24)))
		}
	}
	if !edsCovers(sans, s.host) && len(sans) > 0 {
		out = append(out, "certificate SANs do not include "+s.host+": "+strings.Join(Sorted(sans), ", "))
	}
	return out
}

func edsCovers(sans []string, host string) bool {
	for _, san := range sans {
		if strings.EqualFold(san, host) {
			return true
		}
		if strings.HasPrefix(san, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(san[1:])) {
			return true
		}
	}
	return false
}

type edsInv struct {
	applies   bool
	stores    map[string]*edsStore
	valuesErr string
}

// edsMu serialises the one-time build. The seven checks in this group run
// concurrently and would otherwise each re-read and re-merge the values files.
var edsMu sync.Mutex

func edsInventory(ctx context.Context, c *engine.Ctx) *edsInv {
	edsMu.Lock()
	defer edsMu.Unlock()
	if v, ok := c.Get(edsInventoryKey); ok {
		if inv, ok := v.(*edsInv); ok {
			return inv
		}
	}
	inv := edsBuild(ctx, c)
	c.Set(edsInventoryKey, inv)
	return inv
}

func edsBuild(ctx context.Context, c *engine.Ctx) *edsInv {
	inv := &edsInv{stores: map[string]*edsStore{}}

	// Endpoints are read from values rather than from Rendered(c): the values
	// carry host, port AND the database/bucket inventory as structured data,
	// while the rendered objects carry them only as per-service env strings
	// under a dozen different key names.
	var overrides, defaults map[string]any
	if c.Helm != nil {
		if len(c.Opts.ValuesFiles) > 0 {
			if v, err := c.Helm.MergeValues(EffectiveValuesFiles(c)); err == nil {
				overrides = v
			} else {
				inv.valuesErr = err.Error()
			}
		}
		if c.Opts.ChartDir != "" {
			if chrt, err := c.Helm.LoadChart(c.Opts.ChartDir); err == nil && chrt != nil {
				defaults = chrt.Values
			}
		}
	}
	ovr := edsMap(overrides, "externalServices")
	def := edsMap(defaults, "externalServices")

	// The section name is paired with its builder here rather than looked up
	// inside each builder, so the block the gate judges is provably the block
	// the builder read. `keycloak` is described by two sections at once and
	// takes the whole externalServices tree.
	for _, entry := range []struct {
		section string
		build   func(edsSectionData) *edsStore
	}{
		{"postgresql", edsPostgres},
		{"clickhouse", edsClickHouse},
		{"valkey", edsValkey},
		{"kafka", edsKafka},
		{"mongodb", edsMongo},
		{"s3", edsS3},
		{"", edsKeycloak},
	} {
		var data edsSectionData
		if entry.section == "" {
			data = edsSectionData{
				m:          edsDeepMerge(def, ovr),
				fromValues: len(edsMap(ovr, "oidc")) > 0 || len(edsMap(ovr, "keycloak")) > 0,
			}
		} else {
			data = edsSection(ovr, def, entry.section)
		}
		s := entry.build(data)
		if s == nil {
			continue
		}
		edsClassifyLocation(ctx, c, s)
		inv.stores[s.key] = s
		if s.external {
			inv.applies = true
		}
	}
	return inv
}

// edsClassifyLocation decides whether a store is the customer's or the
// installer's. The answer drives whether the whole group runs.
func edsClassifyLocation(ctx context.Context, c *engine.Ctx, s *edsStore) {
	off, why := edsOffCluster(ctx, c, s.host)
	s.why = why
	switch {
	case !c.Answers.InClusterData && !s.fromValues:
		// The operator declared managed stores but handed over no values, so the
		// endpoint budctl can see is the chart's own in-cluster default.
		s.external, s.unknown = true, true
	case !c.Answers.InClusterData && !off:
		s.external, s.misrouted = true, true
	case off && s.fromValues:
		s.external = true
	}
}

// edsOffCluster reports whether a hostname names something outside the cluster's
// own DNS namespace, and says why — the reason is quoted in every SKIP so the
// operator can see which rule fired.
func edsOffCluster(ctx context.Context, c *engine.Ctx, host string) (bool, string) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false, "no host configured"
	}
	if ip := net.ParseIP(h); ip != nil {
		// Nobody hand-writes a ClusterIP into values; a literal address is an
		// endpoint someone was given.
		return true, "literal IP address"
	}
	labels := strings.Split(h, ".")
	if len(labels) == 1 {
		return false, "bare Service name, resolved in the release namespace"
	}
	if strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".svc.cluster.local") || strings.HasSuffix(h, ".cluster.local") {
		return false, "cluster-internal DNS name"
	}
	if len(labels) == 2 {
		ns := labels[1]
		if c.Profile.IsAppsetComponent(ns) {
			return false, "<service>.<namespace> in " + ns + ", which the cluster-addons ApplicationSet installs"
		}
		// Definitive when the addon is already there; silent when it is not,
		// which is the normal pre-install state and why it is not the only rule.
		if c.Kube != nil && c.Kube.Get(ctx, "services", ns, labels[0]) != nil {
			return false, "resolves to the in-cluster Service " + h
		}
	}
	// A hostname the chart itself publishes under the answered root domain is an
	// in-cluster component's own ingress — `auth.<domain>` is the bundled
	// Keycloak, not a managed IdP.
	for _, published := range c.Answers.Hostnames() {
		if strings.EqualFold(published, h) {
			return false, "a hostname this chart publishes itself (" + h + "), so it is the in-cluster component's own ingress"
		}
	}
	return true, "not a cluster-internal DNS name"
}

// ---------------------------------------------------------------------------
// Per-store construction
// ---------------------------------------------------------------------------

// edsSectionData is one externalServices block plus the fact that decides the
// whole group: whether the operator supplied it, or the chart did.
type edsSectionData struct {
	m          map[string]any
	fromValues bool
}

func edsSection(ovr, def map[string]any, name string) edsSectionData {
	if o := edsMap(ovr, name); len(o) > 0 {
		// Layer the override over the chart default so a values file that sets
		// only `host` still contributes the default database list.
		return edsSectionData{m: edsDeepMerge(edsMap(def, name), o), fromValues: true}
	}
	return edsSectionData{m: edsMap(def, name)}
}

func edsPostgres(d edsSectionData) *edsStore {
	host := edsStr(d.m, "host")
	port := edsInt(d.m, "port", 5432)
	s := &edsStore{
		key: "postgres", label: "PostgreSQL", valuesPath: "postgresql", host: host, port: port,
		fromValues:  d.fromValues,
		consequence: "every service runs `alembic upgrade head` at pod start and none of them will come up",
		needsLabel:  "databases and roles",
	}
	// Each service owns a database and a role; the chart wires them, CNPG
	// creates them, and a managed PostgreSQL creates nothing.
	for name, raw := range edsMap(d.m, "databases") {
		db, _ := raw.(map[string]any)
		dbName := edsStr(db, "name")
		if dbName == "" {
			dbName = name
		}
		entry := dbName
		if u := edsStr(db, "username"); u != "" {
			entry += " (owner " + u + ")"
		}
		// mcpgateway points at the transaction pooler rather than the session
		// pooler; a second endpoint is a second firewall rule.
		if h := edsStr(db, "host"); h != "" && !strings.EqualFold(h, host) {
			entry += " on " + h
		}
		s.needs = append(s.needs, entry)
	}
	s.targets = []edsTarget{{url: fmt.Sprintf("http://%s/", s.endpoint()), label: "PostgreSQL wire protocol", required: true}}
	return s
}

func edsClickHouse(d edsSectionData) *edsStore {
	host := edsStr(d.m, "host")
	secure := edsBool(d.m, "secure")
	native := edsInt(d.m, "port", edsPick(secure, 9440, 9000))
	httpPort := edsInt(d.m, "httpPort", edsPick(secure, 8443, 8123))
	s := &edsStore{
		key: "clickhouse", label: "ClickHouse", valuesPath: "clickhouse", host: host, port: native,
		fromValues:  d.fromValues,
		scheme:      edsPick(secure, "https", "http"),
		consequence: "budmetrics and the gateway's analytics have nowhere to write, so every inference is served but never recorded",
		needsLabel:  "databases",
	}
	for _, raw := range edsMap(d.m, "databases") {
		if name, ok := raw.(string); ok && name != "" {
			s.needs = append(s.needs, name)
		}
	}
	s.targets = []edsTarget{
		{url: fmt.Sprintf("http://%s/", net.JoinHostPort(host, strconv.Itoa(native))), label: "native protocol", required: true},
		// The HTTP interface is what clickhouse-connect, the migration script
		// (`scripts/migrate_clickhouse.py`) and every ad-hoc query use. Losing
		// it degrades rather than blocks, so it is not `required`.
		{url: fmt.Sprintf("%s://%s/ping", s.scheme, net.JoinHostPort(host, strconv.Itoa(httpPort))), label: "HTTP interface", required: false},
	}
	if s.scheme == "https" {
		s.tlsPort = httpPort
	}
	return s
}

func edsValkey(d edsSectionData) *edsStore {
	host := edsStr(d.m, "host")
	port := edsInt(d.m, "port", 6379)
	s := &edsStore{
		key: "valkey", label: "Valkey", valuesPath: "valkey", host: host, port: port,
		fromValues:  d.fromValues,
		consequence: "Dapr's state store, the config store and every pubsub component lose their backing store, so no service passes readiness",
		needsLabel:  "logical database indexes",
	}
	// Valkey "databases" are numeric indexes, not names. The highest one matters:
	// a stock Redis/Valkey ships 16 (0-15), and several managed offerings expose
	// only index 0, which silently collapses every component onto one keyspace.
	highest := -1
	for name, raw := range edsMap(d.m, "databases") {
		idx := edsToInt(raw, -1)
		if idx < 0 {
			continue
		}
		s.needs = append(s.needs, fmt.Sprintf("%d (%s)", idx, name))
		if idx > highest {
			highest = idx
		}
	}
	if highest >= 16 {
		s.soft = append(s.soft, fmt.Sprintf("the values use logical database index %d, beyond the 16 a stock Valkey/Redis ships with — raise `databases` on the server or those components will fail to SELECT", highest))
	} else if highest >= 0 {
		s.notes = append(s.notes, fmt.Sprintf("the server must expose at least %d logical databases (`databases %d` in valkey.conf); several managed Redis offerings, ElastiCache in cluster mode among them, expose only index 0 and silently collapse every component onto one keyspace", highest+1, highest+1))
	}
	s.targets = []edsTarget{{url: fmt.Sprintf("http://%s/", s.endpoint()), label: "Valkey wire protocol", required: true}}
	return s
}

func edsKafka(d edsSectionData) *edsStore {
	host, port := edsHostPort(edsStr(d.m, "endpoint"), 9092)
	s := &edsStore{
		key: "kafka", label: "Kafka", valuesPath: "kafka", host: host, port: port,
		fromValues:  d.fromValues,
		consequence: "Dapr's pubsub has no broker, so every cross-service event and every workflow step stalls",
		needsLabel:  "topics",
	}
	for _, raw := range edsMap(d.m, "topics") {
		if name, ok := raw.(string); ok && name != "" {
			// Auto-create is commonly disabled on a managed broker, and Dapr
			// does not create topics itself.
			s.needs = append(s.needs, name+" (auto-create is off on most managed brokers; Dapr never creates one)")
		}
	}
	s.targets = []edsTarget{{url: fmt.Sprintf("http://%s/", s.endpoint()), label: "Kafka broker", required: true}}
	return s
}

func edsMongo(d edsSectionData) *edsStore {
	raw := edsStr(d.m, "endpoint")
	// A managed MongoDB is usually handed over as a URI or a replica-set seed
	// list; the first seed is the one to probe.
	trimmed := strings.TrimPrefix(strings.TrimPrefix(raw, "mongodb+srv://"), "mongodb://")
	if i := strings.IndexAny(trimmed, "/?"); i >= 0 {
		trimmed = trimmed[:i]
	}
	if i := strings.Index(trimmed, "@"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	first, _, _ := strings.Cut(trimmed, ",")
	host, port := edsHostPort(first, 27017)
	s := &edsStore{
		key: "mongodb", label: "MongoDB", valuesPath: "mongodb", host: host, port: port,
		fromValues:  d.fromValues,
		consequence: "Novu cannot start, so notifications and the in-app inbox are absent while the rest of the platform runs",
		needsLabel:  "databases",
	}
	for _, v := range edsMap(d.m, "databases") {
		if name, ok := v.(string); ok && name != "" {
			s.needs = append(s.needs, name)
		}
	}
	if strings.HasPrefix(raw, "mongodb+srv://") {
		// An Atlas-style seed host carries an SRV record and no A record, so a
		// TCP probe against it fails by design. Reporting that as unreachable
		// would be a blocker invented by the tool.
		s.srv = true
		s.notes = append(s.notes, "the endpoint is an SRV URI: the cluster's resolver must answer _mongodb._tcp."+host+", and the hosts it returns must themselves be reachable on the port it names")
	}
	s.targets = []edsTarget{{url: fmt.Sprintf("http://%s/", s.endpoint()), label: "MongoDB wire protocol", required: true}}
	return s
}

func edsS3(d edsSectionData) *edsStore {
	raw := edsStr(d.m, "endpoint")
	secure := edsBool(d.m, "secure")
	scheme := edsPick(secure, "https", "http")
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme = raw[:i]
		raw = raw[i+3:]
	}
	host, port := edsHostPort(raw, edsPick(scheme == "https", 443, 80))
	s := &edsStore{
		key: "s3", label: "S3 object storage", valuesPath: "s3", host: host, port: port, scheme: scheme,
		fromValues:  d.fromValues,
		consequence: "the model registry has nowhere to put weights, so adding or deploying any model fails",
		needsLabel:  "buckets",
	}
	for _, v := range edsMap(d.m, "buckets") {
		if name, ok := v.(string); ok && name != "" {
			s.needs = append(s.needs, name)
		}
	}
	if scheme != "https" {
		s.soft = append(s.soft, "it is configured over plain HTTP (`externalServices.s3.secure: false`), so the access key, the secret key and every model weight cross the network in clear text")
	}
	// An unauthenticated GET / against S3 answers 403 or 400. That is a
	// reachability PASS for the same reason a registry's 401 is (FRD-020 D7).
	s.targets = []edsTarget{{url: fmt.Sprintf("%s://%s/", scheme, s.endpoint()), label: "S3 API", required: true}}
	return s
}

func edsKeycloak(d edsSectionData) *edsStore {
	// Two sections describe one server: `oidc.url` is the realm URL every
	// service validates tokens against, `keycloak.url` + `realm` is the base URL
	// mcpgateway needs for issuer discovery and role sync. The realm URL is the
	// authoritative one, because it is what fails first.
	realmURL := edsStr(edsMap(d.m, "oidc"), "url")
	kc := edsMap(d.m, "keycloak")
	base := edsStr(kc, "url")
	realm := edsStr(kc, "realm")
	if realmURL == "" && base != "" && realm != "" {
		realmURL = strings.TrimSuffix(base, "/") + "/realms/" + realm
	}
	if realmURL == "" {
		return nil
	}
	u, err := url.Parse(realmURL)
	if err != nil || u.Host == "" {
		return nil
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host, port := edsHostPort(u.Host, edsPick(scheme == "https", 443, 80))
	s := &edsStore{
		key: "keycloak", label: "Keycloak", valuesPath: "oidc.url", host: host, port: port, scheme: scheme,
		fromValues:  d.fromValues,
		consequence: "no one can obtain a token — budadmin, budCustomer and every API caller are locked out, and budapp's realm bootstrap fails at start",
		needsLabel:  "realm and clients",
	}
	if realm == "" {
		realm = strings.TrimPrefix(u.Path, "/realms/")
	}
	if realm != "" {
		// budapp bootstraps the realm and the budadmin-web client at first
		// start; the mcpgateway client is a values-level identity that has to be
		// created on a managed IdP by hand.
		s.needs = append(s.needs, "realm "+realm+" (budapp creates it at first start against the admin account)")
	}
	if id := edsStr(edsMap(edsMap(d.m, "oidc"), "clients", "mcpgateway"), "id"); id != "" {
		s.needs = append(s.needs, "client "+id+" with its secret, for mcpgateway's SSO provider")
	}
	if scheme != "https" {
		s.soft = append(s.soft, "the issuer is plain HTTP, so bearer tokens and the admin credentials cross the network in clear text")
	}
	s.targets = []edsTarget{{
		url:   strings.TrimSuffix(realmURL, "/") + "/.well-known/openid-configuration",
		label: "OIDC discovery", required: true,
	}}
	return s
}

// ---------------------------------------------------------------------------
// The pod probe
// ---------------------------------------------------------------------------

// edsProbe opens each target from a pod. curl is used rather than a TCP dialer
// because the default probe image already carries it and nothing else, and its
// exit codes separate the three failures that have three different remedies:
// the name did not resolve (6), the port refused (7), the packet was dropped
// (28). Anything else means the TCP connection was established and the server
// simply does not speak HTTP — which is the answer for PostgreSQL, Valkey,
// Kafka and MongoDB.
func edsProbe(ctx context.Context, c *engine.Ctx, s *edsStore) (map[int]edsProbeLine, probes.PodOutcome, error) {
	var b strings.Builder
	b.WriteString("set +e\n")
	for i, t := range s.targets {
		fmt.Fprintf(&b,
			"out=$(curl -sS -o /dev/null -w 'code=%%{http_code} t=%%{time_total}s' --connect-timeout 8 --max-time 20 %s 2>&1); rc=$?; echo \"PROBE id=%d rc=$rc $out\"\n",
			edsShellQuote(t.url), i)
	}
	b.WriteString("exit 0\n")

	outcome, err := c.Probes.RunPod(ctx, probes.PodSpec{
		Name:    s.podName(),
		Image:   edsProbeImage(c),
		Command: []string{"/bin/sh", "-c", b.String()},
		Timeout: 60 * time.Second,
	})
	return edsParse(outcome.Logs), outcome, err
}

func edsParse(logs string) map[int]edsProbeLine {
	out := map[int]edsProbeLine{}
	for _, line := range strings.Split(logs, "\n") {
		if !strings.HasPrefix(line, "PROBE id=") {
			continue
		}
		fields := strings.Fields(line)
		var id, rc = -1, -1
		var info []string
		for _, f := range fields[1:] {
			switch {
			case strings.HasPrefix(f, "id="):
				id, _ = strconv.Atoi(strings.TrimPrefix(f, "id="))
			case strings.HasPrefix(f, "rc="):
				rc, _ = strconv.Atoi(strings.TrimPrefix(f, "rc="))
			default:
				info = append(info, f)
			}
		}
		if id >= 0 && rc >= 0 {
			out[id] = edsProbeLine{rc: rc, info: strings.Join(info, " ")}
		}
	}
	return out
}

func edsClassify(rc int) (open bool, what string) {
	switch rc {
	case 0:
		return true, "answered"
	case 6:
		return false, "the name did not resolve from inside the cluster"
	case 7:
		return false, "the port refused the connection, or there is no route to it"
	case 28:
		return false, "the connection timed out — a dropped packet, which is what a security group or firewall looks like from here"
	case 35:
		return true, "the port is open but the TLS handshake failed (protocol or cipher mismatch)"
	case 60:
		return true, "the port is open but its TLS certificate is not trusted by the pod's CA bundle"
	default:
		return true, fmt.Sprintf("the port accepted the connection (curl exit %d: the server does not speak HTTP, which is the expected answer here)", rc)
	}
}

func edsProbeImage(c *engine.Ctx) string {
	if c.Opts.ProbeImage != "" {
		return c.Opts.ProbeImage
	}
	return "curlimages/curl:8.10.1"
}

// ---------------------------------------------------------------------------
// Small readers over untyped values
// ---------------------------------------------------------------------------

// Values reach budctl through two YAML decoders with different number
// behaviour: sigs.k8s.io/yaml (used by Helm) yields float64, gopkg.in/yaml.v3
// yields int. Every reader below tolerates both rather than depending on which
// path a value arrived by.

func edsMap(m map[string]any, path ...string) map[string]any {
	cur := m
	for _, p := range path {
		if cur == nil {
			return nil
		}
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func edsStr(m map[string]any, path ...string) string {
	if m == nil || len(path) == 0 {
		return ""
	}
	if len(path) > 1 {
		m = edsMap(m, path[:len(path)-1]...)
	}
	if m == nil {
		return ""
	}
	s, _ := m[path[len(path)-1]].(string)
	return strings.TrimSpace(s)
}

func edsInt(m map[string]any, key string, def int) int {
	if m == nil {
		return def
	}
	return edsToInt(m[key], def)
}

func edsToInt(v any, def int) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
	}
	return def
}

func edsBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

func edsDeepMerge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if vm, ok := v.(map[string]any); ok {
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = edsDeepMerge(bm, vm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// edsHostPort splits "host:port", "[::1]:port" or a bare host, falling back to
// the protocol's default port when none is given.
func edsHostPort(raw string, def int) (string, int) {
	raw = strings.TrimSpace(strings.Trim(raw, "/"))
	if raw == "" {
		return "", def
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			return h, n
		}
		return h, def
	}
	return strings.Trim(raw, "[]"), def
}

func edsShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func edsTruncate(s string) string {
	const max = 4000
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n… truncated"
}

func edsOr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func edsSuffix(err error) string {
	if err == nil {
		return ""
	}
	return ": " + err.Error()
}

func edsSuffix2(info string) string {
	if strings.TrimSpace(info) == "" {
		return ""
	}
	return " [" + info + "]"
}

func edsPick[T any](cond bool, yes, no T) T {
	if cond {
		return yes
	}
	return no
}
