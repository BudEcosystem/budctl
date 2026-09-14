package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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
)

// The domains group is the one group that talks to the outside world, and that
// is exactly why its failure paths have to be provable without one. Every
// fixture below is pinned to an address whose behaviour is a property of the
// ADDRESS rather than of whatever this machine happens to reach today:
//
//   - a .invalid name can never resolve (RFC 2606 reserves the TLD), so
//     "NXDOMAIN" is guaranteed rather than hoped for;
//   - the RFC 5737 documentation ranges are carried by no router anywhere, so
//     "port 80 is closed" cannot be turned into a false pass by a machine that
//     happens to have a proxy;
//   - an IP literal is its own DNS answer — net.LookupHost short-circuits it —
//     so a fixture can say "this published name resolves to X" with no
//     resolver, no network and no wildcard zone for someone to keep alive.
//
// The tests that need a live listener bind loopback and skip, loudly, if the
// port is not free; a skipped Go test says "not proven here", which is the same
// distinction D5 makes about the checks themselves.

const (
	domainsTestNet  = "203.0.113.10" // TEST-NET-3: never routed
	domainsOtherNet = "198.51.100.7" // TEST-NET-2: never routed, and never equal to the above
	domainsLoopback = "127.0.0.1"
	domainsDeadRoot = "budctl-readiness.invalid"
)

// ---------------------------------------------------------------------------
// helpers

// domainsRun is run() plus the ability to seed the shared context, which is how
// config.render hands this group the hostnames the chart actually publishes.
func domainsRun(t *testing.T, f *fakeCluster, id string, seed ...func(*engine.Ctx)) engine.Result {
	t.Helper()
	ch := engine.Lookup(id)
	if ch == nil {
		t.Fatalf("no such check: %s", id)
	}
	c := f.ctx(t)
	for _, fn := range seed {
		fn(c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return ch.Run(ctx, c)
}

// domainsRenderHosts models what config.render produces from --values: the
// Ingress the chart will really create. The group prefers these over the
// answered domain, because a per-host override makes the answered name a
// phantom.
func domainsRenderHosts(hosts ...string) func(*engine.Ctx) {
	rules := make([]any, 0, len(hosts))
	for _, h := range hosts {
		rules = append(rules, map[string]any{"host": h})
	}
	obj := adapters.Object{
		"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
		"metadata": map[string]any{"name": "bud", "namespace": "bud"},
		"spec":     map[string]any{"rules": rules},
	}
	return func(c *engine.Ctx) { c.Set(engine.KeyRenderedObjects, []adapters.Object{obj}) }
}

// domainsRenderRoute is the OpenShift shape of the same thing.
func domainsRenderRoute(host string) func(*engine.Ctx) {
	obj := adapters.Object{
		"apiVersion": "route.openshift.io/v1", "kind": "Route",
		"metadata": map[string]any{"name": "bud", "namespace": "bud"},
		"spec":     map[string]any{"host": host},
	}
	return func(c *engine.Ctx) { c.Set(engine.KeyRenderedObjects, []adapters.Object{obj}) }
}

// domainsLBService is an ingress controller's Service: the address the cluster
// advertises as its front door, which is what DNS is compared against.
func domainsLBService(ips ...string) adapters.Object {
	ing := make([]any, 0, len(ips))
	for _, ip := range ips {
		ing = append(ing, map[string]any{"ip": ip})
	}
	return adapters.Object{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": "ingress-nginx-controller", "namespace": "ingress-nginx"},
		"spec": map[string]any{"type": "LoadBalancer", "ports": []any{
			map[string]any{"port": int64(80)}, map[string]any{"port": int64(443)},
		}},
		"status": map[string]any{"loadBalancer": map[string]any{"ingress": ing}},
	}
}

func domainsText(r engine.Result) string {
	parts := []string{r.Summary, r.Remedy, r.DoesNotProve}
	parts = append(parts, r.Detail...)
	for _, e := range r.Evidence {
		parts = append(parts, e.What, e.Output)
	}
	return strings.Join(parts, "\n")
}

// domainsAssertMentions is how a finding is judged actionable: naming the host
// or the address is the difference between a report and a shrug.
func domainsAssertMentions(t *testing.T, r engine.Result, want ...string) {
	t.Helper()
	hay := domainsText(r)
	for _, w := range want {
		if !strings.Contains(hay, w) {
			t.Fatalf("%s (%s): nothing in the result mentions %q\n--- result ---\n%s",
				r.ID, r.Status(), w, hay)
		}
	}
}

func domainsAssertRemedy(t *testing.T, r engine.Result, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(r.Remedy, w) {
			t.Fatalf("%s: the remedy does not mention %q, so it does not say what to do: %q", r.ID, w, r.Remedy)
		}
	}
}

// domainsListen binds a fixed port because the checks dial 80 and 443 by
// definition. A busy port is reported as "not proven", never quietly ignored.
func domainsListen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot bind %s (%v): the open-port path is NOT proven on this host", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// domainsServeHTTP answers the ACME challenge path with a 404 on purpose: a 404
// is a pass for HTTP-01 reachability, because it proves a live listener
// answered the exact path the CA will request.
func domainsServeHTTP(t *testing.T, addr string) {
	t.Helper()
	ln := domainsListen(t, addr)
	srv := &http.Server{Handler: http.NotFoundHandler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// domainsServeTCP accepts and drops: inbound-443 asks only whether the port
// answers, so a bare listener is the honest fixture for it.
func domainsServeTCP(t *testing.T, addr string) {
	t.Helper()
	ln := domainsListen(t, addr)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
}

// domainsServeTLS serves one self-signed certificate so domains.tls has
// something real to inspect: issuer, notAfter and the SAN list all come off the
// wire exactly as they would from an ingress. It returns that certificate
// PEM-encoded, so a test can hand it back as an internal CA bundle.
func domainsServeTLS(t *testing.T, addr, issuerCN string, sans []string, notAfter time.Time) []byte {
	t.Helper()
	ln := domainsListen(t, addr)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// An IP fixture needs an IP SAN or Go rejects it for that reason alone,
	// which would mask whatever the test is actually about. The name list is
	// kept in DNSNames as well, because that is what the check reads.
	var ips []net.IP
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	tmpl := &x509.Certificate{
		IPAddresses:           ips,
		SerialNumber:          big.NewInt(4242),
		Subject:               pkix.Name{CommonName: issuerCN},
		Issuer:                pkix.Name{CommonName: issuerCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		DNSNames:              sans,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(conn, cfg)
				_ = tc.Handshake()
				_ = tc.Close()
			}()
		}
	}()
	return pemBytes
}

// domainsTrustCA writes a PEM to disk and points the run's network adapter at
// it, which is what --ca-bundle does.
func domainsTrustCA(t *testing.T, pemBytes []byte) func(*engine.Ctx) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "internal-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca bundle: %v", err)
	}
	return func(c *engine.Ctx) {
		if err := c.Net.TrustCABundle(path); err != nil {
			t.Fatalf("trust ca bundle: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// domains.resolve

// The blocker this whole group exists for: a name that does not exist means the
// ingress never sees the traffic and an ACME order can never validate. A tool
// that reported that as anything softer than BLOCK would let an operator
// install a stack nobody can reach.
func TestDomainsResolveBlocksOnNamesThatCannotExist(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = domainsDeadRoot })
	r := domainsRun(t, f, "domains.resolve")
	assertStatus(t, r, "BLOCK")
	// The operator needs the host AND the record type, or the remedy is a mood.
	domainsAssertMentions(t, r, "admin."+domainsDeadRoot, "unresolved:")
	domainsAssertRemedy(t, r, "A/AAAA records", "ws.novu")
}

// The pass exists to prove the blocker above is not an artefact of the harness
// resolving nothing at all.
func TestDomainsResolvePassesWhenEveryPublishedNameResolves(t *testing.T) {
	f := vanilla()
	r := domainsRun(t, f, "domains.resolve", domainsRenderHosts(domainsTestNet, domainsLoopback))
	assertStatus(t, r, "PASS")
	domainsAssertMentions(t, r, "the rendered chart's Ingress/Route hosts")
	if r.DoesNotProve == "" {
		t.Fatal("domains.resolve passed without bounding the claim; a resolving name says nothing about where it points")
	}
}

// A rendered Ingress may carry a wildcard rule. It is not a name that can be
// looked up, so counting it as unresolved would manufacture a blocker against
// a chart that is configured correctly.
func TestDomainsResolveReportsWildcardRuleInsteadOfBlockingOnIt(t *testing.T) {
	f := vanilla()
	r := domainsRun(t, f, "domains.resolve", domainsRenderHosts("*.bud.example.com", domainsTestNet))
	assertStatus(t, r, "PASS")
	domainsAssertMentions(t, r, "*.bud.example.com", "not itself a resolvable name")
}

// OpenShift renders Routes, not Ingresses. Reading only Ingress would silently
// fall back to the answered domain and check the wrong names.
func TestDomainsResolveReadsRenderedOpenShiftRoutes(t *testing.T) {
	f := openShift()
	r := domainsRun(t, f, "domains.resolve", domainsRenderRoute(domainsTestNet))
	assertStatus(t, r, "PASS")
	domainsAssertMentions(t, r, domainsTestNet)
}

// No domain answered is "we did not look", never "it was fine".
func TestDomainsResolveSkipsWithAReasonWhenNoDomainAnswered(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = "" })
	assertSkipHasReason(t, domainsRun(t, f, "domains.resolve"))
}

// On OpenShift the cluster already owns a wildcard. Both the skip and the
// blocker have to say so, or the operator is told to create DNS they already
// have.
func TestDomainsResolveOffersTheOpenShiftAppsWildcard(t *testing.T) {
	t.Run("skip names it", func(t *testing.T) {
		f := openShift().withAnswers(func(a *intake.Answers) { a.Domain = "" })
		r := domainsRun(t, f, "domains.resolve")
		assertSkipHasReason(t, r)
		domainsAssertMentions(t, r, "apps.ocp.example.com")
	})
	t.Run("remedy names it", func(t *testing.T) {
		f := openShift().withAnswers(func(a *intake.Answers) { a.Domain = domainsDeadRoot })
		r := domainsRun(t, f, "domains.resolve")
		assertStatus(t, r, "BLOCK")
		domainsAssertRemedy(t, r, "--domain apps.ocp.example.com")
	})
}

// ---------------------------------------------------------------------------
// domains.points-at-ingress

// The failure: the name exists, but it belongs to somebody else's address.
// Requests reach them, not Bud, and nothing about the install will say so.
func TestDomainsPointsAtIngressRisksWhenNamesResolveElsewhere(t *testing.T) {
	f := vanilla().with("services", "", domainsLBService(domainsOtherNet))
	r := domainsRun(t, f, "domains.points-at-ingress", domainsRenderHosts(domainsTestNet))
	assertStatus(t, r, "RISK")
	domainsAssertMentions(t, r, domainsTestNet, "not an address of this cluster")
	domainsAssertRemedy(t, r, domainsOtherNet)
}

// FRD-020 §5.9's explicit demand: with only private addresses to compare
// against, the record may be perfectly correct and reached through NAT. RISK
// would be a fabricated finding and PASS would be a lie, so it is INFO and it
// says the tool cannot tell.
func TestDomainsPointsAtIngressIsInfoNotRiskWhenClusterIsPrivateOnly(t *testing.T) {
	// node() advertises an InternalIP and nothing else — the last fallback, and
	// the only one that can produce this verdict.
	f := vanilla().with("nodes", "", node("n1"), node("n2"))
	r := domainsRun(t, f, "domains.points-at-ingress", domainsRenderHosts(domainsTestNet))
	assertStatus(t, r, "INFO")
	domainsAssertMentions(t, r, "cannot tell", "10.0.0.1")
}

// Same fixture, flipped: once the cluster advertises a public address the very
// same private-address logic must not swallow a real mismatch.
func TestDomainsPointsAtIngressPassesWhenTheAddressesMatch(t *testing.T) {
	f := vanilla().with("services", "", domainsLBService(domainsTestNet))
	r := domainsRun(t, f, "domains.points-at-ingress", domainsRenderHosts(domainsTestNet))
	assertStatus(t, r, "PASS")
	if r.DoesNotProve == "" {
		t.Fatal("an address match was reported without bounding it; the ingress still has to admit a route for the host")
	}
}

// Nothing to compare against is not a pass either.
func TestDomainsPointsAtIngressSkipsWhenClusterAdvertisesNoAddress(t *testing.T) {
	r := domainsRun(t, vanilla(), "domains.points-at-ingress", domainsRenderHosts(domainsTestNet))
	assertSkipHasReason(t, r)
}

// Names that do not resolve belong to domains.resolve; comparing them here
// would report the same blocker twice under a softer severity.
func TestDomainsPointsAtIngressSkipsWhenNothingResolved(t *testing.T) {
	f := vanilla().
		with("services", "", domainsLBService(domainsTestNet)).
		withAnswers(func(a *intake.Answers) { a.Domain = domainsDeadRoot })
	r := domainsRun(t, f, "domains.points-at-ingress")
	assertSkipHasReason(t, r)
	domainsAssertMentions(t, r, "domains.resolve")
}

// ---------------------------------------------------------------------------
// domains.inbound-80

// The conditionality IS the check. The same closed port is a blocker under ACME
// HTTP-01 — no certificate will ever be issued — and merely a missing redirect
// under every other answer. Declaring it BLOCK unconditionally would stop
// installs that were never going to need port 80.
func TestDomainsInbound80SeverityFollowsTheTLSAnswer(t *testing.T) {
	cases := []struct {
		name   string
		tls    intake.TLSMethod
		want   string
		remedy []string
	}{
		{
			name:   "ACME HTTP-01 cannot issue without port 80, so it blocks",
			tls:    intake.TLSACMEHTTP01,
			want:   "BLOCK",
			remedy: []string{"ACME DNS-01", "customer-supplied certificate"},
		},
		{
			name:   "ACME DNS-01 validates over DNS, so a closed 80 is only a risk",
			tls:    intake.TLSACMEDNS01,
			want:   "RISK",
			remedy: []string{"not a blocker", "ACME DNS-01"},
		},
		{
			name:   "a customer-supplied certificate needs no challenge, so a closed 80 is only a risk",
			tls:    intake.TLSProvided,
			want:   "RISK",
			remedy: []string{"not a blocker", "customer-supplied certificate"},
		},
		{
			name:   "with TLS answered as none, 80 is the only path in but still not a certificate blocker",
			tls:    intake.TLSNone,
			want:   "RISK",
			remedy: []string{"only path"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := vanilla().withAnswers(func(a *intake.Answers) { a.TLS = tc.tls })
			r := domainsRun(t, f, "domains.inbound-80", domainsRenderHosts(domainsTestNet))
			assertStatus(t, r, tc.want)
			domainsAssertMentions(t, r, domainsTestNet)
			domainsAssertRemedy(t, r, tc.remedy...)
		})
	}
}

// The blocker has to name the mechanism, not just the port: "open 80" without
// "ACME HTTP-01 will never validate" reads as a nicety an operator can defer.
func TestDomainsInbound80BlockerExplainsTheACMEConsequence(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.TLS = intake.TLSACMEHTTP01 })
	r := domainsRun(t, f, "domains.inbound-80", domainsRenderHosts(domainsTestNet))
	assertStatus(t, r, "BLOCK")
	domainsAssertMentions(t, r, "ACME HTTP-01", "acme-challenge")
	if !strings.Contains(r.Summary, "no certificate is ever issued") {
		t.Fatalf("the summary states a closed port but not its cost: %q", r.Summary)
	}
}

func TestDomainsInbound80PassesWhenThePortAnswers(t *testing.T) {
	domainsServeHTTP(t, domainsLoopback+":80")
	f := vanilla()
	r := domainsRun(t, f, "domains.inbound-80", domainsRenderHosts(domainsLoopback))
	assertStatus(t, r, "PASS")
	// A pass from this host is not a pass from Let's Encrypt's validators, and
	// the result has to say so or it will be over-read.
	if !strings.Contains(r.DoesNotProve, "public internet") {
		t.Fatalf("inbound-80 passed without stating its vantage point: %q", r.DoesNotProve)
	}
}

func TestDomainsInbound80SkipsWithAReasonWhenThereIsNothingToDial(t *testing.T) {
	t.Run("no domain answered", func(t *testing.T) {
		f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = "" })
		assertSkipHasReason(t, domainsRun(t, f, "domains.inbound-80"))
	})
	t.Run("no hostname resolves", func(t *testing.T) {
		f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = domainsDeadRoot })
		r := domainsRun(t, f, "domains.inbound-80")
		assertSkipHasReason(t, r)
		domainsAssertMentions(t, r, "domains.resolve")
	})
}

// ---------------------------------------------------------------------------
// domains.inbound-443

// Every Bud URL is HTTPS. A closed 443 is a risk rather than a blocker because
// the install still succeeds — and is then unreachable.
func TestDomainsInbound443RisksWhenThePortIsClosed(t *testing.T) {
	r := domainsRun(t, vanilla(), "domains.inbound-443", domainsRenderHosts(domainsTestNet))
	assertStatus(t, r, "RISK")
	domainsAssertMentions(t, r, domainsTestNet)
	domainsAssertRemedy(t, r, "443")
}

func TestDomainsInbound443PassesWhenThePortAnswers(t *testing.T) {
	domainsServeTCP(t, domainsLoopback+":443")
	r := domainsRun(t, vanilla(), "domains.inbound-443", domainsRenderHosts(domainsLoopback))
	assertStatus(t, r, "PASS")
	// A listener is not a usable certificate; that is domains.tls's job.
	domainsAssertMentions(t, r, "domains.tls")
}

// With TLS answered as 'none' a closed 443 is the configured outcome. Reporting
// it as a risk would train operators to ignore the group.
func TestDomainsInbound443SkipsWithAReasonWhenTLSIsNone(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.TLS = intake.TLSNone })
	r := domainsRun(t, f, "domains.inbound-443", domainsRenderHosts(domainsTestNet))
	assertSkipHasReason(t, r)
	domainsAssertMentions(t, r, "'none'")
}

func TestDomainsInbound443SkipsWithAReasonWhenNoDomainAnswered(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = "" })
	assertSkipHasReason(t, domainsRun(t, f, "domains.inbound-443"))
}

// ---------------------------------------------------------------------------
// domains.tls

// A certificate that expires inside the 14-day floor outlives the install but
// not the first weeks of running it, which is precisely the failure nobody
// notices until every client breaks at once.
func TestDomainsTLSRisksOnACertificateExpiringInsideTheFloor(t *testing.T) {
	// The SAN is the literal published name so the certificate counts as "ours"
	// rather than as the ingress placeholder — otherwise the expiry is never
	// even examined. The extra hour is not cosmetic: domainsDuration truncates
	// whole days, so a certificate minted at exactly now+7d is already reported
	// as "6 days" by the time the handshake happens.
	domainsServeTLS(t, domainsLoopback+":443", "budctl test CA",
		[]string{domainsLoopback}, time.Now().Add(7*24*time.Hour+time.Hour))
	r := domainsRun(t, vanilla(), "domains.tls", domainsRenderHosts(domainsLoopback))
	assertStatus(t, r, "RISK")
	domainsAssertMentions(t, r, "expires in 7 days", "inside the 14-day floor")
}

// The wildcard trap, stated as a fixture: a certificate for one published name
// does not cover the others, and the check has to name the one it misses.
func TestDomainsTLSRisksWhenTheServedCertificateMissesAPublishedName(t *testing.T) {
	domainsServeTLS(t, domainsLoopback+":443", "budctl test CA",
		[]string{domainsLoopback}, time.Now().Add(365*24*time.Hour))
	r := domainsRun(t, vanilla(), "domains.tls",
		domainsRenderHosts(domainsLoopback, domainsTestNet))
	assertStatus(t, r, "RISK")
	domainsAssertMentions(t, r, "does not cover", domainsTestNet)
	domainsAssertRemedy(t, r, domainsTestNet)
}

// An untrusted chain is a finding, not an outage: TLSInspect retries without
// verification so the certificate is reported as what it is.
func TestDomainsTLSRisksWhenTheServedChainDoesNotVerify(t *testing.T) {
	domainsServeTLS(t, domainsLoopback+":443", "budctl test CA",
		[]string{domainsLoopback}, time.Now().Add(365*24*time.Hour))
	r := domainsRun(t, vanilla(), "domains.tls", domainsRenderHosts(domainsLoopback))
	assertStatus(t, r, "RISK")
	domainsAssertMentions(t, r, "does not verify", "budctl test CA")
}

// Before the install the ingress serves its own placeholder. That is the
// expected state, so it is INFO — but it is emphatically not a PASS, because no
// certificate for the published names exists yet.
func TestDomainsTLSReportsThePlaceholderCertificateAsInfo(t *testing.T) {
	domainsServeTLS(t, domainsLoopback+":443", "Kubernetes Ingress Controller Fake Certificate",
		[]string{"ingress.local"}, time.Now().Add(365*24*time.Hour))
	r := domainsRun(t, vanilla(), "domains.tls", domainsRenderHosts(domainsLoopback))
	assertStatus(t, r, "INFO")
	domainsAssertMentions(t, r, "placeholder", "Kubernetes Ingress Controller Fake Certificate")
}

// Nothing on 443 yet is the normal pre-install state: cert-manager has not been
// deployed. The skip has to say that, or an operator reads it as a failure.
func TestDomainsTLSSkipsWithAReasonWhenNothingServesTLSYet(t *testing.T) {
	r := domainsRun(t, vanilla(), "domains.tls", domainsRenderHosts(domainsTestNet))
	assertSkipHasReason(t, r)
	domainsAssertMentions(t, r, "cert-manager")
}

func TestDomainsTLSSkipsWithAReasonWhenNoDomainAnswered(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = "" })
	assertSkipHasReason(t, domainsRun(t, f, "domains.tls"))
}

// ---------------------------------------------------------------------------
// domains.wildcard

// domains.wildcard is INFO by design (FRD-020 §5.9): it reports a fact that
// makes other work unnecessary, and can never fail. Its value is in what the
// detail says — above all the one-label rule, which is the single most common
// way a wildcard is believed to cover names it does not.
func TestDomainsWildcardIsInfoAndNamesTheOneLabelTrap(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = domainsDeadRoot })
	r := domainsRun(t, f, "domains.wildcard")
	assertStatus(t, r, "INFO")
	domainsAssertMentions(t, r,
		"no wildcard record covers "+domainsDeadRoot,
		"a DNS wildcard matches exactly one label",
		"api.novu."+domainsDeadRoot,
		"ws.novu."+domainsDeadRoot,
	)
	// The intermediate zone has to be probed in its own right, or the tool would
	// report "*.<root> exists" and leave the two-label names broken.
	domainsAssertMentions(t, r, domainsProbeLabel+".novu."+domainsDeadRoot)
}

// On OpenShift the apps wildcard already exists and costs the operator nothing.
// A wildcard check that ignored it would send them to their DNS provider for
// records they do not need.
func TestDomainsWildcardAccountsForTheOpenShiftAppsDomain(t *testing.T) {
	f := openShift().withAnswers(func(a *intake.Answers) { a.Domain = domainsDeadRoot })
	r := domainsRun(t, f, "domains.wildcard")
	assertStatus(t, r, "INFO")
	domainsAssertMentions(t, r,
		"OpenShift already owns *.apps.ocp.example.com",
		domainsProbeLabel+".apps.ocp.example.com", // the apps zone is actually probed
	)
}

func TestDomainsWildcardSkipsWithAReasonWhenThereIsNoZoneToProbe(t *testing.T) {
	f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = "" })
	assertSkipHasReason(t, domainsRun(t, f, "domains.wildcard"))
}

// BUG (documented, not asserted as correct): on OpenShift with no --domain the
// apps wildcard alone keeps the zone list non-empty, so the check reports
// instead of skipping — and the summary interpolates an empty root and a zero
// hostname count ("no wildcard record covers , so each of the 0 hostnames...").
// The AppsDomain IS still surfaced in the detail, which is what this asserts;
// the summary should say the same thing domainsNoHostsReason says.
func TestDomainsWildcardOnOpenShiftWithNoDomainStillSurfacesTheAppsWildcard(t *testing.T) {
	f := openShift().withAnswers(func(a *intake.Answers) { a.Domain = "" })
	r := domainsRun(t, f, "domains.wildcard")
	assertStatus(t, r, "INFO")
	domainsAssertMentions(t, r, "OpenShift already owns *.apps.ocp.example.com")
}

// ---------------------------------------------------------------------------
// group-wide

// FRD-020 R1: every result in this group is qualified by where budctl ran.
// Without it, "inbound :80 is open" from a jump host inside the firewall is an
// actively misleading statement.
func TestDomainsEveryResultStatesItsVantagePoint(t *testing.T) {
	ids := []string{
		"domains.resolve", "domains.points-at-ingress", "domains.inbound-80",
		"domains.inbound-443", "domains.tls", "domains.wildcard",
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			f := vanilla().withAnswers(func(a *intake.Answers) { a.Domain = domainsDeadRoot })
			r := domainsRun(t, f, id)
			if !strings.Contains(domainsText(r), "vantage point") {
				t.Fatalf("%s (%s) never states the vantage point it used:\n%s", id, r.Status(), domainsText(r))
			}
		})
	}
}

// A certificate from an internal CA is the normal shape of "I supply my own
// certificate" on-prem. Without the root it cannot be told apart from a
// misissued one, so it is a RISK that names the actual x509 cause; given the
// root through --ca-bundle it verifies like any other.
func TestDomainsTLSVerifiesAnInternalCAWhenGivenItsRoot(t *testing.T) {
	ca := domainsServeTLS(t, domainsLoopback+":443", "Acme Internal CA",
		[]string{domainsLoopback}, time.Now().Add(365*24*time.Hour))
	provided := func(c *engine.Ctx) { c.Answers.TLS = intake.TLSProvided }

	r := domainsRun(t, vanilla(), "domains.tls", domainsRenderHosts(domainsLoopback), provided)
	assertStatus(t, r, "RISK")
	// The cause has to survive: "unknown authority" and "expired" are different
	// problems with different fixes.
	domainsAssertMentions(t, r, "unknown authority", "Acme Internal CA")
	domainsAssertRemedy(t, r, "--ca-bundle")

	r = domainsRun(t, vanilla(), "domains.tls", domainsRenderHosts(domainsLoopback), provided,
		domainsTrustCA(t, ca))
	assertStatus(t, r, "PASS")
}

// The remedy must not invent work. When the only problem is the chain or the
// dates, there is no uncovered name to list.
func TestDomainsTLSRemedyDoesNotAskToCoverNothing(t *testing.T) {
	// Trusted through its own root, so the chain is fine and the dates are the
	// only finding.
	ca := domainsServeTLS(t, domainsLoopback+":443", "budctl test CA",
		[]string{domainsLoopback}, time.Now().Add(7*24*time.Hour+time.Hour))
	r := domainsRun(t, vanilla(), "domains.tls", domainsRenderHosts(domainsLoopback),
		domainsTrustCA(t, ca))
	assertStatus(t, r, "RISK")
	if strings.Contains(r.Remedy, "cover none") || strings.Contains(r.Remedy, "cover  ") {
		t.Errorf("remedy asks the operator to cover nothing: %s", r.Remedy)
	}
}
