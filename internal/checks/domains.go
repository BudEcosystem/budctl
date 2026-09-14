package checks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// The domains group answers "will traffic for the names the chart publishes
// arrive at this cluster, and can a certificate be obtained for them" —
// FRD-020 §5.9. Nothing here inspects cert-manager: cert-manager is installed
// by the cluster-addons ApplicationSet and does not exist yet, so the only
// thing readiness can prove is the *network path* an issuer will need (§5.8).
//
// Every result in this group is qualified by its vantage point. FRD-020 R1: run
// from a jump host inside the cluster's network, an "inbound :80 is open"
// result says nothing about the public internet, and a tool that does not say
// so is actively misleading.

const (
	// domainsVantage is attached to every result in this group.
	domainsVantage = "vantage point: this host, where budctl runs — not from inside the cluster, and not necessarily from the public internet"

	// domainsProbeLabel is a fixed, deliberately unlikely label. A wildcard
	// record is detected by resolving a name nobody would ever create; keeping
	// it fixed rather than random means two runs produce the same transcript.
	domainsProbeLabel = "budctl-wildcard-probe"

	// domainsCertFloor is FRD-020 §5.9's "expiry > 14 days". Below it a
	// certificate outlives the install but not the first weeks of running it.
	domainsCertFloor = 14 * 24 * time.Hour
)

func init() {
	engine.Register(&engine.Check{
		ID: "domains.resolve", Group: "domains", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("domains.resolve")
			if c.Net == nil {
				return ch.Skip("no network adapter: DNS was never queried").With(domainsVantage)
			}
			hosts, wildcards, source := domainHostnames(c)
			if len(hosts) == 0 {
				return ch.Skip(domainsNoHostsReason(c)).With(domainsVantage)
			}

			res := domainResolveAll(ctx, c, hosts)
			var ok, bad []string
			ev := make([]engine.Evidence, 0, len(hosts))
			for _, h := range hosts {
				r := res[h]
				if len(r.addrs) > 0 {
					ok = append(ok, h)
					ev = append(ev, engine.Evidence{What: "resolve " + h, Output: strings.Join(r.addrs, " ")})
					continue
				}
				bad = append(bad, h)
				ev = append(ev, engine.Evidence{What: "resolve " + h, Output: r.err})
			}

			detail := []string{domainsVantage, "hostnames from " + source}
			for _, w := range wildcards {
				// A rendered Ingress rule may itself carry a wildcard host. It
				// is not a name that can be looked up, so it is reported rather
				// than counted as an unresolved blocker.
				detail = append(detail, "the chart publishes the wildcard rule "+w+", which is not itself a resolvable name")
			}
			for _, h := range ok {
				detail = append(detail, h+" -> "+strings.Join(res[h].addrs, ", "))
			}

			if len(bad) > 0 {
				detail = append(detail, "unresolved: "+strings.Join(bad, ", "))
				return ch.Fail(
					fmt.Sprintf("%d of %d hostnames do not resolve (%s); the ingress will never see traffic for them and an ACME order covering them can never validate",
						len(bad), len(hosts), domainsList(bad, 3)),
					domainsResolveRemedy(c, bad),
					detail...).WithEvidence(ev...)
			}
			return ch.Pass(fmt.Sprintf("all %d %s resolve", len(hosts), Plural(len(hosts), "hostname", "hostnames")), detail...).
				WithEvidence(ev...).
				Bounds("that a name resolves says nothing about WHERE it points — domains.points-at-ingress answers that — and nothing about whether the ingress will admit a route for it")
		},
	})

	engine.Register(&engine.Check{
		ID: "domains.points-at-ingress", Group: "domains", Severity: engine.Risk,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("domains.points-at-ingress")
			if c.Net == nil {
				return ch.Skip("no network adapter: DNS was never queried").With(domainsVantage)
			}
			if c.Kube == nil {
				return ch.Skip("cluster unreachable: this cluster's ingress address is unknown, so there is nothing to compare the DNS records against").
					With(domainsVantage)
			}
			hosts, _, source := domainHostnames(c)
			if len(hosts) == 0 {
				return ch.Skip(domainsNoHostsReason(c)).With(domainsVantage)
			}

			ing := domainIngressAddresses(ctx, c)
			if len(ing.addrs) == 0 {
				return ch.Skip("the cluster advertises neither a LoadBalancer address nor any node address, so budctl has nothing to compare these records against").
					With(domainsVantage, "ingress lookup: "+ing.source)
			}

			res := domainResolveAll(ctx, c, hosts)
			var match, miss, missDetail, unresolved []string
			for _, h := range hosts {
				r := res[h]
				if len(r.addrs) == 0 {
					unresolved = append(unresolved, h)
					continue
				}
				if domainIntersects(r.addrs, ing.addrs) {
					match = append(match, h)
					continue
				}
				miss = append(miss, h)
				missDetail = append(missDetail, h+" -> "+strings.Join(r.addrs, ", ")+" (not an address of this cluster)")
			}

			detail := []string{
				domainsVantage,
				"hostnames from " + source,
				"cluster front door (" + ing.source + "): " + strings.Join(ing.display(), ", "),
			}
			if len(unresolved) > 0 {
				detail = append(detail, "not compared because they do not resolve at all (see domains.resolve): "+strings.Join(unresolved, ", "))
			}
			detail = append(detail, missDetail...)
			ev := []engine.Evidence{{What: "addresses this cluster advertises", Output: strings.Join(ing.display(), "\n")}}

			// FRD-020 §5.9: when every address the cluster advertises is
			// private, a public A record CANNOT be matched against it from here
			// — the record may well be correct and reached through NAT. Calling
			// that a RISK would be a fabricated finding; calling it a PASS would
			// be a lie. It is INFO, and it says the tool cannot tell.
			if len(ing.public) == 0 {
				if len(match) > 0 {
					detail = append(detail, fmt.Sprintf("%d of them do resolve to one of those private addresses, which only means this host shares the cluster's network", len(match)))
				}
				return ch.Infof("the cluster advertises only private addresses (%s), so budctl cannot tell whether these %d hostnames point at this ingress",
					domainsList(ing.private, 3), len(hosts)).With(detail...).WithEvidence(ev...)
			}

			if len(miss) > 0 {
				return ch.Fail(
					fmt.Sprintf("%d %s (%s) resolve somewhere other than this cluster's ingress; requests for them reach whoever owns that address, never Bud",
						len(miss), Plural(len(miss), "hostname", "hostnames"), domainsList(miss, 3)),
					fmt.Sprintf("repoint those A/AAAA records at the ingress address (%s), or re-run the intake with the domain that already points here",
						domainsList(ing.public, 2)),
					detail...).WithEvidence(ev...)
			}
			if len(match) == 0 {
				return ch.Skip("no hostname resolves, so none could be compared against the ingress address (see domains.resolve)").
					With(detail...)
			}
			return ch.Pass(fmt.Sprintf("all %d resolving %s point at this cluster's ingress", len(match), Plural(len(match), "hostname", "hostnames")), detail...).
				WithEvidence(ev...).
				Bounds("an address match does not prove the ingress will admit a route for that hostname: on OpenShift admission depends on the IngressController domain and its routeSelector, on vanilla on the IngressClass the values name")
		},
	})

	engine.Register(&engine.Check{
		// Declared BLOCK because that is what it is for the default TLS answer.
		// Every other answer downgrades it through FailAs: without ACME HTTP-01
		// a closed :80 costs a redirect, not the install (FRD-020 §5.9).
		ID: "domains.inbound-80", Group: "domains", Severity: engine.Block,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("domains.inbound-80")
			acme := c.Answers.TLS == intake.TLSACMEHTTP01
			targets, unresolved, skip := domainInboundTargets(ctx, c, ch)
			if skip != nil {
				return *skip
			}

			detail := []string{domainsVantage, "TLS will be obtained by: " + domainsTLSMethod(c)}
			if acme {
				detail = append(detail, "ACME HTTP-01 validates by fetching http://<host>/.well-known/acme-challenge/<token> on port 80; the 301 to 443 that most ingresses install does not remove that requirement, because the challenge has to be answered on 80 first")
			}
			if c.Answers.TLS == intake.TLSNone {
				detail = append(detail, "TLS was answered as 'none', so port 80 is the only inbound path the stack will have")
			}
			if len(unresolved) > 0 {
				detail = append(detail, "not dialled because they do not resolve (see domains.resolve): "+strings.Join(unresolved, ", "))
			}

			var open, closed []string
			var closedHosts []string
			ev := []engine.Evidence{}
			for _, t := range targets {
				ok, why := c.Net.TCP(ctx, t.host, 80)
				if !ok {
					closed = append(closed, t.label()+": "+why)
					closedHosts = append(closedHosts, t.names()...)
					ev = append(ev, engine.Evidence{What: "tcp " + t.host + ":80", Output: why + " (addresses: " + strings.Join(t.addrs, ", ") + ")"})
					continue
				}
				open = append(open, t.label())
				ev = append(ev, engine.Evidence{What: "tcp " + t.host + ":80", Output: "connected via " + strings.Join(t.addrs, ", ")})
				if acme {
					// A 404 here is a PASS: it proves DNS, routing and a live
					// HTTP listener on 80 answered the exact path ACME will
					// request. Only "no answer" disproves the challenge path.
					hr := c.Net.Probe(ctx, "http://"+t.host+"/.well-known/acme-challenge/"+domainsProbeLabel)
					ev = append(ev, engine.Evidence{
						What:   "GET http://" + t.host + "/.well-known/acme-challenge/" + domainsProbeLabel,
						Output: domainsHTTPOutcome(hr) + " — any status, 404 included, means the challenge path reaches a live listener",
					})
				}
			}
			detail = append(detail, closed...)

			if len(closed) > 0 {
				if acme {
					return ch.Fail(
						fmt.Sprintf("port 80 does not answer for %s, so ACME HTTP-01 will never validate: no certificate is ever issued and every Bud URL fails TLS indefinitely",
							domainsList(closedHosts, 3)),
						"open inbound TCP/80 from the internet to the ingress — the LoadBalancer listener, the cloud security group, the on-prem firewall and any upstream WAF — or re-run the intake choosing ACME DNS-01, which needs no inbound 80, or a customer-supplied certificate",
						detail...).WithEvidence(ev...)
				}
				return ch.FailAs(engine.Risk,
					fmt.Sprintf("port 80 does not answer for %s; plain-HTTP clients get nothing and the usual HTTP-to-HTTPS redirect will not exist",
						domainsList(closedHosts, 3)),
					domainsInbound80Remedy(c),
					detail...).WithEvidence(ev...)
			}
			detail = append(detail, "open: "+strings.Join(open, ", "))
			return ch.Pass(fmt.Sprintf("port 80 answers for all %d resolving %s", len(targets), Plural(len(targets), "endpoint", "endpoints")), detail...).
				WithEvidence(ev...).
				Bounds("port 80 was reached from this host's network only; if budctl is running inside the cluster's network or behind the same firewall, this does not prove that the public internet — or Let's Encrypt's validation servers — can reach it")
		},
	})

	engine.Register(&engine.Check{
		ID: "domains.inbound-443", Group: "domains", Severity: engine.Risk,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("domains.inbound-443")
			if c.Answers.TLS == intake.TLSNone {
				return ch.Skip("TLS was answered as 'none': no HTTPS listener is expected, so a closed 443 is the configured outcome rather than a finding").
					With(domainsVantage)
			}
			targets, unresolved, skip := domainInboundTargets(ctx, c, ch)
			if skip != nil {
				return *skip
			}

			detail := []string{domainsVantage, "TLS will be obtained by: " + domainsTLSMethod(c)}
			if len(unresolved) > 0 {
				detail = append(detail, "not dialled because they do not resolve (see domains.resolve): "+strings.Join(unresolved, ", "))
			}
			var open, closed, closedHosts []string
			ev := []engine.Evidence{}
			for _, t := range targets {
				ok, why := c.Net.TCP(ctx, t.host, 443)
				if !ok {
					closed = append(closed, t.label()+": "+why)
					closedHosts = append(closedHosts, t.names()...)
					ev = append(ev, engine.Evidence{What: "tcp " + t.host + ":443", Output: why + " (addresses: " + strings.Join(t.addrs, ", ") + ")"})
					continue
				}
				open = append(open, t.label())
				ev = append(ev, engine.Evidence{What: "tcp " + t.host + ":443", Output: "connected via " + strings.Join(t.addrs, ", ")})
			}
			detail = append(detail, closed...)

			if len(closed) > 0 {
				return ch.Fail(
					fmt.Sprintf("port 443 does not answer for %s; once installed, every Bud URL — the dashboard, the gateway and the Novu websocket — is unreachable over HTTPS",
						domainsList(closedHosts, 3)),
					"open inbound TCP/443 to the ingress LoadBalancer and check the cloud security group, the on-prem firewall and any upstream proxy; if no ingress controller is installed yet, re-run this check after the cluster-addons sync",
					detail...).WithEvidence(ev...)
			}
			detail = append(detail, "open: "+strings.Join(open, ", "))
			return ch.Pass(fmt.Sprintf("port 443 answers for all %d resolving %s", len(targets), Plural(len(targets), "endpoint", "endpoints")), detail...).
				WithEvidence(ev...).
				Bounds("reached from this host's network only, and a listener on 443 is not a usable certificate — domains.tls inspects what is actually served")
		},
	})

	engine.Register(&engine.Check{
		ID: "domains.tls", Group: "domains", Severity: engine.Risk,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("domains.tls")
			if c.Net == nil {
				return ch.Skip("no network adapter: no TLS handshake was attempted").With(domainsVantage)
			}
			hosts, _, source := domainHostnames(c)
			if len(hosts) == 0 {
				return ch.Skip(domainsNoHostsReason(c)).With(domainsVantage)
			}
			res := domainResolveAll(ctx, c, hosts)
			var live []string
			for _, h := range hosts {
				if len(res[h].addrs) > 0 {
					live = append(live, h)
				}
			}
			if len(live) == 0 {
				return ch.Skip("no hostname resolves, so no TLS handshake was possible (see domains.resolve)").With(domainsVantage)
			}

			certs := domainInspectTLS(ctx, c, live)
			now := c.Now()
			detail := []string{domainsVantage, "hostnames from " + source}
			ev := []engine.Evidence{}

			var problems []string     // each names a host and what is wrong with it
			var placeholders []string // the ingress default certificate, pre-install
			var owned []domainCert    // certificates actually meant for one of our names
			untrusted := false        // at least one served chain did not verify
			var sans []string         // SAN union across those certificates
			served := 0

			for _, h := range live {
				cert, seen := certs[h]
				if !seen {
					detail = append(detail, h+": not inspected, the check ran out of time")
					continue
				}
				if !cert.present {
					detail = append(detail, h+": nothing is serving TLS ("+cert.err+")")
					continue
				}
				served++
				ev = append(ev, engine.Evidence{
					What: "tls handshake " + h + ":443",
					Output: fmt.Sprintf("issuer=%q notAfter=%s sans=[%s]%s", cert.issuer,
						cert.expiry.UTC().Format(time.RFC3339), strings.Join(cert.sans, ","), cert.errSuffix()),
				})

				// A certificate whose SANs do not cover the name it was served
				// for is the ingress controller's built-in placeholder (nginx's
				// "Fake Certificate", Traefik's default). An uninstalled cluster
				// is supposed to serve exactly that, so it is reported rather
				// than counted against the operator. OpenShift's router serves a
				// cluster-CA-signed certificate for *.apps that DOES cover the
				// name and is untrusted outside the cluster — also a platform
				// default, and flagging it would fail every clean OpenShift.
				if isDefault := cert.isDefaultRouterCert(c); isDefault || !domainSANsCover(cert.sans, h) {
					what := "the ingress controller's default placeholder certificate"
					if isDefault {
						what = "OpenShift's default router certificate, signed by the cluster CA"
					}
					placeholders = append(placeholders, h+": "+what+" (issuer "+cert.issuer+")")
					continue
				}

				owned = append(owned, cert)
				sans = append(sans, cert.sans...)
				if cert.invalid {
					untrusted = true
					problems = append(problems, h+": the served chain does not verify ("+cert.err+", issuer "+cert.issuer+")")
				}
				switch left := cert.expiry.Sub(now); {
				case left <= 0:
					problems = append(problems, fmt.Sprintf("%s: the certificate expired %s ago", h, domainsDuration(-left)))
				case left < domainsCertFloor:
					problems = append(problems, fmt.Sprintf("%s: the certificate expires in %s, inside the 14-day floor", h, domainsDuration(left)))
				}
			}

			if len(owned) == 0 {
				if served > 0 {
					// We looked, and what we found was the pre-install default.
					// That is a fact worth showing, and it is not a pass.
					return ch.Infof("no hostname is served by a certificate of its own yet; %d %s only the platform placeholder",
						len(placeholders), Plural(len(placeholders), "endpoint serves", "endpoints serve")).
						With(append(detail, placeholders...)...).WithEvidence(ev...)
				}
				return ch.Skip("no hostname is serving TLS yet, which is the expected state before the install: cert-manager is deployed by the cluster-addons ApplicationSet and issues certificates afterwards").
					With(detail...)
			}

			// SAN coverage is judged against every hostname the chart publishes,
			// not only the ones already serving TLS: one certificate is normally
			// expected to carry them all. The wildcard is the trap — *.<root>
			// matches admin.<root> but NOT api.novu.<root>, because a wildcard
			// SAN matches exactly one label.
			sans = Sorted(sans)
			var uncovered []string
			for _, h := range hosts {
				if !domainSANsCover(sans, h) {
					uncovered = append(uncovered, h)
				}
			}
			if len(uncovered) > 0 {
				problems = append(problems, "the served certificate does not cover "+domainsList(uncovered, 4))
			}
			detail = append(detail, "SANs observed: "+strings.Join(sans, ", "))
			detail = append(detail, placeholders...)

			if len(problems) > 0 {
				detail = append(detail, problems...)
				return ch.Fail(
					"the certificate already serving these names is not usable as it stands: "+domainsList(problems, 2),
					domainsTLSRemedy(c, uncovered, untrusted),
					detail...).WithEvidence(ev...)
			}
			return ch.Pass(fmt.Sprintf("the served certificate verifies, expires in %s and covers all %d hostnames",
				domainsDuration(domainSoonestExpiry(owned).Sub(now)), len(hosts)), detail...).
				WithEvidence(ev...).
				Bounds("validated against this host's trust store and from this host's network; a client behind a TLS-inspecting proxy, or with a different root store, may still reject it")
		},
	})

	engine.Register(&engine.Check{
		ID: "domains.wildcard", Group: "domains", Severity: engine.Info,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("domains.wildcard")
			if c.Net == nil {
				return ch.Skip("no network adapter: DNS was never queried").With(domainsVantage)
			}
			hosts, _, _ := domainHostnames(c)
			root := strings.TrimPrefix(strings.TrimSpace(c.Answers.Domain), ".")
			// The zones worth probing are the answered root, every intermediate
			// zone a two-label hostname sits in (api.novu.<root> needs
			// *.novu.<root>, which *.<root> does not provide), and the wildcard
			// OpenShift already owns.
			zones := domainWildcardZones(hosts, root, c)
			if len(zones) == 0 {
				return ch.Skip(domainsNoHostsReason(c)).With(domainsVantage)
			}

			detail := []string{domainsVantage}
			ev := []engine.Evidence{}
			var found, absent []string
			for _, z := range zones {
				probe := domainsProbeLabel + "." + z
				addrs, err := c.Net.Resolve(ctx, probe)
				out := strings.Join(addrs, " ")
				if err != nil {
					out = err.Error()
				}
				ev = append(ev, engine.Evidence{
					What:   "resolve " + probe,
					Output: out + " — this name exists only if *." + z + " does",
				})
				if len(addrs) > 0 {
					found = append(found, "*."+z)
					detail = append(detail, "*."+z+" -> "+strings.Join(Sorted(domainNormalize(addrs)), ", "))
					continue
				}
				absent = append(absent, "*."+z)
			}

			covered := 0
			var deep []string
			for _, h := range hosts {
				if domainSANsCover(found, h) {
					covered++
					continue
				}
				if domainDeeperThanOneLabel(h, root) {
					deep = append(deep, h)
				}
			}
			if len(deep) > 0 {
				detail = append(detail, "a DNS wildcard matches exactly one label, so *."+root+" does NOT cover "+strings.Join(deep, ", "))
			}
			if len(absent) > 0 {
				detail = append(detail, "no wildcard record for "+strings.Join(absent, ", "))
			}
			if c.Platform.IsOpenShift() && c.Platform.AppsDomain != "" {
				detail = append(detail, "OpenShift already owns *."+c.Platform.AppsDomain+"; hostnames under it need no new DNS records at all")
			}

			if len(found) == 0 {
				return ch.Infof("no wildcard record covers %s, so each of the %d hostnames needs an A/AAAA record of its own", root, len(hosts)).
					With(detail...).WithEvidence(ev...)
			}
			return ch.Infof("%s in place, which satisfies domains.resolve for %d of the %d hostnames at once",
				strings.Join(found, " and "), covered, len(hosts)).
				With(detail...).WithEvidence(ev...)
		},
	})
}

// ---------------------------------------------------------------------------
// hostnames

// domainHostnames returns the names the chart will publish. The intake answer
// is the default shape; when --values produced a render, the Ingress and Route
// hosts it actually contains are authoritative, because a per-host override in
// global.ingress.hosts makes the default name a phantom and blocking on it
// would be a fabricated finding (FRD-020 §5.9).
func domainHostnames(c *engine.Ctx) (hosts, wildcards []string, source string) {
	// Rendered is nil when no --values was given; that is a degrade to the
	// answered shape, never a silent check of nothing.
	if objs := Rendered(c); objs != nil {
		for _, o := range objs {
			switch o.Kind() {
			case "Ingress":
				for _, raw := range o.DigSlice("spec", "rules") {
					m, ok := raw.(map[string]any)
					if !ok {
						continue
					}
					h, _ := m["host"].(string)
					if h == "" {
						continue
					}
					if strings.HasPrefix(h, "*.") {
						wildcards = append(wildcards, h)
					} else {
						hosts = append(hosts, h)
					}
				}
			case "Route":
				if h := o.DigString("spec", "host"); h != "" {
					hosts = append(hosts, h)
				}
			}
		}
	}
	if len(hosts) > 0 {
		return Sorted(hosts), Sorted(wildcards), "the rendered chart's Ingress/Route hosts"
	}
	return Sorted(c.Answers.Hostnames()), nil, "the answered domain " + c.Answers.Domain
}

// domainsNoHostsReason keeps every skip in this group specific about WHY there
// is nothing to check, and points OpenShift operators at the wildcard their
// cluster already owns.
func domainsNoHostsReason(c *engine.Ctx) string {
	if c.Platform.IsOpenShift() && c.Platform.AppsDomain != "" {
		return "no domain was answered, so the stack has no hostnames; this cluster already owns *." +
			c.Platform.AppsDomain + ", which would need no new DNS records"
	}
	return "no domain was answered, so the stack has no hostnames to check"
}

func domainsResolveRemedy(c *engine.Ctx, bad []string) string {
	root := strings.TrimPrefix(strings.TrimSpace(c.Answers.Domain), ".")
	r := "create A/AAAA records for " + domainsList(bad, 4) + " pointing at the ingress address"
	if root != "" {
		r += "; one *." + root + " wildcard covers the single-label names, but api.novu/ws.novu need records of their own because a DNS wildcard matches exactly one label"
	}
	if c.Platform.IsOpenShift() && c.Platform.AppsDomain != "" {
		r += ", or re-run the intake with --domain " + c.Platform.AppsDomain + ", the wildcard this cluster already owns"
	}
	return r
}

func domainsTLSMethod(c *engine.Ctx) string {
	switch c.Answers.TLS {
	case intake.TLSACMEHTTP01:
		return "ACME HTTP-01"
	case intake.TLSACMEDNS01:
		return "ACME DNS-01"
	case intake.TLSProvided:
		return "a customer-supplied certificate"
	case intake.TLSNone:
		return "none (plain HTTP)"
	}
	return "unspecified"
}

// domainsInbound80Remedy explains why the same closed port is not a blocker
// here. TLSNone is the uncomfortable case: port 80 is then the only inbound
// path, but FRD-020 §5.9 ties the blocker strictly to ACME HTTP-01, because
// that is the answer under which a certificate can never appear.
func domainsInbound80Remedy(c *engine.Ctx) string {
	if c.Answers.TLS == intake.TLSNone {
		return "open inbound TCP/80 to the ingress: with TLS answered as 'none' it is the only path the stack will have, so nothing will be reachable until it is open. It is a RISK rather than a blocker only because no certificate issuance depends on it"
	}
	return "open inbound TCP/80 to the ingress if you want the HTTP-to-HTTPS redirect; it is not a blocker here because TLS is obtained by " +
		domainsTLSMethod(c) + " rather than ACME HTTP-01, which is the only method that validates over port 80"
}

// domainsTLSRemedy says what to do about the problem actually found. The three
// causes need different actions, and an untrusted chain is not even necessarily
// a fault: an internal CA is how a customer-supplied certificate normally
// arrives on-prem, and budctl can only judge it once it holds the root.
func domainsTLSRemedy(c *engine.Ctx, uncovered []string, untrusted bool) string {
	root := strings.TrimPrefix(strings.TrimSpace(c.Answers.Domain), ".")
	if untrusted {
		if c.Net != nil && c.Net.Roots != nil {
			return "the chain does not verify even against the roots passed to --ca-bundle — check that the ingress serves its intermediates and that the bundle holds the issuing root"
		}
		trailer := ""
		if len(uncovered) > 0 {
			trailer = "; it also needs a SAN for " + domainsList(uncovered, 4)
		}
		if c.Answers.TLS == intake.TLSProvided {
			return "if this certificate comes from an internal CA, re-run with `--ca-bundle <root.pem>` so it is verified against that root — and make sure every client trusts it too, browsers and in-cluster callers alike; otherwise reissue it from a root they already trust" + trailer
		}
		return "replace what is served with a certificate that verifies against a public root, or pass `--ca-bundle <root.pem>` if an internal CA issued it deliberately" + trailer
	}
	if len(uncovered) == 0 {
		// Dates only: nothing is missing and nothing is untrusted.
		if c.Answers.TLS == intake.TLSProvided {
			return "reissue the supplied certificate with a longer validity and load it into the ingress TLS secret the values name"
		}
		return "renew the certificate serving these names before the install, or let cert-manager replace it once the addons are deployed"
	}
	if c.Answers.TLS == intake.TLSProvided {
		return "reissue the supplied certificate so that it has more than 14 days left and carries a SAN for every published name (" +
			domainsList(uncovered, 4) + "), then load it into the ingress TLS secret the values name"
	}
	return "the install asks cert-manager for certificates covering every published name — confirm the issuer can cover " +
		domainsList(uncovered, 4) + " (a *." + root +
		" wildcard does not match the two-label names api.novu/ws.novu), and renew or replace whatever is served today"
}

// ---------------------------------------------------------------------------
// DNS

type domainAddrs struct {
	addrs []string
	err   string
}

// domainResolveAll looks every hostname up once, concurrently. Sequential
// lookups against a blackholed resolver would each burn the full net timeout
// and blow the check budget, and a domains group that times out reports nothing
// at all about the cluster.
func domainResolveAll(ctx context.Context, c *engine.Ctx, hosts []string) map[string]domainAddrs {
	out := map[string]domainAddrs{}
	var mu sync.Mutex
	domainEach(ctx, hosts, func(h string) {
		addrs, err := c.Net.Resolve(ctx, h)
		r := domainAddrs{addrs: Sorted(domainNormalize(addrs))}
		switch {
		case err != nil:
			r.err = err.Error()
		case len(r.addrs) == 0:
			r.err = "resolved to no address"
		}
		mu.Lock()
		out[h] = r
		mu.Unlock()
	})
	// A cancelled context leaves gaps. Fill them explicitly: a missing key would
	// otherwise read as a failed lookup, which is a different fact.
	for _, h := range hosts {
		if _, ok := out[h]; !ok {
			out[h] = domainAddrs{err: "not looked up: the check ran out of time"}
		}
	}
	return out
}

// domainEach fans work out over hosts with a small bound. The bound exists so
// a resolver that blackholes cannot serialise twelve full timeouts.
func domainEach(ctx context.Context, items []string, fn func(string)) {
	const workers = 6
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, it := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(it string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			fn(it)
		}(it)
	}
	wg.Wait()
}

// domainNormalize collapses IPv4-in-IPv6 forms so "::ffff:203.0.113.10" from a
// resolver compares equal to "203.0.113.10" in a Service status.
func domainNormalize(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			out = append(out, a.Unmap().String())
			continue
		}
		out = append(out, s)
	}
	return out
}

func domainIntersects(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, s := range b {
		set[s] = true
	}
	for _, s := range a {
		if set[s] {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// inbound endpoints

// domainTarget is one distinct front door: every hostname that resolves to the
// same address set is dialled once. Twelve names on one LoadBalancer is the
// normal case, and twelve identical dials would only multiply the timeout.
type domainTarget struct {
	host   string
	shared []string
	addrs  []string
}

func (t domainTarget) names() []string { return append([]string{t.host}, t.shared...) }

func (t domainTarget) label() string {
	if len(t.shared) == 0 {
		return t.host
	}
	return fmt.Sprintf("%s (and %d other %s on the same address)", t.host, len(t.shared), Plural(len(t.shared), "name", "names"))
}

// domainInboundTargets is shared by inbound-80 and inbound-443. The third
// return value is non-nil when the check cannot proceed, carrying the skip that
// states why — never a pass.
func domainInboundTargets(ctx context.Context, c *engine.Ctx, ch *engine.Check) ([]domainTarget, []string, *engine.Result) {
	if c.Net == nil {
		r := ch.Skip("no network adapter: nothing was dialled").With(domainsVantage)
		return nil, nil, &r
	}
	hosts, _, _ := domainHostnames(c)
	if len(hosts) == 0 {
		r := ch.Skip(domainsNoHostsReason(c)).With(domainsVantage)
		return nil, nil, &r
	}
	res := domainResolveAll(ctx, c, hosts)
	var targets []domainTarget
	var unresolved []string
	byAddrs := map[string]int{}
	for _, h := range hosts {
		r := res[h]
		if len(r.addrs) == 0 {
			unresolved = append(unresolved, h)
			continue
		}
		key := strings.Join(r.addrs, ",")
		if i, seen := byAddrs[key]; seen {
			targets[i].shared = append(targets[i].shared, h)
			continue
		}
		byAddrs[key] = len(targets)
		targets = append(targets, domainTarget{host: h, addrs: r.addrs})
	}
	if len(targets) == 0 {
		r := ch.Skip("no hostname resolves, so there was no address to connect to (see domains.resolve)").
			With(domainsVantage, "unresolved: "+strings.Join(unresolved, ", "))
		return nil, unresolved, &r
	}
	return targets, unresolved, nil
}

func domainsHTTPOutcome(r adapters.HTTPResult) string {
	if !r.Reachable {
		return "no answer: " + r.Err
	}
	return fmt.Sprintf("HTTP %d in %s", r.Status, r.Latency.Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// where the cluster's front door is

type domainIngressInfo struct {
	addrs   []string // IPs, normalised, to compare DNS answers against
	names   []string // LoadBalancer hostnames, kept because an operator reads those
	public  []string
	private []string
	source  string
}

func (i domainIngressInfo) display() []string {
	return Sorted(append(append([]string{}, i.addrs...), i.names...))
}

// domainCGNAT is carrier-grade NAT space. netip's IsPrivate does not cover it,
// and a node behind it is exactly as unmatchable as one on 10/8.
var domainCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// domainIngressAddresses finds what the cluster advertises as its front door,
// preferring what the components group already recorded so that both groups
// report the same address. The fallbacks descend deliberately: an ingress
// controller's LoadBalancer, any LoadBalancer publishing 80/443, node
// ExternalIPs, and finally node InternalIPs — which can only ever produce the
// "cannot tell" verdict.
func domainIngressAddresses(ctx context.Context, c *engine.Ctx) domainIngressInfo {
	var info domainIngressInfo
	if v, ok := c.Get(engine.KeyIngressAddrs); ok {
		if list, ok := v.([]string); ok && len(list) > 0 {
			info.source = "the ingress controller, as recorded by the components group"
			info.absorb(ctx, c, list)
		}
	}
	if info.empty() {
		preferred, other := domainLoadBalancerAddresses(ctx, c)
		switch {
		case len(preferred) > 0:
			info.source = "an ingress controller Service of type LoadBalancer"
			info.absorb(ctx, c, preferred)
		case len(other) > 0:
			info.source = "a Service of type LoadBalancer publishing 80/443"
			info.absorb(ctx, c, other)
		}
	}
	if info.empty() {
		if ext := domainNodeAddresses(ctx, c, "ExternalIP"); len(ext) > 0 {
			info.source = "node ExternalIPs; no LoadBalancer Service publishes an address"
			info.absorb(ctx, c, ext)
		}
	}
	if info.empty() {
		if in := domainNodeAddresses(ctx, c, "InternalIP"); len(in) > 0 {
			info.source = "node InternalIPs; the cluster publishes no external address at all"
			info.absorb(ctx, c, in)
		}
	}
	if info.source == "" {
		info.source = "nothing found: no LoadBalancer Service and no node address"
	}
	info.classify()
	return info
}

func (i domainIngressInfo) empty() bool { return len(i.addrs) == 0 && len(i.names) == 0 }

// absorb accepts IPs and LoadBalancer hostnames alike; a hostname (an AWS ELB
// DNS name) is resolved, because the records under test point at IPs.
func (i *domainIngressInfo) absorb(ctx context.Context, c *engine.Ctx, vals []string) {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, err := netip.ParseAddr(v); err == nil {
			i.addrs = append(i.addrs, v)
			continue
		}
		i.names = append(i.names, v)
		if c.Net != nil {
			if addrs, err := c.Net.Resolve(ctx, v); err == nil {
				i.addrs = append(i.addrs, addrs...)
			}
		}
	}
	i.addrs = Sorted(domainNormalize(i.addrs))
	i.names = Sorted(i.names)
}

// classify splits the advertised addresses. A cluster whose only address is
// RFC1918, CGNAT or loopback cannot be matched against a public A record from
// here, and that distinction is the whole point of the INFO verdict.
func (i *domainIngressInfo) classify() {
	for _, s := range i.addrs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || domainCGNAT.Contains(a) {
			i.private = append(i.private, s)
			continue
		}
		i.public = append(i.public, s)
	}
}

var domainIngressWords = []string{"ingress", "traefik", "nginx", "router", "istio", "contour", "haproxy", "kong", "envoy"}

func domainLoadBalancerAddresses(ctx context.Context, c *engine.Ctx) (preferred, other []string) {
	for _, s := range c.Kube.List(ctx, "services", "") {
		if s.DigString("spec", "type") != "LoadBalancer" {
			continue
		}
		var vals []string
		for _, raw := range s.DigSlice("status", "loadBalancer", "ingress") {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if ip, _ := m["ip"].(string); ip != "" {
				vals = append(vals, ip)
			}
			if hn, _ := m["hostname"].(string); hn != "" {
				vals = append(vals, hn)
			}
		}
		if len(vals) == 0 {
			continue
		}
		if domainLooksLikeIngress(s) {
			preferred = append(preferred, vals...)
			continue
		}
		// Any other LoadBalancer is a plausible front door only if it actually
		// publishes HTTP ports; comparing DNS against a Postgres LB address
		// would manufacture a mismatch.
		if domainPublishesWebPorts(s) {
			other = append(other, vals...)
		}
	}
	return Sorted(preferred), Sorted(other)
}

func domainLooksLikeIngress(s adapters.Object) bool {
	// OpenShift's router lives in a fixed namespace and is not named after any
	// of the vanilla controllers.
	if s.Namespace() == "openshift-ingress" {
		return true
	}
	hay := strings.ToLower(s.Namespace() + "/" + s.Name())
	for k, v := range s.Labels() {
		hay += " " + strings.ToLower(k+"="+v)
	}
	for _, w := range domainIngressWords {
		if strings.Contains(hay, w) {
			return true
		}
	}
	return false
}

func domainPublishesWebPorts(s adapters.Object) bool {
	for _, raw := range s.DigSlice("spec", "ports") {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// Unstructured JSON numbers arrive as int64 from the API server and as
		// float64 from anything that round-tripped through encoding/json.
		switch p := m["port"].(type) {
		case int64:
			if p == 80 || p == 443 {
				return true
			}
		case float64:
			if p == 80 || p == 443 {
				return true
			}
		}
	}
	return false
}

func domainNodeAddresses(ctx context.Context, c *engine.Ctx, kind string) []string {
	var out []string
	for _, n := range c.Kube.List(ctx, "nodes", "") {
		for _, raw := range n.DigSlice("status", "addresses") {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := m["type"].(string); t == kind {
				if a, _ := m["address"].(string); a != "" {
					out = append(out, a)
				}
			}
		}
	}
	return Sorted(out)
}

// ---------------------------------------------------------------------------
// TLS

type domainCert struct {
	host    string
	issuer  string
	expiry  time.Time
	sans    []string
	present bool
	invalid bool
	err     string
}

func (d domainCert) errSuffix() string {
	if d.err == "" {
		return ""
	}
	return " (" + d.err + ")"
}

// isDefaultRouterCert recognises the certificate OpenShift's router serves out
// of the box: signed by the in-cluster ingress operator CA, valid for the apps
// wildcard, and untrusted everywhere outside the cluster. It covers the name,
// so the SAN test would otherwise call it a real certificate for the host, and
// its untrusted chain would then fail every clean OpenShift cluster.
func (d domainCert) isDefaultRouterCert(c *engine.Ctx) bool {
	if !c.Platform.IsOpenShift() || c.Platform.AppsDomain == "" {
		return false
	}
	if !strings.HasSuffix(d.host, "."+c.Platform.AppsDomain) {
		return false
	}
	i := strings.ToLower(d.issuer)
	return strings.Contains(i, "ingress-operator") || strings.Contains(i, "openshift-service-serving-signer")
}

func domainInspectTLS(ctx context.Context, c *engine.Ctx, hosts []string) map[string]domainCert {
	out := map[string]domainCert{}
	var mu sync.Mutex
	domainEach(ctx, hosts, func(h string) {
		issuer, expiry, sans, err := c.Net.TLSInspect(ctx, h, 443)
		cert := domainCert{host: h, issuer: issuer, expiry: expiry, sans: sans}
		if err != nil {
			cert.err = err.Error()
		}
		// TLSInspect retries without verification, so a non-nil error WITH a
		// certificate attached means "served but untrusted" — a finding — while
		// a non-nil error with no certificate means nothing answered on 443,
		// which before the install is the expected state.
		cert.present = !expiry.IsZero()
		cert.invalid = cert.present && err != nil
		mu.Lock()
		out[h] = cert
		mu.Unlock()
	})
	return out
}

func domainSoonestExpiry(certs []domainCert) time.Time {
	var soonest time.Time
	for _, c := range certs {
		if soonest.IsZero() || c.expiry.Before(soonest) {
			soonest = c.expiry
		}
	}
	return soonest
}

// domainSANsCover implements RFC 6125 wildcard matching: a leading "*." matches
// exactly one label, so *.example.com covers admin.example.com but neither
// api.novu.example.com nor example.com itself. A certificate with no SAN covers
// nothing — a CommonName-only certificate has been ignored by browsers since
// Chrome 58, so reading the CN as coverage would report a pass no client agrees
// with.
func domainSANsCover(sans []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, san := range sans {
		san = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(san), "."))
		if san == "" {
			continue
		}
		if san == host {
			return true
		}
		if rest, ok := strings.CutPrefix(san, "*."); ok {
			if i := strings.Index(host, "."); i > 0 && host[i+1:] == rest {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// wildcards

// domainWildcardZones is every zone worth probing: the answered root, each
// intermediate zone a deeper hostname sits in, and OpenShift's apps domain.
func domainWildcardZones(hosts []string, root string, c *engine.Ctx) []string {
	var zones []string
	if root != "" {
		zones = append(zones, root)
		for _, h := range hosts {
			sub := strings.TrimSuffix(h, "."+root)
			if sub == h {
				continue
			}
			if i := strings.LastIndex(sub, "."); i > 0 {
				zones = append(zones, sub[i+1:]+"."+root)
			}
		}
	}
	if c.Platform.IsOpenShift() && c.Platform.AppsDomain != "" {
		zones = append(zones, c.Platform.AppsDomain)
	}
	return Sorted(zones)
}

func domainDeeperThanOneLabel(host, root string) bool {
	if root == "" {
		return false
	}
	sub := strings.TrimSuffix(host, "."+root)
	return sub != host && strings.Contains(sub, ".")
}

// ---------------------------------------------------------------------------
// formatting

func domainsList(in []string, max int) string {
	in = Sorted(in)
	if len(in) == 0 {
		return "none"
	}
	if len(in) <= max {
		return strings.Join(in, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(in[:max], ", "), len(in)-max)
}

func domainsDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days >= 1 {
		return fmt.Sprintf("%d %s", days, Plural(days, "day", "days"))
	}
	return d.Round(time.Hour).String()
}
