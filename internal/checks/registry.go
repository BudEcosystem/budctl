package checks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// The registry group answers connectivity first and credentials second
// (FRD-020 §5.4). The registry.bud.studio robot account is issued *after*
// readiness passes, so a tool that demanded it would fail every genuine first
// run. The default question is therefore "does /v2/ answer at all", and a 401
// is a PASS: it proves DNS, routing, TLS and a live registry, which is the
// entire question at this stage. Auth and tag resolution run only when
// credentials are supplied and SKIP — never pass — when they are not.
//
// The host inventory is intake.Profile.Registries, not a grep of this
// repository. Three of those hosts (ecr-public.aws.com, reg.kyverno.io,
// sandbox-registry.cn-zhangjiakou…) are upstream chart defaults Bud installs
// unmodified and appear nowhere in the tree (§5.4.0) — precisely the hosts a
// corporate egress policy is most likely to block. registry.upstream-defaults is what keeps that inventory honest
// between releases (§5.4.2).
//
// Nothing here requests a blob. Every question is answered from /v2/ and from
// manifest HEADs: pulling layers would fill the very node disk nodes.imagefs
// is trying to measure (FRD-020 D3).

const (
	// HAMi's one non-Docker-Hub image. budcluster installs HAMi on any cluster
	// where NVIDIA GPUs are detected, and overrides the chart's Alibaba
	// CN-region default (registry.cn-hangzhou.aliyuncs.com/google_containers/
	// kube-scheduler) to the upstream image. The tag is still derived from the
	// cluster's own version, so that tag has to exist upstream (§5.4.1).
	regHAMiRegistry = "registry.k8s.io"
	regHAMiRepo     = "kube-scheduler"

	// A mirror must override BOTH fields. global.imageRegistry alone is a
	// trap: it keeps the chart's google_containers/ prefix, and
	// <mirror>/google_containers/kube-scheduler does not exist.
	regHAMiRemedy = "allow " + regHAMiRegistry + " from the GPU nodes, or mirror " + regHAMiRegistry + "/" + regHAMiRepo +
		" and point HAMi at the mirror (playbooks/setup_cluster.yaml), overriding BOTH fields:\n" +
		"  scheduler:\n" +
		"    kubeScheduler:\n" +
		"      image:\n" +
		"        registry: <mirror>\n" +
		"        repository: kube-scheduler      # NOT google_containers/kube-scheduler\n" +
		"global.imageRegistry alone is NOT sufficient: it keeps the chart's google_containers/ prefix, " +
		"and it also redirects every Docker Hub image in the chart."
)

func init() {
	engine.Register(&engine.Check{
		ID: "registry.reachable", Group: "registry", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regReachable(ctx, c, engine.Lookup("registry.reachable"))
		},
	})

	engine.Register(&engine.Check{
		ID: "registry.tls", Group: "registry", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regTLS(ctx, c, engine.Lookup("registry.tls"))
		},
	})

	engine.Register(&engine.Check{
		ID: "registry.from-cluster", Group: "registry", Severity: engine.Block,
		Probe: true, DependsOn: []string{"platform", "config"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regFromCluster(ctx, c, engine.Lookup("registry.from-cluster"))
		},
	})

	engine.Register(&engine.Check{
		ID: "registry.auth", Group: "registry", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regAuth(ctx, c, engine.Lookup("registry.auth"))
		},
	})

	engine.Register(&engine.Check{
		ID: "registry.tags", Group: "registry", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regTags(ctx, c, engine.Lookup("registry.tags"))
		},
	})

	engine.Register(&engine.Check{
		ID: "registry.pinned-tags", Group: "registry", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regPinnedTags(c, engine.Lookup("registry.pinned-tags"))
		},
	})

	engine.Register(&engine.Check{
		ID: "registry.upstream-defaults", Group: "registry", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regUpstreamDefaults(c, engine.Lookup("registry.upstream-defaults"))
		},
	})

	engine.Register(&engine.Check{
		ID: "registry.hami-scheduler", Group: "registry", Severity: engine.Block,
		DependsOn: []string{"platform", "config"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			return regHAMiScheduler(ctx, c, engine.Lookup("registry.hami-scheduler"))
		},
	})
}

// ---------------------------------------------------------------------------
// The inventory, resolved against THIS install
// ---------------------------------------------------------------------------

// regTarget is one inventory entry resolved against the intake answers: what it
// actually costs this install when the host does not answer.
type regTarget struct {
	intake.RegistryEntry
	// probe is false for a dormant default that nothing in this render pulls
	// from: spending a network round trip on it would only add noise.
	probe    bool
	severity engine.Severity
	why      string
}

// regTargets maps requirement + feature onto a severity. "required" is a
// blocker because the base install cannot complete without it; "conditional" is
// a blocker only when the feature that pulls from it is in play, and a risk
// otherwise (the operator can enable that feature next month); "dormant" is
// information — until the values actually name the host.
func regTargets(ctx context.Context, c *engine.Ctx) []regTarget {
	objs := Rendered(c)
	out := make([]regTarget, 0, len(c.Profile.Registries))
	for _, e := range c.Profile.Registries {
		t := regTarget{RegistryEntry: e, probe: true, severity: engine.Block}
		switch e.Requirement {
		case "required":
			t.why = "required by the base install"
		case "conditional":
			if regFeatureActive(ctx, c, e.Feature) {
				t.why = "the " + e.Feature + " feature is in play for this install"
			} else {
				t.severity = engine.Risk
				t.why = "no " + e.Feature + " today; enabling it later needs this host"
			}
		default:
			// A dormant default stays INFO until the values in play name it.
			// Harbor's trivy.dbRepository is the live example: flip
			// trivy.enabled and mirror.gcr.io becomes a required fetch. The
			// signal is the render itself, not a hardcoded flag list, so a
			// values change promotes the host without a code change.
			if where, named := regMentioned(objs, e.Host); named {
				t.why = "no longer dormant: the render names it in " + where
			} else {
				t.probe = false
				t.severity = engine.Info
				t.why = "disabled by default in the values in play"
			}
		}
		out = append(out, t)
	}
	return out
}

func regFeatureActive(ctx context.Context, c *engine.Ctx, feature string) bool {
	switch feature {
	case "gpu":
		// Either the operator said GPU, or the cluster already has the nodes.
		// Both are "in play": budcluster installs HAMi and the GPU operator on
		// detection, without asking.
		if c.Answers.GPU {
			return true
		}
		nodes, known := regGPUNodes(ctx, c)
		return known && len(nodes) > 0
	case "opensandbox":
		return c.Answers.OpenSandbox
	case "":
		return true
	default:
		// An inventory entry gated on a feature this build does not know about.
		// Over-reporting a host is recoverable; silently dropping one is the
		// failure mode §5.4.0 exists to prevent.
		return true
	}
}

// regGPUNodes reports the NVIDIA nodes. known is false when nothing can be
// determined (no cluster), which is a SKIP for the caller and never a pass.
//
// Two signals, because they fail in opposite directions: allocatable
// nvidia.com/* proves a working device plugin but is absent on a GPU node whose
// plugin is not installed yet — which is exactly the cluster budcluster is
// about to onboard — while the NFD/GPU-operator labels see the hardware before
// any plugin advertises it.
func regGPUNodes(ctx context.Context, c *engine.Ctx) (names []string, known bool) {
	if v, ok := c.Get(engine.KeyGPUNodes); ok {
		if list, ok := v.([]string); ok {
			return list, true
		}
	}
	if c.Kube == nil {
		return nil, false
	}
	found := []string{}
	for _, n := range c.Kube.List(ctx, "nodes", "") {
		gpu := false
		if alloc, ok := n.Dig("status", "allocatable").(map[string]any); ok {
			for k, v := range alloc {
				if strings.HasPrefix(k, "nvidia.com/") && ParseQuantity(fmt.Sprint(v)) > 0 {
					gpu = true
				}
			}
		}
		labels := n.Labels()
		if labels["nvidia.com/gpu.present"] == "true" ||
			labels["feature.node.kubernetes.io/pci-10de.present"] == "true" {
			gpu = true
		}
		if gpu {
			found = append(found, n.Name())
		}
	}
	return Sorted(found), true
}

// regMentioned finds a host anywhere in the rendered objects, not only in an
// image field: Harbor's trivy DB and SigNoz's Redpanda reference their hosts
// from values, not from a container image.
func regMentioned(objs []adapters.Object, host string) (string, bool) {
	for _, o := range objs {
		if regTreeHas(map[string]any(o), host) {
			name := o.Kind() + "/" + o.Name()
			return strings.TrimPrefix(name, "/"), true
		}
	}
	return "", false
}

func regTreeHas(v any, needle string) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(t, needle)
	case map[string]any:
		for _, vv := range t {
			if regTreeHas(vv, needle) {
				return true
			}
		}
	case []any:
		for _, vv := range t {
			if regTreeHas(vv, needle) {
				return true
			}
		}
	}
	return false
}

// regAPIHost is the host the v2 API actually lives on. Docker Hub's registry is
// registry-1.docker.io; "docker.io" is the name in every image reference and
// the name the operator must allowlist, so both spellings are reported.
func regAPIHost(host string) string {
	if host == "docker.io" {
		return "registry-1.docker.io"
	}
	return host
}

// regTLSTarget splits a registry host into the address to dial and the port.
//
// A self-hosted registry often listens somewhere other than 443 — Harbor on
// :8443, a plain distribution on :5000 — and the operator writes that port into
// the host, as the image references in a values file already do. Dialing 443
// regardless reaches nothing, and the result then reads "no TLS handshake" for
// a registry that is serving correctly. The port also has to come off the name
// before it is used as SNI, which rejects a host:port string.
func regTLSTarget(host string) (string, int) {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host, 443 // no port in the name: the default for a registry
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return host, 443
	}
	return h, n
}

// ---------------------------------------------------------------------------
// registry.reachable
// ---------------------------------------------------------------------------

func regReachable(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	if c.OCI == nil {
		return ch.Skip("no network adapter: registry reachability was not tested")
	}
	var blockers, risks, dormant, reached []string
	evidence := []engine.Evidence{}

	for _, t := range regTargets(ctx, c) {
		if !t.probe {
			dormant = append(dormant, fmt.Sprintf("%s: not probed — %s (would pull: %s)", t.Host, t.why, t.PulledBy))
			continue
		}
		r := c.OCI.Reachable(ctx, t.Host)
		answer := regAnswer(r)
		evidence = append(evidence, engine.Evidence{
			What:   "GET https://" + regAPIHost(t.Host) + "/v2/",
			Output: answer,
		})
		line := fmt.Sprintf("%s: %s — pulls %s", t.Host, answer, t.PulledBy)
		if regAnswerOK(r) {
			reached = append(reached, line)
			continue
		}
		line += " [" + t.why + "]"
		if t.severity == engine.Block {
			blockers = append(blockers, line)
		} else {
			risks = append(risks, line)
		}
	}

	detail := append(append(append([]string{}, blockers...), risks...), reached...)
	detail = append(detail, dormant...)

	switch {
	case len(blockers) > 0:
		return ch.Fail(
			fmt.Sprintf("%d required %s do not answer /v2/ — every image they hold fails to pull and the install stalls in ImagePullBackOff",
				len(blockers), Plural(len(blockers), "registry", "registries")),
			"allowlist these hosts on egress (port 443, and the proxy if there is one), or mirror their images into a registry "+
				"this cluster can reach and override the corresponding chart image registries",
			detail...).WithEvidence(evidence...)
	case len(risks) > 0:
		return ch.FailAs(engine.Risk,
			fmt.Sprintf("%d conditional %s do not answer /v2/ — the features that pull from them cannot be enabled on this cluster",
				len(risks), Plural(len(risks), "registry", "registries")),
			"allowlist or mirror these hosts before enabling the feature that needs them; the base install is unaffected",
			detail...).WithEvidence(evidence...)
	}

	if len(reached) == 0 {
		return ch.Skip("no registry in the inventory is pulled from by this install, so nothing was tested")
	}
	return ch.Pass(
		fmt.Sprintf("all %d %s in scope answer /v2/ with 200 or 401",
			len(reached), Plural(len(reached), "registry", "registries")),
		detail...).
		WithEvidence(evidence...).
		Bounds("reachability from this workstation only, and only of the registry API: node egress is registry.from-cluster, " +
			"credential acceptance is registry.auth, and an answering /v2/ is not a completed layer pull")
}

// regAnswerOK decides what counts as "a registry is there". A 401 is a PASS —
// the whole point of this group: it proves DNS resolved, the route exists, TLS
// terminated and a registry answered, which is everything that can be known
// before a robot account is issued. A 403 is the same fact from a registry that
// refuses anonymous API access outright.
func regAnswerOK(r adapters.HTTPResult) bool {
	if !r.Reachable {
		return false
	}
	if r.Status >= 200 && r.Status < 300 {
		return true
	}
	return r.Status == http.StatusUnauthorized || r.Status == http.StatusForbidden
}

func regAnswer(r adapters.HTTPResult) string {
	if !r.Reachable {
		if r.Err != "" {
			return r.Err
		}
		return "no answer"
	}
	return fmt.Sprintf("HTTP %d in %s", r.Status, r.Latency.Round(time.Millisecond))
}

// ---------------------------------------------------------------------------
// registry.tls
// ---------------------------------------------------------------------------

func regTLS(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	if c.Net == nil {
		return ch.Skip("no network adapter: registry certificates were not inspected")
	}
	now := c.Now()
	var invalid, expiring, unreachable, ok []string
	evidence := []engine.Evidence{}

	for _, t := range regTargets(ctx, c) {
		// Only the hosts this install must pull from: interception shows up
		// on those as readily as anywhere, and a certificate finding on a host
		// no enabled feature uses must not block the install.
		if !t.probe || t.severity != engine.Block {
			continue
		}
		host := regAPIHost(t.Host)
		dialHost, dialPort := regTLSTarget(host)
		issuer, expiry, _, err := c.Net.TLSInspect(ctx, dialHost, dialPort)
		// TLSInspect retries without verification, so a verification failure
		// still returns the served leaf. No leaf at all means the connection
		// never happened — that is registry.reachable's finding, not a TLS one,
		// and reporting it twice would send the operator after the wrong cause.
		if err != nil && issuer == "" {
			unreachable = append(unreachable, fmt.Sprintf("%s: no TLS handshake (%s) — see registry.reachable", host, err))
			continue
		}
		evidence = append(evidence, engine.Evidence{
			What:   "TLS handshake with " + host + ":443",
			Output: fmt.Sprintf("issuer %q, notAfter %s", issuer, expiry.Format(time.RFC3339)),
		})
		switch {
		case err != nil:
			invalid = append(invalid, fmt.Sprintf("%s: %s — certificate issued by %q", host, err, issuer))
		case expiry.Before(now):
			invalid = append(invalid, fmt.Sprintf("%s: certificate expired %s (issuer %q)", host, expiry.Format("2006-01-02"), issuer))
		case expiry.Before(now.AddDate(0, 0, 15)):
			expiring = append(expiring, fmt.Sprintf("%s: certificate expires %s (issuer %q)", host, expiry.Format("2006-01-02"), issuer))
		default:
			ok = append(ok, fmt.Sprintf("%s: valid until %s (issuer %q)", host, expiry.Format("2006-01-02"), issuer))
		}
	}

	if len(invalid) == 0 && len(expiring) == 0 && len(ok) == 0 {
		return ch.Skip("no registry completed a TLS handshake, so no certificate could be inspected — see registry.reachable")
	}
	detail := append(append(append([]string{}, invalid...), expiring...), ok...)
	detail = append(detail, unreachable...)

	if len(invalid) > 0 {
		return ch.Fail(
			fmt.Sprintf("TLS to %d %s does not validate — every pull and every `helm registry login` fails with an x509 error before authentication is even attempted",
				len(invalid), Plural(len(invalid), "registry", "registries")),
			"an unexpected issuer here means TLS interception: add that CA to the node trust store (on OpenShift, the cluster-wide "+
				"proxy's trustedCA ConfigMap; elsewhere the node image's CA bundle) and to this workstation, or exempt the registry "+
				"hosts from interception. If the certificate is simply expired, that is the registry operator's to renew.",
			detail...).WithEvidence(evidence...)
	}
	if len(expiring) > 0 {
		return ch.FailAs(engine.Risk,
			fmt.Sprintf("%d registry %s expires within 15 days — pulls start failing mid-install once it does",
				len(expiring), Plural(len(expiring), "certificate", "certificates")),
			"renew the certificate, or confirm with the registry operator that renewal is automated before starting the install",
			detail...).WithEvidence(evidence...)
	}
	return ch.Pass(
		fmt.Sprintf("%d registry %s validate and are in date", len(ok), Plural(len(ok), "certificate", "certificates")),
		detail...).
		WithEvidence(evidence...).
		Bounds("the chain validates against THIS workstation's trust store: the nodes have their own, and a proxy that intercepts " +
			"only node traffic would not be visible here")
}

// ---------------------------------------------------------------------------
// registry.from-cluster  [probe]
// ---------------------------------------------------------------------------

// regFromCluster asks the same question from inside the cluster, because node
// egress is not workstation egress: a VPN, a split-horizon resolver or a
// node-network policy routinely make one work and the other fail, and the pull
// that matters happens on the node.
func regFromCluster(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	if c.Opts.NoProbe || c.Probes == nil {
		return ch.Skip("--no-probe: node-side registry egress was NOT verified, only this workstation's")
	}
	if c.Kube == nil {
		return ch.Skip("cluster unreachable: no pod could be run, so node-side registry egress was not verified")
	}
	hosts := []string{}
	for _, t := range regTargets(ctx, c) {
		// Only the hosts this install must have. A dormant or inactive-feature
		// host failing from a pod is not worth a probe pod's minute.
		if t.probe && t.severity == engine.Block {
			hosts = append(hosts, t.Host)
		}
	}
	if len(hosts) == 0 {
		return ch.Skip("no registry in the inventory is required by this install's answers")
	}

	out, err := c.Probes.RunPod(ctx, probes.PodSpec{
		Name:    "budctl-registry-egress",
		Image:   c.Opts.ProbeImage,
		Command: []string{"/bin/sh", "-c", regEgressScript(hosts, c.Platform.ClusterProxy)},
		Timeout: 3 * time.Minute,
	})

	switch {
	case !out.Scheduled:
		return ch.Skip(fmt.Sprintf("probe pod never scheduled (%s), so node-side registry egress was not verified: %s",
			out.Phase, firstNonEmpty(out.Reason, strings.Join(out.Events, "; "), "no reason reported")))
	case !out.Started && regImagePullFailure(out.Reason):
		// The probe image failing to pull IS the registry answer, not a tool
		// error: it is the first real image pull this cluster attempted.
		reg := adapters.RegistryOf(c.Opts.ProbeImage)
		return ch.Fail(
			fmt.Sprintf("the nodes cannot pull the probe image %s from %s — no image in the stack can be pulled either", c.Opts.ProbeImage, reg),
			"allowlist "+reg+" for the node network, or pass --probe-image pointing at an image already mirrored into a reachable registry",
			"kubelet: "+out.Reason).WithEvidence(engine.Evidence{What: "pull " + c.Opts.ProbeImage + " on a node", Output: strings.Join(out.Events, "\n")})
	}

	codes := regParseEgress(out.Logs)
	if len(codes) == 0 {
		return ch.Skip(fmt.Sprintf("probe pod produced no readable output (phase %s, %s), so node-side registry egress was not verified",
			out.Phase, firstNonEmpty(out.Reason, regErrText(err), "no reason reported")))
	}

	var failed, reached, silent []string
	fromPodOnly := 0
	for _, h := range hosts {
		code, seen := codes[h]
		if !seen {
			silent = append(silent, h+": the probe reported nothing for this host")
			continue
		}
		if regCodeOK(code) {
			reached = append(reached, fmt.Sprintf("%s: HTTP %s from the pod", h, code))
			continue
		}
		// Contrast the two vantage points for exactly the hosts that failed:
		// "the workstation can, the pod cannot" is a different problem, with a
		// different remedy, than "nobody can".
		ws := "workstation: not tested"
		if c.OCI != nil {
			r := c.OCI.Reachable(ctx, h)
			if regAnswerOK(r) {
				fromPodOnly++
				ws = "but answers " + regAnswer(r) + " from this workstation"
			} else {
				ws = "and also fails from this workstation (" + regAnswer(r) + ")"
			}
		}
		failed = append(failed, fmt.Sprintf("%s: %s from the pod, %s", h, regCodeText(code), ws))
	}

	detail := append(append(append([]string{}, failed...), silent...), reached...)
	if c.Platform.ClusterProxy != "" {
		detail = append(detail, "probe used the cluster-wide proxy "+c.Platform.ClusterProxy+
			" — ordinary pods do NOT inherit it, but the kubelet's image pulls are configured with it")
	}
	evidence := []engine.Evidence{{
		What:   fmt.Sprintf("curl https://<host>/v2/ from a pod in namespace %s", c.Probes.Namespace()),
		Output: strings.TrimSpace(out.Logs),
	}}

	if len(failed) > 0 {
		summary := fmt.Sprintf("%d required %s unreachable from inside the cluster — the kubelet cannot pull those images even though this workstation can reach them",
			len(failed), Plural(len(failed), "registry is", "registries are"))
		if fromPodOnly != len(failed) {
			summary = fmt.Sprintf("%d required %s unreachable from inside the cluster, so the install stalls in ImagePullBackOff",
				len(failed), Plural(len(failed), "registry is", "registries are"))
		}
		return ch.Fail(summary,
			"fix egress on the NODE network — the workstation's route is not the node's: open 443 to these hosts from the node subnet, "+
				"set the proxy the nodes use (on OpenShift, proxy.config.openshift.io/cluster), or mirror the images into a reachable registry",
			detail...).WithEvidence(evidence...)
	}
	if len(silent) > 0 {
		return ch.FailAs(engine.Risk,
			fmt.Sprintf("%d of %d required registries were not answered for by the probe, so their node-side reachability is unknown", len(silent), len(hosts)),
			"re-run without --no-probe on a cluster with schedulable capacity, or test by hand: kubectl run -it --rm curl --image="+c.Opts.ProbeImage+" -- sh",
			detail...).WithEvidence(evidence...)
	}
	return ch.Pass(
		fmt.Sprintf("all %d required registries answer /v2/ from a pod in this cluster", len(reached)),
		detail...).
		WithEvidence(evidence...).
		Bounds("a pod's curl is not the kubelet's pull: the kubelet uses the node's own proxy, CA bundle and imagePullSecrets, " +
			"and this proves neither pull throughput nor node disk")
}

// regEgressScript prints one "host|code" line per registry. curl writes 000 on
// a connection failure, which is why the code — not the exit status — is what
// gets parsed.
func regEgressScript(hosts []string, proxy string) string {
	var b strings.Builder
	if proxy != "" {
		b.WriteString("export https_proxy=" + proxy + " HTTPS_PROXY=" + proxy + "\n")
	}
	for _, h := range hosts {
		b.WriteString(fmt.Sprintf(
			"code=$(curl -s -o /dev/null -w '%%{http_code}' -m 10 https://%s/v2/ 2>/dev/null); echo \"%s|${code:-000}\"\n",
			regAPIHost(h), h))
	}
	return b.String()
}

func regParseEgress(logs string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(logs, "\n") {
		host, code, ok := strings.Cut(strings.TrimSpace(line), "|")
		if !ok || host == "" {
			continue
		}
		out[host] = code
	}
	return out
}

func regCodeOK(code string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(code))
	if err != nil {
		return false
	}
	if n >= 200 && n < 300 {
		return true
	}
	return n == http.StatusUnauthorized || n == http.StatusForbidden
}

func regCodeText(code string) string {
	if strings.TrimSpace(code) == "000" {
		return "no answer (DNS, routing or TLS)"
	}
	return "HTTP " + code
}

func regImagePullFailure(reason string) bool {
	r := strings.ToLower(reason)
	return strings.Contains(r, "imagepull") || strings.Contains(r, "errimage") || strings.Contains(r, "invalidimagename")
}

func regErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---------------------------------------------------------------------------
// registry.auth
// ---------------------------------------------------------------------------

func regAuth(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	if len(c.Opts.RegistryCreds) == 0 {
		// Never a pass. The robot account is issued after readiness, so having
		// no credentials is the expected first-run state — but "we did not
		// look" and "we looked and it was fine" must read differently.
		return ch.Skip("no registry credentials supplied (--registry-user/--registry-password, or a values file): " +
			"credential acceptance was NOT verified and remains unknown")
	}
	if c.OCI == nil {
		return ch.Skip("no network adapter: supplied registry credentials were not tested")
	}

	hosts := []string{}
	for h := range c.Opts.RegistryCreds {
		hosts = append(hosts, h)
	}
	var accepted, rejected, inconclusive []string
	evidence := []engine.Evidence{}

	for _, host := range Sorted(hosts) {
		cred := c.Opts.RegistryCreds[host]
		repo, ref, fromRender := regRepresentative(c, host)
		status, note := c.OCI.Manifest(ctx, host, repo, ref, &cred)
		evidence = append(evidence, engine.Evidence{
			What:   fmt.Sprintf("HEAD https://%s/v2/%s/manifests/%s as %q", regAPIHost(host), repo, ref, cred.Username),
			Output: string(status) + ": " + note,
		})
		switch status {
		case adapters.ManifestOK:
			accepted = append(accepted, fmt.Sprintf("%s: %s accepted, %s:%s resolved", host, cred.Username, repo, ref))
		case adapters.ManifestNotFound:
			// A 404 is a PASS here: the registry authenticated the request and
			// only then answered "no such tag". That is the whole question when
			// no render names a real repository to ask for.
			accepted = append(accepted, fmt.Sprintf("%s: %s accepted (registry authenticated, then reported no such tag)", host, cred.Username))
		case adapters.ManifestUnauthorized:
			line := fmt.Sprintf("%s: %s rejected — %s", host, cred.Username, note)
			if !fromRender {
				line += " (no --values render, so a synthetic repository was used: a project-scoped robot account that cannot see it answers the same way)"
			}
			rejected = append(rejected, line)
		default:
			inconclusive = append(inconclusive, fmt.Sprintf("%s: %s — credentials untested", host, note))
		}
	}

	if len(accepted) == 0 && len(rejected) == 0 {
		return ch.Skip("no registry with credentials could be reached, so the credentials were not tested — see registry.reachable")
	}
	detail := append(append(append([]string{}, rejected...), accepted...), inconclusive...)
	if len(rejected) > 0 {
		return ch.Fail(
			fmt.Sprintf("%d %s rejected the supplied credentials — every first-party image pull fails with 401 and the platform pods never start",
				len(rejected), Plural(len(rejected), "registry", "registries")),
			"re-issue the robot account and confirm it has pull scope on the project, then re-run with --registry-user/--registry-password; "+
				"the same value must end up in the install's imagePullSecret",
			detail...).WithEvidence(evidence...)
	}
	return ch.Pass(
		fmt.Sprintf("credentials accepted by %d %s", len(accepted), Plural(len(accepted), "registry", "registries")),
		detail...).
		WithEvidence(evidence...).
		Bounds("acceptance at the registry API is not a pull: the nodes need the same credentials as an imagePullSecret and their own " +
			"route to the host (registry.from-cluster)")
}

// regRepresentative picks something real to authenticate against. A repository
// from the render is best — it is what the install will actually pull.
func regRepresentative(c *engine.Ctx, host string) (repo, ref string, fromRender bool) {
	for _, img := range Sorted(RenderedImages(c)) {
		if r, rp, rf := adapters.ImageRef(img); r == host && rp != "" {
			return rp, rf, true
		}
	}
	// Without a render there is no repository to name, so ask for one that
	// cannot exist: valid credentials produce a 404 (authenticated, no such
	// tag) and invalid ones produce a 401. No blob, no bandwidth.
	return "budctl/readiness-probe", "budctl-does-not-exist", false
}

// ---------------------------------------------------------------------------
// registry.tags
// ---------------------------------------------------------------------------

func regTags(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	images := Sorted(RenderedImages(c))
	if len(images) == 0 {
		return ch.Skip("no chart render available (pass --chart and --values): the image tags this install would pull are unknown")
	}
	if len(c.Opts.RegistryCreds) == 0 {
		return ch.Skip("no registry credentials supplied: private tags cannot be resolved, so tag existence was NOT verified")
	}
	if c.OCI == nil {
		return ch.Skip("no network adapter: image tags were not resolved")
	}

	type tagOutcome struct {
		image  string
		status adapters.ManifestStatus
		note   string
	}
	outcomes := make([]tagOutcome, len(images))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, img := range images {
		wg.Add(1)
		go func(i int, img string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			registry, repo, ref := adapters.ImageRef(img)
			var cred *adapters.Credential
			if v, ok := c.Opts.RegistryCreds[registry]; ok {
				cred = &v
			}
			// HEAD only — resolving a manifest proves the tag exists without
			// pulling a single layer (FRD-020 D3).
			st, note := c.OCI.Manifest(ctx, registry, repo, ref, cred)
			outcomes[i] = tagOutcome{image: img, status: st, note: note}
		}(i, img)
	}
	wg.Wait()

	var missing, unresolved, resolved []string
	evidence := []engine.Evidence{}
	for _, o := range outcomes {
		switch o.status {
		case adapters.ManifestOK:
			resolved = append(resolved, o.image)
		case adapters.ManifestNotFound:
			missing = append(missing, fmt.Sprintf("%s: %s", o.image, o.note))
			evidence = append(evidence, engine.Evidence{What: "HEAD manifest for " + o.image, Output: o.note})
		case adapters.ManifestUnauthorized:
			unresolved = append(unresolved, fmt.Sprintf("%s: %s — see registry.auth", o.image, o.note))
		default:
			unresolved = append(unresolved, fmt.Sprintf("%s: %s — see registry.reachable", o.image, o.note))
		}
	}

	if len(missing) > 0 {
		return ch.Fail(
			fmt.Sprintf("%d pinned image %s does not exist in its registry — those pods never start, they sit in ImagePullBackOff",
				len(missing), Plural(len(missing), "tag", "tags")),
			"correct the tag in the values file (or push the missing tag to the registry) and re-run; the tag named below is the one "+
				"the render resolved, so it is exactly what the install would apply",
			append(missing, fmt.Sprintf("%d of %d image references resolved", len(resolved), len(images)))...).
			WithEvidence(evidence...)
	}
	if len(unresolved) > 0 {
		return ch.FailAs(engine.Risk,
			fmt.Sprintf("%d of %d image references could not be resolved, so their tags are unverified", len(unresolved), len(images)),
			"clear the reachability or credential finding these depend on (registry.reachable, registry.auth) and re-run",
			unresolved...)
	}
	return ch.Pass(
		fmt.Sprintf("all %d distinct image references in the render resolve to a manifest", len(resolved)),
		Sorted(resolved)...).
		Bounds("a manifest HEAD is not a pull: it proves nothing about layer size, node disk (nodes.imagefs) or pull throughput, " +
			"and images pulled at runtime — vLLM runtimes, HAMi, the GPU operator — are not in this render")
}

// ---------------------------------------------------------------------------
// registry.pinned-tags
// ---------------------------------------------------------------------------

// regMutableTags are tags whose content changes under a fixed name. Two nodes
// pulling the same reference a week apart then run different code, and a
// rollback cannot reproduce what was running.
var regMutableTags = map[string]bool{
	"latest": true, "nightly": true, "edge": true, "dev": true,
	"main": true, "master": true, "stable": true,
}

func regPinnedTags(c *engine.Ctx, ch *engine.Check) engine.Result {
	images := Sorted(RenderedImages(c))
	if len(images) == 0 {
		return ch.Skip("no chart render available (pass --chart and --values): the image references were not inspected")
	}
	var mutable, untagged []string
	for _, img := range images {
		// A digest reference is the strongest possible pin; nothing to say.
		if strings.Contains(img, "@sha256:") {
			continue
		}
		if !regHasExplicitTag(img) {
			untagged = append(untagged, img+" (no tag — the runtime resolves it as :latest)")
			continue
		}
		_, _, ref := adapters.ImageRef(img)
		if regMutableTags[strings.ToLower(ref)] {
			mutable = append(mutable, img)
		}
	}
	bad := append(append([]string{}, untagged...), mutable...)
	if len(bad) > 0 {
		return ch.Fail(
			fmt.Sprintf("%d image %s is not pinned to an immutable tag — a node that pulls tomorrow runs different code than one that pulled today, and the running version cannot be reproduced",
				len(bad), Plural(len(bad), "reference", "references")),
			"pin each of these to a released version tag, or to a @sha256 digest, in the values file",
			bad...)
	}
	return ch.Pass(
		fmt.Sprintf("all %d image references carry an explicit, immutable tag", len(images))).
		Bounds("an immutable-looking tag is a convention, not a guarantee: a registry that allows tag overwrite can still move it")
}

// regHasExplicitTag reports whether the reference names a tag. The tag, if
// any, follows the last colon that is not part of a registry host:port.
func regHasExplicitTag(image string) bool {
	slash := strings.LastIndex(image, "/")
	return strings.Contains(image[slash+1:], ":")
}

// ---------------------------------------------------------------------------
// registry.upstream-defaults
// ---------------------------------------------------------------------------

// regUpstreamDefaults is the check that keeps the inventory from going stale
// (§5.4.2). HAMi, Kyverno and ArgoCD's bundled Redis are one failure class, not
// three coincidences: an upstream chart default this platform installs
// unmodified. A registry list built by grepping this repository is wrong by
// construction, so the honest source is the render itself — and any host in the
// render that the inventory does not know about means a chart moved.
func regUpstreamDefaults(c *engine.Ctx, ch *engine.Check) engine.Result {
	objs := Rendered(c)
	images := RenderedImages(c)
	if len(objs) == 0 && len(images) == 0 {
		return ch.Skip("no chart render available (pass --chart and --values): the registries this install pulls from cannot be " +
			"resolved, and grepping the repository for them would miss exactly the upstream defaults this check exists to catch")
	}

	known := map[string]bool{}
	for _, e := range c.Profile.Registries {
		known[e.Host] = true
	}
	// Where an unexpected host came from, so the finding names the chart rather
	// than just the host.
	origin := map[string][]string{}
	seen := map[string]bool{}

	for _, o := range objs {
		chart := firstNonEmpty(o.Labels()["helm.sh/chart"], o.Labels()["app.kubernetes.io/name"], o.Kind()+"/"+o.Name())
		for _, container := range o.Containers() {
			img, _ := container["image"].(string)
			if img == "" {
				continue
			}
			host := adapters.RegistryOf(img)
			seen[host] = true
			if !known[host] {
				origin[host] = append(origin[host], fmt.Sprintf("%s — %s (%s)", host, img, chart))
			}
		}
	}
	// The image inventory may carry references the object walk misses (a values
	// key rather than a container image), so fold it in too.
	for _, img := range images {
		host := adapters.RegistryOf(img)
		seen[host] = true
		if !known[host] && len(origin[host]) == 0 {
			origin[host] = append(origin[host], fmt.Sprintf("%s — %s", host, img))
		}
	}

	if len(origin) > 0 {
		lines := []string{}
		for _, h := range Sorted(regKeys(origin)) {
			lines = append(lines, Sorted(origin[h])...)
		}
		return ch.Fail(
			fmt.Sprintf("%d image %s in the render %s not in budctl's registry inventory — an upstream chart moved, so the egress allowlist built from that inventory is now incomplete",
				len(origin), Plural(len(origin), "host", "hosts"), Plural(len(origin), "is", "are")),
			"confirm each host is intentional, then add it to internal/intake/defaults.yaml (registries:) and to the customer's egress "+
				"allowlist; if it is not intentional, pin the chart version that introduced it",
			lines...)
	}
	return ch.Pass(
		fmt.Sprintf("every image host in the render (%d) is in the inventory", len(seen)),
		Sorted(regKeys(seen))...).
		Bounds("only the charts budctl was given were templated: HAMi and the NVIDIA GPU operator are installed by budcluster at " +
			"onboarding with no chart_version pinned, so they can introduce a new registry between two onboardings of the same release")
}

func regKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// registry.hami-scheduler
// ---------------------------------------------------------------------------

// regHAMiScheduler probes the one HAMi image that is not on Docker Hub. Three
// facts make it a blocker rather than a curiosity (§5.4.1): budcluster installs
// HAMi automatically wherever NVIDIA GPUs are detected, the image's tag is the
// cluster's own Kubernetes version, and the Helm task runs with atomic: true —
// so this single unpullable image rolls the entire release back instead of
// leaving a diagnosable ImagePullBackOff.
func regHAMiScheduler(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	nodes, known := regGPUNodes(ctx, c)
	if !known {
		return ch.Skip("cluster unreachable: neither the presence of GPU nodes nor the kube-scheduler tag HAMi would derive can be determined")
	}
	if len(nodes) == 0 {
		return ch.Skip("no NVIDIA GPU nodes in this cluster: budcluster installs HAMi only when NVIDIA GPUs are detected, so this image is never pulled")
	}
	if c.OCI == nil {
		return ch.Skip("no network adapter: the HAMi kube-scheduler image was not resolved")
	}

	version := c.Platform.Version
	if version == "" && c.Kube != nil {
		if v, err := c.Kube.ServerVersion(); err == nil {
			version = v.GitVersion
		}
	}
	tag := regStrippedKubeVersion(version)
	if tag == "" {
		return ch.Skip("the server version is unreadable, and HAMi's tag is derived from it — probing a hardcoded tag would check the wrong image")
	}

	status, note := c.OCI.Manifest(ctx, regHAMiRegistry, regHAMiRepo, tag, nil)
	ref := fmt.Sprintf("%s/%s:%s", regHAMiRegistry, regHAMiRepo, tag)
	ev := engine.Evidence{
		What:   fmt.Sprintf("HEAD https://%s/v2/%s/manifests/%s", regHAMiRegistry, regHAMiRepo, tag),
		Output: string(status) + ": " + note,
	}
	detail := []string{
		fmt.Sprintf("tag derived from the cluster's own version %s, the way the chart's strippedKubeVersion helper does — never hardcoded", version),
		fmt.Sprintf("%d GPU %s: %s", len(nodes), Plural(len(nodes), "node", "nodes"), strings.Join(nodes, ", ")),
		"HAMi is installed unpinned (chart_ref: hami-charts/hami, no chart_version), so this default can change between onboardings",
	}

	switch status {
	case adapters.ManifestOK:
		return ch.Pass(ref+" resolves", detail...).
			WithEvidence(ev).
			Bounds("resolved from this workstation: the pull happens on the GPU node (registry.from-cluster), and HAMi's install is " +
				"atomic, so a node-side failure rolls the whole release back")
	case adapters.ManifestNotFound:
		// registry.k8s.io publishes kube-scheduler for every Kubernetes patch
		// release, so a miss means this cluster reports a version upstream
		// never shipped — but either way the pull fails, and the fix is a
		// mirror carrying the tag.
		return ch.FailAs(engine.Risk,
			fmt.Sprintf("%s answers but has no tag %s — HAMi would try to pull an image that does not exist and its atomic install would roll back", regHAMiRegistry, tag),
			regHAMiRemedy,
			detail...).WithEvidence(ev)
	case adapters.ManifestUnauthorized:
		return ch.FailAs(engine.Risk,
			fmt.Sprintf("%s refuses anonymous access to %s, so HAMi's scheduler image may not pull on the GPU nodes", regHAMiRegistry, regHAMiRepo),
			regHAMiRemedy,
			detail...).WithEvidence(ev)
	default:
		return ch.Fail(
			fmt.Sprintf("%s is unreachable, so HAMi cannot pull %s — GPU cluster onboarding fails with a rolled-back release (atomic: true), not with a visible ImagePullBackOff", regHAMiRegistry, ref),
			regHAMiRemedy,
			append(detail, "reachability is the whole risk here: "+regHAMiRegistry+" publishes kube-scheduler for every Kubernetes release, so the tag itself is rarely the problem")...).
			WithEvidence(ev)
	}
}

// regStrippedKubeVersion reproduces HAMi's strippedKubeVersion helper: the tag
// comes from .Capabilities.KubeVersion.Version with the distribution suffix
// removed, so v1.35.7+k3s1 becomes v1.35.7 and v1.30.8-eks-2d5f260 becomes
// v1.30.8. Hardcoding a tag here would check an image the cluster never pulls.
func regStrippedKubeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if i := strings.IndexAny(v, "+-"); i > 0 {
		v = v[:i]
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if len(v) < 2 {
		return ""
	}
	return v
}
