package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// The egress group asks one question: can the network where the workloads
// actually run reach the endpoints the install and the platform need? The
// default vantage point is therefore a pod and not this workstation — an
// operator laptop on a corporate VPN routinely reaches Docker Hub when the node
// subnet cannot, and that difference is the commonest cause of a sync that
// stalls in ImagePullBackOff with nothing wrong upstream (FRD-020 §5.10).
//
// All of the URL and TCP work happens in ONE pod. Thirty endpoints do not
// warrant thirty pods, and a single pod keeps the probe footprint to what §6
// promises the operator on the confirmation screen. The pod prints one
// "code|when|label|target" line per endpoint so the raw log is both what budctl
// parses and what an operator can re-read by hand.

const (
	egressVantageCluster     = "the cluster"
	egressVantageWorkstation = "this workstation"

	keyEgressCluster     = "egress.report.cluster"
	keyEgressWorkstation = "egress.report.workstation"

	// egressDefaultProbeImage is only a fallback: --probe-image is the real control,
	// and an air-gapped site points it at its own mirror.
	egressDefaultProbeImage = "curlimages/curl:8.11.1"

	egressPodName   = "budctl-egress"
	egressHFPodName = "budctl-hf-throughput"

	// egressHFSampleURL is a real weights file, range-limited to a few MiB. NG4: the
	// tool never downloads a model — it samples the first few megabytes of one,
	// and only when --hf-throughput asks it to.
	egressHFSampleURL   = "https://huggingface.co/openai-community/gpt2/resolve/main/pytorch_model.bin"
	egressHFSampleBytes = 8 << 20

	egressDefaultClockWarnS = 30
	egressDefaultClockFailS = 120
	egressDefaultHFFloorMBs = 5.0
)

func init() {
	engine.Register(&engine.Check{
		ID: "egress.install", Group: "egress", Severity: engine.Block,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.install")
			return egressEvaluate(ctx, c, ch, "install",
				"the ApplicationSet sync stops at the first image or chart it cannot fetch")
		},
	})

	engine.Register(&engine.Check{
		ID: "egress.runtime", Group: "egress", Severity: engine.Risk,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.runtime")
			return egressEvaluate(ctx, c, ch, "runtime",
				"the install completes and the named capability is absent at runtime")
		},
	})

	engine.Register(&engine.Check{
		ID: "egress.optional", Group: "egress", Severity: engine.Info,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.optional")
			return egressEvaluate(ctx, c, ch, "optional",
				"only the addon or provider behind it is affected")
		},
	})

	// The ACME directory is not an install-time fetch: the sync completes
	// without it and cert-manager simply never issues. It is on the path only
	// when the operator chose ACME — a provided certificate is a Secret, and
	// 'none' publishes plain HTTP — so it gets its own check and its own gate.
	engine.Register(&engine.Check{
		ID: "egress.acme", Group: "egress", Severity: engine.Block,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.acme")
			if !strings.HasPrefix(string(c.Answers.TLS), "acme") {
				return ch.Skip("TLS will be obtained by " + domainsTLSMethod(c) + ", so cert-manager never calls an ACME directory")
			}
			r := egressEvaluate(ctx, c, ch, "acme",
				"cert-manager cannot register an ACME account, so no certificate is issued and every hostname serves an untrusted one")
			if r.State == engine.StateFail {
				r.Remedy += " — or answer TLS as 'provided' and supply the certificate, which takes ACME off the path"
			}
			return r
		},
	})

	// Port 22, not 443. An egress allowlist written as "HTTPS to the internet"
	// covers every other check in this group and still breaks every ArgoCD
	// Application whose repoURL is ssh:// — and it breaks them quietly, as a
	// repository that never syncs rather than as a network error.
	engine.Register(&engine.Check{
		ID: "egress.ssh", Group: "egress", Severity: engine.Block,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.ssh")
			return egressEvaluateSSH(ctx, c, ch)
		},
	})

	engine.Register(&engine.Check{
		ID: "egress.proxy", Group: "egress", Severity: engine.Info,
		DependsOn: []string{"platform"},
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.proxy")
			return egressReportProxy(ctx, c, ch)
		},
	})

	engine.Register(&engine.Check{
		ID: "egress.clock-nodes", Group: "egress", Severity: engine.Risk,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.clock-nodes")
			return egressEvaluateClock(ctx, c, ch)
		},
	})

	engine.Register(&engine.Check{
		ID: "egress.hf-throughput", Group: "egress", Severity: engine.Risk,
		DependsOn: []string{"platform"}, Probe: true,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("egress.hf-throughput")
			return egressEvaluateHF(ctx, c, ch)
		},
	})
}

// ---------------------------------------------------------------------------
// vantage points
// ---------------------------------------------------------------------------

// egressEndpoint is one endpoint's answer from one vantage point. Code holds an
// HTTP status as text, "000" when nothing came back, or "open"/"closed" for a
// raw TCP target.
type egressEndpoint struct {
	Target string
	Code   string
	Err    string
	OK     bool
}

// egressVantage is everything one vantage point learned. Ran distinguishes "we
// looked" from "we could not look": a vantage that never ran must never be read
// as a set of passes.
type egressVantage struct {
	Name string
	Ran  bool
	// Why states, in operator terms, why this vantage produced nothing. It
	// becomes the Skip reason, so it is never empty when Ran is false.
	Why string
	// ImagePull is set when the probe image itself could not be pulled. FRD §6:
	// that is an egress answer about the node network, not a tool error.
	ImagePull string
	Results   map[string]egressEndpoint
	Raw       string
	Partial   string

	// Clock sampling, cluster vantage only. PodStart/PodEnd are the node's own
	// clock; Window* bracket it with this workstation's clock.
	PodStart, PodEnd       int64
	WindowStart, WindowEnd time.Time

	// ServerTime is a Date header seen from this workstation — the only
	// independent opinion budctl gets about its own clock.
	ServerTime time.Time
	ServerHost string
}

func (v *egressVantage) result(target string) (egressEndpoint, bool) {
	if v == nil || v.Results == nil {
		return egressEndpoint{}, false
	}
	r, ok := v.Results[target]
	return r, ok
}

// egressVantagePlan turns --egress-from into the two booleans every check branches
// on. The default is the cluster, because that is where the workloads run.
func egressVantagePlan(c *engine.Ctx) (cluster, workstation bool) {
	switch strings.ToLower(strings.TrimSpace(c.Opts.EgressFrom)) {
	case "workstation":
		return false, true
	case "both":
		return true, true
	default:
		return true, false
	}
}

// Separate mutexes so that, under --egress-from both, the pod run and the
// workstation sweep proceed in parallel instead of one waiting out the other.
var (
	clusterEgressMu sync.Mutex
	wsEgressMu      sync.Mutex
)

// egressReportsFor gathers whichever vantages the plan calls for. Every check in the
// group calls it; the reports are computed once per run and memoised on Ctx.
func egressReportsFor(ctx context.Context, c *engine.Ctx) (cl, ws *egressVantage) {
	wantCluster, wantWS := egressVantagePlan(c)
	if wantCluster {
		cl = egressClusterReport(ctx, c)
	}
	if wantWS {
		ws = egressWorkstationReport(ctx, c)
	}
	return cl, ws
}

// egressPrimaryVantage picks the report the verdict follows. Under "both" that is
// always the cluster: a host the laptop can reach and the node cannot is a
// failure, not a pass.
func egressPrimaryVantage(cl, ws *egressVantage) (primary, other *egressVantage) {
	if cl != nil && cl.Ran {
		return cl, ws
	}
	if ws != nil && ws.Ran {
		return ws, cl
	}
	return nil, nil
}

func egressVantageSkipReason(cl, ws *egressVantage) string {
	switch {
	case cl != nil && cl.Why != "":
		return cl.Why
	case ws != nil && ws.Why != "":
		return ws.Why
	default:
		return "no vantage point was available to dial from"
	}
}

// ---------------------------------------------------------------------------
// the workstation vantage
// ---------------------------------------------------------------------------

func egressWorkstationReport(ctx context.Context, c *engine.Ctx) *egressVantage {
	wsEgressMu.Lock()
	defer wsEgressMu.Unlock()
	if v, ok := c.Get(keyEgressWorkstation); ok {
		if rep, ok := v.(*egressVantage); ok {
			return rep
		}
	}
	rep := &egressVantage{Name: egressVantageWorkstation, Results: map[string]egressEndpoint{}}
	defer func() { c.Set(keyEgressWorkstation, rep) }()

	if c.Net == nil {
		rep.Why = "budctl has no network adapter, so nothing was dialled from this workstation"
		return rep
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	// Eight at a time: enough that thirty endpoints finish inside the check
	// budget, few enough that a corporate proxy does not rate-limit us into
	// reporting its throttling as an outage.
	sem := make(chan struct{}, 8)

	for _, t := range c.Profile.Egress {
		if t.URL == "" {
			continue
		}
		wg.Add(1)
		go func(t intake.EgressTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := c.Net.Probe(ctx, t.URL)
			out := egressEndpoint{Target: t.URL, Err: res.Err, Code: "000"}
			if res.Reachable {
				out.Code = strconv.Itoa(res.Status)
			}
			out.OK = egressCodeOK(out.Code)
			mu.Lock()
			rep.Results[t.URL] = out
			if rep.ServerTime.IsZero() && !res.ServerTime.IsZero() {
				rep.ServerTime = res.ServerTime
				rep.ServerHost = egressHostOf(t.URL)
			}
			mu.Unlock()
		}(t)
	}

	for _, t := range c.Profile.EgressTCP {
		if t.Host == "" || t.Port == 0 {
			continue
		}
		wg.Add(1)
		go func(t intake.TCPTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			key := fmt.Sprintf("%s:%d", t.Host, t.Port)
			ok, errMsg := c.Net.TCP(ctx, t.Host, t.Port)
			out := egressEndpoint{Target: key, Err: errMsg, Code: "closed", OK: false}
			if ok {
				out.Code, out.OK = "open", true
			}
			mu.Lock()
			rep.Results[key] = out
			mu.Unlock()
		}(t)
	}

	wg.Wait()
	rep.Ran = len(rep.Results) > 0
	if !rep.Ran {
		rep.Why = "the embedded catalogue contains no endpoints to dial"
	}
	return rep
}

// ---------------------------------------------------------------------------
// the cluster vantage — one pod
// ---------------------------------------------------------------------------

func egressClusterReport(ctx context.Context, c *engine.Ctx) *egressVantage {
	clusterEgressMu.Lock()
	defer clusterEgressMu.Unlock()
	if v, ok := c.Get(keyEgressCluster); ok {
		if rep, ok := v.(*egressVantage); ok {
			return rep
		}
	}
	rep := &egressVantage{Name: egressVantageCluster, Results: map[string]egressEndpoint{}}
	defer func() { c.Set(keyEgressCluster, rep) }()

	if c.Probes == nil {
		rep.Why = "no probe runner: egress from the cluster was not tested, and is therefore not confirmed working"
		return rep
	}

	// The script is built from the run's options, never from whichever check
	// happened to reach this function first — otherwise the single memoised pod
	// would carry different contents depending on a goroutine race.
	wantCluster, _ := egressVantagePlan(c)
	var (
		urls []intake.EgressTarget
		tcp  []intake.TCPTarget
	)
	if wantCluster {
		urls, tcp = c.Profile.Egress, c.Profile.EgressTCP
	}
	// Under --egress-from workstation the pod still runs, with a clock-only
	// script: egress.clock-nodes can only read a node's clock from a node.

	image := c.Opts.ProbeImage
	if image == "" {
		image = egressDefaultProbeImage
	}

	rep.WindowStart = c.Now()
	out, err := c.Probes.RunPod(ctx, probes.PodSpec{
		Name:    egressPodName,
		Image:   image,
		Command: []string{"/bin/sh", "-c", egressScript(urls, tcp)},
		Timeout: egressPodBudget(c),
	})
	rep.WindowEnd = c.Now()
	rep.Raw = strings.TrimSpace(out.Logs)

	parseEgressLines(rep.Raw, rep)

	switch {
	case len(rep.Results) > 0 || rep.PodStart > 0:
		// Partial output still answers for the endpoints it reached; the ones
		// with no line are reported as untested rather than as unreachable.
		rep.Ran = true
		if err != nil {
			rep.Partial = "the probe pod did not finish (" + err.Error() + "); endpoints with no line below were not reached"
		}
	case egressImagePullFailure(out):
		rep.ImagePull = fmt.Sprintf("the probe image %s could not be pulled: %s", image, egressProbeReason(out))
		rep.Why = rep.ImagePull
	case !out.Scheduled:
		rep.Why = "the probe pod was never scheduled (" + egressProbeReason(out) + "), so egress from the cluster was not tested"
	default:
		rep.Why = fmt.Sprintf("the probe pod produced no output (phase %s%s)", egressNonEmpty(out.Phase, "unknown"), egressSuffixReason(out))
		if err != nil {
			rep.Why += ": " + err.Error()
		}
	}
	return rep
}

// egressProbeShell is the fixed head of the probe script. Every endpoint is
// dialled in its own background subshell and reports a single line, so thirty
// endpoints cost one round of ~10s rather than thirty. Each result is one echo
// of well under PIPE_BUF, which the kernel writes to the container's stdout
// atomically — that is what makes concurrent writers safe here.
const egressProbeShell = `set -u
probe() {
  code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 "$3" 2>/dev/null)
  [ -z "$code" ] && code=000
  echo "$code|$1|$2|$3"
}
tcpprobe() {
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w 5 "$3" "$4" >/dev/null 2>&1; then code=open; else code=closed; fi
  else
    # No nc in the image: dial the port with curl and read its exit code.
    # 6 (DNS), 7 (refused) and 28 (timeout) are real network failures; every
    # other code means the TCP connection was established and only the protocol
    # was wrong — which is exactly what an SSH banner looks like to an HTTP
    # client, and is the answer this check wants.
    curl -s -o /dev/null --connect-timeout 5 --max-time 8 "http://$3:$4" >/dev/null 2>&1
    case "$?" in 6|7|28) code=closed ;; *) code=open ;; esac
  fi
  echo "$code|$1|$2|$3:$4"
}
echo "CLOCK|start|$(date +%s)"
`

func egressScript(urls []intake.EgressTarget, tcp []intake.TCPTarget) string {
	var b strings.Builder
	b.WriteString(egressProbeShell)
	for _, t := range urls {
		if t.URL == "" {
			continue
		}
		fmt.Fprintf(&b, "probe %s %s %s &\n",
			egressShellQuote(t.When), egressShellQuote(egressSanitizeField(t.Label)), egressShellQuote(t.URL))
	}
	for _, t := range tcp {
		if t.Host == "" || t.Port == 0 {
			continue
		}
		fmt.Fprintf(&b, "tcpprobe %s %s %s %s &\n",
			egressShellQuote(t.When), egressShellQuote(egressSanitizeField(t.Label)), egressShellQuote(t.Host), egressShellQuote(strconv.Itoa(t.Port)))
	}
	b.WriteString("wait\n")
	b.WriteString("echo \"CLOCK|end|$(date +%s)\"\n")
	return b.String()
}

func parseEgressLines(raw string, rep *egressVantage) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if parts[0] == "CLOCK" && len(parts) == 3 {
			n, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
			if err != nil {
				continue
			}
			if parts[1] == "start" {
				rep.PodStart = n
			} else {
				rep.PodEnd = n
			}
			continue
		}
		if len(parts) < 4 {
			continue
		}
		code := strings.TrimSpace(parts[0])
		target := strings.Join(parts[3:], "|")
		rep.Results[target] = egressEndpoint{Target: target, Code: code, OK: egressCodeOK(code)}
	}
}

// egressCodeOK decides what counts as reachable. Any HTTP status answers the question
// this group asks — a registry's 401 and a moved chart index's 404 both prove
// DNS, routing, TLS and a live server (FRD-020 D7). Two do not: "000" is curl's
// "nothing came back at all", and 407 is a proxy refusing us, which is the exact
// state in which every image pull fails.
func egressCodeOK(code string) bool {
	switch code {
	case "", "000", "407", "closed":
		return false
	case "open":
		return true
	}
	n, err := strconv.Atoi(code)
	if err != nil {
		return false
	}
	return n >= 100 && n < 600
}

func egressPodBudget(c *engine.Ctx) time.Duration {
	budget := c.Opts.CheckTimeout
	if budget <= 0 {
		budget = 90 * time.Second
	}
	t := budget - 20*time.Second
	if t < 30*time.Second {
		t = 30 * time.Second
	}
	return t
}

func egressImagePullFailure(out probes.PodOutcome) bool {
	r := strings.ToLower(out.Reason + " " + strings.Join(out.Events, " "))
	return !out.Started && (strings.Contains(r, "imagepull") || strings.Contains(r, "errimage") ||
		strings.Contains(r, "invalidimagename") || strings.Contains(r, "pull access denied"))
}

func egressProbeReason(out probes.PodOutcome) string {
	if out.Reason != "" {
		return out.Reason
	}
	if len(out.Events) > 0 {
		return strings.Join(out.Events, "; ")
	}
	return "no reason reported"
}

func egressSuffixReason(out probes.PodOutcome) string {
	if r := egressProbeReason(out); r != "no reason reported" {
		return ", " + r
	}
	return ""
}

// ---------------------------------------------------------------------------
// egress.install / egress.runtime / egress.optional
// ---------------------------------------------------------------------------

func egressEvaluate(ctx context.Context, c *engine.Ctx, ch *engine.Check, when, cost string) engine.Result {
	noun := egressNoun(when)
	targets := egressTargetsWhen(c.Profile.Egress, when)
	if len(targets) == 0 {
		return ch.Skip("the embedded catalogue lists no " + noun + " endpoints")
	}

	cl, ws := egressReportsFor(ctx, c)

	// FRD §6: an unpullable probe image is itself the egress answer. For the
	// install-time set it is the strongest possible one — the node could not
	// fetch an image from a public registry, which is what every chart in the
	// ApplicationSet is about to ask it to do.
	if cl != nil && cl.ImagePull != "" && (ws == nil || !ws.Ran) {
		if when == "install" {
			img := c.Opts.ProbeImage
			if img == "" {
				img = egressDefaultProbeImage
			}
			return ch.Fail(
				fmt.Sprintf("the node could not pull %s, so no image in the install will pull either", img),
				"open egress from the node network to the registry that serves the probe image, or point --probe-image at a mirror the nodes can already reach",
				cl.ImagePull).
				WithEvidence(engine.Evidence{What: "probe pod events", Output: cl.ImagePull})
		}
		return ch.Skip(cl.ImagePull)
	}

	primary, other := egressPrimaryVantage(cl, ws)
	if primary == nil {
		return ch.Skip(egressVantageSkipReason(cl, ws))
	}

	var (
		failed   []string
		untested []string
		labels   []string
		hosts    []string
		evidence []engine.Evidence
		detail   []string
	)
	for _, t := range targets {
		r, seen := primary.result(t.URL)
		if !seen {
			untested = append(untested, fmt.Sprintf("%s — %s: no answer recorded before the probe deadline", t.Label, t.URL))
			continue
		}
		evidence = append(evidence, engine.Evidence{
			What:   fmt.Sprintf("GET %s from %s", t.URL, primary.Name),
			Output: fmt.Sprintf("%s|%s|%s|%s", r.Code, t.When, egressSanitizeField(t.Label), t.URL),
		})
		if r.OK {
			continue
		}
		line := egressFailDetail(t.Label, t.URL, r, t.Consequence)
		// The two vantages disagreeing is itself the finding: it localises the
		// problem to the node network or the proxy rather than to DNS or an
		// upstream outage.
		if o, ok := other.result(t.URL); ok && o.OK {
			line += fmt.Sprintf(" [reachable from %s — the difference is the node network or the proxy, not DNS or an upstream outage]", other.Name)
		}
		failed = append(failed, line)
		labels = append(labels, t.Label)
		hosts = append(hosts, egressHostOf(t.URL))
	}

	detail = append(detail, fmt.Sprintf("vantage point: %s", primary.Name))
	if other != nil && other.Ran {
		detail = append(detail, fmt.Sprintf("second vantage point %s: %d of %d reachable — the verdict follows %s, because that is where the workloads run",
			other.Name, egressCountOK(other, targets), len(targets), primary.Name))
	} else if other != nil && other.Why != "" {
		detail = append(detail, fmt.Sprintf("the %s vantage point produced nothing: %s", other.Name, other.Why))
	}
	detail = append(detail, egressProxyNote(c)...)
	if primary.Partial != "" {
		detail = append(detail, primary.Partial)
	}
	detail = append(detail, untested...)
	detail = append(detail, failed...)

	if len(failed) == 0 {
		// A partial sweep is not a pass. The endpoints with no line were never
		// dialled, and D5 keeps "we did not look" apart from "we looked and it
		// was fine" — the ones that did answer are still in the detail.
		if len(untested) > 0 {
			return ch.Skip(fmt.Sprintf("%d of %d %s endpoints answered from %s and %d were never dialled, so this run did not verify the set",
				len(targets)-len(untested), len(targets), noun, primary.Name, len(untested))).
				With(detail...).WithEvidence(evidence...)
		}
		return ch.Pass(fmt.Sprintf("all %d %s %s answered from %s",
			len(targets), noun, Plural(len(targets), "endpoint", "endpoints"), primary.Name), detail...).
			WithEvidence(evidence...).
			Bounds("that a host answered is not that it will serve what is asked of it: this dials the endpoint, it does not pull a layer or a chart — and a proxy that answers every request with a block page also counts as an answer, which is why the status codes are in the evidence")
	}

	summary := fmt.Sprintf("%d of %d %s %s unreachable from %s (%s); %s",
		len(failed), len(targets), noun, Plural(len(failed), "endpoint is", "endpoints are"),
		primary.Name, egressJoinLabels(labels), cost)
	remedy := fmt.Sprintf("allow outbound HTTPS from the node network to %s, then re-run `budctl check --only egress`", strings.Join(Sorted(hosts), ", "))
	if c.Platform != nil && c.Platform.ClusterProxy != "" {
		remedy = fmt.Sprintf("add %s to the allowlist of the cluster-wide proxy %s (a node firewall rule will not help — the proxy is the egress path), then re-run `budctl check --only egress`",
			strings.Join(Sorted(hosts), ", "), c.Platform.ClusterProxy)
	}

	switch when {
	case "optional":
		// Optional endpoints never move the verdict; the operator still needs to
		// know which addon will not work.
		return ch.FailAs(engine.Info, summary, remedy, detail...).WithEvidence(evidence...)
	default:
		return ch.Fail(summary, remedy, detail...).WithEvidence(evidence...)
	}
}

// egressNoun names a catalogue slice the way the report should read it:
// "install-time", not "install", and never "runtime-time".
func egressNoun(when string) string {
	switch when {
	case "install":
		return "install-time"
	case "acme":
		return "ACME"
	}
	return when
}

func egressTargetsWhen(all []intake.EgressTarget, when string) []intake.EgressTarget {
	out := []intake.EgressTarget{}
	for _, t := range all {
		if t.When == when && t.URL != "" {
			out = append(out, t)
		}
	}
	return out
}

func egressCountOK(rep *egressVantage, targets []intake.EgressTarget) int {
	n := 0
	for _, t := range targets {
		if r, ok := rep.result(t.URL); ok && r.OK {
			n++
		}
	}
	return n
}

func egressFailDetail(label, target string, r egressEndpoint, consequence string) string {
	why := "no answer"
	switch {
	case r.Code == "407":
		why = "HTTP 407 — the proxy refused us; nothing will pull until it accepts these hosts"
	case r.Code == "closed":
		why = "the port did not accept a connection"
	case r.Err != "":
		why = r.Err
	case r.Code != "" && r.Code != "000":
		why = "HTTP " + r.Code
	}
	if consequence == "" {
		return fmt.Sprintf("%s — %s: %s", label, target, why)
	}
	return fmt.Sprintf("%s — %s: %s → %s", label, target, why, consequence)
}

func egressJoinLabels(labels []string) string {
	labels = Sorted(labels)
	if len(labels) <= 3 {
		return strings.Join(labels, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(labels[:3], ", "), len(labels)-3)
}

// egressProxyNote is appended to every egress result: a failure means something
// different when a proxy is the only way out, and a pass means something
// different when a proxy is answering on the internet's behalf.
func egressProxyNote(c *engine.Ctx) []string {
	if c.Platform == nil || c.Platform.ClusterProxy == "" {
		return nil
	}
	return []string{
		"read against the cluster-wide egress proxy " + c.Platform.ClusterProxy,
		"the probe pod dials directly and does not inherit that proxy — and neither do the chart's own workloads unless their values set HTTP_PROXY/HTTPS_PROXY/NO_PROXY, so a failure here with a proxy configured means the workloads need the proxy environment, not that the network is dead",
	}
}

// ---------------------------------------------------------------------------
// egress.ssh
// ---------------------------------------------------------------------------

func egressEvaluateSSH(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	targets := []intake.TCPTarget{}
	for _, t := range c.Profile.EgressTCP {
		if t.Host != "" && t.Port != 0 {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return ch.Skip("the embedded catalogue lists no raw TCP endpoints")
	}
	if !c.Answers.UseArgoCD {
		return ch.Skip("ArgoCD is not part of this install, so nothing syncs from git over SSH")
	}

	repo := strings.TrimSpace(c.Answers.ConfigRepo)
	usesSSH := strings.HasPrefix(repo, "ssh://") || strings.HasPrefix(repo, "git@")
	usesHTTPS := strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://")
	if usesHTTPS {
		return ch.Skip("the config repo is " + repo + ", which ArgoCD reaches over 443; port 22 is not on its path")
	}

	// Severity is conditional: a stated ssh:// repoURL makes a closed port 22 a
	// blocker, an unstated one makes it a risk the operator has to decide on.
	sev := engine.Risk
	if usesSSH {
		sev = engine.Block
	}

	cl, ws := egressReportsFor(ctx, c)
	primary, other := egressPrimaryVantage(cl, ws)
	if primary == nil {
		return ch.Skip(egressVantageSkipReason(cl, ws))
	}

	var (
		closed   []string
		hosts    []string
		detail   []string
		evidence []engine.Evidence
		tested   int
	)
	detail = append(detail, "vantage point: "+primary.Name)
	if repo != "" {
		detail = append(detail, "ArgoCD repoURL: "+repo)
	} else {
		detail = append(detail, "no config repoURL was stated at intake, so this is reported as a risk rather than a blocker")
	}
	for _, t := range targets {
		key := fmt.Sprintf("%s:%d", t.Host, t.Port)
		r, seen := primary.result(key)
		if !seen {
			detail = append(detail, fmt.Sprintf("%s — %s: no answer recorded before the probe deadline", t.Label, key))
			continue
		}
		tested++
		evidence = append(evidence, engine.Evidence{
			What:   fmt.Sprintf("TCP %s from %s", key, primary.Name),
			Output: fmt.Sprintf("%s|%s|%s|%s", r.Code, t.When, egressSanitizeField(t.Label), key),
		})
		if r.OK {
			continue
		}
		line := egressFailDetail(t.Label, key, r, t.Consequence)
		if o, ok := other.result(key); ok && o.OK {
			line += fmt.Sprintf(" [open from %s — the block is on the node network, not at GitHub]", other.Name)
		}
		closed = append(closed, line)
		hosts = append(hosts, key)
	}
	if tested == 0 {
		return ch.Skip("no TCP target produced an answer from " + primary.Name)
	}
	detail = append(detail, egressProxyNote(c)...)
	detail = append(detail, closed...)

	if len(closed) == 0 {
		return ch.Pass(fmt.Sprintf("%s accepts connections from %s", strings.Join(egressTCPKeys(targets), ", "), primary.Name), detail...).
			WithEvidence(evidence...).
			Bounds("an accepted TCP connection is not an accepted key: ArgoCD still needs a deploy key the repository trusts, and the SSH host key in its known_hosts")
	}

	return ch.FailAs(sev,
		fmt.Sprintf("%s refused from %s: every ArgoCD Application sourcing from ssh:// stops syncing, and reports as OutOfSync rather than as a network error",
			strings.Join(Sorted(hosts), ", "), primary.Name),
		"open outbound TCP 22 to github.com from the node network — an egress allowlist that covers 443 only does NOT cover git over SSH, which is a different port and a different protocol; alternatively switch the repoURL to https:// with a token and re-run",
		detail...).WithEvidence(evidence...)
}

func egressTCPKeys(targets []intake.TCPTarget) []string {
	out := []string{}
	for _, t := range targets {
		out = append(out, fmt.Sprintf("%s:%d", t.Host, t.Port))
	}
	return Sorted(out)
}

// ---------------------------------------------------------------------------
// egress.proxy
// ---------------------------------------------------------------------------

func egressReportProxy(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	detail := []string{}
	var evidence []engine.Evidence

	clusterProxy := ""
	if c.Platform != nil {
		clusterProxy = c.Platform.ClusterProxy
	}
	noProxy := ""
	if c.Kube != nil && c.Platform.IsOpenShift() {
		if p := c.Kube.Get(ctx, "proxies.config.openshift.io", "", "cluster"); p != nil {
			noProxy = p.DigString("status", "noProxy")
			if noProxy == "" {
				noProxy = p.DigString("spec", "noProxy")
			}
			evidence = append(evidence, engine.Evidence{
				What: "proxy.config.openshift.io/cluster",
				Output: fmt.Sprintf("httpProxy=%s httpsProxy=%s noProxy=%s",
					p.DigString("spec", "httpProxy"), p.DigString("spec", "httpsProxy"), noProxy),
			})
		}
	}

	// The workstation's own environment matters because Go's HTTP client honours
	// it: under --egress-from workstation, a green result may be the proxy's.
	env := []string{}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}

	hints := egressNodeProxyHints(ctx, c)

	switch {
	case clusterProxy != "":
		detail = append(detail, "every egress result in this group is that proxy's answer for the hosts it allows, and a refusal for the hosts it does not")
		if noProxy != "" {
			detail = append(detail, "noProxy: "+noProxy)
		}
	case len(hints) > 0:
		detail = append(detail, "no cluster-wide proxy object, but workloads in kube-system carry proxy environment variables, so the node environment almost certainly has one")
		detail = append(detail, hints...)
	}
	if len(env) > 0 {
		detail = append(detail, "this workstation's environment (it shapes every workstation-vantage result below): "+strings.Join(env, " "))
	}
	detail = append(detail, "node-level proxy configuration lives in the container runtime's systemd drop-in and is not exposed through the Kubernetes API, so a proxy configured only there is invisible to budctl and would show up here as a set of unexplained egress failures")

	summary := "no egress proxy detected: the results in this group are direct connections"
	switch {
	case clusterProxy != "":
		summary = "cluster-wide egress proxy in effect: " + clusterProxy
	case len(hints) > 0:
		summary = "proxy environment variables found on kube-system workloads"
	case len(env) > 0:
		summary = "no cluster proxy; this workstation itself is behind " + strings.Join(env, " ")
	}
	return ch.Infof("%s", summary).With(detail...).WithEvidence(evidence...)
}

// egressNodeProxyHints looks for proxy environment variables on workloads that are
// already running. It is a heuristic, not a reading of the node environment —
// which is why the result is INFO and says so.
//
// NO_PROXY on its own is not a hint: k3s's helm controller sets it on every
// helm-install pod whether or not a proxy exists, so it is reported only beside
// an HTTP_PROXY or HTTPS_PROXY on the same container.
func egressNodeProxyHints(ctx context.Context, c *engine.Ctx) []string {
	if c.Kube == nil {
		return nil
	}
	out := []string{}
	for _, p := range c.Kube.List(ctx, "pods", "kube-system") {
		for _, ct := range p.Containers() {
			envs, ok := ct["env"].([]any)
			if !ok {
				continue
			}
			var proxies, noProxy []string
			for _, e := range envs {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				name, _ := em["name"].(string)
				value, _ := em["value"].(string)
				if value == "" {
					continue
				}
				line := fmt.Sprintf("pod/%s: %s=%s", p.Name(), strings.ToUpper(name), value)
				switch strings.ToUpper(name) {
				case "HTTP_PROXY", "HTTPS_PROXY":
					proxies = append(proxies, line)
				case "NO_PROXY":
					noProxy = append(noProxy, line)
				}
			}
			if len(proxies) > 0 {
				out = append(append(out, proxies...), noProxy...)
			}
		}
	}
	return Sorted(out)
}

// ---------------------------------------------------------------------------
// egress.clock-nodes
// ---------------------------------------------------------------------------

func egressEvaluateClock(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	if c.Probes == nil {
		return ch.Skip("no probe runner: a node's clock can only be read from a pod on that node")
	}
	rep := egressClusterReport(ctx, c)
	if rep.PodStart == 0 {
		reason := rep.Why
		if reason == "" {
			reason = "the probe pod printed no CLOCK line"
		}
		return ch.Skip("node clock not sampled: " + reason)
	}

	skew, uncertainty, work, earliest, direction := egressClockSkew(rep)

	warn := int64(c.Profile.ClockSkewWarnS)
	if warn <= 0 {
		warn = egressDefaultClockWarnS
	}
	fail := int64(c.Profile.ClockSkewFailS)
	if fail <= 0 {
		fail = egressDefaultClockFailS
	}

	detail := []string{
		fmt.Sprintf("node clock %s, this workstation %s–%s, sampling uncertainty ±%ds",
			time.Unix(rep.PodStart, 0).UTC().Format(time.RFC3339),
			rep.WindowStart.UTC().Format("15:04:05"), rep.WindowEnd.UTC().Format("15:04:05"), uncertainty),
		"nothing in the Bud chart or in either ApplicationSet configures time sync; the node's clock is the node owner's responsibility",
	}
	// The independent opinion about budctl's own clock, when a workstation probe
	// gave us a Date header to compare against.
	if _, wantWS := egressVantagePlan(c); wantWS {
		if ws := egressWorkstationReport(ctx, c); ws != nil && !ws.ServerTime.IsZero() {
			delta := int64(rep.WindowStart.Sub(ws.ServerTime).Seconds())
			detail = append(detail, fmt.Sprintf("this workstation is %ds from the Date header served by %s, so the reference clock here is itself sound to about that much", delta, ws.ServerHost))
		}
	}
	evidence := []engine.Evidence{{
		What:   "date +%s inside the probe pod, against this workstation's clock",
		Output: fmt.Sprintf("pod=%d workstation window=[%d,%d] pod work=%ds", rep.PodStart, earliest, rep.WindowEnd.Unix(), work),
	}}

	consequence := "Keycloak rejects freshly minted tokens as expired, budevent's 300s HMAC timestamp window closes, and S3 SigV4 refuses signed requests"
	remedy := "enable and verify NTP (chrony/systemd-timesyncd) on every node — nothing in the platform does it — then re-run `budctl check --only egress`"

	switch {
	case skew > fail:
		return ch.FailAs(engine.Block,
			fmt.Sprintf("the node running the probe is at least %ds %s this workstation: %s", skew, direction, consequence),
			remedy, detail...).WithEvidence(evidence...)
	case skew > warn:
		return ch.Fail(
			fmt.Sprintf("the node running the probe is at least %ds %s this workstation; at this drift %s", skew, direction, consequence),
			remedy, detail...).WithEvidence(evidence...)
	case uncertainty > fail:
		// The pod took so long to schedule and pull that the bracket is wider
		// than the blocking threshold. Reporting a PASS here would be claiming a
		// measurement that was never made.
		return ch.Infof("node clock agrees to within the sampling window, but that window was %ds wide — wider than the %ds blocking threshold, so this run did not bound the skew", uncertainty, fail).
			With(append(detail, "re-run when the probe image is already cached on the node, or with a longer --check-timeout, to get a usable bound")...).
			WithEvidence(evidence...)
	default:
		return ch.Pass(fmt.Sprintf("node clock within %ds of this workstation (warn at %ds, block at %ds)", uncertainty, warn, fail), detail...).
			WithEvidence(evidence...).
			Bounds("one pod runs on one node, so this is that node's clock and not the cluster's — a single badly drifted node elsewhere is not covered; and the comparison is against this workstation's clock, not against UTC")
	}
}

// ---------------------------------------------------------------------------
// egress.hf-throughput
// ---------------------------------------------------------------------------

func egressEvaluateHF(ctx context.Context, c *engine.Ctx, ch *engine.Check) engine.Result {
	if !c.Opts.HFThroughput {
		return ch.Skip("--hf-throughput was not given: Hugging Face reachability was checked, sustained download rate was not")
	}
	floor := c.Profile.HFThroughputMBs
	if floor <= 0 {
		floor = egressDefaultHFFloorMBs
	}
	wantCluster, _ := egressVantagePlan(c)

	var (
		mbs     float64
		bytes   float64
		from    string
		httpRes string
		err     error
	)
	switch {
	case wantCluster && c.Probes != nil:
		from = egressVantageCluster
		mbs, bytes, httpRes, err = egressHFSampleFromCluster(ctx, c)
	case c.Net != nil:
		from = egressVantageWorkstation
		mbs, bytes, httpRes, err = egressHFSampleFromWorkstation(ctx, c)
	default:
		return ch.Skip("no vantage point available to sample Hugging Face from")
	}
	if err != nil && bytes == 0 {
		return ch.Skip(fmt.Sprintf("no bytes came back from huggingface.co via %s (%v); egress.runtime carries the reachability finding", from, err))
	}
	if bytes == 0 {
		return ch.Skip(fmt.Sprintf("huggingface.co returned no bytes via %s (%s); egress.runtime carries the reachability finding", from, httpRes))
	}

	evidence := []engine.Evidence{{
		What:   fmt.Sprintf("ranged GET %s (first %s) from %s", egressHFSampleURL, HumanBytes(egressHFSampleBytes), from),
		Output: fmt.Sprintf("%s transferred, %.2f MB/s, %s", HumanBytes(bytes), mbs, httpRes),
	}}
	detail := []string{
		fmt.Sprintf("sampled %s from %s; MB means 10^6 bytes", HumanBytes(bytes), from),
		fmt.Sprintf("at this rate the %d GiB of model storage stated at intake takes %s to fill from Hugging Face",
			c.Answers.ModelStorageGi, egressHumanDuration(float64(c.Answers.ModelStorageGi)*1073.741824/mbs)),
	}
	detail = append(detail, egressProxyNote(c)...)

	if mbs < floor {
		return ch.Fail(
			fmt.Sprintf("%.2f MB/s from %s, below the %.1f MB/s floor: model downloads will run for hours and the deploy workflow will time out long before the weights land", mbs, from, floor),
			"check the egress path for a proxy or IDS that inspects and throttles large downloads, or stage weights into the cluster's object store ahead of the deployment; re-run with --hf-throughput to confirm",
			detail...).WithEvidence(evidence...)
	}
	return ch.Pass(fmt.Sprintf("%.2f MB/s from %s, at or above the %.1f MB/s floor", mbs, from, floor), detail...).
		WithEvidence(evidence...).
		Bounds("one few-megabyte sample, from one CDN edge, at one moment — sustained throughput for a multi-hundred-gigabyte pull can be far lower, and a per-connection rate is not the rate several parallel deployments will see")
}

func egressHFSampleFromCluster(ctx context.Context, c *engine.Ctx) (mbs, bytes float64, status string, err error) {
	image := c.Opts.ProbeImage
	if image == "" {
		image = egressDefaultProbeImage
	}
	script := fmt.Sprintf(
		"curl -s -o /dev/null -r 0-%d --connect-timeout 10 --max-time 45 -w 'HF|%%{http_code}|%%{size_download}|%%{speed_download}\\n' %s",
		egressHFSampleBytes-1, egressShellQuote(egressHFSampleURL))
	out, runErr := c.Probes.RunPod(ctx, probes.PodSpec{
		Name:    egressHFPodName,
		Image:   image,
		Command: []string{"/bin/sh", "-c", script},
		Timeout: egressPodBudget(c),
	})
	for _, line := range strings.Split(out.Logs, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) != 4 || parts[0] != "HF" {
			continue
		}
		size, _ := strconv.ParseFloat(parts[2], 64)
		speed, _ := strconv.ParseFloat(parts[3], 64)
		return speed / 1e6, size, "HTTP " + parts[1], nil
	}
	if runErr != nil {
		return 0, 0, "", runErr
	}
	return 0, 0, "no HF line in the probe pod's output: " + egressProbeReason(out), nil
}

func egressHFSampleFromWorkstation(ctx context.Context, c *engine.Ctx) (mbs, bytes float64, status string, err error) {
	// A 45s ceiling, not a byte count: on a slow link the sample IS the partial
	// transfer, and aborting it mid-stream is what makes the measurement
	// possible at all.
	sctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(sctx, http.MethodGet, egressHFSampleURL, nil)
	if err != nil {
		return 0, 0, "", err
	}
	req.Header.Set("User-Agent", "budctl/1.0")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", egressHFSampleBytes-1))

	// Reuse the adapter's transport so proxy settings and timeouts configured
	// for the run apply, but not its overall Timeout: that would abort the
	// sample as an error instead of ending it as a measurement.
	client := &http.Client{Transport: c.Net.Client.Transport}
	start := c.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, "", err
	}
	defer resp.Body.Close()
	n, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, egressHFSampleBytes))
	elapsed := c.Now().Sub(start)
	if elapsed <= 0 {
		elapsed = time.Millisecond
	}
	status = fmt.Sprintf("HTTP %d", resp.StatusCode)
	if copyErr != nil {
		status += " (transfer cut short: " + copyErr.Error() + ")"
	}
	return (float64(n) / 1e6) / elapsed.Seconds(), float64(n), status, nil
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func egressShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// egressSanitizeField keeps a catalogue label out of the field separator, so the
// pod's output stays parseable whatever a future catalogue entry is called.
func egressSanitizeField(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "/"), "\n", " ")
}

func egressHostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	return u.Hostname()
}

func egressNonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func egressHumanDuration(seconds float64) string {
	switch {
	case seconds < 90:
		return fmt.Sprintf("%.0fs", seconds)
	case seconds < 5400:
		return fmt.Sprintf("%.0f minutes", seconds/60)
	case seconds < 172800:
		return fmt.Sprintf("%.1f hours", seconds/3600)
	default:
		return fmt.Sprintf("%.1f days", seconds/86400)
	}
}

// egressClockSkew turns one in-pod timestamp into a LOWER BOUND on the node's
// clock skew plus the uncertainty of the measurement.
//
// The pod's `date` ran at an unknown instant between creating the pod and
// observing it finish, so a single subtraction would report scheduling and
// image-pull time as skew and call every cold node badly drifted. Bracket it
// instead: the sample cannot have been taken before we created the pod, and
// cannot have been taken later than completion minus the pod's own measured
// work. A timestamp inside that bracket proves nothing beyond its width; one
// outside it is skew that no amount of scheduling latency can explain.
func egressClockSkew(rep *egressVantage) (skew, uncertainty, work, earliest int64, direction string) {
	if rep.PodEnd > rep.PodStart {
		work = rep.PodEnd - rep.PodStart
	}
	earliest = rep.WindowStart.Unix()
	latest := rep.WindowEnd.Unix() - work
	if latest < earliest {
		latest = earliest
	}
	behind := earliest - rep.PodStart
	ahead := rep.PodStart - latest
	skew = max(max(behind, ahead), int64(0))
	uncertainty = latest - earliest
	direction = "ahead of"
	if behind > ahead {
		direction = "behind"
	}
	return skew, uncertainty, work, earliest, direction
}
