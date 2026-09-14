package checks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/BudEcosystem/budctl/internal/engine"
)

// The toolchain group is short by design (FRD-020 §5.1). budctl ships as a
// static binary that carries client-go, Helm's templating engine, SOPS and age
// as LIBRARIES, so there is deliberately no kubectl / helm / sops / age binary
// check here — looking for them would assert a dependency the tool does not
// have. What the binary cannot absorb is exactly two things: credentials, and
// an `exec` credential plugin the kubeconfig delegates to. Those, plus the
// workstation clock that every TLS and token exchange is measured against, are
// the whole group.

func init() {
	engine.Register(&engine.Check{
		ID: "toolchain.kubeconfig", Group: "toolchain", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("toolchain.kubeconfig")
			files := toolchainKubeconfigFiles()

			// c.Kube is nil only when the kubeconfig itself did not resolve:
			// adapters.NewKube fails on a missing file, an unknown context or an
			// unparseable exec stanza, never on an unreachable API server — that
			// surfaces below, on the first request.
			if c.Kube == nil {
				detail := []string{"searched: " + strings.Join(files, ", ")}
				ev := []engine.Evidence{{What: "kubeconfig loading precedence", Output: strings.Join(files, "\n")}}
				if v, ok := c.Get("kube.error"); ok {
					if s, ok := v.(string); ok && s != "" {
						detail = append(detail, s)
						ev = append(ev, engine.Evidence{What: "client-go kubeconfig load", Output: s})
					}
				}
				return ch.Fail(
					"no kubeconfig resolved, so every cluster, node, storage and probe check is skipped and nothing is known about the target cluster",
					"point budctl at a working kubeconfig — `export KUBECONFIG=/path/to/config`, or pass `--kubeconfig <path> --context <name>` — then re-run `budctl check --only toolchain`",
					detail...).WithEvidence(ev...)
			}

			ctxName := c.Kube.Context
			if ctxName == "" {
				ctxName = "(current)"
			}
			host := c.Kube.Host()

			// One real request. This is also the only thing that exercises an
			// exec credential plugin end to end: LookPath in toolchain.exec-plugin
			// proves the binary exists, this proves it returns a usable token.
			start := c.Now()
			v, err := c.Kube.ServerVersion()
			elapsed := c.Now().Sub(start)
			if err != nil {
				return ch.Fail(
					fmt.Sprintf("the Kubernetes API at %s did not answer, so no cluster-side check can run: %s", host, toolchainShortErr(err.Error())),
					toolchainAPIRemedy(err.Error(), host),
					"context: "+ctxName,
					"searched: "+strings.Join(files, ", "),
				).WithEvidence(engine.Evidence{
					What:   "GET " + strings.TrimSuffix(host, "/") + "/version (client-go, in-process)",
					Output: err.Error(),
				})
			}

			return ch.Pass(
				fmt.Sprintf("context %q reaches the API server at %s, serving Kubernetes %s", ctxName, host, v.GitVersion),
				fmt.Sprintf("/version answered in %s", elapsed.Round(time.Millisecond)),
				"resolved in-process through client-go, including any exec credential plugin; no kubectl binary is involved",
			).WithEvidence(engine.Evidence{
				What:   "GET " + strings.TrimSuffix(host, "/") + "/version (client-go, in-process)",
				Output: fmt.Sprintf("gitVersion=%s platform=%s/%s", v.GitVersion, v.Major, v.Minor),
			}).Bounds("that this identity may create what the install needs — that is cluster.installer-rbac — nor that the cluster's node clocks agree, which is egress.clock-nodes")
		},
	})

	engine.Register(&engine.Check{
		ID: "toolchain.exec-plugin", Group: "toolchain", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("toolchain.exec-plugin")

			raw, err := toolchainRawKubeconfig()
			if err != nil {
				return ch.Skip("the kubeconfig could not be parsed, so its credential plugins cannot be inspected: " + err.Error())
			}
			ctxName := raw.CurrentContext
			// adapters.Kube records the context actually in use, which is what
			// --context selected; raw.CurrentContext is only the file's default.
			if c.Kube != nil && c.Kube.Context != "" {
				ctxName = c.Kube.Context
			}
			if ctxName == "" {
				return ch.Skip("the kubeconfig names no current context, so there is no credential plugin to resolve")
			}
			kctx, ok := raw.Contexts[ctxName]
			if !ok || kctx == nil {
				return ch.Skip(fmt.Sprintf("context %q is not present in the kubeconfig files on this machine", ctxName))
			}
			auth, ok := raw.AuthInfos[kctx.AuthInfo]
			if !ok || auth == nil || auth.Exec == nil {
				// Not applicable is a SKIP, never a PASS: a static token or client
				// certificate means this check looked at nothing (FRD-020 D5).
				return ch.Skip(fmt.Sprintf("context %q authenticates with a static credential, not an exec plugin", ctxName))
			}

			ex := auth.Exec
			resolved, lerr := toolchainLookPlugin(ex.Command)
			if lerr != nil {
				return ch.Fail(
					fmt.Sprintf("the %q credential plugin that context %q depends on is not on PATH, so every API call fails before it leaves this machine", ex.Command, ctxName),
					toolchainPluginRemedy(ex),
					"kubeconfig user: "+kctx.AuthInfo,
					"exec apiVersion: "+ex.APIVersion,
				).WithEvidence(
					engine.Evidence{What: fmt.Sprintf("users[%s].exec.command", kctx.AuthInfo), Output: strings.TrimSpace(ex.Command + " " + strings.Join(ex.Args, " "))},
					engine.Evidence{What: "exec.LookPath(" + ex.Command + ")", Output: lerr.Error()},
					engine.Evidence{What: "PATH", Output: os.Getenv("PATH")},
				)
			}

			detail := []string{
				"kubeconfig user: " + kctx.AuthInfo,
				"exec apiVersion: " + ex.APIVersion,
			}
			if len(ex.Args) > 0 {
				detail = append(detail, "args: "+strings.Join(ex.Args, " "))
			}
			// Environment VALUES are withheld: an exec stanza routinely carries
			// AWS_PROFILE alongside a token or a role ARN, and evidence is read
			// aloud in support threads.
			if names := toolchainEnvNames(ex); len(names) > 0 {
				detail = append(detail, "exec env: "+strings.Join(names, ", "))
			}
			if ex.InteractiveMode == clientcmdapi.AlwaysExecInteractiveMode {
				detail = append(detail, "interactiveMode=Always: this plugin needs a terminal, so `budctl check` will not work from CI with this context")
			}

			return ch.Pass(
				fmt.Sprintf("context %q delegates to the %s credential plugin, found at %s", ctxName, ex.Command, resolved),
				detail...,
			).WithEvidence(engine.Evidence{
				What:   fmt.Sprintf("users[%s].exec.command resolved on PATH", kctx.AuthInfo),
				Output: resolved,
			}).Bounds("that the plugin returns a usable credential: budctl never executes it, because a plugin in interactive mode would block on an SSO prompt — toolchain.kubeconfig is what actually exercises it against the API server")
		},
	})

	engine.Register(&engine.Check{
		ID: "toolchain.clock", Group: "toolchain", Severity: engine.Risk,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("toolchain.clock")
			if c.Net == nil {
				return ch.Skip("no network adapter is configured, so there is no reference clock to compare against")
			}

			warn := time.Duration(c.Profile.ClockSkewWarnS) * time.Second
			if warn <= 0 {
				warn = 30 * time.Second
			}
			hard := time.Duration(c.Profile.ClockSkewFailS) * time.Second

			samples, tried := toolchainClockSamples(ctx, c)
			if len(samples) == 0 {
				return ch.Skip("no HTTPS reference clock answered, so this workstation's clock was not compared to anything (tried " +
					strings.Join(tried, ", ") + ")")
			}

			// Fail only when EVERY reference agrees the clock is out of band, and
			// report the smallest skew observed. One host with a broken clock of
			// its own must not be enough to call the operator's machine wrong.
			best := samples[0]
			outOfBand := true
			detail := make([]string, 0, len(samples)+1)
			ev := make([]engine.Evidence, 0, len(samples))
			for _, s := range samples {
				if toolchainAbs(s.skew) < toolchainAbs(best.skew) {
					best = s
				}
				if toolchainAbs(s.skew) <= warn {
					outOfBand = false
				}
				detail = append(detail, fmt.Sprintf("%s: %s (round trip %s)", s.source, toolchainSkew(s.skew), s.latency.Round(time.Millisecond)))
				ev = append(ev, engine.Evidence{
					What:   "Date header from " + s.source,
					Output: fmt.Sprintf("server %s / local %s", s.server.UTC().Format(time.RFC1123), s.local.UTC().Format(time.RFC1123)),
				})
			}
			// The Date header has one-second granularity and carries half a round
			// trip of error, so anything under a couple of seconds is measurement
			// noise — which is why the floor is tens of seconds, not one.
			detail = append(detail, fmt.Sprintf("tolerance %s; HTTP Date resolution is 1s, corrected for half the round trip", warn))

			if outOfBand {
				res := ch.Fail(
					fmt.Sprintf("this workstation's clock is %s %s the internet, so registry token exchange and TLS validation fail here with errors that read as rejected credentials or expired certificates",
						toolchainSkew(best.skew), toolchainDirection(best.skew)),
					"sync the clock before trusting any other result: `sudo timedatectl set-ntp true` then `timedatectl status` (systemd), `sudo chronyc makestep` (chrony), or macOS System Settings › General › Date & Time › Set automatically",
					detail...)
				if hard > 0 && toolchainAbs(best.skew) > hard {
					res = res.With(fmt.Sprintf("past the %s hard band: OIDC and registry tokens carry exp/nbf windows of 60-300s, so authentication fails outright rather than intermittently", hard))
				}
				return res.WithEvidence(ev...)
			}

			return ch.Pass(
				fmt.Sprintf("workstation clock within %s of %s", toolchainSkew(best.skew), best.source),
				detail...,
			).WithEvidence(ev...).
				Bounds("that the cluster's NODE clocks agree — that is what Keycloak token exp, budevent's HMAC replay window and S3 SigV4 actually depend on, and it is checked by egress.clock-nodes")
		},
	})

	engine.Register(&engine.Check{
		ID: "toolchain.age-identity", Group: "toolchain", Severity: engine.Block,
		Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
			ch := engine.Lookup("toolchain.age-identity")

			// Conditional by construction: an age identity is only a prerequisite
			// when the operator hands budctl a SOPS file to read.
			secrets := strings.TrimSpace(c.Opts.SecretsFile)
			if secrets == "" {
				return ch.Skip("no --secrets file was given, so nothing in this run has to be decrypted")
			}
			body, err := os.ReadFile(secrets)
			if err != nil {
				return ch.Fail(
					fmt.Sprintf("--secrets names %s, which this machine cannot read, so every encrypted value the install depends on is unverifiable", secrets),
					"point --secrets at the SOPS file you will install with, e.g. `--secrets infra/values/bud/secrets.bud.yaml`, and check the path is readable by this user",
					err.Error())
			}
			if !toolchainLooksEncrypted(body) {
				// A plaintext values file needs no identity. Saying so is honest;
				// blocking on a key nothing would use is not.
				return ch.Skip(fmt.Sprintf("%s carries no SOPS metadata, so no age identity is needed to read it", secrets))
			}

			recipients := toolchainRecipients(body)
			searched := toolchainAgeKeyPaths()

			source, notes, ferr := toolchainAgeIdentity(searched)
			if ferr != nil {
				detail := append([]string{}, notes...)
				detail = append(detail, "searched: "+strings.Join(searched, ", "))
				if len(recipients) > 0 {
					detail = append(detail, fmt.Sprintf("%s is encrypted to %d age %s: %s",
						filepath.Base(secrets), len(recipients), Plural(len(recipients), "recipient", "recipients"), strings.Join(recipients, ", ")))
				}
				return ch.Fail(
					fmt.Sprintf("no age identity on this machine, so budctl cannot decrypt %s and the install would be driven from values nobody has read: %s", filepath.Base(secrets), ferr.Error()),
					"install the age key this file was encrypted to — `mkdir -p ~/.config/sops/age && cp <your key> ~/.config/sops/age/keys.txt`, or `export SOPS_AGE_KEY='AGE-SECRET-KEY-1…'`; in this repo, `nix develop` then `bud_sops` bootstraps it, and a new key comes from `age-keygen -o ~/.config/sops/age/keys.txt` followed by `bud_sops_sync` to re-key the secrets",
					detail...).WithEvidence(
					engine.Evidence{What: "paths searched for an age identity", Output: strings.Join(searched, "\n")},
					engine.Evidence{What: "SOPS_AGE_KEY / SOPS_AGE_KEY_FILE", Output: toolchainEnvState()},
				)
			}

			detail := append([]string{}, notes...)
			if len(recipients) > 0 {
				detail = append(detail, fmt.Sprintf("%s is encrypted to %d age %s: %s",
					filepath.Base(secrets), len(recipients), Plural(len(recipients), "recipient", "recipients"), strings.Join(recipients, ", ")))
			}
			return ch.Pass(
				fmt.Sprintf("age identity available from %s for %s", source, filepath.Base(secrets)),
				detail...,
			).WithEvidence(engine.Evidence{
				What:   "age identity source",
				Output: source,
			}).Bounds("that this identity is one of the recipients the file was encrypted to: budctl does not attempt a decrypt here, so a key belonging to a different recipient still fails at render time")
		},
	})
}

// ---------------------------------------------------------------- kubeconfig

// toolchainKubeconfigFiles reports the files client-go would merge, so a
// "no kubeconfig" failure names where it looked instead of leaving the operator
// to guess whether KUBECONFIG was honoured.
func toolchainKubeconfigFiles() []string {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	files := rules.GetLoadingPrecedence()
	if len(files) == 0 {
		return []string{"(no kubeconfig path in KUBECONFIG or $HOME/.kube/config)"}
	}
	return files
}

// toolchainRawKubeconfig returns the merged kubeconfig as written on disk —
// the exec stanza is only visible here, because rest.Config exposes the
// resolved credential and not the plugin that produced it.
func toolchainRawKubeconfig() (clientcmdapi.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})
	return cc.RawConfig()
}

// toolchainLookPlugin resolves an exec plugin the way client-go will: a bare
// name through PATH, anything with a separator as a path that must be
// executable by this user.
func toolchainLookPlugin(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("the exec stanza sets no command")
	}
	if strings.ContainsRune(cmd, filepath.Separator) {
		st, err := os.Stat(cmd)
		if err != nil {
			return "", err
		}
		if st.IsDir() || st.Mode()&0o111 == 0 {
			return "", fmt.Errorf("%s exists but is not executable (mode %s)", cmd, st.Mode())
		}
		return cmd, nil
	}
	return exec.LookPath(cmd)
}

// toolchainPluginRemedy prefers the kubeconfig's own installHint — it exists
// precisely to be shown at this moment — and falls back to what the common
// cloud plugins are actually shipped in.
func toolchainPluginRemedy(ex *clientcmdapi.ExecConfig) string {
	if hint := strings.TrimSpace(ex.InstallHint); hint != "" {
		return "the kubeconfig ships an install hint for this plugin: " + hint
	}
	switch filepath.Base(ex.Command) {
	case "aws", "aws-iam-authenticator":
		return "install the AWS CLI v2 (`curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip && unzip -q awscliv2.zip && sudo ./aws/install`) and confirm with `aws --version`"
	case "gke-gcloud-auth-plugin":
		return "install the GKE auth plugin: `gcloud components install gke-gcloud-auth-plugin`, then `gke-gcloud-auth-plugin --version`"
	case "gcloud":
		return "install the Google Cloud SDK and confirm with `gcloud version`"
	case "kubelogin", "kubectl-oidc_login":
		return "install kubelogin (`brew install int128/kubelogin/kubelogin`, or the release binary for your platform) and confirm with `kubelogin --version`"
	case "az":
		return "install the Azure CLI and confirm with `az version`"
	case "doctl", "oci", "linode-cli":
		return "install the " + filepath.Base(ex.Command) + " CLI for this cloud and confirm it answers `" + filepath.Base(ex.Command) + " version`"
	}
	return fmt.Sprintf("install %s and put it on the PATH budctl runs with, or switch to a kubeconfig context that uses a static credential", ex.Command)
}

func toolchainEnvNames(ex *clientcmdapi.ExecConfig) []string {
	out := make([]string, 0, len(ex.Env))
	for _, e := range ex.Env {
		out = append(out, e.Name)
	}
	return Sorted(out)
}

// toolchainAPIRemedy turns a client-go transport error into the one action that
// addresses it. A generic "check your kubeconfig" is a restatement, not a fix.
func toolchainAPIRemedy(err, host string) string {
	e := strings.ToLower(err)
	switch {
	case strings.Contains(e, "getting credentials") || strings.Contains(e, "exec plugin") || strings.Contains(e, "exec: "):
		return "the kubeconfig's exec credential plugin failed — run it by hand to see why (`aws eks get-token --cluster-name <cluster>`, `gcloud container clusters get-credentials <cluster>`, `az aks get-credentials …`) and refresh the session (`aws sso login`, `gcloud auth login`, `az login`)"
	case strings.Contains(e, "x509") || strings.Contains(e, "certificate"):
		return "the API server certificate did not verify — re-fetch the kubeconfig so certificate-authority-data matches the cluster, and check whether a corporate TLS proxy is intercepting " + host
	case strings.Contains(e, "no such host"):
		return "the API hostname does not resolve from this machine — connect the VPN or split-horizon DNS that serves " + host + ", then re-run"
	case strings.Contains(e, "connection refused") || strings.Contains(e, "i/o timeout") || strings.Contains(e, "deadline exceeded") || strings.Contains(e, "network is unreachable"):
		return "nothing is listening for this machine at " + host + " — open the VPN or bastion route to the API server, or point --context at a reachable cluster"
	case strings.Contains(e, "unauthorized") || strings.Contains(e, "forbidden"):
		return "the API server rejected this credential — re-authenticate (`oc login` on OpenShift, whose tokens expire after 24 hours by default; `aws sso login`, `gcloud auth login`, `az login`; or re-issue the service-account token) and re-run"
	}
	return "confirm the context points at a live cluster: `budctl check --only toolchain --kubeconfig <path> --context <name>`"
}

// toolchainShortErr keeps a summary to one line; the full error goes to evidence.
func toolchainShortErr(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

// --------------------------------------------------------------------- clock

type toolchainClockSample struct {
	source  string
	skew    time.Duration
	latency time.Duration
	server  time.Time
	local   time.Time
}

// toolchainClockSamples takes up to two readings from distinct hosts. The
// reference is an HTTPS Date header from a host the install already depends on:
// no NTP client, no extra egress allowance, and a host that is blocked here is
// a finding the egress group reports anyway.
func toolchainClockSamples(ctx context.Context, c *engine.Ctx) ([]toolchainClockSample, []string) {
	const wantSamples, maxAttempts = 2, 4

	samples := []toolchainClockSample{}
	tried := []string{}

	for _, url := range toolchainClockURLs(c) {
		if len(samples) >= wantSamples || len(tried) >= maxAttempts {
			break
		}
		tried = append(tried, toolchainHostOf(url))
		r := c.Net.Probe(ctx, url)
		local := c.Now()
		if !r.Reachable || r.ServerTime.IsZero() {
			continue
		}
		// The Date header is stamped when the response is SENT, roughly half a
		// round trip before it landed here; without that correction a slow link
		// reads as a fast clock.
		skew := local.Add(-r.Latency / 2).Sub(r.ServerTime)
		samples = append(samples, toolchainClockSample{
			source: toolchainHostOf(url), skew: skew, latency: r.Latency,
			server: r.ServerTime, local: local,
		})
	}

	// Fall back to the registry API, which answers /v2/ with a Date header even
	// when it answers 401 and even when the chart repos are blocked.
	if len(samples) == 0 && c.OCI != nil {
		for _, reg := range c.Profile.Registries {
			if reg.Requirement != "required" || len(tried) >= maxAttempts+2 {
				continue
			}
			tried = append(tried, reg.Host)
			if t, ok := c.OCI.ServerClock(ctx, reg.Host); ok {
				local := c.Now()
				samples = append(samples, toolchainClockSample{
					source: reg.Host, skew: local.Sub(t), server: t, local: local,
				})
				break
			}
		}
	}
	if len(tried) == 0 {
		tried = append(tried, "(no reference host in the embedded profile)")
	}
	return samples, Sorted(tried)
}

func toolchainClockURLs(c *engine.Ctx) []string {
	out := []string{}
	for _, t := range c.Profile.Egress {
		if t.When == "install" && strings.HasPrefix(t.URL, "https://") {
			out = append(out, t.URL)
		}
	}
	return out
}

func toolchainHostOf(rawURL string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return s
}

func toolchainAbs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func toolchainSkew(d time.Duration) string { return toolchainAbs(d).Round(time.Second).String() }

func toolchainDirection(d time.Duration) string {
	if d < 0 {
		return "behind"
	}
	return "ahead of"
}

// ------------------------------------------------------------- age identity

const ageSecretMarker = "AGE-SECRET-KEY-1"

var (
	// Matches the SOPS metadata block (YAML or JSON) and the ciphertext marker
	// it writes into every encrypted value, so a file is recognised whether the
	// metadata sits at the top, the bottom, or under a "sops" JSON key.
	sopsMetaRE  = regexp.MustCompile(`(?m)^\s*("?sops"?\s*:|sops_version)|ENC\[`)
	ageRecipRE  = regexp.MustCompile(`age1[0-9a-z]{20,}`)
	agePlacePat = "sops/age/keys.txt"
)

// toolchainLooksEncrypted distinguishes a SOPS file from a plaintext values
// file. Blocking on an age key for a file that carries no ciphertext would be a
// failure the operator cannot act on.
func toolchainLooksEncrypted(body []byte) bool {
	return sopsMetaRE.Match(body)
}

// toolchainRecipients lists the age public keys the file was encrypted to.
// Public keys are not secret, and printing them is what lets an operator see at
// a glance that they hold the wrong identity.
func toolchainRecipients(body []byte) []string {
	found := ageRecipRE.FindAllString(string(body), -1)
	return Sorted(found)
}

// toolchainAgeKeyPaths is where sops itself looks, in order.
func toolchainAgeKeyPaths() []string {
	out := []string{}
	if f := strings.TrimSpace(os.Getenv("SOPS_AGE_KEY_FILE")); f != "" {
		out = append(out, f)
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		out = append(out, filepath.Join(xdg, agePlacePat))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, filepath.Join(home, ".config", agePlacePat))
		// sops uses the platform config dir, which on macOS is not ~/.config.
		out = append(out, filepath.Join(home, "Library", "Application Support", agePlacePat))
	}
	return Sorted(out)
}

// toolchainEnvState reports whether the two env vars are set without ever
// echoing a private key into a report that gets pasted into a ticket.
func toolchainEnvState() string {
	key := "SOPS_AGE_KEY unset"
	if strings.TrimSpace(os.Getenv("SOPS_AGE_KEY")) != "" {
		key = "SOPS_AGE_KEY set (value withheld)"
	}
	file := "SOPS_AGE_KEY_FILE unset"
	if f := strings.TrimSpace(os.Getenv("SOPS_AGE_KEY_FILE")); f != "" {
		file = "SOPS_AGE_KEY_FILE=" + f
	}
	return key + "\n" + file
}

// toolchainAgeIdentity returns the source of a usable identity, plus notes an
// operator should see. "The file exists" is not "an identity exists": a
// comment-only keys.txt is the trap this walks past.
func toolchainAgeIdentity(paths []string) (source string, notes []string, err error) {
	if key := strings.TrimSpace(os.Getenv("SOPS_AGE_KEY")); key != "" {
		if !strings.Contains(key, ageSecretMarker) {
			return "", nil, fmt.Errorf("SOPS_AGE_KEY is set but holds no %s value", ageSecretMarker)
		}
		return "SOPS_AGE_KEY (environment)", nil, nil
	}

	empty := []string{}
	for _, p := range paths {
		st, serr := os.Stat(p)
		if serr != nil || st.IsDir() {
			continue
		}
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			empty = append(empty, fmt.Sprintf("%s exists but is unreadable: %v", p, rerr))
			continue
		}
		if !strings.Contains(string(body), ageSecretMarker) {
			empty = append(empty, fmt.Sprintf("%s exists but contains no %s line", p, ageSecretMarker))
			continue
		}
		notes = []string{}
		// A private key readable by anyone else on a shared workstation is worth
		// saying out loud, but it does not stop the decrypt, so it is a note.
		if mode := st.Mode().Perm(); mode&0o077 != 0 {
			notes = append(notes, fmt.Sprintf("%s is group/world readable (mode %04o); `chmod 600 %s`", p, mode, p))
		}
		return p, notes, nil
	}

	if len(empty) > 0 {
		return "", empty, fmt.Errorf("an age key file was found but carries no identity")
	}
	return "", nil, fmt.Errorf("neither SOPS_AGE_KEY nor an age keys.txt was found")
}
