package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
)

// questions is the intake as plain data: the values the form binds to, and the
// rules that judge and explain them. It knows nothing about rendering, so every
// rule is testable without driving a terminal, and the form is only a view of it.
//
// Readiness has no meaning against an unstated target — "is 200 GiB enough?"
// has no answer until someone says how many models they intend to hold
// (FRD-020 §7). Each consequence method therefore states what the current value
// will be checked against, and it is shown live under the field.
type questions struct {
	ctx *engine.Ctx

	Domain       string
	TLS          string
	CABundle     string
	ModelStorage string
	Models       string
	Deployments  string
	Retention    string
	GPU          bool
	DataStores   string // "in-cluster" | "external"
	ArgoCD       bool
	ConfigRepo   string
	OpenSandbox  bool
	RegistryUser string
	RegistryPass string
	ValuesFile   string
	SecretsFile  string
	ChartDir     string
	Probe        bool
}

// newQuestions seeds every answer from what the operator already supplied on
// the command line or in an answers file, so the form is a confirmation for a
// scripted run and a questionnaire for a cold one — never a second source of
// truth.
func newQuestions(c *engine.Ctx, appsDomain string) *questions {
	a := c.Answers
	q := &questions{
		ctx:          c,
		Domain:       a.Domain,
		TLS:          string(a.TLS),
		CABundle:     a.CABundle,
		ModelStorage: itoa(a.ModelStorageGi),
		Models:       itoa(a.ModelCount),
		Deployments:  itoa(a.Deployments),
		Retention:    itoa(a.RetentionDays),
		GPU:          a.GPU,
		DataStores:   "in-cluster",
		ArgoCD:       a.UseArgoCD,
		ConfigRepo:   a.ConfigRepo,
		OpenSandbox:  a.OpenSandbox,
		RegistryUser: a.RegistryUser,
		RegistryPass: a.RegistryPass,
		SecretsFile:  c.Opts.SecretsFile,
		ChartDir:     c.Opts.ChartDir,
		Probe:        !c.Opts.NoProbe,
	}
	if !a.InClusterData {
		q.DataStores = "external"
	}
	if q.TLS == "" {
		q.TLS = string(intake.TLSACMEHTTP01)
	}
	if len(c.Opts.ValuesFiles) > 0 {
		q.ValuesFile = c.Opts.ValuesFiles[0]
	}
	// OpenShift already owns a wildcard; offering it saves inventing a domain
	// the cluster cannot serve. An explicit answer still wins.
	if q.Domain == "" && appsDomain != "" {
		q.Domain = appsDomain
	}
	return q
}

func itoa(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// ── validation ──────────────────────────────────────────────────────────────

func (q *questions) validateDomain(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("required — without it there is nothing to check DNS, TLS or ingress against")
	}
	if !strings.Contains(v, ".") || strings.ContainsAny(v, " /:") {
		return fmt.Errorf("must be a domain such as bud.example.com")
	}
	return nil
}

func (q *questions) validateStorage(v string) error {
	if atoi(v) <= 0 {
		return fmt.Errorf("enter a size in GiB — \"is the storage enough?\" has no answer without it")
	}
	return nil
}

func validateWhole(label string) func(string) error {
	return func(v string) error {
		v = strings.TrimSpace(v)
		if v == "" {
			return nil
		}
		if n, err := strconv.Atoi(v); err != nil || n < 0 {
			return fmt.Errorf("%s must be a whole number", label)
		}
		return nil
	}
}

// validateConfigRepo is mandatory under ArgoCD: the ApplicationSets read values
// and secrets from this repo, so without one there is nothing to sync.
func (q *questions) validateConfigRepo(v string) error {
	if !q.ArgoCD {
		return nil
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("required when installing via ArgoCD — the ApplicationSets read your values and secrets from it")
	}
	if !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "ssh://") && !strings.HasPrefix(v, "git@") {
		return fmt.Errorf("must be a git URL: https://… for token auth, or ssh://git@… for key auth")
	}
	return nil
}

// validateCABundle is checked here rather than at the first handshake: a typo
// in a path is worth catching while the operator is still on the field.
func (q *questions) validateCABundle(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil // optional: a publicly trusted chain needs no extra root
	}
	if _, err := adapters.LoadCABundle(v); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}

// validateAll is the last gate before a run, independent of which pages the
// form happened to visit.
func (q *questions) validateAll() error {
	checks := []struct {
		label string
		err   error
	}{
		{"Root domain", q.validateDomain(q.Domain)},
		{"Model storage", q.validateStorage(q.ModelStorage)},
		{"Config repo", q.validateConfigRepo(q.ConfigRepo)},
		{"CA bundle", q.validateCABundle(q.CABundle)},
	}
	for _, c := range checks {
		if c.err != nil {
			return fmt.Errorf("%s: %w", c.label, c.err)
		}
	}
	return nil
}

// ── visibility ──────────────────────────────────────────────────────────────

func (q *questions) hideCABundle() bool      { return intake.TLSMethod(q.TLS) != intake.TLSProvided }
func (q *questions) hideConfigRepo() bool    { return !q.ArgoCD }
func (q *questions) hideRegistryToken() bool { return strings.TrimSpace(q.RegistryUser) == "" }
func (q *questions) hideChartFiles() bool    { return strings.TrimSpace(q.ValuesFile) == "" }

// ── consequences ────────────────────────────────────────────────────────────

func (q *questions) domainConsequence() string {
	d := strings.TrimSpace(q.Domain)
	if d == "" {
		return "The stack publishes twelve hostnames under this domain."
	}
	return fmt.Sprintf("Checks DNS, inbound reachability and TLS for admin.%s, app.%s, gateway.%s and 9 more.", d, d, d)
}

func (q *questions) tlsConsequence() string {
	switch intake.TLSMethod(q.TLS) {
	case intake.TLSACMEHTTP01:
		return "Inbound port 80 from the internet becomes a BLOCKER — ACME HTTP-01 cannot issue without it."
	case intake.TLSACMEDNS01:
		return "Inbound :80 is not required; DNS-01 validates out of band."
	case intake.TLSProvided:
		return "The existing certificate is checked for expiry and SAN coverage of every hostname."
	default:
		return "No certificate checks; the platform serves the ingress controller's default certificate."
	}
}

func (q *questions) caBundleConsequence() string {
	if v := strings.TrimSpace(q.CABundle); v != "" {
		return "The certificate served on every hostname is verified against the roots in " + v + "."
	}
	return "Leave empty if the certificate chains to a public root. An internal CA cannot be verified without it, and is reported as an unverifiable chain."
}

// storageConsequence shows its arithmetic rather than a bare total: a figure the
// operator cannot decompose is one they cannot sanity-check — and it is how a
// wrong constant once survived unnoticed.
func (q *questions) storageConsequence() string {
	a := q.ctx.Answers
	a.ModelStorageGi = atoi(q.ModelStorage)
	a.RetentionDays = atoi(q.Retention)
	a.InClusterData = q.DataStores == "in-cluster"
	if a.ModelStorageGi <= 0 {
		return fmt.Sprintf("Enter a size — before any model weights the platform already needs %d GiB (%s).",
			a.RequiredStorageGi(q.ctx.Profile), a.ExplainStorage(q.ctx.Profile))
	}
	return fmt.Sprintf("%s = %d GiB the cluster must be able to provision.",
		a.ExplainStorage(q.ctx.Profile), a.RequiredStorageGi(q.ctx.Profile))
}

func (q *questions) deploymentsConsequence() string {
	d := atoi(q.Deployments)
	if d <= 0 {
		return "How many models serve traffic at the same time — drives the CPU and memory floor."
	}
	return fmt.Sprintf("Checks the cluster has headroom for the platform plus %d concurrent deployment(s).", d)
}

func (q *questions) gpuConsequence() string {
	if q.GPU {
		return "Runs the GPU checks — device plugin, RuntimeClass, and a pod that actually requests a GPU. NVIDIA NGC and the HAMi registries become required."
	}
	return "GPU checks are skipped; the platform runs CPU-only, which is supported."
}

func (q *questions) dataStoresConsequence() string {
	if q.DataStores == "in-cluster" {
		return "The ApplicationSet installs Postgres, ClickHouse, Kafka, MongoDB, Valkey and S3, so they are NOT checked as prerequisites."
	}
	return "Each external endpoint is resolved and probed from inside the cluster, and the databases that must already exist are listed."
}

func (q *questions) argoConsequence() string {
	if q.ArgoCD {
		return "ArgoCD being absent is never a blocker — it is normally installed after this check. Only its inputs are required."
	}
	return "The ArgoCD checks are skipped; a direct Helm install is assumed."
}

func (q *questions) configRepoConsequence() string {
	v := strings.TrimSpace(q.ConfigRepo)
	switch {
	case v == "":
		return "Required — ArgoCD has nowhere to read values or secrets from without it."
	case strings.HasPrefix(v, "ssh://") || strings.HasPrefix(v, "git@"):
		return "Checks outbound TCP/22 — a 443-only egress policy breaks every Application silently."
	default:
		return "Checks the repository answers a git-upload-pack request."
	}
}

func (q *questions) sandboxConsequence() string {
	if q.OpenSandbox {
		return "Makes sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com required — an Alibaba CN-region registry, commonly blocked outside China."
	}
	return "The sandboxed code interpreter's images are not checked."
}

func (q *questions) registryConsequence() string {
	if strings.TrimSpace(q.RegistryUser) == "" {
		return "Optional — normally issued after readiness passes. Without it, reachability is still proven (a 401 answers the question); tag existence is reported as not verified."
	}
	return "Also resolves every image tag the chart would pull, catching a tag that does not exist."
}

func (q *questions) valuesConsequence() string {
	if strings.TrimSpace(q.ValuesFile) == "" {
		return "Optional — without it the chart is never rendered, so image tags, the server-side dry run and the credential audit are skipped."
	}
	return "Renders the chart, runs a server-side dry run, and audits the credentials in it."
}

func (q *questions) probeConsequence() string {
	if q.Probe {
		return "Creates one short-lived namespace and removes it. Proves node egress, that a StorageClass actually binds, and that the GPU stack delivers a device — none of which can be inferred."
	}
	return "Read-only: nothing is created, and those checks report NOT VERIFIED rather than passing."
}

// ── applying ────────────────────────────────────────────────────────────────

// apply writes the answers onto the context the checks will read.
func (q *questions) apply(c *engine.Ctx) {
	a := c.Answers
	a.Domain = strings.TrimSpace(q.Domain)
	a.TLS = intake.TLSMethod(q.TLS)
	a.CABundle = strings.TrimSpace(q.CABundle)
	if a.TLS != intake.TLSProvided {
		a.CABundle = "" // an answer left behind by a changed TLS method is not an answer
	}
	a.ModelStorageGi = atoi(q.ModelStorage)
	a.ModelCount = atoi(q.Models)
	a.Deployments = atoi(q.Deployments)
	a.RetentionDays = atoi(q.Retention)
	a.GPU = q.GPU
	a.InClusterData = q.DataStores == "in-cluster"
	a.UseArgoCD = q.ArgoCD
	a.ConfigRepo = strings.TrimSpace(q.ConfigRepo)
	a.OpenSandbox = q.OpenSandbox
	a.RegistryUser = strings.TrimSpace(q.RegistryUser)
	a.RegistryPass = q.RegistryPass
	c.Answers = a

	// validateCABundle has already proven this path loads; a failure here can
	// only be a file that changed under us, and the run then reports the chain
	// as unverified rather than silently trusting it.
	if a.CABundle != "" && c.Net != nil {
		_ = c.Net.TrustCABundle(a.CABundle)
	}

	c.Opts.ArgoCDEnabled = a.UseArgoCD
	c.Opts.NoProbe = !q.Probe
	if v := strings.TrimSpace(q.ValuesFile); v != "" {
		c.Opts.ValuesFiles = []string{v}
		c.Opts.SecretsFile = strings.TrimSpace(q.SecretsFile)
		if d := strings.TrimSpace(q.ChartDir); d != "" {
			c.Opts.ChartDir = d
		}
	} else {
		c.Opts.ValuesFiles = nil
		c.Opts.SecretsFile = ""
	}
	if a.RegistryUser != "" {
		if c.Opts.RegistryCreds == nil {
			c.Opts.RegistryCreds = map[string]adapters.Credential{}
		}
		c.Opts.RegistryCreds["registry.bud.studio"] = adapters.Credential{
			Username: a.RegistryUser, Password: a.RegistryPass,
		}
	}
}
