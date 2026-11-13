package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/check"
	_ "github.com/BudEcosystem/budctl/check/checks"
	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/install/spec"
	"github.com/BudEcosystem/budctl/internal/helm"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/net"
	"github.com/BudEcosystem/budctl/internal/oci"
	"github.com/BudEcosystem/budctl/internal/probes"
	"github.com/BudEcosystem/budctl/output"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

const checkExample = `  # check against a sized target
  budctl check --domain bud.example.com --model-storage-gi 600 --models 12

  # read-only, nothing created in the cluster
  budctl check --domain bud.example.com --no-probe

  # also validate the values you will hand to ArgoCD
  budctl check --domain bud.example.com --chart infra/charts/bud \
      --values bud=infra/values/bud/values.prod.yaml

  # CI gate
  budctl check --answers readiness.yaml --output json --strict`

type checkParams struct {
	*globalFlags
	intakeFlags
	version         string
	retentionDays   int
	externalData    bool
	answersFile     string
	saveAnswers     string
	chartDir        string
	valuesFiles     multiFlag
	secretsFile     string
	only            multiFlag
	skip            multiFlag
	noProbe         bool
	keepProbes      bool
	probeNamespace  string
	probeImage      string
	gpuProbeImage   string
	egressFrom      string
	hfThroughput    bool
	argocdNamespace string
	format          string
	jsonOut         string
	save            bool
	strict          bool
	verbose         bool
	checkTimeout    time.Duration
	netTimeout      time.Duration
}

func newCheckCommand(g *globalFlags) *cobra.Command {
	p := &checkParams{globalFlags: g, version: defaults.Version}
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run the readiness checks (default)",
		Long: `Run the readiness checks against the cluster and the inputs an install will use.

check accepts every install flag, so an install command line can be checked
unchanged before it is run; the flags only install acts on are ignored.`,
		Example: checkExample,
		Args:    cobra.NoArgs,
		// An unreachable cluster is a finding (toolchain.kubeconfig), not a reason
		// to stop: the off-cluster checks still produce real answers.
		Annotations: needsCluster("optional"),
		PreRunE:     func(*cobra.Command, []string) error { return p.validate() },
		RunE: func(cmd *cobra.Command, _ []string) error {
			return exitCode(runCheck(cmd.Context(), p))
		},
	}
	p.register(cmd.Flags())
	return cmd
}

func (p *checkParams) register(fs *pflag.FlagSet) {
	p.intakeFlags.register(fs)
	fs.IntVar(&p.retentionDays, "retention-days", 0, "observability retention, sizes ClickHouse")
	fs.BoolVar(&p.externalData, "external-datastores", false, "data stores are managed externally, not installed in-cluster")
	fs.StringVar(&p.answersFile, "answers", "", "read intake answers from a file")
	fs.StringVar(&p.saveAnswers, "save-answers", "", "write the resolved answers to a file for re-runs")

	fs.StringVar(&p.chartDir, "chart", "", "path to the bud chart, enabling the config group")
	fs.Var(&p.valuesFiles, "values", "values file for one component, as <component>=<file>; repeatable (check validates bud's against --chart)")
	fs.StringVar(&p.secretsFile, "secrets", "", "SOPS-encrypted values file")

	fs.Var(&p.only, "only", "run only these groups or check ids, repeatable")
	fs.Var(&p.skip, "skip", "skip these groups or check ids, repeatable")

	fs.BoolVar(&p.noProbe, "no-probe", false, "read-only: create nothing in the cluster")
	fs.BoolVar(&p.keepProbes, "keep", false, "keep the probe namespace for debugging")
	fs.StringVar(&p.probeNamespace, "probe-namespace", "", "namespace for probe objects")
	fs.StringVar(&p.probeImage, "probe-image", "curlimages/curl:8.10.1", "image for network probes")
	fs.StringVar(&p.gpuProbeImage, "gpu-probe-image", "debian:trixie-slim", "image for the GPU probe (a slim glibc image, deliberately not a CUDA image)")
	fs.StringVar(&p.egressFrom, "egress-from", "cluster", "where egress is tested: cluster | workstation | both")
	fs.BoolVar(&p.hfThroughput, "hf-throughput", false, "sample Hugging Face download throughput")
	fs.StringVar(&p.argocdNamespace, "argocd-namespace", "argocd", "namespace ArgoCD is (or will be) installed in")

	fs.StringVarP(&p.format, "output", "o", "table", "table | json | junit")
	fs.StringVar(&p.jsonOut, "json", "", "also write the full report to this file")
	fs.BoolVar(&p.save, "save", false, "write the report as .json and .md (the same files the TUI 's' key writes)")
	fs.BoolVar(&p.strict, "strict", false, "exit non-zero on risks as well as blockers")
	fs.BoolVar(&p.verbose, "verbose", false, "show detail and evidence for passing checks too")
	fs.DurationVar(&p.checkTimeout, "check-timeout", 90*time.Second, "per-check timeout")
	fs.DurationVar(&p.netTimeout, "net-timeout", 15*time.Second, "per-network-probe timeout")

	acceptInstallFlags(fs)
}

func (p *checkParams) validate() error {
	switch p.egressFrom {
	case "cluster", "workstation", "both":
	default:
		return fmt.Errorf("--egress-from must be cluster, workstation or both")
	}
	return nil
}

func runCheck(ctx context.Context, cfg *checkParams) int {
	profile, err := intake.LoadProfile()
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl: embedded profile is invalid:", err)
		return 3
	}

	answers := intake.Defaults()
	if cfg.answersFile != "" {
		answers, err = intake.Load(cfg.answersFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "budctl: answers:", err)
			return 3
		}
	}
	applyAnswerFlags(&answers, cfg)

	if err := answers.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "budctl:", err)
		fmt.Fprintln(os.Stderr, "  pass --domain, or --answers <file>")
		return 3
	}

	c := check.NewCtx()
	c.Answers = answers
	c.Profile = profile
	c.Net = net.New(cfg.netTimeout)
	if answers.CABundle != "" {
		if err := c.Net.TrustCABundle(answers.CABundle); err != nil {
			fmt.Fprintln(os.Stderr, "budctl: --ca-bundle:", err)
			return 3
		}
	}
	c.OCI = oci.New(c.Net)
	c.Helm = helm.New()
	c.Opts = check.Options{
		Kubeconfig:      cfg.kubeconfig,
		KubeContext:     cfg.kubecontext,
		NoProbe:         cfg.noProbe,
		ProbeImage:      cfg.probeImage,
		GPUProbeImage:   cfg.gpuProbeImage,
		KeepProbes:      cfg.keepProbes,
		EgressFrom:      cfg.egressFrom,
		HFThroughput:    cfg.hfThroughput,
		CheckTimeout:    cfg.checkTimeout,
		NetTimeout:      cfg.netTimeout,
		ChartDir:        cfg.chartDir,
		ValuesFiles:     budValuesFiles(cfg.valuesFiles),
		SecretsFile:     cfg.secretsFile,
		ArgoCDNamespace: cfg.argocdNamespace,
		ArgoCDEnabled:   true,
		RegistryCreds:   map[string]oci.Credential{},
		BudctlVersion:   cfg.version,
	}
	if answers.RegistryUser != "" {
		c.Opts.RegistryCreds["registry.bud.studio"] = oci.Credential{
			Username: answers.RegistryUser, Password: answers.RegistryPass,
		}
	}

	// A cluster we cannot reach is reported by toolchain.kubeconfig as a
	// blocker; it must not abort the run, because the off-cluster checks
	// (registries, chart repos, domains, egress) still produce real answers.
	kube, kerr := clusterFrom(ctx)
	if kerr == nil {
		c.Kube = kube
		if !cfg.noProbe {
			c.Probes = probes.NewRunner(kube, cfg.probeNamespace, probeSuffix(cfg), cfg.keepProbes)
			defer c.Probes.Cleanup()
		}
	} else {
		c.Set("kube.error", kerr.Error())
	}

	sel := check.Selection{Only: cfg.only, Skip: cfg.skip}
	rep := check.Summarize(check.Run(ctx, c, sel, nil))
	rep.Stamp(c)

	switch cfg.format {
	case "json":
		_ = output.JSON(os.Stdout, rep)
	case "junit":
		_ = output.JUnit(os.Stdout, rep)
	default:
		fmt.Printf("budctl %s · cluster %s · domain %s\n", cfg.version, orUnknown(c.Platform.Version), answers.Domain)
		output.Table(os.Stdout, rep, output.Options{Color: useColor(), Verbose: cfg.verbose, Width: terminalWidth()})
	}

	if cfg.save {
		if paths, err := output.Save(rep, answers); err != nil {
			fmt.Fprintln(os.Stderr, "budctl: save failed:", err)
		} else {
			fmt.Fprintln(os.Stderr, "report saved to "+paths)
		}
	}

	if cfg.jsonOut != "" {
		f, err := os.Create(cfg.jsonOut)
		if err == nil {
			_ = output.JSON(f, rep)
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "report written to %s\n", cfg.jsonOut)
		}
	}

	if c.Probes != nil && c.Probes.Kept() {
		fmt.Fprintf(os.Stderr, "\nprobe namespace %s was KEPT (--keep); remove it with `budctl cleanup`\n", c.Probes.Namespace())
	}

	return verdictExitCode(rep.Verdict, cfg.strict)
}

// verdictExitCode is the documented CI contract: 0 READY, 1 NOT READY, and 2
// for risks only under --strict.
func verdictExitCode(v check.Verdict, strict bool) int {
	switch v {
	case check.NotReady:
		return 1
	case check.ReadyWithRisks:
		if strict {
			return 2
		}
	}
	return 0
}

func applyAnswerFlags(a *intake.Answers, c *checkParams) {
	if c.domain != "" {
		a.Domain = c.domain
	}
	if c.tls != "" {
		a.TLS = checkTLS(c.tls)
	}
	if c.caBundle != "" {
		a.CABundle = c.caBundle
	}
	if c.modelStorageGi > 0 {
		a.ModelStorageGi = c.modelStorageGi
	}
	if c.modelCount > 0 {
		a.ModelCount = c.modelCount
	}
	if c.deployments > 0 {
		a.Deployments = c.deployments
	}
	if c.retentionDays > 0 {
		a.RetentionDays = c.retentionDays
	}
	if c.gpu {
		a.GPU = true
	}
	a.OpenSandbox = true
	if c.externalData {
		a.InClusterData = false
	}
	// GitOps is the sole supported delivery path. Keep the persisted answer for
	// answers-file compatibility, but never revive the retired direct mode.
	a.UseArgoCD = true
	if c.repo != "" {
		a.ConfigRepo = c.repo
	}
	if c.registryUser != "" {
		a.RegistryUser = c.registryUser
	}
	if c.registryPass != "" {
		a.RegistryPass = c.registryPass
	}
	if env := os.Getenv("BUD_REGISTRY_USER"); env != "" && a.RegistryUser == "" {
		a.RegistryUser = env
		a.RegistryPass = os.Getenv("BUD_REGISTRY_PASSWORD")
	}
	if c.saveAnswers != "" {
		_ = a.Save(c.saveAnswers)
	}
}

// probeSuffix is derived from the context name rather than randomness, so a
// re-run reuses the same namespace instead of accumulating orphans.
func probeSuffix(cfg *checkParams) string {
	base := cfg.kubecontext
	if base == "" {
		base = "default"
	}
	var h uint32 = 2166136261
	for _, b := range []byte(base + cfg.chartDir) {
		h ^= uint32(b)
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}

func orUnknown(s string) string {
	if s == "" {
		return "unreachable"
	}
	return s
}

// useColor honours NO_COLOR and a non-terminal stdout, so piping to a file or
// a CI log never emits escapes.
// noColor is the global --no-color flag.
var noColor bool

func useColor() bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// terminalWidth is the width to wrap the report to: the terminal's, capped so
// a wide window still gets readable lines, or 0 (no wrapping) when stdout is
// a file or a pipe.
func terminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width <= 0 {
		return 0
	}
	return min(width-1, 110)
}

// checkTLS maps install's TLS modes onto what check asks of the network, so
// both commands take the same --tls. A certificate that is not issued through
// ACME is, to check, a provided one: nothing needs inbound :80.
func checkTLS(mode string) intake.TLSMethod {
	switch spec.TLSMode(mode) {
	case spec.TLSSelfSigned, spec.TLSInternalCA, spec.TLSExternal:
		return intake.TLSProvided
	}
	return intake.TLSMethod(mode)
}

// budValuesFiles takes --values as install does, <component>=<file>, and
// keeps the bud chart's: that is the chart the config group renders.
func budValuesFiles(entries []string) []string {
	var out []string
	for _, entry := range entries {
		if name, path, _ := strings.Cut(entry, "="); name == "bud" {
			out = append(out, path)
		}
	}
	return out
}

// acceptInstallFlags lets check take an install command line unchanged, so the
// same flags can be checked first and then installed. The flags only install
// acts on (--environment, --set, --yes …) are accepted, hidden and ignored.
func acceptInstallFlags(fs *pflag.FlagSet) {
	install := pflag.NewFlagSet("install", pflag.ContinueOnError)
	(&installParams{globalFlags: &globalFlags{}}).register(install)
	install.VisitAll(func(f *pflag.Flag) {
		if fs.Lookup(f.Name) == nil {
			f.Hidden = true
			fs.AddFlag(f)
		}
	})
}
