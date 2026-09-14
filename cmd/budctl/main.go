// budctl verifies that a Kubernetes or OpenShift cluster can host the Bud
// platform, before anything is installed into it. FRD-020.
//
// It ships as a static binary carrying client-go, Helm, SOPS and age as
// libraries, so no kubectl, helm, sops or age binary is required on the host.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	_ "github.com/BudEcosystem/budctl/internal/checks"
	"github.com/BudEcosystem/budctl/internal/engine"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/output"
	"github.com/BudEcosystem/budctl/internal/probes"
	"github.com/BudEcosystem/budctl/internal/tui"
)

// Version and CatalogVersion are stamped at build time. A report records both,
// so a result produced by a stale binary is identifiable after the fact.
var (
	Version = "dev"
	Commit  = "none"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl:", err)
		return 3
	}
	if cfg.showHelp {
		usage()
		return 0
	}
	if cfg.showVersion {
		p, _ := intake.LoadProfile()
		fmt.Printf("budctl %s (%s)\ncheck catalogue %s\n", Version, Commit, p.CatalogVersion)
		return 0
	}

	// Writing to a closed stdout — `budctl check | head`, or quitting `less`
	// early — kills a Go program outright on SIGPIPE, and a deferred cleanup
	// never runs, so a probe namespace is left behind in the operator's
	// cluster. Registering a handler turns that into an ignored write error,
	// which is recoverable; the signal is deliberately never read.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	if cfg.command == "cleanup" {
		return cleanup(ctx, cfg)
	}

	// A missing domain is only an error when nothing can ask for it. On a
	// terminal the guided form collects it — the operator should not have to
	// read --help to discover which questions exist.
	interactive := cfg.useTUI(output.UseColor())
	if !interactive {
		if err := answers.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "budctl:", err)
			fmt.Fprintln(os.Stderr, "  pass --domain, or --answers <file>, or run on a terminal for the guided form")
			return 3
		}
	}

	c := engine.NewCtx()
	c.Answers = answers
	c.Profile = profile
	c.Net = adapters.NewNet(cfg.netTimeout)
	if answers.CABundle != "" {
		if err := c.Net.TrustCABundle(answers.CABundle); err != nil {
			fmt.Fprintln(os.Stderr, "budctl: --ca-bundle:", err)
			return 3
		}
	}
	c.OCI = adapters.NewOCI(c.Net)
	c.Helm = adapters.NewHelm()
	c.Opts = engine.Options{
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
		ValuesFiles:     cfg.valuesFiles,
		SecretsFile:     cfg.secretsFile,
		ArgoCDNamespace: cfg.argocdNamespace,
		ArgoCDEnabled:   !cfg.noArgoCD,
		RegistryCreds:   map[string]adapters.Credential{},
	}
	if answers.RegistryUser != "" {
		c.Opts.RegistryCreds["registry.bud.studio"] = adapters.Credential{
			Username: answers.RegistryUser, Password: answers.RegistryPass,
		}
	}

	// A cluster we cannot reach is reported by toolchain.kubeconfig as a
	// blocker; it must not abort the run, because the off-cluster checks
	// (registries, chart repos, domains, egress) still produce real answers.
	kube, kerr := adapters.NewKube(cfg.kubeconfig, cfg.kubecontext)
	if kerr == nil {
		c.Kube = kube
		if !cfg.noProbe {
			c.Probes = probes.NewRunner(kube, cfg.probeNamespace, probeSuffix(cfg), cfg.keepProbes)
			defer c.Probes.Cleanup()
		}
	} else {
		c.Set("kube.error", kerr.Error())
	}

	sel := engine.Selection{Only: cfg.only, Skip: cfg.skip}

	// The TUI is the primary surface, but only when there is a terminal to draw
	// on and a human to read it: piping to a file or running in CI must produce
	// the same results as plain text, from the same engine.
	var rep engine.Report
	if interactive {
		// The form is skipped only when the operator has already answered
		// everything AND asked not to be prompted; otherwise flags act as
		// defaults for the form rather than as a substitute for it.
		skipSetup := cfg.noPrompt && answers.Validate() == nil
		appsDomain := detectAppsDomain(ctx, c)
		// Resolve the palette before Bubble Tea owns the terminal: background
		// detection queries the terminal, which it cannot do once the program runs.
		tui.ApplyTheme(tui.ThemeMode(cfg.theme))
		if cfg.noColor {
			tui.DisableColor()
		}
		var aborted bool
		var terr error
		rep, aborted, terr = tui.Run(ctx, c, sel, skipSetup, appsDomain)
		if terr != nil {
			fmt.Fprintln(os.Stderr, "budctl: interactive mode failed:", terr)
			return 3
		}
		if aborted {
			fmt.Fprintln(os.Stderr, "budctl: cancelled before any check ran")
			return 3
		}
		answers = c.Answers
		if cfg.saveAnswers != "" {
			_ = answers.Save(cfg.saveAnswers)
		}
	} else {
		rep = engine.Summarize(engine.Run(ctx, c, sel, nil))
	}
	rep.Platform = string(c.Platform.Distribution)
	rep.Meta = map[string]string{
		"budctlVersion":  Version,
		"catalogVersion": profile.CatalogVersion,
		"serverVersion":  c.Platform.Version,
		"domain":         answers.Domain,
	}

	switch cfg.format {
	case "json":
		_ = output.JSON(os.Stdout, rep)
	case "junit":
		_ = output.JUnit(os.Stdout, rep)
	default:
		if cfg.useTUI(output.UseColor()) {
			// The user has just read the results interactively; reprint only the
			// verdict and what blocks, so the shell keeps something durable.
			printTailSummary(rep)
			break
		}
		fmt.Printf("budctl %s · cluster %s · domain %s\n", Version, orUnknown(c.Platform.Version), answers.Domain)
		output.Table(os.Stdout, rep, output.Options{Color: output.UseColor() && !cfg.noColor, Verbose: cfg.verbose})
	}

	if cfg.save && !interactive {
		if paths, err := tui.SaveReport(rep, answers); err != nil {
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

	switch rep.Verdict {
	case engine.NotReady:
		return 1
	case engine.ReadyWithRisks:
		if cfg.strict {
			return 2
		}
	}
	return 0
}

// detectAppsDomain reads OpenShift's own wildcard so the form can offer it as
// the default. A cluster that already owns *.apps.<cluster>.<base> usually has
// nothing else the operator would rather type.
func detectAppsDomain(ctx context.Context, c *engine.Ctx) string {
	if c.Kube == nil {
		return ""
	}
	if !c.Kube.HasAPIVersion(ctx, "route.openshift.io/v1") {
		return ""
	}
	if ing := c.Kube.Get(ctx, "ingresses.config.openshift.io", "", "cluster"); ing != nil {
		return ing.DigString("spec", "domain")
	}
	return ""
}

func printTailSummary(rep engine.Report) {
	fmt.Printf("\nVerdict: %s\n", rep.Verdict)
	for _, r := range rep.Results {
		if r.IsBlocker() {
			fmt.Printf("  • [%s] %s\n", r.Group, r.Summary)
			if r.Remedy != "" {
				fmt.Printf("      → %s\n", r.Remedy)
			}
		}
	}
}

func cleanup(ctx context.Context, cfg config) int {
	kube, err := adapters.NewKube(cfg.kubeconfig, cfg.kubecontext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl: cannot reach the cluster:", err)
		return 3
	}
	removed := 0
	for _, ns := range kube.List(ctx, "namespaces", "") {
		name := ns.Name()
		if ns.Labels()[probes.ManagedByKey] == probes.ManagedByValue || strings.HasPrefix(name, probes.NamePrefix) {
			r := probes.NewRunner(kube, name, "", false)
			_ = r.Ensure(ctx)
			r.Cleanup()
			fmt.Printf("removed probe namespace %s\n", name)
			removed++
		}
	}
	if removed == 0 {
		fmt.Println("nothing to clean up")
	}
	return 0
}

// probeSuffix is derived from the context name rather than randomness, so a
// re-run reuses the same namespace instead of accumulating orphans.
func probeSuffix(cfg config) string {
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

var _ = time.Second
