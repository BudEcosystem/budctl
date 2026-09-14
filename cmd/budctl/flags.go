package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/internal/intake"
)

type config struct {
	command         string
	caBundle        string
	kubeconfig      string
	kubecontext     string
	domain          string
	tls             string
	modelStorageGi  int
	modelCount      int
	deployments     int
	gpu             bool
	retentionDays   int
	externalData    bool
	noArgoCD        bool
	configRepo      string
	registryUser    string
	registryPass    string
	openSandbox     bool
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
	strict          bool
	verbose         bool
	noColor         bool
	checkTimeout    time.Duration
	netTimeout      time.Duration
	showHelp        bool
	showVersion     bool
	noTUI           bool
	noPrompt        bool
	save            bool
	theme           string
	tuiForced       bool
}

// useTUI: interactive by default when there is a terminal and the operator
// asked for neither a machine format nor a file. Anything scripted must get the
// plain renderer without having to know a flag exists.
func (c config) useTUI(isTerminal bool) bool {
	if c.noTUI || c.format != "table" {
		return false
	}
	if c.tuiForced {
		return true
	}
	return isTerminal
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

func parseFlags(argv []string) (config, error) {
	var c config
	c.command = "check"
	if len(argv) > 0 && !strings.HasPrefix(argv[0], "-") {
		c.command = argv[0]
		argv = argv[1:]
	}
	switch c.command {
	case "check", "cleanup", "version", "help":
	default:
		return c, fmt.Errorf("unknown command %q (want: check, cleanup, version)", c.command)
	}
	if c.command == "version" {
		c.showVersion = true
		return c, nil
	}
	if c.command == "help" {
		c.showHelp = true
		return c, nil
	}

	fs := flag.NewFlagSet("budctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = usage

	fs.StringVar(&c.caBundle, "ca-bundle", "", "PEM file of extra roots to trust when verifying served certificates (an internal CA)")
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: the usual discovery)")
	fs.StringVar(&c.kubecontext, "context", "", "kube context to use")

	// Intake — FRD-020 §7. These are asked, not guessed.
	fs.StringVar(&c.domain, "domain", "", "root domain the stack will publish under (required)")
	fs.StringVar(&c.tls, "tls", "", "how TLS is obtained: acme-http01 | acme-dns01 | provided | none")
	fs.IntVar(&c.modelStorageGi, "model-storage-gi", 0, "GiB of model weight storage to provision for")
	fs.IntVar(&c.modelCount, "models", 0, "roughly how many models will be held")
	fs.IntVar(&c.deployments, "deployments", 0, "expected concurrent model deployments")
	fs.BoolVar(&c.gpu, "gpu", false, "GPU deployments are expected")
	fs.IntVar(&c.retentionDays, "retention-days", 0, "observability retention, sizes ClickHouse")
	fs.BoolVar(&c.externalData, "external-datastores", false, "data stores are managed externally, not installed in-cluster")
	fs.BoolVar(&c.noArgoCD, "no-argocd", false, "installing with Helm directly rather than ArgoCD")
	fs.StringVar(&c.configRepo, "config-repo", "", "the config repo ArgoCD will read (https:// or ssh://)")
	fs.StringVar(&c.registryUser, "registry-user", "", "registry.bud.studio robot account (optional at this stage)")
	fs.StringVar(&c.registryPass, "registry-password", "", "registry.bud.studio token (optional at this stage)")
	fs.BoolVar(&c.openSandbox, "opensandbox", false, "the OpenSandbox code interpreter will be enabled")
	fs.StringVar(&c.answersFile, "answers", "", "read intake answers from a file")
	fs.StringVar(&c.saveAnswers, "save-answers", "", "write the resolved answers to a file for re-runs")

	fs.StringVar(&c.chartDir, "chart", "", "path to the bud chart, enabling the config group")
	fs.Var(&c.valuesFiles, "values", "values file, repeatable")
	fs.StringVar(&c.secretsFile, "secrets", "", "SOPS-encrypted values file")

	fs.Var(&c.only, "only", "run only these groups or check ids, repeatable")
	fs.Var(&c.skip, "skip", "skip these groups or check ids, repeatable")

	fs.BoolVar(&c.noProbe, "no-probe", false, "read-only: create nothing in the cluster")
	fs.BoolVar(&c.keepProbes, "keep", false, "keep the probe namespace for debugging")
	fs.StringVar(&c.probeNamespace, "probe-namespace", "", "namespace for probe objects")
	fs.StringVar(&c.probeImage, "probe-image", "curlimages/curl:8.10.1", "image for network probes")
	fs.StringVar(&c.gpuProbeImage, "gpu-probe-image", "debian:trixie-slim", "image for the GPU probe (a slim glibc image, deliberately not a CUDA image)")
	fs.StringVar(&c.egressFrom, "egress-from", "cluster", "where egress is tested: cluster | workstation | both")
	fs.BoolVar(&c.hfThroughput, "hf-throughput", false, "sample Hugging Face download throughput")
	fs.StringVar(&c.argocdNamespace, "argocd-namespace", "argocd", "namespace ArgoCD is (or will be) installed in")

	fs.StringVar(&c.format, "output", "table", "table | json | junit")
	fs.StringVar(&c.jsonOut, "json", "", "also write the full report to this file")
	fs.BoolVar(&c.save, "save", false, "write the report as .json and .md (the same files the TUI 's' key writes)")
	fs.BoolVar(&c.strict, "strict", false, "exit non-zero on risks as well as blockers")
	fs.BoolVar(&c.verbose, "verbose", false, "show detail and evidence for passing checks too")
	fs.BoolVar(&c.noColor, "no-color", false, "disable colour")
	fs.DurationVar(&c.checkTimeout, "check-timeout", 90*time.Second, "per-check timeout")
	fs.DurationVar(&c.netTimeout, "net-timeout", 15*time.Second, "per-network-probe timeout")
	fs.BoolVar(&c.showHelp, "help", false, "show usage")
	fs.BoolVar(&c.showVersion, "version", false, "show version")
	fs.BoolVar(&c.noTUI, "no-tui", false, "plain output even on a terminal")
	fs.BoolVar(&c.noPrompt, "no-prompt", false, "skip the guided form when every answer is already supplied")
	fs.StringVar(&c.theme, "theme", "auto", "interactive colours: auto (follow the terminal background) | dark | light")
	fs.BoolVar(&c.tuiForced, "tui", false, "force the interactive view")

	if err := fs.Parse(argv); err != nil {
		return c, err
	}
	switch c.theme {
	case "auto", "dark", "light":
	default:
		return c, fmt.Errorf("--theme must be auto, dark or light")
	}
	switch c.egressFrom {
	case "cluster", "workstation", "both":
	default:
		return c, fmt.Errorf("--egress-from must be cluster, workstation or both")
	}
	return c, nil
}

func applyAnswerFlags(a *intake.Answers, c config) {
	if c.domain != "" {
		a.Domain = c.domain
	}
	if c.tls != "" {
		a.TLS = intake.TLSMethod(c.tls)
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
	if c.openSandbox {
		a.OpenSandbox = true
	}
	if c.externalData {
		a.InClusterData = false
	}
	if c.noArgoCD {
		a.UseArgoCD = false
	}
	if c.configRepo != "" {
		a.ConfigRepo = c.configRepo
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

func usage() {
	fmt.Fprint(os.Stderr, `budctl — is this cluster fit to host Bud?

USAGE
  budctl check   [flags]     run the readiness checks (default)
  budctl cleanup [flags]     remove probe namespaces left by an interrupted run
  budctl version

On a terminal budctl opens a GUIDED FORM and asks for everything below, so you
do not need any of these flags — they only pre-fill the form. Readiness is
meaningless against an unstated target: "is 200 GiB enough?" has no answer until
someone says how many models they intend to hold.

Use the flags for scripted runs, where there is no terminal to ask on.

  --domain example.com          root domain the stack will publish under
  --model-storage-gi 600        GiB of model weights to provision for
  --models 12                   roughly how many models
  --deployments 4               expected concurrent deployments
  --gpu                         GPU deployments are expected
  --tls acme-http01             how TLS is obtained (decides whether inbound :80 blocks)
  --ca-bundle root.pem          trust these roots too, when an internal CA issued your certificate
  --external-datastores         data stores are managed externally
  --config-repo ssh://...       the repo ArgoCD will read

EXAMPLES
  # guided: asks for the domain, storage, GPU, TLS and the rest
  budctl check

  # pre-fill the form, then confirm it
  budctl check --domain bud.example.com --model-storage-gi 600 --models 12

  # read-only, nothing created in the cluster
  budctl check --domain bud.example.com --no-probe

  # also validate the values you will hand to ArgoCD
  budctl check --domain bud.example.com --chart infra/charts/bud \
      --values infra/values/bud/values.prod.yaml

  # CI gate
  budctl check --answers readiness.yaml --output json --strict

EXIT CODES
  0 READY    1 NOT READY    2 risks under --strict    3 budctl could not run

FLAGS
`)
	fmt.Fprintln(os.Stderr, "  (see --help output above; all flags accept -flag=value form)")
}
