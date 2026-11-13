package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/install"
	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/install/spec"
	"github.com/BudEcosystem/budctl/k8s"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

const installExample = `  # preview: the plan and every file it would commit, with no side effects
  budctl install --dry-run --repo https://github.com/acme/bud-config.git \
      --environment production --domain bud.example.com --tls self-signed \
      --registry-user robot --registry-password token --admin-email admin@example.com

  # install: push the configuration and bootstrap ArgoCD
  budctl install --repo https://github.com/acme/bud-config.git --environment production \
      --domain bud.example.com --tls self-signed --registry-user robot \
      --registry-password token --admin-email admin@example.com --yes

  # resume or correct the last run: only the flags that change are needed
  budctl install --admin-email ops@example.com --yes

  # override any chart value, routed by component name
  budctl install --set keycloak.ingress.className=nginx --values bud=bud-overrides.yaml --yes

  # show the merged values Helm will receive
  budctl install --dry-run-values --component bud`

type installParams struct {
	*globalFlags
	intakeFlags
	environment     string
	pushBranch      string
	ingressClass    string
	storageClass    string
	adminEmail      string
	adminPassword   string
	cloudflareToken string
	issuerCACert    string
	issuerCAKey     string
	ageRecipients   multiFlag
	budStudio       bool
	skipComponents  []string
	studioModel     string
	recoveryKey     string
	dryRun          string
	dryRunValues    bool
	renderDir       string
	component       string
	showSecrets     bool
	yes             bool
	noPush          bool
	noBootstrap     bool
	noSync          bool
	statePath       string
	fresh           bool
	overrides       install.Overrides
	// isSet reports whether the operator gave a flag explicitly, so a resumed
	// session keeps its saved answer for everything else.
	isSet func(name string) bool
}

func newInstallCommand(g *globalFlags) *cobra.Command {
	p := &installParams{globalFlags: g}
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Prepare, push and bootstrap a GitOps installation",
		Long: `Generate the Bud configuration for an environment, commit it to a GitOps
repository, and bootstrap ArgoCD on the cluster to sync it.

Everything is set with flags; nothing is asked. A run that is missing a value
lists every flag it still needs. The choices of the last run, and the
credentials it generated, are kept in an encrypted resume state, so a later run
needs only the flags that change.

Pushing and installing onto the cluster are both irreversible, so they need
--yes. Without it, install prints the plan and stops.`,
		Example:     installExample,
		Args:        cobra.NoArgs,
		Annotations: needsCluster("optional"),
		PreRunE:     func(*cobra.Command, []string) error { return p.validate() },
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInstall(cmd.Context(), cmd.OutOrStdout(), p)
		},
	}
	p.register(cmd.Flags())
	return cmd
}

func (p *installParams) register(fs *pflag.FlagSet) {
	p.intakeFlags.register(fs)
	// GitOps installation. The readiness flags are deliberately reused for
	// domain, TLS, capacity, GPU, registry and kube context.
	fs.StringVar(&p.environment, "environment", "", "DNS-safe environment name (default: derived from the kube context, else production)")
	fs.StringVar(&p.pushBranch, "branch", "", "branch to create or update in the target repository (default: main)")
	fs.StringVar(&p.ingressClass, "ingress-class", "", "Kubernetes IngressClass (detected when possible; default: traefik)")
	fs.StringVar(&p.storageClass, "storage-class", "", "Kubernetes StorageClass (detected when possible)")
	fs.StringVar(&p.adminEmail, "admin-email", "", "initial Bud administrator email")
	fs.StringVar(&p.adminPassword, "admin-password", "", "initial administrator password (generated when omitted)")
	fs.StringVar(&p.cloudflareToken, "cloudflare-token", "", "Cloudflare API token for ACME DNS-01 (or CLOUDFLARE_API_TOKEN)")
	fs.StringVar(&p.issuerCACert, "issuer-ca-cert", "", "PEM certificate for an existing internal issuing CA")
	fs.StringVar(&p.issuerCAKey, "issuer-ca-key", "", "PEM private key for an existing internal issuing CA")
	fs.Var(&p.ageRecipients, "age-recipient", "additional age recipient, repeatable")
	fs.BoolVar(&p.budStudio, "bud-studio", false, "install the optional Bud Studio add-on")
	fs.StringArrayVar(&p.skipComponents, "skip-component", nil, "leave a component out of the installation, for a staged or partial install; repeatable")
	fs.StringVar(&p.studioModel, "studio-model", "", "model used by Bud Studio")
	fs.StringVar(&p.recoveryKey, "recovery-key", "", "path outside Git for the generated SOPS age identity")
	fs.StringVar(&p.statePath, "state", "", "encrypted installer resume-state path")
	fs.BoolVar(&p.fresh, "fresh", false, "ignore the previous installer state and start with defaults")

	fs.StringVar(&p.dryRun, "dry-run", "", "show what would happen and change nothing: plan (the summary and every file), manifests (the ApplicationSet and root Application) or render (every chart templated with its final values, like helm template)")
	fs.StringVar(&p.renderDir, "render-dir", "", "with --dry-run=render, write one <component>.yaml per component here instead of to stdout")
	fs.Lookup("dry-run").NoOptDefVal = "plan"
	fs.BoolVar(&p.dryRunValues, "dry-run-values", false, "print the merged values each component's chart receives, and change nothing")
	fs.StringVar(&p.component, "component", "", "with --dry-run-values or --dry-run=render, only this component")
	fs.BoolVar(&p.showSecrets, "show-secrets", false, "with --dry-run-values, also print the values that are committed encrypted")
	fs.BoolVar(&p.yes, "yes", false, "accept both the Git push and the cluster installation")
	fs.BoolVar(&p.noPush, "no-push", false, "create a local committed workspace without pushing (requires --no-bootstrap)")
	fs.BoolVar(&p.noBootstrap, "no-bootstrap", false, "do not install ArgoCD or apply its root Application")
	fs.BoolVar(&p.noSync, "no-sync", false, "bootstrap ArgoCD and the ApplicationSet but leave child Applications unsynced")

	o := &p.overrides
	fs.StringArrayVar(&o.ValueFiles, "values", nil, "values file for one component, as <component>=<file>; repeatable (check validates bud's against --chart)")
	fs.StringArrayVar(&o.Values, "set", nil, "set a value, as <component>.<key>=<value>; repeatable")
	fs.StringArrayVar(&o.StringValues, "set-string", nil, "like --set, but the value is always a string")
	fs.StringArrayVar(&o.FileValues, "set-file", nil, "like --set, but the value is read from a file")
	fs.StringArrayVar(&o.JSONValues, "set-json", nil, "like --set, but the value is JSON")
	fs.StringArrayVar(&o.SecretValues, "set-secret", nil, "like --set, but the value is committed SOPS-encrypted")
	p.isSet = fs.Changed
}

func (p *installParams) validate() error {
	switch p.dryRun {
	case "", "plan", "manifests", "render":
	default:
		return fmt.Errorf("--dry-run must be plan, manifests or render")
	}
	if p.component != "" && !p.dryRunValues && p.dryRun != "render" {
		return fmt.Errorf("--component only applies to --dry-run-values and --dry-run=render")
	}
	if p.renderDir != "" && p.dryRun != "render" {
		return fmt.Errorf("--render-dir only applies to --dry-run=render")
	}
	if p.showSecrets && !p.dryRunValues {
		return fmt.Errorf("--show-secrets only applies to --dry-run-values")
	}
	return nil
}

func (p *installParams) dryRunning() bool { return p.dryRun != "" || p.dryRunValues }

func runInstall(ctx context.Context, out io.Writer, p *installParams) error {
	values, secrets, err := p.overrides.Resolve()
	if err != nil {
		return err
	}
	client, clientErr := clusterFrom(ctx)
	inst := &install.Installer{
		Params: install.Parameters{
			StatePath: p.statePath,
			Fresh:     p.fresh,
			Apply: func(s *spec.Spec) {
				applyInstallFlags(s, p)
				if !p.overrides.Empty() {
					s.Values, s.SecretValues = values, secrets
				}
			},
			RecoveryKeyPath: p.recoveryKey,
			DryRun:          p.dryRunning(),
			NoPush:          p.noPush,
			NoBootstrap:     p.noBootstrap,
			NoSync:          p.noSync,
			Yes:             p.yes,
		},
		Client:    client,
		ClientErr: clientErr,
		Observer:  installPrinter{out},
	}

	plan, err := inst.Plan(ctx)
	if err != nil {
		var missing *install.MissingError
		if errors.As(err, &missing) {
			return missingFlagsError(missing, p.dryRunning())
		}
		return fmt.Errorf("install: %w", err)
	}
	switch {
	case p.dryRunValues:
		return printValues(out, plan.Bundle, p.component, p.showSecrets)
	case p.dryRun == "manifests":
		fmt.Fprintf(out, "%s---\n%s", plan.Bundle.ApplicationSet, plan.Bundle.RootApplication)
		return nil
	case p.dryRun == "render":
		return renderCharts(ctx, out, plan, client, p)
	}
	printInstallPlan(out, plan, p)
	if p.dryRun != "" {
		return nil
	}

	result, err := inst.Apply(ctx, plan)
	if errors.Is(err, install.ErrConfirmationRequired) {
		return errors.New("install: nothing was changed. Pushing to the repository and installing onto the cluster need --yes (or preview with --dry-run)")
	}
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	printInstallResult(out, plan, result, p)
	return nil
}

// installFlags names the flag that sets each required Spec field.
var installFlags = map[string]string{
	"targetRepo":       "--repo",
	"repoSSHKeyPath":   "--repo-key",
	"domain":           "--domain",
	"storageClass":     "--storage-class",
	"registryUser":     "--registry-user (or BUD_REGISTRY_USER)",
	"registryPassword": "--registry-password (or BUD_REGISTRY_PASSWORD)",
	"adminEmail":       "--admin-email",
	"cloudflareToken":  "--cloudflare-token (or CLOUDFLARE_API_TOKEN)",
	"issuerCACertPath": "--issuer-ca-cert",
	"issuerCAKeyPath":  "--issuer-ca-key",
}

func missingFlagsError(m *install.MissingError, dryRun bool) error {
	var b strings.Builder
	b.WriteString("install: missing required flags:")
	for _, f := range m.Fields {
		flag := installFlags[f.Name]
		if flag == "" {
			flag = f.Name
		}
		fmt.Fprintf(&b, "\n  %-48s %s", flag, f.Reason)
	}
	if !dryRun {
		b.WriteString("\n  everything else from this run was saved; the next run needs only these")
	}
	return errors.New(b.String())
}

type installPrinter struct{ out io.Writer }

func (p installPrinter) PhaseStarted(ph install.Phase) {
	switch ph {
	case install.PhasePrepare:
		fmt.Fprintln(p.out, "\nCommitting the configuration")
	case install.PhasePush:
		fmt.Fprintln(p.out, "Pushing")
	case install.PhaseBootstrap:
		fmt.Fprintln(p.out, "Bootstrapping ArgoCD")
	case install.PhaseExportCA:
		fmt.Fprintln(p.out, "Exporting the self-signed root CA")
	}
}

func (p installPrinter) Step(_ install.Phase, message string) { fmt.Fprintln(p.out, "  →", message) }

func (installPrinter) PhaseFinished(install.Phase, error) {}

func printInstallPlan(out io.Writer, plan *install.Plan, p *installParams) {
	s := plan.Spec
	fmt.Fprintln(out, "Bud GitOps installation plan")
	fmt.Fprintln(out, "  Environment:", s.Environment)
	fmt.Fprintln(out, "  Target:", spec.RepositoryURL(s.TargetRepo), "branch", s.PushBranch)
	fmt.Fprintln(out, "  Domain:", s.Domain)
	fmt.Fprintln(out, "  TLS:", s.TLS)
	fmt.Fprintln(out, "  Ingress / storage:", s.IngressClass, "/", s.StorageClass)
	fmt.Fprintf(out, "  Capacity: %d GiB models, %d expected models, %d concurrent deployments\n", s.ModelStorageGi, s.Models, s.Deployments)
	fmt.Fprintln(out, "  Bud Studio:", yesNo(s.BudStudio))
	fmt.Fprintln(out, "  Components:")
	for _, c := range plan.Bundle.Components {
		src := c.Component.Source
		version := src.Chart + " " + src.Version
		if src.GitPath != "" {
			version = src.GitPath + " @ " + shortRevision(src.GitRevision)
		}
		overridden := ""
		if s.Values[c.Component.Name] != nil || s.SecretValues[c.Component.Name] != nil {
			overridden = "  (overridden)"
		}
		fmt.Fprintf(out, "    %-13s %-20s %s%s\n", c.Component.Name, c.Component.Namespace, version, overridden)
	}
	fmt.Fprintln(out, "  Resume state:", plan.StatePath)
	if plan.Resumed {
		fmt.Fprintln(out, "  Resume: previous selections and generated credentials loaded")
	}
	sensitive := 0
	for _, a := range plan.Bundle.Artifacts {
		if a.Sensitive {
			sensitive++
		}
	}
	fmt.Fprintf(out, "  Generated files: %d (%d SOPS-encrypted)\n", len(plan.Bundle.Artifacts), sensitive)
	if p.dryRun != "" {
		for _, a := range plan.Bundle.Artifacts {
			mark := ""
			if a.Sensitive {
				mark = "  (encrypted)"
			}
			fmt.Fprintf(out, "    %s%s\n", a.Path, mark)
		}
	}
	switch {
	case p.dryRun != "":
		fmt.Fprintln(out, "  Actions: none (--dry-run)")
	case p.noPush:
		fmt.Fprintln(out, "  Actions: clone, generate and commit locally")
	case p.noBootstrap:
		fmt.Fprintln(out, "  Actions: clone, generate, commit and push")
	case p.noSync:
		fmt.Fprintln(out, "  Actions: clone, generate, commit, push, install ArgoCD and create the root Application")
	default:
		fmt.Fprintln(out, "  Actions: clone, generate, commit, push, bootstrap ArgoCD and sync the platform")
	}
}

func printValues(out io.Writer, bundle install.Bundle, only string, showSecrets bool) error {
	found := false
	for _, c := range bundle.Components {
		if only != "" && c.Component.Name != only {
			continue
		}
		found = true
		fmt.Fprintf(out, "# %s (namespace %s)\n", c.Component.Name, c.Component.Namespace)
		if len(c.Component.ChartValueFiles) > 0 {
			fmt.Fprintf(out, "# after the chart's own %s\n", strings.Join(c.Component.ChartValueFiles, ", "))
		}
		merged := c.Values
		if c.Secrets != nil {
			if showSecrets {
				merged = components.Merge(c.Values, c.Secrets)
			} else {
				fmt.Fprintf(out, "# %d encrypted keys hidden (--show-secrets prints them)\n", countLeaves(c.Secrets))
			}
		}
		body, err := yaml.Marshal(merged)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s---\n", body)
	}
	if !found {
		var names []string
		for _, c := range bundle.Components {
			names = append(names, c.Component.Name)
		}
		sort.Strings(names)
		return fmt.Errorf("--component %q is not part of this installation (components: %s)", only, strings.Join(names, ", "))
	}
	return nil
}

func printInstallResult(out io.Writer, plan *install.Plan, r *install.Result, p *installParams) {
	s := plan.Spec
	fmt.Fprintln(out, "\nCommit:")
	fmt.Fprintln(out, indent(r.DiffStat, "  "))
	if r.Deferred {
		fmt.Fprintln(out, "\nRepository pushed; the cluster installation was deferred.")
		fmt.Fprintln(out, "  Resume state:", r.StatePath)
		fmt.Fprintln(out, "  Recovery key:", r.RecoveryKeyPath)
		return
	}
	fmt.Fprintf(out, "\nInstallation prepared successfully.\n  Git: %s @ %s\n  Recovery key: %s\n", spec.RepositoryURL(s.TargetRepo), s.PushBranch, r.RecoveryKeyPath)
	fmt.Fprintln(out, "  Resume state:", r.StatePath)
	if r.CAPath != "" {
		fmt.Fprintln(out, "  Root CA certificate:", r.CAPath)
		fmt.Fprintln(out, "  Import this certificate into clients that access Bud endpoints.")
	}
	if r.LocalRepository != "" {
		fmt.Fprintln(out, "  Local repository:", r.LocalRepository)
	}
	if s.AdminPassword == "" {
		fmt.Fprintln(out, "  Initial admin password:", plan.Bundle.AdminPassword)
		fmt.Fprintln(out, "  Store this password now; budctl will not write a plaintext copy.")
	}
	if !p.noBootstrap {
		if p.noSync {
			fmt.Fprintln(out, "  ArgoCD root Application created; child Applications await an explicit sync.")
		} else {
			fmt.Fprintln(out, "  ArgoCD synchronized the platform Applications in dependency order.")
			fmt.Fprintln(out, "  Watch them with: budctl status --environment", s.Environment)
		}
	}
}

func applyInstallFlags(s *spec.Spec, cfg *installParams) {
	if cfg.isSet("repo") {
		s.TargetRepo = cfg.repo
	}
	if cfg.isSet("environment") {
		s.Environment = cfg.environment
	}
	if cfg.isSet("branch") {
		s.PushBranch = cfg.pushBranch
	}
	if cfg.isSet("repo-key") {
		s.RepoSSHKeyPath, s.RepoSSHPrivateKey = cfg.repoKey, ""
	}
	if cfg.isSet("domain") {
		s.Domain = cfg.domain
	}
	if cfg.isSet("ingress-class") {
		s.IngressClass = cfg.ingressClass
	}
	if cfg.isSet("storage-class") {
		s.StorageClass = cfg.storageClass
	}
	if cfg.isSet("model-storage-gi") {
		s.ModelStorageGi = cfg.modelStorageGi
	}
	if cfg.isSet("models") {
		s.Models = cfg.modelCount
	}
	if cfg.isSet("deployments") {
		s.Deployments = cfg.deployments
	}
	if cfg.isSet("gpu") {
		s.GPU = cfg.gpu
	}
	if cfg.isSet("registry-user") {
		s.RegistryUser = cfg.registryUser
	}
	if cfg.isSet("registry-password") {
		s.RegistryPassword = cfg.registryPass
	}
	if value := os.Getenv("BUD_REGISTRY_USER"); value != "" {
		s.RegistryUser = value
	}
	if value := os.Getenv("BUD_REGISTRY_PASSWORD"); value != "" {
		s.RegistryPassword = value
	}
	if cfg.isSet("admin-email") {
		s.AdminEmail = cfg.adminEmail
	}
	if cfg.isSet("admin-password") {
		s.AdminPassword = cfg.adminPassword
	}
	if cfg.isSet("cloudflare-token") {
		s.CloudflareToken = cfg.cloudflareToken
	}
	if cfg.isSet("ca-bundle") {
		s.CABundlePath, s.TrustedCAPEM = cfg.caBundle, ""
	}
	if cfg.isSet("issuer-ca-cert") {
		s.IssuerCACertPath, s.IssuerCACertPEM = cfg.issuerCACert, ""
	}
	if cfg.isSet("issuer-ca-key") {
		s.IssuerCAKeyPath, s.IssuerCAKeyPEM = cfg.issuerCAKey, ""
	}
	if value := os.Getenv("CLOUDFLARE_API_TOKEN"); value != "" {
		s.CloudflareToken = value
	}
	if cfg.isSet("age-recipient") {
		s.AgeRecipients = append([]string(nil), cfg.ageRecipients...)
	}
	if cfg.isSet("bud-studio") {
		s.BudStudio = cfg.budStudio
	}
	if cfg.isSet("skip-component") {
		s.SkipComponents = append([]string(nil), cfg.skipComponents...)
	}
	if cfg.isSet("studio-model") {
		s.StudioModel = cfg.studioModel
	}
	if cfg.isSet("tls") {
		s.TLS = spec.TLSMode(cfg.tls)
	}
}

func countLeaves(m map[string]any) int {
	n := 0
	for _, v := range m {
		if sub, ok := v.(map[string]any); ok {
			n += countLeaves(sub)
		} else {
			n++
		}
	}
	return n
}

func shortRevision(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func indent(value, prefix string) string {
	return prefix + strings.ReplaceAll(value, "\n", "\n"+prefix)
}

func yesNo(value bool) string {
	if value {
		return "enabled"
	}
	return "not selected"
}

func renderCharts(ctx context.Context, out io.Writer, plan *install.Plan, client *k8s.Client, p *installParams) error {
	bundle := plan.Bundle
	if p.component != "" {
		var only []install.RenderedComponent
		for _, c := range bundle.Components {
			if c.Component.Name == p.component {
				only = append(only, c)
			}
		}
		if only == nil {
			return printValues(io.Discard, bundle, p.component, false)
		}
		bundle.Components = only
	}
	kubeVersion := ""
	if client != nil {
		if v, err := client.ServerVersion(); err == nil {
			kubeVersion = v.GitVersion
		}
	}
	progress := func(s string) { fmt.Fprintln(os.Stderr, "  →", s) }
	results := install.RenderCharts(ctx, plan.Spec, bundle, kubeVersion, progress)
	if p.renderDir != "" {
		if err := os.MkdirAll(p.renderDir, 0o755); err != nil {
			return err
		}
	}
	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
			continue
		}
		if p.renderDir != "" {
			if err := os.WriteFile(filepath.Join(p.renderDir, r.Component.Name+".yaml"), []byte(r.Manifest), 0o644); err != nil {
				return err
			}
			continue
		}
		fmt.Fprintf(out, "---\n# budctl: component %s, namespace %s\n%s", r.Component.Name, r.Component.Namespace, r.Manifest)
	}
	fmt.Fprintln(os.Stderr, "\nRendered:")
	for _, r := range results {
		fmt.Fprintln(os.Stderr, " ", r.Summary())
	}
	if p.renderDir != "" {
		fmt.Fprintln(os.Stderr, "Manifests written to", p.renderDir)
	}
	if failed > 0 {
		return fmt.Errorf("install: %d of %d components did not render", failed, len(results))
	}
	return nil
}
