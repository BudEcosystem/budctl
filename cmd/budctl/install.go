package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	installer "github.com/BudEcosystem/budctl/internal/install"
	"golang.org/x/term"
)

func runInstall(ctx context.Context, cfg config) int {
	statePath, err := installStatePath(cfg.statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl install:", err)
		return 3
	}
	state, resumed, err := installer.LoadState(statePath)
	if err != nil && !cfg.fresh {
		fmt.Fprintln(os.Stderr, "budctl install: load resume state:", err)
		fmt.Fprintln(os.Stderr, "  use --fresh to start over, or restore", installer.StateKeyPath(statePath))
		return 3
	}
	if cfg.fresh {
		state, resumed = installer.State{}, false
	}
	// An explicit different environment starts a new session. This prevents the
	// last environment's generated credentials from being reused accidentally.
	if resumed && cfg.isSet("environment") && cfg.environment != state.Spec.Environment {
		state, resumed = installer.State{}, false
	}

	spec := installer.Defaults()
	if resumed {
		spec = state.Spec
	}
	applyInstallFlags(&spec, cfg)
	upgradeCachedTemplateRef(&spec, resumed, cfg.isSet("template-ref"))
	priorSpec := state.Spec

	kube, kubeErr := adapters.NewKube(cfg.kubeconfig, cfg.kubecontext)
	if kubeErr == nil {
		installer.DetectDefaults(ctx, kube, &spec)
	}
	if spec.Environment == "" {
		spec.Environment = "production"
	}
	spec.Normalize()

	interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	if interactive && !cfg.noPrompt {
		if err := installer.Prompt(&spec); err != nil {
			fmt.Fprintln(os.Stderr, "budctl install:", err)
			return 3
		}
	}
	if err := spec.LoadTLSMaterial(); err != nil {
		fmt.Fprintln(os.Stderr, "budctl install:", err)
		return 3
	}
	if resumed && (spec.Environment != priorSpec.Environment || installer.RepositoryURL(spec.TargetRepo) != installer.RepositoryURL(priorSpec.TargetRepo)) {
		state, resumed = installer.State{}, false
	}
	if spec.TLS != installer.TLSSelfSigned {
		state.CAPath = ""
	}
	state.Spec = spec
	if !cfg.plan {
		if err := saveInstallState(statePath, &state, "selected"); err != nil {
			fmt.Fprintln(os.Stderr, "budctl install: save resume state:", err)
			return 3
		}
	}
	if err := spec.LoadRepositoryKey(); err != nil {
		fmt.Fprintln(os.Stderr, "budctl install:", err)
		return 3
	}
	state.Spec = spec
	if !cfg.plan {
		if err := saveInstallState(statePath, &state, "selected"); err != nil {
			fmt.Fprintln(os.Stderr, "budctl install: save resume state:", err)
			return 3
		}
	}
	if err := spec.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "budctl install:", err)
		if !interactive || cfg.noPrompt {
			fmt.Fprintln(os.Stderr, "  supply all required flags, or run in a terminal for the guided installer")
		}
		return 3
	}

	var generated installer.GeneratedSecrets
	if state.Secrets != nil {
		generated = *state.Secrets
	} else {
		generated, err = installer.GenerateSecrets(spec.AdminPassword)
		if err != nil {
			fmt.Fprintln(os.Stderr, "budctl install: generate credentials:", err)
			return 3
		}
	}
	if spec.AdminPassword != "" {
		generated.AdminPassword = spec.AdminPassword
	}
	state.Spec, state.Secrets = spec, &generated
	if !cfg.plan {
		if err := saveInstallState(statePath, &state, "generated"); err != nil {
			fmt.Fprintln(os.Stderr, "budctl install: save resume state:", err)
			return 3
		}
	}
	bundle, err := installer.RenderWithSecrets(spec, generated)
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl install: generate configuration:", err)
		return 3
	}
	printInstallPlan(spec, bundle, cfg, statePath, resumed)
	if cfg.plan {
		return 0
	}
	if cfg.noPush && !cfg.noBootstrap {
		fmt.Fprintln(os.Stderr, "budctl install: --no-push requires --no-bootstrap because ArgoCD cannot consume an unpushed revision")
		return 3
	}
	if !cfg.yes {
		if !interactive {
			fmt.Fprintln(os.Stderr, "budctl install: non-interactive installation requires --yes (or use --plan)")
			return 3
		}
		proceed, err := installer.Confirm("Generate, commit, and push this installation?")
		if err != nil || !proceed {
			fmt.Fprintln(os.Stderr, "budctl install: cancelled")
			return 3
		}
	}

	recoveryPath, err := recoveryKeyPath(cfg.recoveryKey, state.RecoveryPath, bundle.RecoveryFileName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl install:", err)
		return 3
	}
	workspace, err := os.MkdirTemp("", "budctl-install-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl install:", err)
		return 3
	}
	repoDir := filepath.Join(workspace, "repository")
	keepWorkspace := cfg.noPush
	if !keepWorkspace {
		defer os.RemoveAll(workspace)
	}
	prepared, err := installer.PrepareRepository(ctx, spec, bundle, repoDir, false, resumed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "budctl install: prepare repository:", err)
		return 3
	}
	fmt.Println("\nGenerated commit:")
	fmt.Println(indent(prepared.DiffStat, "  "))
	state.Commit = prepared.Commit
	state.RecoveryPath = recoveryPath
	if err := saveInstallState(statePath, &state, "prepared"); err != nil {
		fmt.Fprintln(os.Stderr, "budctl install: save resume state:", err)
		return 3
	}

	// The identity is deliberately persisted before the only irreversible
	// operation (push). If pushing succeeds, the operator is guaranteed to have
	// the key needed to recover and add another recipient later.
	if err := installer.EnsureRecoveryKey(recoveryPath, bundle); err != nil {
		fmt.Fprintln(os.Stderr, "budctl install: save recovery key:", err)
		return 3
	}
	if !cfg.noPush {
		if err := installer.PushRepository(ctx, prepared, spec.PushBranch); err != nil {
			fmt.Fprintln(os.Stderr, "budctl install:", err)
			fmt.Fprintln(os.Stderr, "the recovery key was retained at", recoveryPath)
			return 3
		}
		if err := saveInstallState(statePath, &state, "pushed"); err != nil {
			fmt.Fprintln(os.Stderr, "budctl install: save resume state:", err)
			return 3
		}
	}

	if !cfg.noBootstrap {
		if !cfg.yes {
			cluster := "the configured Kubernetes cluster"
			if kube != nil {
				cluster = firstNonEmpty(kube.Context, kube.Host(), cluster)
			}
			proceed, err := installer.Confirm("Git push complete. Start the ArgoCD installation on " + cluster + "?")
			if err != nil {
				fmt.Fprintln(os.Stderr, "budctl install: confirm cluster installation:", err)
				return 3
			}
			if !proceed {
				fmt.Println("\nRepository pushed successfully; cluster installation was deferred.")
				fmt.Println("  Resume state:", statePath)
				fmt.Println("  Recovery key:", recoveryPath)
				return 0
			}
		}
		if kubeErr != nil {
			fmt.Fprintln(os.Stderr, "budctl install: repository was pushed, but the cluster cannot be reached:", kubeErr)
			fmt.Fprintln(os.Stderr, "re-run with the same repository/environment after fixing kube access; key:", recoveryPath)
			return 3
		}
		if err := installer.Bootstrap(ctx, kube, prepared.Dir, spec, bundle, !cfg.noSync, func(step string) {
			fmt.Println("  →", step)
		}); err != nil {
			fmt.Fprintln(os.Stderr, "budctl install: repository was pushed, but ArgoCD bootstrap failed:", err)
			fmt.Fprintln(os.Stderr, "recovery key:", recoveryPath)
			return 3
		}
		if spec.TLS == installer.TLSSelfSigned && !cfg.noSync {
			certificate, err := kube.SecretData(ctx, "cert-manager", "selfsigned-ca-root", "tls.crt")
			if err != nil {
				fmt.Fprintln(os.Stderr, "budctl install: platform synchronized, but the self-signed root CA could not be exported:", err)
				fmt.Fprintln(os.Stderr, "retrieve cert-manager/selfsigned-ca-root key tls.crt before accessing Bud endpoints")
				return 3
			}
			caPath := state.CAPath
			if caPath == "" {
				caPath = filepath.Join(filepath.Dir(recoveryPath), "budctl-"+spec.Environment+"-ca.crt")
			}
			if err := installer.EnsureCACertificate(caPath, certificate); err != nil {
				fmt.Fprintln(os.Stderr, "budctl install: save self-signed root CA:", err)
				return 3
			}
			state.CAPath = caPath
		}
	}
	if err := saveInstallState(statePath, &state, "complete"); err != nil {
		fmt.Fprintln(os.Stderr, "budctl install: save resume state:", err)
		return 3
	}

	fmt.Printf("\nInstallation prepared successfully.\n  Git: %s @ %s\n  Recovery key: %s\n", installer.RepositoryURL(spec.TargetRepo), spec.PushBranch, recoveryPath)
	fmt.Println("  Resume state:", statePath)
	if state.CAPath != "" {
		fmt.Println("  Root CA certificate:", state.CAPath)
		fmt.Println("  Import this certificate into clients that access Bud endpoints.")
	}
	if cfg.noPush {
		fmt.Println("  Local repository:", prepared.Dir)
	}
	if spec.AdminPassword == "" {
		fmt.Println("  Initial admin password:", bundle.AdminPassword)
		fmt.Println("  Store this password now; budctl will not write a plaintext copy.")
	}
	if !cfg.noBootstrap {
		if cfg.noSync {
			fmt.Println("  ArgoCD bootstrap Application created; child Applications await an explicit sync.")
		} else {
			fmt.Println("  ArgoCD synchronized the platform Applications in dependency order.")
		}
	}
	return 0
}

func printInstallPlan(spec installer.Spec, bundle installer.Bundle, cfg config, statePath string, resumed bool) {
	fmt.Println("Bud GitOps installation plan")
	fmt.Println("  Environment:", spec.Environment)
	fmt.Println("  Target:", installer.RepositoryURL(spec.TargetRepo), "branch", spec.PushBranch)
	fmt.Println("  Template:", installer.RepositoryURL(spec.TemplateRepo), "@", spec.TemplateRef)
	fmt.Println("  Domain:", spec.Domain)
	fmt.Println("  TLS:", spec.TLS)
	fmt.Println("  Ingress / storage:", spec.IngressClass, "/", spec.StorageClass)
	fmt.Printf("  Capacity: %d GiB models, %d expected models, %d concurrent deployments\n", spec.ModelStorageGi, spec.Models, spec.Deployments)
	fmt.Println("  OpenSandbox: enabled (platform default)")
	fmt.Println("  Bud Studio:", yesNo(spec.BudStudio))
	fmt.Println("  Resume state:", statePath)
	if resumed {
		fmt.Println("  Resume: previous selections and generated credentials loaded")
	}
	fmt.Printf("  Generated files: %d (%d SOPS-encrypted)\n", len(bundle.Artifacts), countSensitive(bundle.Artifacts))
	if cfg.plan {
		fmt.Println("  Actions: none (--plan)")
	} else if cfg.noPush {
		fmt.Println("  Actions: clone, generate and commit locally")
	} else if cfg.noBootstrap {
		fmt.Println("  Actions: clone, generate, commit and push")
	} else if cfg.noSync {
		fmt.Println("  Actions: clone, generate, commit, push, install ArgoCD and create bootstrap Application")
	} else {
		fmt.Println("  Actions: clone, generate, commit, push, bootstrap ArgoCD and sync the platform")
	}
}

// The installer pins its maintained template as part of the binary contract.
// A resume checkpoint should preserve user-selected custom templates, but an
// old default pin must not strand the run on a revision that lacks files the
// current installer requires.
func upgradeCachedTemplateRef(spec *installer.Spec, resumed, explicitRef bool) {
	if spec == nil || !resumed || explicitRef {
		return
	}
	if spec.TemplateRepo == "" || installer.IsMaintainedTemplateRepository(spec.TemplateRepo) {
		spec.TemplateRepo = installer.DefaultTemplateRepo
		spec.TemplateRef = installer.DefaultTemplateRef
	}
}

func countSensitive(artifacts []installer.Artifact) int {
	n := 0
	for _, a := range artifacts {
		if a.Sensitive {
			n++
		}
	}
	return n
}

func recoveryKeyPath(given, cached, fallback string) (string, error) {
	if given == "" {
		given = firstNonEmpty(cached, fallback)
	}
	abs, err := filepath.Abs(given)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func installStatePath(given string) (string, error) {
	if given == "" {
		return installer.DefaultStatePath()
	}
	return filepath.Abs(given)
}

func saveInstallState(path string, state *installer.State, phase string) error {
	state.Phase = phase
	return installer.SaveState(path, *state)
}

func applyInstallFlags(spec *installer.Spec, cfg config) {
	if cfg.isSet("repo") {
		spec.TargetRepo = cfg.installRepo
	} else if cfg.isSet("config-repo") {
		spec.TargetRepo = cfg.configRepo
	}
	if cfg.isSet("environment") {
		spec.Environment = cfg.environment
	}
	if cfg.isSet("branch") {
		spec.PushBranch = cfg.pushBranch
	}
	if cfg.isSet("repo-ssh-key") {
		spec.RepoSSHKeyPath, spec.RepoSSHPrivateKey = cfg.repoSSHKey, ""
	}
	if cfg.isSet("domain") {
		spec.Domain = cfg.domain
	}
	if cfg.isSet("ingress-class") {
		spec.IngressClass = cfg.ingressClass
	}
	if cfg.isSet("storage-class") {
		spec.StorageClass = cfg.storageClass
	}
	if cfg.isSet("model-storage-gi") {
		spec.ModelStorageGi = cfg.modelStorageGi
	}
	if cfg.isSet("models") {
		spec.Models = cfg.modelCount
	}
	if cfg.isSet("deployments") {
		spec.Deployments = cfg.deployments
	}
	if cfg.isSet("gpu") {
		spec.GPU = cfg.gpu
	}
	if cfg.isSet("registry-user") {
		spec.RegistryUser = cfg.registryUser
	}
	if cfg.isSet("registry-password") {
		spec.RegistryPassword = cfg.registryPass
	}
	if value := os.Getenv("BUD_REGISTRY_USER"); value != "" {
		spec.RegistryUser = value
	}
	if value := os.Getenv("BUD_REGISTRY_PASSWORD"); value != "" {
		spec.RegistryPassword = value
	}
	if cfg.isSet("admin-email") {
		spec.AdminEmail = cfg.adminEmail
	}
	if cfg.isSet("admin-password") {
		spec.AdminPassword = cfg.adminPassword
	}
	if cfg.isSet("cloudflare-token") {
		spec.CloudflareToken = cfg.cloudflareToken
	}
	if cfg.isSet("ca-bundle") {
		spec.CABundlePath, spec.TrustedCAPEM = cfg.caBundle, ""
	}
	if cfg.isSet("issuer-ca-cert") {
		spec.IssuerCACertPath, spec.IssuerCACertPEM = cfg.issuerCACert, ""
	}
	if cfg.isSet("issuer-ca-key") {
		spec.IssuerCAKeyPath, spec.IssuerCAKeyPEM = cfg.issuerCAKey, ""
	}
	if value := os.Getenv("CLOUDFLARE_API_TOKEN"); value != "" {
		spec.CloudflareToken = value
	}
	if cfg.isSet("age-recipient") {
		spec.AgeRecipients = append([]string(nil), cfg.ageRecipients...)
	}
	if cfg.isSet("bud-studio") {
		spec.BudStudio = cfg.budStudio
	}
	if cfg.isSet("studio-model") {
		spec.StudioModel = cfg.studioModel
	}
	if cfg.isSet("template-repo") {
		spec.TemplateRepo = cfg.templateRepo
	}
	if cfg.isSet("template-ref") {
		spec.TemplateRef = cfg.templateRef
	}
	if cfg.isSet("tls") {
		spec.TLS = installer.TLSMode(cfg.tls)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
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
