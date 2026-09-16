package install

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/charmbracelet/huh"
)

func DetectDefaults(ctx context.Context, kube *adapters.Kube, spec *Spec) {
	if kube == nil || spec == nil {
		return
	}
	if spec.Environment == "" {
		spec.Environment = environmentName(kube.Context)
	}
	if kube.HasAPIVersion(ctx, "route.openshift.io/v1") {
		spec.IsOpenShift = true
		if spec.IngressClass == "" {
			spec.IngressClass = "openshift-default"
		}
		spec.IsTraefik = false
		if spec.Domain == "" {
			if ing := kube.Get(ctx, "ingresses.config.openshift.io", "", "cluster"); ing != nil {
				spec.Domain = ing.DigString("spec", "domain")
			}
		}
	}
	if spec.IngressClass == "" {
		classes := kube.List(ctx, "ingressclasses.networking.k8s.io", "")
		for _, class := range classes {
			annotations := class.Annotations()
			if annotations["ingressclass.kubernetes.io/is-default-class"] == "true" {
				spec.IngressClass = class.Name()
				break
			}
		}
		if spec.IngressClass == "" && len(classes) == 1 {
			spec.IngressClass = classes[0].Name()
		}
	}
	if strings.Contains(strings.ToLower(spec.IngressClass), "traefik") {
		spec.IsTraefik = true
	}
	if spec.StorageClass == "" {
		classes := kube.List(ctx, "storageclasses.storage.k8s.io", "")
		for _, class := range classes {
			a := class.Annotations()
			if a["storageclass.kubernetes.io/is-default-class"] == "true" || a["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
				spec.StorageClass = class.Name()
				break
			}
		}
		if spec.StorageClass == "" && len(classes) == 1 {
			spec.StorageClass = classes[0].Name()
		}
	}
	spec.Normalize()
}

func Prompt(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("installation spec is nil")
	}
	spec.Normalize()
	modelGi := strconv.Itoa(spec.ModelStorageGi)
	models := strconv.Itoa(spec.Models)
	deployments := strconv.Itoa(spec.Deployments)
	recipients := strings.Join(spec.AgeRecipients, ",")
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Target configuration repository").Value(&spec.TargetRepo).
				Description("budctl clones this repository, commits an environment branch, and pushes it."),
			huh.NewInput().Title("Environment name").Value(&spec.Environment),
			huh.NewInput().Title("Push branch").Value(&spec.PushBranch),
		).Title("1 · GitOps target"),
		huh.NewGroup(
			huh.NewInput().Title("Repository SSH deploy key").Value(&spec.RepoSSHKeyPath).
				Description("Stored only in SOPS-encrypted ArgoCD values."),
		).Title("1 · Private repository access").WithHideFunc(func() bool { return !isSSHRepository(spec.TargetRepo) }),
		huh.NewGroup(
			huh.NewInput().Title("Root domain").Value(&spec.Domain),
			huh.NewInput().Title("Ingress class").Value(&spec.IngressClass),
			huh.NewSelect[TLSMode]().Title("TLS strategy").Options(
				huh.NewOption("ACME DNS-01 with Cloudflare", TLSACMEDNS01),
				huh.NewOption("ACME HTTP-01", TLSACMEHTTP01),
				huh.NewOption("Self-signed internal CA", TLSSelfSigned),
				huh.NewOption("Existing internal issuing CA", TLSInternalCA),
				huh.NewOption("TLS terminated by an external LB/WAF", TLSExternal),
			).Value(&spec.TLS),
		).Title("2 · Network and TLS"),
		huh.NewGroup(
			huh.NewInput().Title("Cloudflare API token").EchoMode(huh.EchoModePassword).Value(&spec.CloudflareToken),
		).Title("2 · DNS-01 credentials").WithHideFunc(func() bool { return spec.TLS != TLSACMEDNS01 }),
		huh.NewGroup(
			huh.NewInput().Title("Additional trusted CA bundle").Value(&spec.CABundlePath).
				Description("Optional PEM file added to the in-cluster trust bundle."),
		).Title("2 · Additional CA trust").WithHideFunc(func() bool {
			return spec.TLS != TLSSelfSigned && spec.TLS != TLSInternalCA
		}),
		huh.NewGroup(
			huh.NewInput().Title("Issuing CA certificate").Value(&spec.IssuerCACertPath),
			huh.NewInput().Title("Issuing CA private key").EchoMode(huh.EchoModePassword).Value(&spec.IssuerCAKeyPath).
				Description("The key is stored only in encrypted installer state and SOPS values."),
		).Title("2 · Existing internal CA").WithHideFunc(func() bool { return spec.TLS != TLSInternalCA }),
		huh.NewGroup(
			huh.NewInput().Title("StorageClass").Value(&spec.StorageClass),
			huh.NewInput().Title("Model storage (GiB)").Value(&modelGi),
			huh.NewInput().Title("Expected models").Value(&models),
			huh.NewInput().Title("Concurrent deployments").Value(&deployments),
			huh.NewConfirm().Title("GPU workloads expected?").Affirmative("Yes").Negative("No").Value(&spec.GPU),
		).Title("3 · Capacity"),
		huh.NewGroup(
			huh.NewInput().Title("registry.bud.studio username").Value(&spec.RegistryUser),
			huh.NewInput().Title("registry.bud.studio token").EchoMode(huh.EchoModePassword).Value(&spec.RegistryPassword),
			huh.NewInput().Title("Initial administrator email").Value(&spec.AdminEmail),
			huh.NewInput().Title("Initial administrator password").EchoMode(huh.EchoModePassword).Value(&spec.AdminPassword).
				Description("Leave empty for a generated password shown once after preparation."),
			huh.NewInput().Title("Additional age recipients").Value(&recipients).
				Description("Optional comma-separated public recipients for other operators or devices."),
		).Title("4 · Credentials"),
		huh.NewGroup(
			huh.NewConfirm().Title("Install Bud Studio?").Affirmative("Yes").Negative("No").Value(&spec.BudStudio),
		).Title("5 · Optional add-on"),
		huh.NewGroup(
			huh.NewInput().Title("Bud Studio model").Value(&spec.StudioModel).
				Description("Optional on a fresh cluster; configure it after the first model is onboarded."),
		).Title("5 · Bud Studio").WithHideFunc(func() bool { return !spec.BudStudio }),
	)
	if err := form.Run(); err != nil {
		return err
	}
	var err error
	if spec.ModelStorageGi, err = positiveInt("model storage", modelGi); err != nil {
		return err
	}
	if spec.Models, err = positiveInt("expected models", models); err != nil {
		return err
	}
	if spec.Deployments, err = positiveInt("concurrent deployments", deployments); err != nil {
		return err
	}
	spec.AgeRecipients = splitRecipients(recipients)
	spec.Normalize()
	return nil
}

func Confirm(message string) (bool, error) {
	yes := false
	err := huh.NewConfirm().Title(message).Affirmative("Proceed").Negative("Cancel").Value(&yes).Run()
	return yes, err
}

func positiveInt(name, value string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive whole number", name)
	}
	return n, nil
}

func splitRecipients(value string) []string {
	out := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

var invalidEnvironment = regexp.MustCompile(`[^a-z0-9-]+`)

func environmentName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = invalidEnvironment.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if len(value) > 63 {
		value = strings.Trim(value[:63], "-")
	}
	if value == "" {
		return "production"
	}
	return value
}
