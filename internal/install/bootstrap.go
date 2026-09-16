package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"gopkg.in/yaml.v3"
)

const (
	argoChartRef     = "oci://registry.bud.studio/charts/argocd"
	argoChartVersion = "0.1.1"
)

// Bootstrap installs ArgoCD, applies the generated root Application, and asks
// ArgoCD to sync the ApplicationSet. When syncChildren is true it then syncs
// each child in dependency order instead of racing every Application at once.
func Bootstrap(ctx context.Context, kube *adapters.Kube, repositoryDir string, spec Spec, bundle Bundle, syncChildren bool, progress func(string)) error {
	report := func(message string) {
		if progress != nil {
			progress(message)
		}
	}
	values, err := bootstrapValues(repositoryDir, bundle.BootstrapValues)
	if err != nil {
		return err
	}
	helm := adapters.NewHelm()
	credential := adapters.Credential{Username: spec.RegistryUser, Password: spec.RegistryPassword}
	report("installing or upgrading ArgoCD (CRDs first on a fresh cluster)")
	if err := helm.InstallOrUpgradeOCIStaged(ctx, kube, argoChartRef, argoChartVersion, "argocd", "argocd", values, argoFirstInstallValues(values), credential); err != nil {
		return err
	}
	manifest := []byte(renderBootstrap(spec))
	if err := kube.ApplyApplication(ctx, manifest); err != nil {
		return err
	}
	report("syncing bootstrap ApplicationSet")
	if err := kube.SyncArgoApplication(ctx, "argocd", "bootstrap", 10*time.Minute); err != nil {
		return fmt.Errorf("sync bootstrap Application: %w", err)
	}
	if !syncChildren {
		return nil
	}
	applications := []string{"argocd"}
	if spec.TLS != TLSExternal {
		applications = append(applications, "cert-manager")
	}
	if spec.TLS == TLSSelfSigned || spec.TLS == TLSInternalCA {
		applications = append(applications, "kyverno")
	}
	applications = append(applications,
		"dapr", "kafka", "mongodb", "clickhouse", "postgres", "seaweedfs",
		"valkey", "keycloak", "opensandbox", "bud",
	)
	if spec.BudStudio {
		applications = append(applications, "bud-studio")
	}
	for _, app := range applications {
		name := spec.Environment + "-" + app
		report("syncing " + name)
		if err := kube.SyncArgoApplication(ctx, "argocd", name, 20*time.Minute); err != nil {
			return fmt.Errorf("sync %s: %w", name, err)
		}
	}
	return nil
}

// The upstream argo-cd chart deliberately keeps upgradeable CRDs in templates.
// The Bud wrapper also renders AppProjects, so a fresh release must omit those
// custom resources until the first Helm pass has established their CRDs.
func argoFirstInstallValues(values map[string]any) map[string]any {
	initial := make(map[string]any, len(values))
	for key, value := range values {
		initial[key] = value
	}
	initial["projects"] = map[string]any{}
	return initial
}

func bootstrapValues(repositoryDir string, generated map[string]any) (map[string]any, error) {
	path := filepath.Join(repositoryDir, "values", "argocd", "values.budruntime.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ArgoCD base values: %w", err)
	}
	base := map[string]any{}
	if err := yaml.Unmarshal(body, &base); err != nil {
		return nil, fmt.Errorf("parse ArgoCD base values: %w", err)
	}
	return mergeValueMaps(base, generated), nil
}
