package install

import (
	"context"
	"fmt"

	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/install/appset"
	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/internal/helm"
	"github.com/BudEcosystem/budctl/internal/oci"
)

// bootstrap installs ArgoCD, applies the root Application, and asks ArgoCD to
// sync the ApplicationSet. Unless NoSync is set it then syncs each child in
// the component table's wave order instead of racing every Application at
// once.
func (i *Installer) bootstrap(ctx context.Context, p *Plan) error {
	step := func(message string) { i.observer().Step(PhaseBootstrap, message) }
	s := p.Spec
	credential := oci.Credential{Username: s.RegistryUser, Password: s.RegistryPassword}
	values := p.Bundle.BootstrapValues
	step("installing or upgrading ArgoCD (CRDs first on a fresh cluster)")
	if err := helm.New().InstallOrUpgradeOCIStaged(ctx, i.Client, defaults.ArgoCDChartRef, defaults.ArgoCDChartVersion,
		"argocd", defaults.ArgoCDNamespace, values, argoFirstInstallValues(values), credential, defaults.ArgoCDInstallTimeout); err != nil {
		return err
	}
	return i.applyRoot(ctx, p)
}

// applyRoot applies the root Application, syncs it so ArgoCD creates the
// ApplicationSet, then, unless NoSync is set, syncs each child.
func (i *Installer) applyRoot(ctx context.Context, p *Plan) error {
	step := func(message string) { i.observer().Step(PhaseBootstrap, message) }
	s := p.Spec
	if err := i.Client.ApplyApplication(ctx, p.Bundle.RootApplication); err != nil {
		return err
	}
	step("syncing the root Application and the ApplicationSet")
	if err := i.Client.SyncArgoApplication(ctx, defaults.ArgoCDNamespace, appset.RootName, defaults.RootSyncTimeout); err != nil {
		return fmt.Errorf("sync %s Application: %w", appset.RootName, err)
	}
	if i.Params.NoSync {
		return nil
	}
	for _, c := range components.BySyncWave(components.Enabled(s)) {
		name := s.Environment + "-" + c.Name
		step("syncing " + name)
		if err := i.Client.SyncArgoApplication(ctx, defaults.ArgoCDNamespace, name, defaults.ChildSyncTimeout); err != nil {
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

// checkArgoCDRelease refuses an ArgoCD that was installed some other way under
// the same release name. Upgrading it to Bud's chart would replace an ArgoCD
// that is not budctl's to replace.
func (i *Installer) checkArgoCDRelease() error {
	chart, version, found, err := helm.New().ReleaseChart(i.Client, "argocd", defaults.ArgoCDNamespace)
	if err != nil {
		return fmt.Errorf("read the existing ArgoCD release: %w", err)
	}
	if found && chart != defaults.ArgoCDChartName {
		return fmt.Errorf("namespace %s already has an ArgoCD release from chart %s %s, not Bud's %s chart; budctl will not replace it. Uninstall it first (helm uninstall argocd -n %s), or pass --no-bootstrap to only push the configuration", defaults.ArgoCDNamespace, chart, version, defaults.ArgoCDChartName, defaults.ArgoCDNamespace)
	}
	return nil
}
