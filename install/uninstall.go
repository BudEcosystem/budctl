package install

import (
	"context"
	"fmt"
	"time"

	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/install/appset"
	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/k8s"
)

// Uninstall removes an environment's components from the cluster, in the
// reverse of the order they were synced.
//
// The root Application and the ApplicationSet go first, without touching what
// they generated: either would otherwise recreate an Application as soon as it
// is deleted. Each component's Application is then deleted with ArgoCD's
// resources finalizer, so ArgoCD prunes what it deployed before the
// Application disappears; Uninstall waits for that, one component at a time.
//
// ArgoCD itself is kept: its Application is released without pruning, so
// ArgoCD keeps running and the Helm release budctl installed it with still
// owns it. The GitOps repository is not changed.
func Uninstall(ctx context.Context, client *k8s.Client, environment string, timeout time.Duration, step func(string)) error {
	ns := defaults.ArgoCDNamespace
	set, err := client.GetFresh(ctx, k8s.ApplicationSetGVR, ns, environment)
	if err != nil {
		return fmt.Errorf("read ApplicationSet %s: %w", environment, err)
	}
	var present []components.Component
	for _, c := range components.BySyncWave(components.All) {
		app, err := client.GetFresh(ctx, k8s.ApplicationGVR, ns, environment+"-"+c.Name)
		if err != nil {
			return err
		}
		if app != nil {
			present = append(present, c)
		}
	}
	if set == nil && len(present) == 0 {
		return fmt.Errorf("environment %q is not installed in this cluster", environment)
	}

	root, err := client.GetFresh(ctx, k8s.ApplicationGVR, ns, appset.RootName)
	if err != nil {
		return err
	}
	if root != nil && root.DigString("spec", "source", "directory", "include") == environment+".yaml" {
		step("deleting the root Application, so it cannot recreate the ApplicationSet")
		if err := client.Delete(ctx, k8s.ApplicationGVR, ns, appset.RootName, true); err != nil {
			return err
		}
	}
	if set != nil {
		step("deleting the ApplicationSet " + environment + ", keeping its Applications for an ordered prune")
		if err := client.Delete(ctx, k8s.ApplicationSetGVR, ns, environment, true); err != nil {
			return err
		}
	}

	for i := len(present) - 1; i >= 0; i-- {
		c := present[i]
		name := environment + "-" + c.Name
		if c.Name == "argocd" {
			continue
		}
		step("pruning " + name)
		if err := client.AddFinalizer(ctx, k8s.ApplicationGVR, ns, name, k8s.ResourcesFinalizer); err != nil {
			return fmt.Errorf("mark %s for pruning: %w", name, err)
		}
		if err := client.Delete(ctx, k8s.ApplicationGVR, ns, name, false); err != nil {
			return err
		}
		if err := waitGone(ctx, client, ns, name, timeout); err != nil {
			return err
		}
	}
	for _, c := range present {
		if c.Name == "argocd" {
			name := environment + "-argocd"
			step("releasing " + name + " without pruning, so ArgoCD keeps running")
			if err := client.Delete(ctx, k8s.ApplicationGVR, ns, name, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func waitGone(ctx context.Context, client *k8s.Client, ns, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		app, err := client.GetFresh(ctx, k8s.ApplicationGVR, ns, name)
		if err != nil {
			return err
		}
		if app == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s was not pruned within %s; ArgoCD reports: %s", name, timeout, app.DigString("status", "operationState", "message"))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
