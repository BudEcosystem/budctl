// Package defaults holds the values budctl is built with: the version stamped
// at build time, and the constants more than one package shares.
package defaults

import "time"

// Version and Commit are stamped at build time with
// -ldflags "-X github.com/BudEcosystem/budctl/defaults.Version=…". A report
// records both, so a result produced by a stale binary is identifiable after
// the fact.
var (
	Version = "dev"
	Commit  = "none"
)

// Installation defaults, used when neither a flag nor the cluster decides.
const (
	Branch         = "main"
	IngressClass   = "traefik"
	ModelStorageGi = 300
	Models         = 5
	Deployments    = 3
)

// ArgoCD is installed from Bud's wrapper chart before anything else, so it is
// the one chart budctl installs directly rather than through an Application.
const (
	ArgoCDNamespace    = "argocd"
	ArgoCDChartName    = "argocd"
	ArgoCDChartRef     = "oci://registry.bud.studio/charts/" + ArgoCDChartName
	ArgoCDChartVersion = "0.1.1"
)

// Timeouts the installer waits on. Installing ArgoCD waits for every pod to
// be ready, and Bud's repo-server downloads its SOPS tooling from GitHub as it
// starts, which on a slow or flaky link has taken over ten minutes.
const (
	ArgoCDInstallTimeout = 20 * time.Minute
	RootSyncTimeout      = 10 * time.Minute
	ChildSyncTimeout     = 20 * time.Minute
)
