package adapters

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/kube"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/storage"
	"helm.sh/helm/v3/pkg/storage/driver"
	"sigs.k8s.io/yaml"
)

// Helm renders charts in-process. FRD-020 §9.1: no helm binary on the host,
// which is what makes the single-artifact hand-off possible.
type Helm struct {
	settings *cli.EnvSettings
}

func NewHelm() *Helm { return &Helm{settings: cli.New()} }

// LoadChart reads a chart from a directory or archive.
func (h *Helm) LoadChart(path string) (*chart.Chart, error) { return loader.Load(path) }

// MergeValues layers values files in order, the way `helm -f a -f b` does,
// transparently decrypting any SOPS-encrypted file. Decryption has to happen
// here rather than at the call site: an encrypted file parses as valid YAML, so
// skipping it would yield ciphertext values instead of an error.
func (h *Helm) MergeValues(paths []string) (map[string]any, error) {
	sops := SOPS{}
	out := map[string]any{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		v, err := sops.Decrypt(p)
		if err != nil {
			return nil, err
		}
		out = mergeMaps(out, v)
	}
	return out, nil
}

func mergeMaps(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if vm, ok := v.(map[string]any); ok {
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = mergeMaps(bm, vm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// RenderResult carries the rendered objects plus the raw manifest, so a check
// can either inspect structure or quote the chart's own error text.
type RenderResult struct {
	Objects  []Object
	Manifest string
	// ServerSide records whether the API server validated the apply. A chart
	// that templates cleanly can still be rejected by the API server, and only
	// a server-side dry run distinguishes the two (FRD-020 §5.11).
	ServerSide bool
}

// Render templates the chart client-side. This reproduces `helm template`.
func (h *Helm) Render(ch *chart.Chart, vals map[string]any, releaseName, namespace string, kubeVersion string) (*RenderResult, error) {
	inst := action.NewInstall(&action.Configuration{})
	inst.DryRun = true
	inst.ClientOnly = true
	inst.ReleaseName = releaseName
	inst.Namespace = namespace
	inst.IncludeCRDs = true
	if kubeVersion != "" {
		if kv, err := chartutil.ParseKubeVersion(kubeVersion); err == nil {
			inst.KubeVersion = kv
		}
	}
	rel, err := inst.Run(ch, vals)
	if err != nil {
		return nil, err
	}
	return &RenderResult{Objects: splitManifest(rel.Manifest), Manifest: rel.Manifest}, nil
}

// RenderServerSide performs a dry run the API server validates, which is what
// catches an object Helm cannot adopt or a webhook that would deny the apply.
func (h *Helm) RenderServerSide(ctx context.Context, k *Kube, ch *chart.Chart, vals map[string]any, releaseName, namespace string) (*RenderResult, error) {
	cfg, err := h.configuration(k, namespace)
	if err != nil {
		return nil, err
	}
	inst := action.NewInstall(cfg)
	inst.DryRun = true
	inst.DryRunOption = "server"
	inst.ReleaseName = releaseName
	inst.Namespace = namespace
	inst.IncludeCRDs = true
	rel, err := inst.RunWithContext(ctx, ch, vals)
	if err != nil {
		return nil, err
	}
	return &RenderResult{Objects: splitManifest(rel.Manifest), Manifest: rel.Manifest, ServerSide: true}, nil
}

// InstallOrUpgradeOCI bootstraps a release without requiring a helm binary or
// persisting registry credentials. Release state is stored in the cluster in
// the same Secret-backed format as the Helm CLI, so later upgrades can adopt it.
func (h *Helm) InstallOrUpgradeOCI(ctx context.Context, k *Kube, ref, version, releaseName, namespace string, vals map[string]any, credential Credential) error {
	return h.installOrUpgradeOCI(ctx, k, ref, version, releaseName, namespace, vals, nil, credential)
}

// InstallOrUpgradeOCIStaged uses firstInstallValues only when the release does
// not exist, then immediately upgrades to vals. This supports charts that keep
// CRDs in templates while also rendering custom resources from those CRDs:
// Helm cannot REST-map both kinds during a single first installation.
func (h *Helm) InstallOrUpgradeOCIStaged(ctx context.Context, k *Kube, ref, version, releaseName, namespace string, vals, firstInstallValues map[string]any, credential Credential) error {
	return h.installOrUpgradeOCI(ctx, k, ref, version, releaseName, namespace, vals, firstInstallValues, credential)
}

func (h *Helm) installOrUpgradeOCI(ctx context.Context, k *Kube, ref, version, releaseName, namespace string, vals, firstInstallValues map[string]any, credential Credential) error {
	if k == nil {
		return fmt.Errorf("a Kubernetes client is required")
	}
	reg, err := registry.NewClient(
		registry.ClientOptWriter(io.Discard),
		registry.ClientOptBasicAuth(credential.Username, credential.Password),
	)
	if err != nil {
		return fmt.Errorf("create OCI client: %w", err)
	}
	cfg := &action.Configuration{}
	getter := &restClientGetter{k: k, namespace: namespace}
	if err := cfg.Init(getter, namespace, "secret", func(string, ...any) {}); err != nil {
		return fmt.Errorf("initialize Helm client: %w", err)
	}
	cfg.RegistryClient = reg

	locator := action.ChartPathOptions{Version: version}
	// ChartPathOptions has no public setter; Install exposes the supported
	// setter and the locator embedded in it.
	puller := action.NewInstall(cfg)
	puller.ChartPathOptions = locator
	puller.SetRegistryClient(reg)
	chartPath, err := puller.LocateChart(ref, h.settings)
	if err != nil {
		return fmt.Errorf("pull %s:%s: %w", ref, version, err)
	}
	ch, err := loader.Load(chartPath)
	if err != nil {
		return fmt.Errorf("load downloaded chart: %w", err)
	}

	const timeout = 10 * time.Minute
	upgrade := func() error {
		up := action.NewUpgrade(cfg)
		up.Namespace = namespace
		up.Version = version
		up.Wait = true
		up.WaitForJobs = true
		up.Atomic = true
		up.Timeout = timeout
		up.SetRegistryClient(reg)
		if _, err := up.RunWithContext(ctx, releaseName, ch, vals); err != nil {
			return fmt.Errorf("upgrade release %s: %w", releaseName, err)
		}
		return nil
	}
	if _, err := action.NewStatus(cfg).Run(releaseName); err == nil {
		return upgrade()
	}

	installValues := vals
	if firstInstallValues != nil {
		installValues = firstInstallValues
	}
	inst := action.NewInstall(cfg)
	inst.ReleaseName = releaseName
	inst.Namespace = namespace
	inst.CreateNamespace = true
	inst.IncludeCRDs = true
	inst.Wait = true
	inst.WaitForJobs = true
	inst.Atomic = true
	inst.Timeout = timeout
	inst.SetRegistryClient(reg)
	if _, err := inst.RunWithContext(ctx, ch, installValues); err != nil {
		return fmt.Errorf("install release %s: %w", releaseName, err)
	}
	if firstInstallValues != nil {
		if err := upgrade(); err != nil {
			return fmt.Errorf("finish staged installation after CRDs became available: %w", err)
		}
	}
	return nil
}

func (h *Helm) configuration(k *Kube, namespace string) (*action.Configuration, error) {
	cfg := &action.Configuration{}
	getter := &restClientGetter{k: k, namespace: namespace}
	kc := kube.New(getter)
	cfg.KubeClient = kc
	cfg.Releases = storage.Init(driver.NewMemory())
	cfg.RESTClientGetter = getter
	cfg.Capabilities = chartutil.DefaultCapabilities.Copy()
	cfg.Log = func(string, ...any) {}
	if k != nil {
		if v, err := k.ServerVersion(); err == nil {
			cfg.Capabilities.KubeVersion = chartutil.KubeVersion{
				Version: v.GitVersion, Major: v.Major, Minor: v.Minor,
			}
		}
		vs := chartutil.VersionSet{}
		for gv := range k.APIGroups(context.Background()) {
			if strings.Contains(gv, "/") {
				vs = append(vs, gv)
			}
		}
		if len(vs) > 0 {
			cfg.Capabilities.APIVersions = vs
		}
	}
	return cfg, nil
}

// splitManifest turns the rendered YAML stream into objects, ignoring the
// source comments Helm interleaves and any empty documents.
func splitManifest(manifest string) []Object {
	out := []Object{}
	for _, doc := range strings.Split(manifest, "\n---") {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var o Object
		if err := yaml.Unmarshal([]byte(doc), &o); err != nil || o == nil {
			continue
		}
		if o.Kind() == "" {
			continue
		}
		out = append(out, o)
	}
	return out
}

// Images returns every distinct image referenced by the rendered objects.
func Images(objs []Object) []string {
	seen, out := map[string]bool{}, []string{}
	for _, o := range objs {
		for _, c := range o.Containers() {
			if img, ok := c["image"].(string); ok && img != "" && !seen[img] {
				seen[img] = true
				out = append(out, img)
			}
		}
	}
	return out
}

var _ = release.Release{}
