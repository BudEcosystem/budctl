package engine

import (
	"sync"
	"time"

	"github.com/BudEcosystem/budctl/internal/adapters"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/internal/probes"
)

// Distribution is what the platform group detects. Every group that renders
// differently on OpenShift branches on this rather than guessing from values.
type Distribution string

const (
	DistUnknown   Distribution = "unknown"
	DistVanilla   Distribution = "kubernetes"
	DistOpenShift Distribution = "openshift"
	DistK3s       Distribution = "k3s"
	DistEKS       Distribution = "eks"
	DistAKS       Distribution = "aks"
	DistGKE       Distribution = "gke"
)

// PlatformInfo is filled in by the platform group and read by everything after.
type PlatformInfo struct {
	Distribution Distribution
	Version      string
	// OpenShiftVersion is the ClusterVersion, empty on vanilla.
	OpenShiftVersion string
	// ClusterProxy is OpenShift's proxy.config.openshift.io/cluster, recorded
	// against every egress result so a blocked host is interpreted correctly.
	ClusterProxy string
	// AppsDomain is OpenShift's *.apps.<cluster>.<base> wildcard.
	AppsDomain string
}

func (p *PlatformInfo) IsOpenShift() bool {
	return p != nil && p.Distribution == DistOpenShift
}

// Options are the run-level switches.
type Options struct {
	// Kubeconfig and KubeContext are the paths as the operator gave them.
	// rest.Config exposes the RESOLVED credential, not the exec plugin that
	// produced it, so a check that must inspect the kubeconfig as written has to
	// be told where it is.
	Kubeconfig  string
	KubeContext string

	NoProbe         bool
	ProbeImage      string
	GPUProbeImage   string
	ProbeNamespace  string
	KeepProbes      bool
	EgressFrom      string // cluster | workstation | both
	HFThroughput    bool
	CheckTimeout    time.Duration
	NetTimeout      time.Duration
	ChartDir        string
	ValuesFiles     []string
	SecretsFile     string
	ArgoCDNamespace string
	ArgoCDEnabled   bool
	RegistryCreds   map[string]adapters.Credential

	// BudctlVersion is the build that ran, recorded in every report it writes.
	BudctlVersion string
}

// Ctx is handed to every check. Anything a check discovers that a later check
// needs goes in Shared, guarded, rather than in a package-level variable.
type Ctx struct {
	Kube     *adapters.Kube
	Probes   *probes.Runner
	Net      *adapters.Net
	OCI      *adapters.OCI
	Helm     *adapters.Helm
	Answers  intake.Answers
	Platform *PlatformInfo
	Opts     Options
	Profile  intake.Profile

	// Clock is injectable so recorded transcripts replay deterministically.
	Clock func() time.Time

	mu     sync.RWMutex
	shared map[string]any
}

func NewCtx() *Ctx {
	return &Ctx{
		Platform: &PlatformInfo{Distribution: DistUnknown},
		shared:   map[string]any{},
		Clock:    time.Now,
	}
}

func (c *Ctx) Now() time.Time {
	if c.Clock == nil {
		return time.Now()
	}
	return c.Clock()
}

func (c *Ctx) Set(key string, v any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shared == nil {
		c.shared = map[string]any{}
	}
	c.shared[key] = v
}

func (c *Ctx) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.shared[key]
	return v, ok
}

// Shared keys used across groups.
const (
	KeyRenderedObjects = "rendered.objects" // []adapters.Object from config.render
	KeyImages          = "rendered.images"  // []string
	KeyGPUNodes        = "gpu.nodes"        // []string
	KeyIngressAddrs    = "ingress.addresses"
)
