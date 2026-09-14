package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// Kube is the read-only cluster client. It caches per (resource, namespace) so
// a run that inspects nodes from six different checks pays for one LIST.
type Kube struct {
	// Interfaces rather than concrete types so the check suite can drive every
	// code path — notably the OpenShift branches — against a synthetic cluster.
	Clientset kubernetes.Interface
	Dynamic   dynamic.Interface
	Discovery discovery.DiscoveryInterface
	Config    *rest.Config
	Context   string

	mu        sync.Mutex
	cache     map[string][]Object
	apiGroups map[string]bool
	mapper    meta.RESTMapper

	// statsFn is overridable because the kubelet /stats/summary proxy has no
	// fake implementation in client-go; tests inject node filesystem figures.
	statsFn func(ctx context.Context, node string) NodeStats
}

// NewKube loads the kubeconfig the same way kubectl does, including exec
// credential plugins (aws eks get-token, gcloud, az) — the reason client-go is
// a library here rather than a subprocess.
func NewKube(kubeconfig, kubecontext string) (*Kube, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	}
	overrides := &clientcmd.ConfigOverrides{}
	if kubecontext != "" {
		overrides.CurrentContext = kubecontext
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, err
	}
	cfg.QPS, cfg.Burst = 50, 100
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	name := kubecontext
	if name == "" {
		if raw, err := cc.RawConfig(); err == nil {
			name = raw.CurrentContext
		}
	}
	return &Kube{
		Clientset: cs, Dynamic: dyn, Discovery: cs.Discovery(), Config: cfg,
		Context: name, cache: map[string][]Object{},
	}, nil
}

func (k *Kube) ServerVersion() (*version.Info, error) {
	if k.Discovery == nil {
		return nil, fmt.Errorf("no discovery client")
	}
	return k.Discovery.ServerVersion()
}

// Host is the API server URL, used to tell the operator which cluster answered.
func (k *Kube) Host() string {
	if k.Config == nil {
		return ""
	}
	return k.Config.Host
}

// APIGroups returns every served resource as "resource.group" (core group as
// bare "resource"), so a CRD presence test is one map lookup.
func (k *Kube) APIGroups(ctx context.Context) map[string]bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.apiGroups != nil {
		return k.apiGroups
	}
	out := map[string]bool{}
	// ServerGroupsAndResources returns partial results with an error when some
	// aggregated API is unavailable; that is common and must not blank the map.
	_, lists, _ := k.Discovery.ServerGroupsAndResources()
	for _, l := range lists {
		gv, err := schema.ParseGroupVersion(l.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range l.APIResources {
			if gv.Group == "" {
				out[r.Name] = true
			} else {
				out[r.Name+"."+gv.Group] = true
			}
			out[l.GroupVersion] = true
		}
	}
	k.apiGroups = out
	return out
}

// HasResource reports whether "clusters.postgresql.cnpg.io" style names are served.
func (k *Kube) HasResource(ctx context.Context, fq string) bool {
	return k.APIGroups(ctx)[fq]
}

// HasAPIVersion reports whether a groupVersion such as "route.openshift.io/v1" is served.
func (k *Kube) HasAPIVersion(ctx context.Context, gv string) bool {
	return k.APIGroups(ctx)[gv]
}

// List fetches any resource by "resource.group" name. It never returns an error
// for an absent kind — a missing CRD is a finding, not a failure of the tool.
func (k *Kube) List(ctx context.Context, fq, namespace string) []Object {
	key := fq + "|" + namespace
	k.mu.Lock()
	if v, ok := k.cache[key]; ok {
		k.mu.Unlock()
		return v
	}
	k.mu.Unlock()

	gvr, err := k.resolve(fq)
	out := []Object{}
	if err == nil {
		var ri dynamic.ResourceInterface = k.Dynamic.Resource(gvr)
		if namespace != "" {
			ri = k.Dynamic.Resource(gvr).Namespace(namespace)
		}
		if l, err := ri.List(ctx, metav1.ListOptions{}); err == nil {
			for _, item := range l.Items {
				out = append(out, Object(item.Object))
			}
		}
	}
	k.mu.Lock()
	k.cache[key] = out
	k.mu.Unlock()
	return out
}

// Get returns one object or nil.
func (k *Kube) Get(ctx context.Context, fq, namespace, name string) Object {
	for _, o := range k.List(ctx, fq, namespace) {
		if o.Name() == name {
			return o
		}
	}
	return nil
}

// Invalidate drops the cache for a resource that is actively changing, such as
// a probe pod being polled.
func (k *Kube) Invalidate(fq, namespace string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.cache, fq+"|"+namespace)
}

func (k *Kube) resolve(fq string) (schema.GroupVersionResource, error) {
	// A Kube with no discovery client is a fake cluster driven entirely by
	// Seed(); asking it to resolve a GVR would dereference nil. Returning an
	// error here makes List fall through to the empty result it already
	// produces for an absent kind.
	if k.Discovery == nil || k.Dynamic == nil {
		return schema.GroupVersionResource{}, fmt.Errorf("no discovery client")
	}
	k.mu.Lock()
	if k.mapper == nil {
		groups, err := restmapper.GetAPIGroupResources(k.Discovery)
		if err != nil {
			k.mu.Unlock()
			return schema.GroupVersionResource{}, err
		}
		k.mapper = restmapper.NewDiscoveryRESTMapper(groups)
	}
	mapper := k.mapper
	k.mu.Unlock()

	resource, group, _ := strings.Cut(fq, ".")
	gvrs, err := mapper.ResourcesFor(schema.GroupVersionResource{Group: group, Resource: resource})
	if err != nil || len(gvrs) == 0 {
		return schema.GroupVersionResource{}, fmt.Errorf("unknown resource %q", fq)
	}
	return gvrs[0], nil
}

// CanI answers through SelfSubjectAccessReview — the API behind `kubectl auth can-i`.
func (k *Kube) CanI(ctx context.Context, verb, group, resource, namespace string) bool {
	rev := &authzv1.SelfSubjectAccessReview{
		Spec: authzv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: namespace, Verb: verb, Group: group, Resource: resource,
			},
		},
	}
	res, err := k.Clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, rev, metav1.CreateOptions{})
	if err != nil {
		return false
	}
	return res.Status.Allowed
}

// CanServiceAccount answers the same question for another identity, used to ask
// whether ArgoCD's controller — not the operator — may create CRDs.
func (k *Kube) CanServiceAccount(ctx context.Context, sa, saNamespace, verb, group, resource string) (bool, error) {
	rev := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: fmt.Sprintf("system:serviceaccount:%s:%s", saNamespace, sa),
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb: verb, Group: group, Resource: resource,
			},
		},
	}
	res, err := k.Clientset.AuthorizationV1().SubjectAccessReviews().Create(ctx, rev, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return res.Status.Allowed, nil
}

// NodeStats is the kubelet's own view of a node's filesystems, reached through
// the API server proxy. This is the only source for image-layer headroom:
// allocatable ephemeral-storage does not tell you how much the image store has
// left (FRD-020 §5.6).
type NodeStats struct {
	Node             string
	FsCapacityBytes  uint64
	FsAvailableBytes uint64
	FsUsedBytes      uint64
	ImageFsCapacity  uint64
	ImageFsAvailable uint64
	ImageFsUsed      uint64
	Err              string
}

func (k *Kube) NodeStats(ctx context.Context, node string) NodeStats {
	if k.statsFn != nil {
		return k.statsFn(ctx, node)
	}
	out := NodeStats{Node: node}
	raw, err := k.Clientset.CoreV1().RESTClient().Get().
		Resource("nodes").Name(node).SubResource("proxy").
		Suffix("stats", "summary").DoRaw(ctx)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	var parsed struct {
		Node struct {
			Fs struct {
				CapacityBytes  uint64 `json:"capacityBytes"`
				AvailableBytes uint64 `json:"availableBytes"`
				UsedBytes      uint64 `json:"usedBytes"`
			} `json:"fs"`
			Runtime struct {
				ImageFs struct {
					CapacityBytes  uint64 `json:"capacityBytes"`
					AvailableBytes uint64 `json:"availableBytes"`
					UsedBytes      uint64 `json:"usedBytes"`
				} `json:"imageFs"`
			} `json:"runtime"`
		} `json:"node"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		out.Err = err.Error()
		return out
	}
	out.FsCapacityBytes = parsed.Node.Fs.CapacityBytes
	out.FsAvailableBytes = parsed.Node.Fs.AvailableBytes
	out.FsUsedBytes = parsed.Node.Fs.UsedBytes
	out.ImageFsCapacity = parsed.Node.Runtime.ImageFs.CapacityBytes
	out.ImageFsAvailable = parsed.Node.Runtime.ImageFs.AvailableBytes
	out.ImageFsUsed = parsed.Node.Runtime.ImageFs.UsedBytes
	// Some runtimes share the node filesystem and report no separate imageFs.
	if out.ImageFsCapacity == 0 {
		out.ImageFsCapacity = out.FsCapacityBytes
		out.ImageFsAvailable = out.FsAvailableBytes
		out.ImageFsUsed = out.FsUsedBytes
	}
	return out
}

// PodLogs returns a finished pod's output, used by every in-cluster probe.
func (k *Kube) PodLogs(ctx context.Context, namespace, pod string) (string, error) {
	req := k.Clientset.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{})
	b, err := req.DoRaw(ctx)
	return string(b), err
}

// NewFakeKube builds a Kube backed by in-memory objects. It exists so the check
// suite can exercise paths a single real cluster can never cover at once — an
// OpenShift control plane and a vanilla one, a tainted fleet, a node short of
// image-filesystem space — without pretending a green run on one cluster proved
// them.
func NewFakeKube(clientset kubernetes.Interface, dyn dynamic.Interface, disco discovery.DiscoveryInterface, mapper meta.RESTMapper, stats func(context.Context, string) NodeStats) *Kube {
	return &Kube{
		Clientset: clientset,
		Dynamic:   dyn,
		Discovery: disco,
		mapper:    mapper,
		statsFn:   stats,
		Context:   "fake",
		cache:     map[string][]Object{},
	}
}

// SetAPIGroups pre-seeds the served-resource set for a fake cluster, which is
// how a test declares "this is OpenShift" (route.openshift.io/v1 plus
// security.openshift.io/v1) or "this is vanilla".
func (k *Kube) SetAPIGroups(groups map[string]bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.apiGroups = groups
}

// Seed injects objects for a resource so a fake cluster needs no RESTMapper
// round trip for kinds client-go's scheme does not know (OpenShift CRDs).
func (k *Kube) Seed(fq, namespace string, objs []Object) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cache == nil {
		k.cache = map[string][]Object{}
	}
	k.cache[fq+"|"+namespace] = objs
}
