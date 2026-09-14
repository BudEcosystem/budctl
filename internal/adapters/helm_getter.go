package adapters

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// restClientGetter adapts our client-go config to the interface Helm's action
// configuration expects, so Helm reuses the very connection (and exec
// credential plugin) budctl already authenticated with.
type restClientGetter struct {
	k         *Kube
	namespace string
}

var _ genericclioptions.RESTClientGetter = (*restClientGetter)(nil)

func (g *restClientGetter) ToRESTConfig() (*rest.Config, error) { return g.k.Config, nil }

func (g *restClientGetter) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	dc, err := discovery.NewDiscoveryClientForConfig(g.k.Config)
	if err != nil {
		return nil, err
	}
	return memory.NewMemCacheClient(dc), nil
}

func (g *restClientGetter) ToRESTMapper() (meta.RESTMapper, error) {
	dc, err := g.ToDiscoveryClient()
	if err != nil {
		return nil, err
	}
	groups, err := restmapper.GetAPIGroupResources(dc)
	if err != nil {
		return nil, err
	}
	return restmapper.NewDiscoveryRESTMapper(groups), nil
}

func (g *restClientGetter) ToRawKubeConfigLoader() clientcmd.ClientConfig {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{Context: clientcmdapi.Context{Namespace: g.namespace}}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
}
