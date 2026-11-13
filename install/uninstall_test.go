package install

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BudEcosystem/budctl/k8s"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func argoObject(kind, name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": "argocd"},
		"spec":     spec,
	}}
}

func TestUninstallPrunesInReverseOrderAndKeepsArgoCD(t *testing.T) {
	objects := []runtime.Object{
		argoObject("ApplicationSet", "production", nil),
		argoObject("Application", "bootstrap", map[string]any{"source": map[string]any{"directory": map[string]any{"include": "production.yaml"}}}),
	}
	for _, c := range []string{"argocd", "cert-manager", "postgres", "keycloak", "bud"} {
		objects = append(objects, argoObject("Application", "production-"+c, nil))
	}
	objects = append(objects, argoObject("Application", "staging-bud", nil))
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		k8s.ApplicationGVR:    "ApplicationList",
		k8s.ApplicationSetGVR: "ApplicationSetList",
	}, objects...)
	clientset := k8sfake.NewSimpleClientset()
	client := k8s.NewFakeClient(clientset, dyn, clientset.Discovery(), nil, nil)

	var steps []string
	if err := Uninstall(context.Background(), client, "production", time.Second, func(s string) { steps = append(steps, s) }); err != nil {
		t.Fatal(err)
	}

	var deleted []string
	finalized := map[string]bool{}
	for _, a := range dyn.Actions() {
		switch action := a.(type) {
		case k8stesting.DeleteAction:
			deleted = append(deleted, action.GetName())
		case k8stesting.PatchAction:
			if strings.Contains(string(action.GetPatch()), k8s.ResourcesFinalizer) {
				finalized[action.GetName()] = true
			}
		}
	}
	want := "bootstrap production production-bud production-keycloak production-postgres production-cert-manager production-argocd"
	if got := strings.Join(deleted, " "); got != want {
		t.Fatalf("deletion order:\n got %s\nwant %s", got, want)
	}
	for _, name := range []string{"production-bud", "production-keycloak", "production-postgres", "production-cert-manager"} {
		if !finalized[name] {
			t.Errorf("%s was deleted without the resources finalizer, so ArgoCD would not prune it", name)
		}
	}
	if finalized["production-argocd"] {
		t.Error("the argocd Application was pruned, which would delete ArgoCD mid-uninstall")
	}
	if len(steps) == 0 {
		t.Error("no progress was reported")
	}
}

func TestUninstallUnknownEnvironment(t *testing.T) {
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		k8s.ApplicationGVR:    "ApplicationList",
		k8s.ApplicationSetGVR: "ApplicationSetList",
	})
	clientset := k8sfake.NewSimpleClientset()
	client := k8s.NewFakeClient(clientset, dyn, clientset.Discovery(), nil, nil)
	err := Uninstall(context.Background(), client, "nope", time.Second, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("got %v", err)
	}
}
