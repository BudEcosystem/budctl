package status

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
)

func object(kind, name string, fields map[string]any) *unstructured.Unstructured {
	o := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": "argocd"},
	}
	for k, v := range fields {
		o[k] = v
	}
	return &unstructured.Unstructured{Object: o}
}

func app(env, component, sync, health string) *unstructured.Unstructured {
	u := object("Application", env+"-"+component, map[string]any{
		"spec": map[string]any{"sources": []any{
			map[string]any{"repoURL": "registry.bud.studio/charts", "chart": component, "targetRevision": "1.0.0"},
			map[string]any{"repoURL": "https://example.com/config", "ref": "values"},
		}},
		"status": map[string]any{
			"sync":   map[string]any{"status": sync},
			"health": map[string]any{"status": health},
		},
	})
	u.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationSet", "name": env},
	}
	return u
}

func fakeClient(objects ...runtime.Object) *k8s.Client {
	scheme := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		k8s.ApplicationGVR:    "ApplicationList",
		k8s.ApplicationSetGVR: "ApplicationSetList",
	}, objects...)
	clientset := k8sfake.NewSimpleClientset()
	return k8s.NewFakeClient(clientset, dyn, clientset.Discovery(), nil, nil)
}

func TestCollectGroupsApplicationsByEnvironment(t *testing.T) {
	c := fakeClient(
		object("ApplicationSet", "production", nil),
		object("ApplicationSet", "staging", nil),
		object("Application", "bootstrap", map[string]any{"status": map[string]any{
			"sync": map[string]any{"status": "Synced"}, "health": map[string]any{"status": "Healthy"},
		}}),
		app("production", "bud", "Synced", "Healthy"),
		app("production", "keycloak", "OutOfSync", "Progressing"),
		app("staging", "bud", "Synced", "Healthy"),
	)
	r, err := Collect(context.Background(), c, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Root == nil || !r.Root.Ready() {
		t.Fatalf("root Application not reported: %#v", r.Root)
	}
	if len(r.Environments) != 2 || r.Environments[0].Name != "production" || len(r.Environments[0].Applications) != 2 {
		t.Fatalf("environments = %#v", r.Environments)
	}
	bud := r.Environments[0].Applications[0]
	if bud.Component != "bud" || bud.Chart != "bud" || bud.Revision != "1.0.0" {
		t.Fatalf("application = %#v", bud)
	}
	if r.Ready() {
		t.Fatal("an OutOfSync Application was reported ready")
	}

	only, err := Collect(context.Background(), c, "staging")
	if err != nil {
		t.Fatal(err)
	}
	if len(only.Environments) != 1 || !only.Ready() {
		t.Fatalf("--environment staging = %#v", only.Environments)
	}
	if _, err := Collect(context.Background(), c, "nope"); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("an unknown environment: %v", err)
	}
}

func TestWaitTimesOutWithTheLastReport(t *testing.T) {
	c := fakeClient(object("ApplicationSet", "production", nil), app("production", "bud", "OutOfSync", "Missing"))
	polls := 0
	r, err := Wait(context.Background(), c, "", 10*time.Millisecond, time.Millisecond, func(Report) { polls++ })
	if err == nil {
		t.Fatal("Wait returned success for an unhealthy Application")
	}
	if polls == 0 || len(r.Environments) != 1 {
		t.Fatalf("Wait did not report progress: polls=%d report=%#v", polls, r)
	}
}
