package install

import (
	"reflect"
	"testing"
)

func TestArgoFirstInstallValuesSuppressesProjectsWithoutChangingDesiredValues(t *testing.T) {
	desiredProjects := map[string]any{"kind-colima-kind": map[string]any{"description": "target"}}
	desired := map[string]any{
		"global":   map[string]any{"domain": "argocd.example.com"},
		"projects": desiredProjects,
	}
	initial := argoFirstInstallValues(desired)
	projects, ok := initial["projects"].(map[string]any)
	if !ok || len(projects) != 0 {
		t.Fatalf("first install projects = %#v, want an empty map", initial["projects"])
	}
	if len(desired["projects"].(map[string]any)) != 1 {
		t.Fatal("building first-install values mutated the desired projects")
	}
	if !reflect.DeepEqual(initial["global"], desired["global"]) {
		t.Fatal("unrelated ArgoCD values were not preserved")
	}
}
