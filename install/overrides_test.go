package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOverridesRouteByComponent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "keycloak.yaml")
	if err := os.WriteFile(file, []byte("ingress:\n  className: from-file\n  host: file.example.com\nreplicas: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(cert, []byte("PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	values, secrets, err := Overrides{
		ValueFiles:   []string{"keycloak=" + file},
		Values:       []string{"keycloak.ingress.className=from-set", "bud.replicas=3"},
		StringValues: []string{"bud.tag=0123"},
		FileValues:   []string{"cert-manager.ca=" + cert},
		JSONValues:   []string{`valkey.resources={"limits":{"cpu":"1"}}`},
		SecretValues: []string{"bud.appApiToken=s3cret"},
	}.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	ingress := values["keycloak"]["ingress"].(map[string]any)
	if ingress["className"] != "from-set" {
		t.Errorf("--set must win over --values: %v", ingress["className"])
	}
	if ingress["host"] != "file.example.com" {
		t.Error("--set replaced sibling keys from the values file")
	}
	if values["bud"]["replicas"] != int64(3) {
		t.Errorf("--set should parse numbers like Helm: %#v", values["bud"]["replicas"])
	}
	if values["bud"]["tag"] != "0123" {
		t.Errorf("--set-string should keep strings: %#v", values["bud"]["tag"])
	}
	if values["cert-manager"]["ca"] != "PEM" {
		t.Errorf("--set-file should read the file: %#v", values["cert-manager"]["ca"])
	}
	if _, ok := values["valkey"]["resources"].(map[string]any); !ok {
		t.Errorf("--set-json was not parsed: %#v", values["valkey"])
	}
	if secrets["bud"]["appApiToken"] != "s3cret" {
		t.Errorf("--set-secret was not routed to bud's secrets: %#v", secrets)
	}
	if _, leaked := values["bud"]["appApiToken"]; leaked {
		t.Error("a --set-secret value landed in the public values")
	}
}

func TestOverridesRejectUnknownComponentAndBareKeys(t *testing.T) {
	_, _, err := Overrides{Values: []string{"keycloack.x=1"}}.Resolve()
	if err == nil || !strings.Contains(err.Error(), "unknown component") || !strings.Contains(err.Error(), "keycloak") {
		t.Fatalf("misspelt component: %v", err)
	}
	_, _, err = Overrides{Values: []string{"bud=1"}}.Resolve()
	if err == nil || !strings.Contains(err.Error(), "as in keycloak.ingress.className") {
		t.Fatalf("a key with no path inside the component: %v", err)
	}
	_, _, err = Overrides{ValueFiles: []string{"just-a-file.yaml"}}.Resolve()
	if err == nil || !strings.Contains(err.Error(), "<component>=<file>") {
		t.Fatalf("--values without a component: %v", err)
	}
}

func TestSetSecretErrorsDoNotEchoTheValue(t *testing.T) {
	_, _, err := Overrides{SecretValues: []string{"bud.a[=super-secret-value"}}.Resolve()
	if err != nil && strings.Contains(err.Error(), "super-secret-value") {
		t.Fatalf("error echoes the secret: %v", err)
	}
}
