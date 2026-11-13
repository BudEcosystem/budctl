package install

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BudEcosystem/budctl/install/spec"
	"gopkg.in/yaml.v3"
)

func validSpec() spec.Spec {
	s := spec.Defaults()
	s.Environment = "production"
	s.TargetRepo = "https://github.com/example/bud-config.git"
	s.Domain = "bud.example.com"
	s.IngressClass = "nginx"
	s.StorageClass = "standard"
	s.TLS = spec.TLSSelfSigned
	s.RegistryUser = "robot"
	s.RegistryPassword = "registry-secret"
	s.AdminEmail = "admin@example.com"
	s.Normalize()
	return s
}

func render(t *testing.T, s spec.Spec) Bundle {
	t.Helper()
	generated, err := spec.GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Render(s, generated)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func artifact(t *testing.T, bundle Bundle, path string) []byte {
	t.Helper()
	for _, item := range bundle.Artifacts {
		if item.Path == path {
			return item.Data
		}
	}
	t.Fatalf("artifact %s not found", path)
	return nil
}

func values(t *testing.T, bundle Bundle, component string) map[string]any {
	t.Helper()
	for _, c := range bundle.Components {
		if c.Component.Name == component {
			return c.Values
		}
	}
	t.Fatalf("component %s was not rendered", component)
	return nil
}

func TestSensitiveArtifactsAreSOPSAndDoNotLeak(t *testing.T) {
	s := validSpec()
	bundle := render(t, s)
	if !bytes.Contains(bundle.RecoveryKey, []byte("AGE-SECRET-KEY-")) {
		t.Fatal("bundle has no age recovery identity")
	}
	for _, item := range bundle.Artifacts {
		if !item.Sensitive {
			if bytes.Contains(item.Data, []byte(s.RegistryPassword)) {
				t.Fatalf("%s is committed in plaintext and contains the registry password", item.Path)
			}
			continue
		}
		if !bytes.Contains(item.Data, []byte("sops:")) || !bytes.Contains(item.Data, []byte("ENC[AES256_GCM")) {
			t.Fatalf("%s is marked sensitive but is not a SOPS document", item.Path)
		}
		if bytes.Contains(item.Data, []byte(s.RegistryPassword)) {
			t.Fatalf("%s leaks the registry password", item.Path)
		}
	}
}

func TestRenderIncludesBudStudioWhenSelected(t *testing.T) {
	s := validSpec()
	s.BudStudio = true
	bundle := render(t, s)
	artifact(t, bundle, "values/bud-studio/values.production.yaml")
	artifact(t, bundle, "values/bud-studio/secrets.production.yaml")
}

func TestGeneratedManifestsAreYAML(t *testing.T) {
	bundle := render(t, validSpec())
	for _, path := range []string{"apps/production.yaml", "appsets/production.yaml"} {
		var value any
		if err := yaml.Unmarshal(artifact(t, bundle, path), &value); err != nil {
			t.Fatalf("%s is invalid YAML: %v", path, err)
		}
	}
}

// The internal CA private key must live only in SOPS ciphertext.
func TestInternalCAKeyIsEncrypted(t *testing.T) {
	s := validSpec()
	s.TLS = spec.TLSInternalCA
	s.IssuerCACertPEM = string(readTestdata(t, "ca.crt"))
	s.IssuerCAKeyPEM = string(readTestdata(t, "ca.key"))
	secret := artifact(t, render(t, s), "values/cert-manager/secrets.production.yaml")
	if !bytes.Contains(secret, []byte("sops:")) || bytes.Contains(secret, []byte("PRIVATE KEY")) {
		t.Fatal("internal CA key was not stored exclusively in SOPS ciphertext")
	}
}

func TestRenderKeepsCredentialsStable(t *testing.T) {
	generated, err := spec.GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	first, err := Render(validSpec(), generated)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(validSpec(), generated)
	if err != nil {
		t.Fatal(err)
	}
	if first.AdminPassword != second.AdminPassword || !bytes.Equal(first.RecoveryKey, second.RecoveryKey) {
		t.Fatal("resumed render rotated generated credentials")
	}
}

// The Bud chart evaluates these with tpl. budctl must commit them byte for
// byte; a template engine in budctl would have eaten them.
func TestChartTemplateExpressionsSurviveUnchanged(t *testing.T) {
	file := artifact(t, render(t, validSpec()), "values/bud/values.production.yaml")
	for _, want := range []string{
		`{{ include "bud.ingress.hosts.budadmin" . }}`,
		`{{ include "bud.ingress.url.budplayground" . }}`,
	} {
		if !bytes.Contains(file, []byte(want)) {
			t.Fatalf("bud values lost %s:\n%s", want, file)
		}
	}
	appSet := artifact(t, render(t, validSpec()), "appsets/production.yaml")
	for _, want := range []string{"production-{{.name}}", "{{- if .gitPath }}", "{{- .valueFiles | toYaml | nindent 12 }}"} {
		if !bytes.Contains(appSet, []byte(want)) {
			t.Fatalf("ApplicationSet lost ArgoCD's %s", want)
		}
	}
}

// Precedence: shared layer < values derived from the Spec < operator
// override. The committed file is the merge, so it is what ArgoCD reads.
func TestOverridesWinOverDerivedAndSharedValues(t *testing.T) {
	s := validSpec()
	s.Values = map[string]map[string]any{
		// keycloakValues sets ingress.className from the Spec.
		"keycloak": {"ingress": map[string]any{"className": "custom"}},
		// valkey's base layer sets architecture; nothing derived touches it.
		"valkey": {"brandNew": "added"},
	}
	bundle := render(t, s)
	keycloak := values(t, bundle, "keycloak")
	ingress := keycloak["ingress"].(map[string]any)
	if ingress["className"] != "custom" {
		t.Fatalf("override lost to the derived value: %v", ingress["className"])
	}
	if ingress["host"] != "auth.bud.example.com" {
		t.Fatal("an override replaced its sibling keys instead of merging")
	}
	if values(t, bundle, "valkey")["brandNew"] != "added" {
		t.Fatal("override for a base-only component was dropped")
	}
	committed := artifact(t, bundle, "values/keycloak/values.production.yaml")
	if !bytes.Contains(committed, []byte("className: custom")) {
		t.Fatalf("the committed values file does not carry the override:\n%s", committed)
	}
}

func TestSecretOverridesAreEncrypted(t *testing.T) {
	s := validSpec()
	s.SecretValues = map[string]map[string]any{"bud": {"appApiToken": "operator-chosen-token"}}
	bundle := render(t, s)
	for _, item := range bundle.Artifacts {
		if bytes.Contains(item.Data, []byte("operator-chosen-token")) {
			t.Fatalf("%s carries a --set-secret value in plaintext", item.Path)
		}
	}
	for _, c := range bundle.Components {
		if c.Component.Name == "bud" && c.Secrets["appApiToken"] != "operator-chosen-token" {
			t.Fatal("the secret override did not replace the generated token")
		}
	}
}

func TestOverrideForUnknownOrDisabledComponentFails(t *testing.T) {
	generated, err := spec.GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	s := validSpec()
	s.Values = map[string]map[string]any{"keycloack": {"x": 1}}
	if _, err := Render(s, generated); err == nil || !strings.Contains(err.Error(), "unknown component") || !strings.Contains(err.Error(), "keycloak") {
		t.Fatalf("a misspelt component was not rejected with the valid names: %v", err)
	}
	s = validSpec()
	s.Values = map[string]map[string]any{"bud-studio": {"x": 1}}
	if _, err := Render(s, generated); err == nil || !strings.Contains(err.Error(), "not part of this installation") {
		t.Fatalf("an override for a disabled component was silently ignored: %v", err)
	}
}

// Each ApplicationSet element lists exactly the files the bundle contains,
// after the chart's own files.
func TestApplicationSetReferencesOnlyGeneratedFiles(t *testing.T) {
	bundle := render(t, validSpec())
	paths := map[string]bool{}
	for _, a := range bundle.Artifacts {
		paths[a.Path] = true
	}
	for _, c := range bundle.Components {
		for _, f := range c.ValueFiles {
			if p, ok := strings.CutPrefix(f, "$values/"); ok && !paths[p] {
				t.Errorf("%s references %s, which is not generated", c.Component.Name, p)
			}
		}
	}
}

// A resume re-encrypts every secret; the committed file must be kept when
// the values and recipients are the same, and replaced when either changes.
func TestSameSecretsComparesValuesAndRecipients(t *testing.T) {
	generated, err := spec.GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	s := validSpec()
	first, err := Render(s, generated)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(s, generated)
	if err != nil {
		t.Fatal(err)
	}
	path := "values/bud/secrets.production.yaml"
	a, b := artifact(t, first, path), artifact(t, second, path)
	if bytes.Equal(a, b) {
		t.Fatal("expected SOPS to randomize the ciphertext")
	}
	same := sameSecrets(generated.AgeIdentity)
	if !same(path, a, b) {
		t.Fatal("identical values were reported as changed")
	}
	s.AdminEmail = "someone-else@example.com"
	changed, err := Render(s, generated)
	if err != nil {
		t.Fatal(err)
	}
	if same(path, a, artifact(t, changed, path)) {
		t.Fatal("changed values were reported as unchanged")
	}
	other, err := spec.GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	s = validSpec()
	s.AgeRecipients = []string{other.AgeRecipient}
	recipients, err := Render(s, generated)
	if err != nil {
		t.Fatal(err)
	}
	if same(path, a, artifact(t, recipients, path)) {
		t.Fatal("a new recipient must re-encrypt, even with the same values")
	}
}

func TestSkipComponentLeavesItOutEverywhere(t *testing.T) {
	s := validSpec()
	s.SkipComponents = []string{"bud", "opensandbox"}
	bundle := render(t, s)
	for _, c := range bundle.Components {
		if c.Component.Name == "bud" || c.Component.Name == "opensandbox" {
			t.Fatalf("%s was skipped but still rendered", c.Component.Name)
		}
	}
	for _, a := range bundle.Artifacts {
		if strings.HasPrefix(a.Path, "values/bud/") || strings.HasPrefix(a.Path, "values/opensandbox/") {
			t.Fatalf("%s was generated for a skipped component", a.Path)
		}
	}
	if bytes.Contains(bundle.ApplicationSet, []byte("name: bud\n")) {
		t.Fatal("the ApplicationSet still lists bud")
	}
	generated, _ := spec.GenerateSecrets("")
	for _, bad := range [][]string{{"argocd"}, {"budd"}} {
		s.SkipComponents = bad
		if _, err := Render(s, generated); err == nil {
			t.Errorf("--skip-component %v was accepted", bad)
		}
	}
}
