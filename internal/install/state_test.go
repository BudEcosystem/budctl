package install

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultsUseMainBranch(t *testing.T) {
	defaults := Defaults()
	if got := defaults.PushBranch; got != "main" {
		t.Fatalf("default push branch = %q, want main", got)
	}
	if got := defaults.TemplateRepo; got != "https://github.com/BudEcosystem/example-bud-foundry-config.git" {
		t.Fatalf("default template repository = %q", got)
	}
	if len(defaults.TemplateRef) != 40 {
		t.Fatalf("default template ref %q is not a full commit hash", defaults.TemplateRef)
	}
}

func TestStateRoundTripIsEncryptedAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "install-state.age")
	want := State{
		Phase: "generated",
		Spec: Spec{
			Environment:      "production",
			TargetRepo:       "https://example.com/config.git",
			RegistryPassword: "registry-secret-marker",
			IssuerCACertPEM:  "issuer-certificate-marker",
			IssuerCAKeyPEM:   "issuer-private-key-marker",
		},
		Secrets: &GeneratedSecrets{
			AgeIdentity:   "AGE-SECRET-KEY-STATE-MARKER",
			AgeRecipient:  "age1recipient",
			AdminPassword: "admin-secret-marker",
			Values:        map[string]string{"postgres": "database-secret-marker"},
		},
	}
	if err := SaveState(path, want); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"registry-secret-marker", "issuer-certificate-marker", "issuer-private-key-marker", "admin-secret-marker", "database-secret-marker", "AGE-SECRET-KEY-STATE-MARKER"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("encrypted state contains plaintext secret %q", secret)
		}
	}
	for _, privatePath := range []string{path, StateKeyPath(path)} {
		info, err := os.Stat(privatePath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", privatePath, got)
		}
	}

	got, found, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("saved installer state was not found")
	}
	if got.Phase != want.Phase || !reflect.DeepEqual(got.Spec, want.Spec) || !reflect.DeepEqual(got.Secrets, want.Secrets) {
		t.Fatalf("loaded state differs from saved state\n got: %#v\nwant: %#v", got, want)
	}
}

func TestRenderWithSecretsKeepsCredentialsStable(t *testing.T) {
	spec := validSpec()
	generated, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	first, err := RenderWithSecrets(spec, generated)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderWithSecrets(spec, generated)
	if err != nil {
		t.Fatal(err)
	}
	if first.AdminPassword != second.AdminPassword || !bytes.Equal(first.RecoveryKey, second.RecoveryKey) {
		t.Fatal("resumed render rotated generated credentials")
	}
}

func TestResumeOverwritesOnlyGeneratedBundleFiles(t *testing.T) {
	root := t.TempDir()
	first := Bundle{Artifacts: []Artifact{{Path: "values/bud/values.production.yaml", Data: []byte("old\n")}}}
	second := Bundle{Artifacts: []Artifact{{Path: "values/bud/values.production.yaml", Data: []byte("corrected\n")}}}
	if err := writeBundle(root, first, false); err != nil {
		t.Fatal(err)
	}
	if err := writeBundle(root, second, false); err == nil {
		t.Fatal("new installation overwrote an existing environment file")
	}
	if err := writeBundle(root, second, true); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, "values", "bud", "values.production.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "corrected\n" {
		t.Fatalf("resumed content = %q", body)
	}
}

func TestEnsureRecoveryKeyCanResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.agekey")
	bundle := Bundle{RecoveryKey: []byte("same-key\n")}
	if err := EnsureRecoveryKey(path, bundle); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRecoveryKey(path, bundle); err != nil {
		t.Fatalf("matching recovery key rejected on resume: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := EnsureRecoveryKey(path, bundle); err != nil {
		t.Fatalf("lost recovery key was not recreated from cached credentials: %v", err)
	}
	if err := EnsureRecoveryKey(path, Bundle{RecoveryKey: []byte("different-key\n")}); err == nil {
		t.Fatal("mismatched recovery key was accepted")
	}
}

func TestEnsureCACertificateDoesNotReplaceTrustAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bud-ca.crt")
	if err := EnsureCACertificate(path, []byte("first certificate\n")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureCACertificate(path, []byte("first certificate\n")); err != nil {
		t.Fatalf("matching CA was rejected: %v", err)
	}
	if err := EnsureCACertificate(path, []byte("different certificate\n")); err == nil {
		t.Fatal("existing trust anchor was replaced without an error")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("CA mode = %o, want 644", info.Mode().Perm())
	}
}
