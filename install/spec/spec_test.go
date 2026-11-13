package spec

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validSpec() Spec {
	s := Defaults()
	s.Environment = "production"
	s.TargetRepo = "https://github.com/example/bud-config.git"
	s.Domain = "bud.example.com"
	s.IngressClass = "nginx"
	s.StorageClass = "standard"
	s.TLS = TLSSelfSigned
	s.RegistryUser = "robot"
	s.RegistryPassword = "registry-secret"
	s.AdminEmail = "admin@example.com"
	s.Normalize()
	return s
}

func TestDefaultsUseMainBranch(t *testing.T) {
	if got := Defaults().PushBranch; got != "main" {
		t.Fatalf("default push branch = %q, want main", got)
	}
}

func TestDefaultIngressIsTraefik(t *testing.T) {
	s := Defaults()
	s.Normalize()
	if s.IngressClass != "traefik" || !s.IsTraefik {
		t.Fatalf("default ingress = %q, isTraefik=%v", s.IngressClass, s.IsTraefik)
	}
	s.IngressClass = "openshift-default"
	s.Normalize()
	if s.IsTraefik {
		t.Fatal("non-Traefik ingress class retained the Traefik chart mode")
	}
}

func TestSpecValidation(t *testing.T) {
	s := validSpec()
	s.Environment = "Not Valid"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "DNS-safe") {
		t.Fatalf("expected environment validation error, got %v", err)
	}
	s = validSpec()
	s.TLS = TLSACMEDNS01
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "cloudflareToken") {
		t.Fatalf("expected DNS credential validation error, got %v", err)
	}
}

// Missing reports everything at once, so a flags-only run can name every
// flag that is still needed in a single error.
func TestMissingListsEveryUnsetDecision(t *testing.T) {
	s := Spec{TLS: TLSInternalCA}
	var names []string
	for _, f := range s.Missing() {
		names = append(names, f.Name)
		if f.Reason == "" {
			t.Errorf("%s is missing without a reason", f.Name)
		}
	}
	want := "targetRepo domain storageClass registryUser registryPassword adminEmail issuerCACertPath issuerCAKeyPath"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("missing = %s\n   want %s", got, want)
	}
	if len(validSpec().Missing()) != 0 {
		t.Fatalf("a complete spec reported missing fields: %v", validSpec().Missing())
	}
}

func TestInternalCAValidation(t *testing.T) {
	certPEM, keyPEM := testCA(t)
	internal := validSpec()
	internal.TLS = TLSInternalCA
	internal.IssuerCACertPEM, internal.IssuerCAKeyPEM = certPEM, keyPEM
	if err := internal.Validate(); err != nil {
		t.Fatalf("valid internal CA rejected: %v", err)
	}
	bad := internal
	bad.IssuerCAKeyPEM = keyPEM[:len(keyPEM)/2]
	if err := bad.Validate(); err == nil {
		t.Fatal("mismatched internal CA material was accepted")
	}
}

func TestLoadTLSMaterialSupportsCorrectionAndClearsIrrelevantSecrets(t *testing.T) {
	certPEM, keyPEM := testCA(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "issuer.crt"), filepath.Join(dir, "issuer.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	s := validSpec()
	s.TLS = TLSInternalCA
	s.IssuerCACertPath, s.IssuerCAKeyPath = certPath, keyPath
	if err := s.LoadTLSMaterial(); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("loaded internal CA material is invalid: %v", err)
	}
	s.TLS = TLSExternal
	if err := s.LoadTLSMaterial(); err != nil {
		t.Fatal(err)
	}
	if s.IssuerCACertPEM != "" || s.IssuerCAKeyPEM != "" || s.TrustedCAPEM != "" {
		t.Fatal("TLS secrets survived after switching to an unrelated mode")
	}
}

func TestRepositoryURLStripsCredentials(t *testing.T) {
	if got := RepositoryURL("https://user:token@github.com/acme/config.git"); got != "https://github.com/acme/config" {
		t.Fatalf("RepositoryURL = %q", got)
	}
	if got := RepositoryURL("git@github.com:acme/config.git"); got != "git@github.com:acme/config.git" {
		t.Fatalf("an SCP-style URL was rewritten: %q", got)
	}
}

func testCA(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "budctl test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(cert), string(privateKey)
}

// The Bud chart uses these as raw AES-256 keys, and the Dapr key as PEM.
func TestGeneratedFixedFormatKeys(t *testing.T) {
	g, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dapr-symmetric", "dapr-budevent", "novu-encryption", "notify-store"} {
		if len(g.Values[name]) != 32 {
			t.Errorf("%s is %d bytes, the chart needs 32", name, len(g.Values[name]))
		}
	}
	if !isPrivateKeyPEM(g.Values["dapr-asymmetric"]) {
		t.Error("dapr-asymmetric is not a PEM private key")
	}
}

// Cached keys from earlier releases are repaired; valid keys are never
// rotated, because that would orphan what was encrypted under them.
func TestRepairSecretsFixesOnlyInvalidKeys(t *testing.T) {
	g, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	valid := g.Values["dapr-budevent"]
	pemKey := g.Values["dapr-asymmetric"]
	g.Values["dapr-symmetric"] = "a-43-character-token-from-an-old-budctl-xyz"
	g.Values["novu-encryption"] = "a-43-character-token-from-an-old-budctl-xyz"
	if err := RepairSecrets(&g); err != nil {
		t.Fatal(err)
	}
	if len(g.Values["dapr-symmetric"]) != 32 || len(g.Values["novu-encryption"]) != 32 {
		t.Error("an invalid cached key was not repaired")
	}
	if g.Values["dapr-budevent"] != valid || g.Values["dapr-asymmetric"] != pemKey {
		t.Error("a valid key was rotated")
	}
}
