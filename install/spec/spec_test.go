package spec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

// State saved before Bud chart 1.4.0 has no kv-cache-salt; a resumed install
// gets one, and a valid one is kept, since rotating it empties every tenant's
// shared KV cache.
func TestRepairSecretsAddsKVCacheSalt(t *testing.T) {
	g, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	if !isKVCacheSalt(g.Values["kv-cache-salt"]) {
		t.Fatalf("generated kv-cache-salt %q is not standard base64 of 32+ bytes", g.Values["kv-cache-salt"])
	}
	kept := g.Values["kv-cache-salt"]
	if err := RepairSecrets(&g); err != nil {
		t.Fatal(err)
	}
	if g.Values["kv-cache-salt"] != kept {
		t.Error("a valid kv-cache-salt was rotated")
	}
	for _, old := range []string{"", "a-43-character-token-from-an-old-budctl-xyz"} {
		g.Values["kv-cache-salt"] = old
		if err := RepairSecrets(&g); err != nil {
			t.Fatal(err)
		}
		if !isKVCacheSalt(g.Values["kv-cache-salt"]) {
			t.Errorf("kv-cache-salt %q was not repaired", old)
		}
	}
}

// waav-front-api is generated for state that predates it, and never rotated.
func TestRepairSecretsAddsWaavFrontKey(t *testing.T) {
	g, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	kept := g.Values["waav-front-api"]
	if kept == "" {
		t.Fatal("waav-front-api was not generated")
	}
	if err := RepairSecrets(&g); err != nil {
		t.Fatal(err)
	}
	if g.Values["waav-front-api"] != kept {
		t.Error("an existing waav-front-api was rotated")
	}
	delete(g.Values, "waav-front-api")
	if err := RepairSecrets(&g); err != nil {
		t.Fatal(err)
	}
	if g.Values["waav-front-api"] == "" {
		t.Error("a missing waav-front-api was not added")
	}
}

// decryptPKCS8 opens an encrypted PKCS#8 PEM block the way a reader of the
// Bud chart's RSA key does.
func decryptPKCS8(t *testing.T, privatePEM, password string) *rsa.PrivateKey {
	t.Helper()
	block, rest := pem.Decode([]byte(privatePEM))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("the private key is not a single PEM block")
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" || len(block.Headers) != 0 {
		t.Fatalf("PEM block is %q with headers %v, want a bare ENCRYPTED PRIVATE KEY", block.Type, block.Headers)
	}
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(block.Bytes, &info); err != nil || len(rest) != 0 {
		t.Fatalf("parse EncryptedPrivateKeyInfo: %v", err)
	}
	kdf, enc := info.Algorithm.Parameters.KeyDerivation, info.Algorithm.Parameters.Encryption
	if !info.Algorithm.Algorithm.Equal(oidPBES2) || !kdf.Algorithm.Equal(oidPBKDF2) ||
		!kdf.Parameters.PRF.Algorithm.Equal(oidHMACWithSHA256) || !enc.Algorithm.Equal(oidAES256CBC) {
		t.Fatal("the key is not PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC")
	}
	key, err := pbkdf2.Key(sha256.New, password, kdf.Parameters.Salt, kdf.Parameters.Iterations, 32)
	if err != nil {
		t.Fatal(err)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(c, enc.IV).CryptBlocks(plain, info.EncryptedData)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > aes.BlockSize {
		t.Fatal("wrong password or corrupt key: bad padding")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(plain[:len(plain)-pad])
	if err != nil {
		t.Fatalf("parse decrypted key: %v", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("decrypted key is %T, want RSA", parsed)
	}
	return rsaKey
}

func publicKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// WaaV reads the RSA key as RFC 7468 encrypted PKCS#8 and refuses the legacy
// "Proc-Type" PEM, so the generated key must be the former and must open with
// the generated password.
func TestGeneratedRSAKeyIsEncryptedPKCS8(t *testing.T) {
	g, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	key := decryptPKCS8(t, g.RSAPrivate, g.Values["rsa-password"])
	if publicKeyPEM(t, key) != g.RSAPublic {
		t.Error("the private key does not match the generated public key")
	}
}

// State saved by an earlier budctl holds the legacy form. It is re-wrapped
// with the same key and password, and a converted key is left alone.
func TestRepairSecretsConvertsLegacyRSAKey(t *testing.T) {
	g, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	password := g.Values["rsa-password"]
	legacy, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte(password), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	g.RSAPrivate, g.RSAPublic = string(pem.EncodeToMemory(legacy)), publicKeyPEM(t, key)
	if err := RepairSecrets(&g); err != nil {
		t.Fatal(err)
	}
	if !decryptPKCS8(t, g.RSAPrivate, password).Equal(key) {
		t.Error("the converted key is not the cached key")
	}
	if g.Values["rsa-password"] != password || g.RSAPublic != publicKeyPEM(t, key) {
		t.Error("the password or public key changed")
	}
	converted := g.RSAPrivate
	if err := RepairSecrets(&g); err != nil {
		t.Fatal(err)
	}
	if g.RSAPrivate != converted {
		t.Error("an already converted key was rewritten")
	}
}

// Novu refuses a password without a digit, both letter cases and one of its
// symbols, and budnotify then crash-loops. A refused password is replaced; an
// accepted one is the live admin login and is never rotated.
func TestNovuAdminPasswordMeetsPolicy(t *testing.T) {
	for range 200 {
		password, err := novuPassword()
		if err != nil {
			t.Fatal(err)
		}
		if !isNovuPassword(password) || strings.Contains(password, "_") {
			t.Fatalf("generated password %q does not meet Novu's policy", password)
		}
	}
	g, err := GenerateSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	kept := g.Values["novu-admin"]
	if !isNovuPassword(kept) {
		t.Fatalf("generated novu-admin %q does not meet Novu's policy", kept)
	}
	if err := RepairSecrets(&g); err != nil {
		t.Fatal(err)
	}
	if g.Values["novu-admin"] != kept {
		t.Error("an accepted novu-admin was rotated")
	}
	for _, old := range []string{"", "NoSymbolFromAnOldBudctl_0123456789abcdefghi", "short-A1", strings.Repeat("aA1-", 17)} {
		g.Values["novu-admin"] = old
		if err := RepairSecrets(&g); err != nil {
			t.Fatal(err)
		}
		if old == "short-A1" {
			if g.Values["novu-admin"] != old {
				t.Errorf("accepted password %q was rotated", old)
			}
			continue
		}
		if !isNovuPassword(g.Values["novu-admin"]) || g.Values["novu-admin"] == old {
			t.Errorf("novu-admin %q was not repaired", old)
		}
	}
}
