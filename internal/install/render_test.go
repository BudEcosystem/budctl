package install

import (
	"bytes"
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

	"gopkg.in/yaml.v3"
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

func TestRenderUsesChartDefaultsAndEnablesOnlyDefaultOffServices(t *testing.T) {
	spec := validSpec()
	bundle, err := Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	bud := artifact(t, bundle, "values/bud/values.production.yaml")
	if bytes.Contains(bud, []byte("enabled: false")) {
		t.Fatalf("normal service was disabled in generated Bud values:\n%s", bud)
	}
	values := budValues(spec)
	services := values["microservices"].(map[string]any)
	for _, service := range []string{"budeval", "budcodeinterpreter"} {
		config := services[service].(map[string]any)
		if config["enabled"] != true {
			t.Errorf("chart-default-off service %s was not enabled", service)
		}
	}
	for _, service := range []string{"askbud", "budadmin", "budcustomer", "buddoc", "budpipeline", "budsentinel", "semanticRouter"} {
		if _, present := services[service]; present {
			t.Errorf("chart-default-on service %s was redundantly overridden", service)
		}
	}
	if _, present := services["budapp"].(map[string]any)["enabled"]; present {
		t.Fatal("budapp enabled flag was redundantly overridden")
	}
	if !bytes.Contains(bundle.RecoveryKey, []byte("AGE-SECRET-KEY-")) {
		t.Fatal("bundle has no age recovery identity")
	}

	for _, item := range bundle.Artifacts {
		if !item.Sensitive {
			continue
		}
		if !bytes.Contains(item.Data, []byte("sops:")) || !bytes.Contains(item.Data, []byte("ENC[AES256_GCM")) {
			t.Fatalf("%s is marked sensitive but is not a SOPS document", item.Path)
		}
		if bytes.Contains(item.Data, []byte(spec.RegistryPassword)) {
			t.Fatalf("%s leaks the registry password", item.Path)
		}
	}
}

func TestDefaultIngressIsTraefik(t *testing.T) {
	spec := Defaults()
	spec.Normalize()
	if spec.IngressClass != "traefik" || !spec.IsTraefik {
		t.Fatalf("default ingress = %q, isTraefik=%v", spec.IngressClass, spec.IsTraefik)
	}
	spec.IngressClass = "openshift-default"
	spec.Normalize()
	if spec.IsTraefik {
		t.Fatal("non-Traefik ingress class retained the Traefik chart mode")
	}
}

func TestBudValuesIncludeReferenceRedirectFlow(t *testing.T) {
	values := budValues(validSpec())
	services := values["microservices"].(map[string]any)
	budapp := services["budapp"].(map[string]any)
	redirect := budapp["redirectFlow"].(map[string]any)
	clients := redirect["clientsByHost"].(map[string]any)
	for _, name := range []string{"budadmin", "budcustomer", "budplayground"} {
		client := clients[name].(map[string]any)
		hosts := client["hosts"].([]any)
		origins := client["allowedReturnUrlOrigins"].([]any)
		if len(hosts) != 1 || len(origins) != 1 || !strings.Contains(hosts[0].(string), "bud.ingress.hosts."+name) || !strings.Contains(origins[0].(string), "bud.ingress.url."+name) {
			t.Fatalf("redirect flow for %s does not match the infra reference: %#v", name, client)
		}
	}
}

func TestRenderIncludesBudStudioWhenSelected(t *testing.T) {
	spec := validSpec()
	spec.BudStudio = true
	bundle, err := Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	artifact(t, bundle, "values/bud-studio/values.production.yaml")
	artifact(t, bundle, "values/bud-studio/secrets.production.yaml")
}

func TestOpenSandboxAndCodeInterpreterShareAPIKey(t *testing.T) {
	spec := validSpec()
	generated := GeneratedSecrets{Values: map[string]string{"opensandbox-api": "shared-key"}}
	bud := budSecrets(spec, generated)
	services := bud["microservices"].(map[string]any)
	interpreter := services["budcodeinterpreter"].(map[string]any)
	interpreterEnv := interpreter["env"].(map[string]any)
	if interpreterEnv["SECRETS_OPENSANDBOX_API_KEY"] != "shared-key" {
		t.Fatal("Bud code interpreter does not receive the OpenSandbox API key")
	}
	sandbox := openSandboxSecrets(spec, generated)
	chart := sandbox["opensandbox"].(map[string]any)
	server := chart["opensandbox-server"].(map[string]any)["server"].(map[string]any)
	env := server["env"].([]any)
	if env[0].(map[string]any)["value"] != "shared-key" {
		t.Fatal("OpenSandbox server does not receive the shared API key")
	}
}

func TestGeneratedManifestsAreYAML(t *testing.T) {
	bundle, err := Render(validSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"apps/production.yaml", "appsets/production.yaml"} {
		var value any
		if err := yaml.Unmarshal(artifact(t, bundle, path), &value); err != nil {
			t.Fatalf("%s is invalid YAML: %v", path, err)
		}
	}
}

func TestSpecValidation(t *testing.T) {
	spec := validSpec()
	spec.Environment = "Not Valid"
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "DNS-safe") {
		t.Fatalf("expected environment validation error, got %v", err)
	}
	spec = validSpec()
	spec.TLS = TLSACMEDNS01
	if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "Cloudflare") {
		t.Fatalf("expected DNS credential validation error, got %v", err)
	}
}

func TestArgoCDReceivesPrivateOCIRepositoryCredentials(t *testing.T) {
	spec := validSpec()
	values := argocdSecrets(spec, GeneratedSecrets{AgeIdentity: "AGE-SECRET-KEY-TEST"})
	argo := values["argo-cd"].(map[string]any)
	configs := argo["configs"].(map[string]any)
	repositories := configs["repositories"].(map[string]any)
	repository := repositories["bud-charts"].(map[string]any)
	if repository["url"] != "registry.bud.studio/charts" || repository["enableOCI"] != "true" {
		t.Fatalf("unexpected OCI repository configuration: %#v", repository)
	}
	if repository["username"] != spec.RegistryUser || repository["password"] != spec.RegistryPassword {
		t.Fatal("OCI repository does not use the selected registry credentials")
	}
}

func TestKeycloakOverridesAllEnvironmentURLs(t *testing.T) {
	values := keycloakValues(validSpec())
	realms := values["realms"].(map[string]any)
	realm := realms["keycloak-bud-keycloak-realm"].(map[string]any)
	clients := realm["clients"].(map[string]any)
	customer := clients["budcustomer-web"].(map[string]any)
	redirects := customer["redirectUris"].([]any)
	if !containsAny(redirects, "https://customer.bud.example.com/*") {
		t.Fatalf("customer wildcard redirect is absent: %#v", redirects)
	}
	for _, client := range []string{"budadmin-web", "budcustomer-web", "budplayground-web", "mcp-gateway"} {
		attributes := clients[client].(map[string]any)["attributes"].(map[string]any)
		logout, _ := attributes["post.logout.redirect.uris"].(string)
		if logout == "" || strings.Contains(logout, "bud.lan") {
			t.Fatalf("%s retains an invalid logout URL: %q", client, logout)
		}
	}
}

func TestCertificateModesMatchInstallationContract(t *testing.T) {
	dns := validSpec()
	dns.TLS = TLSACMEDNS01
	dns.CloudflareToken = "cloudflare-token"
	dnsValues := certManagerValues(dns)
	issuers := dnsValues["issuers"].(map[string]any)
	acme := issuers["letsencrypt-dns01"].(map[string]any)["acme"].(map[string]any)
	if acme["profile"] != "tlsserver" {
		t.Fatalf("DNS issuer profile = %#v", acme["profile"])
	}

	certPEM, keyPEM := testCA(t)
	internal := validSpec()
	internal.TLS = TLSInternalCA
	internal.IssuerCACertPEM, internal.IssuerCAKeyPEM = certPEM, keyPEM
	if err := internal.Validate(); err != nil {
		t.Fatalf("valid internal CA rejected: %v", err)
	}
	bundle, err := Render(internal)
	if err != nil {
		t.Fatalf("render internal CA installation: %v", err)
	}
	secret := artifact(t, bundle, "values/cert-manager/secrets.production.yaml")
	if !bytes.Contains(secret, []byte("sops:")) || bytes.Contains(secret, []byte("PRIVATE KEY")) {
		t.Fatal("internal CA key was not stored exclusively in SOPS ciphertext")
	}
	values := certManagerValues(internal)
	issuer := values["issuers"].(map[string]any)["bud-internal-ca"].(map[string]any)
	if issuer["ca"].(map[string]any)["secretName"] != "bud-internal-ca" {
		t.Fatalf("internal issuer does not reference encrypted CA Secret: %#v", issuer)
	}

	bad := internal
	bad.IssuerCAKeyPEM = keyPEM[:len(keyPEM)/2]
	if err := bad.Validate(); err == nil {
		t.Fatal("mismatched internal CA material was accepted")
	}
}

func TestOpenShiftAddsSeaweedFSWebhookOverride(t *testing.T) {
	spec := validSpec()
	spec.IsOpenShift = true
	values := seaweedValues(spec)
	operator := values["seaweedfs-operator"].(map[string]any)
	webhook := operator["webhook"].(map[string]any)
	if value, present := webhook["podSecurityContext"]; !present || value != nil {
		t.Fatalf("OpenShift webhook podSecurityContext override = %#v", webhook)
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
	spec := validSpec()
	spec.TLS = TLSInternalCA
	spec.IssuerCACertPath, spec.IssuerCAKeyPath = certPath, keyPath
	if err := spec.LoadTLSMaterial(); err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(); err != nil {
		t.Fatalf("loaded internal CA material is invalid: %v", err)
	}
	spec.TLS = TLSExternal
	if err := spec.LoadTLSMaterial(); err != nil {
		t.Fatal(err)
	}
	if spec.IssuerCACertPEM != "" || spec.IssuerCAKeyPEM != "" || spec.TrustedCAPEM != "" {
		t.Fatal("TLS secrets survived after switching to an unrelated mode")
	}
}

func containsAny(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
