// Package install prepares and applies the supported GitOps installation.
package install

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	DefaultTemplateRepo = "https://github.com/BudEcosystem/example-bud-foundry-config.git"
	LegacyTemplateRepo  = "https://github.com/BudEcosystem/infra.git"
	// Pinned so an installer binary always generates the configuration it was
	// tested against. A budctl release deliberately updates this value.
	DefaultTemplateRef  = "9b4ac59e00a5920e6d624ac33a1e317842da4398"
	DefaultBranch       = "main"
	DefaultIngressClass = "traefik"
	DefaultModelGi      = 300
)

type TLSMode string

const (
	TLSACMEDNS01  TLSMode = "acme-dns01"
	TLSACMEHTTP01 TLSMode = "acme-http01"
	TLSSelfSigned TLSMode = "self-signed"
	TLSInternalCA TLSMode = "internal-ca"
	TLSExternal   TLSMode = "external"
)

// Spec is the small set of installation decisions that cannot safely be
// inferred. Internal service passwords and cryptographic keys are generated.
type Spec struct {
	Environment       string   `yaml:"environment"`
	TargetRepo        string   `yaml:"targetRepo"`
	PushBranch        string   `yaml:"pushBranch"`
	RepoSSHKeyPath    string   `yaml:"repoSSHKeyPath,omitempty"`
	RepoSSHPrivateKey string   `yaml:"repoSSHPrivateKey,omitempty"`
	Domain            string   `yaml:"domain"`
	IngressClass      string   `yaml:"ingressClass"`
	IsTraefik         bool     `yaml:"isTraefik"`
	IsOpenShift       bool     `yaml:"isOpenShift"`
	TLS               TLSMode  `yaml:"tls"`
	StorageClass      string   `yaml:"storageClass"`
	ModelStorageGi    int      `yaml:"modelStorageGi"`
	Models            int      `yaml:"models"`
	Deployments       int      `yaml:"deployments"`
	GPU               bool     `yaml:"gpu"`
	RegistryUser      string   `yaml:"registryUser"`
	RegistryPassword  string   `yaml:"registryPassword"`
	AdminEmail        string   `yaml:"adminEmail"`
	AdminPassword     string   `yaml:"adminPassword,omitempty"`
	CloudflareToken   string   `yaml:"cloudflareToken,omitempty"`
	TrustedCAPEM      string   `yaml:"trustedCAPEM,omitempty"`
	IssuerCACertPEM   string   `yaml:"issuerCACertPEM,omitempty"`
	IssuerCAKeyPEM    string   `yaml:"issuerCAKeyPEM,omitempty"`
	AgeRecipients     []string `yaml:"ageRecipients,omitempty"`
	BudStudio         bool     `yaml:"budStudio"`
	StudioModel       string   `yaml:"studioModel,omitempty"`
	TemplateRepo      string   `yaml:"templateRepo"`
	TemplateRef       string   `yaml:"templateRef"`
	CABundlePath      string   `yaml:"-"`
	IssuerCACertPath  string   `yaml:"-"`
	IssuerCAKeyPath   string   `yaml:"-"`
}

func Defaults() Spec {
	return Spec{
		PushBranch:     DefaultBranch,
		TLS:            TLSACMEDNS01,
		ModelStorageGi: DefaultModelGi,
		Models:         5,
		Deployments:    3,
		TemplateRepo:   DefaultTemplateRepo,
		TemplateRef:    DefaultTemplateRef,
	}
}

var environmentRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (s *Spec) Normalize() {
	s.Environment = strings.ToLower(strings.TrimSpace(s.Environment))
	s.TargetRepo = strings.TrimSpace(s.TargetRepo)
	s.PushBranch = strings.TrimSpace(s.PushBranch)
	s.Domain = strings.Trim(strings.ToLower(strings.TrimSpace(s.Domain)), ".")
	s.IngressClass = strings.TrimSpace(s.IngressClass)
	if s.IngressClass == "" {
		s.IngressClass = DefaultIngressClass
	}
	s.IsTraefik = strings.Contains(strings.ToLower(s.IngressClass), "traefik")
	s.RegistryUser = strings.TrimSpace(s.RegistryUser)
	s.AdminEmail = strings.TrimSpace(s.AdminEmail)
	s.TemplateRepo = strings.TrimSpace(s.TemplateRepo)
	s.TemplateRef = strings.TrimSpace(s.TemplateRef)
	s.RepoSSHKeyPath = strings.TrimSpace(s.RepoSSHKeyPath)
	s.CABundlePath = strings.TrimSpace(s.CABundlePath)
	s.IssuerCACertPath = strings.TrimSpace(s.IssuerCACertPath)
	s.IssuerCAKeyPath = strings.TrimSpace(s.IssuerCAKeyPath)
	if !isSSHRepository(s.TargetRepo) {
		s.RepoSSHKeyPath = ""
		s.RepoSSHPrivateKey = ""
	}
	if s.PushBranch == "" {
		s.PushBranch = DefaultBranch
	}
	if s.TLS == "" {
		s.TLS = TLSACMEDNS01
	}
	if s.ModelStorageGi <= 0 {
		s.ModelStorageGi = DefaultModelGi
	}
	if s.Models <= 0 {
		s.Models = 5
	}
	if s.Deployments <= 0 {
		s.Deployments = 3
	}
	if s.TemplateRepo == "" {
		s.TemplateRepo = DefaultTemplateRepo
	}
	if s.TemplateRef == "" {
		s.TemplateRef = DefaultTemplateRef
	}
}

// LoadTLSMaterial imports user-selected CA files into the encrypted resume
// state. The source paths themselves are local hints and are never rendered.
func (s *Spec) LoadTLSMaterial() error {
	for _, material := range []struct {
		path   string
		target *string
	}{
		{s.CABundlePath, &s.TrustedCAPEM},
		{s.IssuerCACertPath, &s.IssuerCACertPEM},
		{s.IssuerCAKeyPath, &s.IssuerCAKeyPEM},
	} {
		path, target := material.path, material.target
		if path == "" {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read CA material %s: %w", path, err)
		}
		*target = string(body)
	}
	if s.TLS != TLSInternalCA {
		s.IssuerCACertPEM, s.IssuerCAKeyPEM = "", ""
	}
	if s.TLS != TLSSelfSigned && s.TLS != TLSInternalCA {
		s.TrustedCAPEM = ""
	}
	return nil
}

// LoadRepositoryKey reads the Git deploy key only into memory. Render places
// it in the SOPS-encrypted ArgoCD values; it is never emitted as plaintext.
func (s *Spec) LoadRepositoryKey() error {
	if s.RepoSSHKeyPath == "" {
		if !isSSHRepository(s.TargetRepo) {
			s.RepoSSHPrivateKey = ""
		}
		return nil
	}
	body, err := os.ReadFile(s.RepoSSHKeyPath)
	if err != nil {
		return fmt.Errorf("read repository SSH key: %w", err)
	}
	s.RepoSSHPrivateKey = string(body)
	return nil
}

func (s Spec) Validate() error {
	if !environmentRE.MatchString(s.Environment) {
		return fmt.Errorf("environment must be a DNS-safe name (lowercase letters, numbers and hyphens)")
	}
	if s.TargetRepo == "" {
		return fmt.Errorf("target repository is required")
	}
	if isSSHRepository(s.TargetRepo) && strings.TrimSpace(s.RepoSSHPrivateKey) == "" {
		return fmt.Errorf("an SSH target repository requires --repo-ssh-key so ArgoCD can clone it")
	}
	if s.Domain == "" || !strings.Contains(s.Domain, ".") || strings.ContainsAny(s.Domain, " /:") {
		return fmt.Errorf("domain must be a hostname such as bud.example.com")
	}
	if s.IngressClass == "" {
		return fmt.Errorf("ingress class is required when it cannot be detected from the cluster")
	}
	if s.StorageClass == "" {
		return fmt.Errorf("storage class is required when the cluster has no unambiguous default")
	}
	if s.RegistryUser == "" || s.RegistryPassword == "" {
		return fmt.Errorf("registry.bud.studio username and token are required for installation")
	}
	if s.AdminEmail == "" || !strings.Contains(s.AdminEmail, "@") {
		return fmt.Errorf("a valid initial administrator email is required")
	}
	if s.TrustedCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(s.TrustedCAPEM)) {
			return fmt.Errorf("CA bundle does not contain a valid PEM certificate")
		}
	}
	switch s.TLS {
	case TLSACMEDNS01:
		if s.CloudflareToken == "" {
			return fmt.Errorf("Cloudflare API token is required for the current DNS-01 installer")
		}
	case TLSInternalCA:
		pair, err := tls.X509KeyPair([]byte(s.IssuerCACertPEM), []byte(s.IssuerCAKeyPEM))
		if err != nil {
			return fmt.Errorf("internal CA requires a matching PEM certificate and private key: %w", err)
		}
		certificate, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || !certificate.IsCA {
			return fmt.Errorf("internal CA certificate must have CA=true")
		}
	case TLSACMEHTTP01, TLSSelfSigned, TLSExternal:
	default:
		return fmt.Errorf("TLS mode must be acme-dns01, acme-http01, self-signed, internal-ca or external")
	}
	return nil
}

func isSSHRepository(repository string) bool {
	return strings.HasPrefix(repository, "ssh://") || strings.HasPrefix(repository, "git@")
}

// IsMaintainedTemplateRepository identifies both the current installer
// template and the legacy infra source used by early installer builds, while
// tolerating the optional .git suffix. Legacy resume state can then advance to
// the current template rather than looking for installer-only files in infra.
func IsMaintainedTemplateRepository(repository string) bool {
	normalize := func(value string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ".git"))
	}
	value := normalize(repository)
	return value == normalize(DefaultTemplateRepo) || value == normalize(LegacyTemplateRepo)
}
