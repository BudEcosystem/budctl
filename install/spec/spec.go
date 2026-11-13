// Package spec holds the decisions an installation is made from: the Spec the
// operator supplies (or budctl detects), and the credentials budctl generates.
// It is the leaf every other install package builds on.
package spec

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/BudEcosystem/budctl/defaults"
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
	// SkipComponents leaves components out of the installation entirely, for a
	// staged or partial install. Persisted, so a resume keeps them out.
	SkipComponents []string `yaml:"skipComponents,omitempty"`
	StudioModel    string   `yaml:"studioModel,omitempty"`
	// Values and SecretValues are the operator's per-component overrides
	// (--values, --set …, --set-secret), keyed by component name. They are
	// part of the encrypted resume state, so a resumed run renders the same
	// configuration without the flags being repeated.
	Values           map[string]map[string]any `yaml:"values,omitempty"`
	SecretValues     map[string]map[string]any `yaml:"secretValues,omitempty"`
	CABundlePath     string                    `yaml:"-"`
	IssuerCACertPath string                    `yaml:"-"`
	IssuerCAKeyPath  string                    `yaml:"-"`
}

func Defaults() Spec {
	return Spec{
		PushBranch:     defaults.Branch,
		TLS:            TLSACMEDNS01,
		ModelStorageGi: defaults.ModelStorageGi,
		Models:         defaults.Models,
		Deployments:    defaults.Deployments,
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
		s.IngressClass = defaults.IngressClass
	}
	s.IsTraefik = strings.Contains(strings.ToLower(s.IngressClass), "traefik")
	s.RegistryUser = strings.TrimSpace(s.RegistryUser)
	s.AdminEmail = strings.TrimSpace(s.AdminEmail)
	s.RepoSSHKeyPath = strings.TrimSpace(s.RepoSSHKeyPath)
	s.CABundlePath = strings.TrimSpace(s.CABundlePath)
	s.IssuerCACertPath = strings.TrimSpace(s.IssuerCACertPath)
	s.IssuerCAKeyPath = strings.TrimSpace(s.IssuerCAKeyPath)
	if !IsSSHRepository(s.TargetRepo) {
		s.RepoSSHKeyPath = ""
		s.RepoSSHPrivateKey = ""
	}
	if s.PushBranch == "" {
		s.PushBranch = defaults.Branch
	}
	if s.TLS == "" {
		s.TLS = TLSACMEDNS01
	}
	if s.ModelStorageGi <= 0 {
		s.ModelStorageGi = defaults.ModelStorageGi
	}
	if s.Models <= 0 {
		s.Models = defaults.Models
	}
	if s.Deployments <= 0 {
		s.Deployments = defaults.Deployments
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
		if !IsSSHRepository(s.TargetRepo) {
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

// Field names one required decision the Spec does not yet carry. Name is the
// Spec's YAML key, so each frontend can map it to its own way of asking: a
// flag, a form field.
type Field struct {
	Name   string
	Reason string
}

// Missing lists every required decision that is still unset. It reports them
// all at once, so an operator fixes a command line in one pass rather than one
// error at a time. Validate checks the values that are present.
func (s Spec) Missing() []Field {
	var out []Field
	add := func(name, reason string) { out = append(out, Field{name, reason}) }
	if s.TargetRepo == "" {
		add("targetRepo", "the GitOps repository to push the configuration to")
	}
	if IsSSHRepository(s.TargetRepo) && strings.TrimSpace(s.RepoSSHPrivateKey) == "" && s.RepoSSHKeyPath == "" {
		add("repoSSHKeyPath", "an SSH repository needs a deploy key ArgoCD can clone it with")
	}
	if s.Domain == "" {
		add("domain", "the root domain every hostname is published under")
	}
	if s.StorageClass == "" {
		add("storageClass", "the cluster has no unambiguous default StorageClass")
	}
	if s.RegistryUser == "" {
		add("registryUser", "the registry.bud.studio robot account")
	}
	if s.RegistryPassword == "" {
		add("registryPassword", "the registry.bud.studio token")
	}
	if s.AdminEmail == "" {
		add("adminEmail", "the initial Bud administrator")
	}
	switch s.TLS {
	case TLSACMEDNS01:
		if s.CloudflareToken == "" {
			add("cloudflareToken", "ACME DNS-01 solves its challenge through Cloudflare")
		}
	case TLSInternalCA:
		if s.IssuerCACertPEM == "" && s.IssuerCACertPath == "" {
			add("issuerCACertPath", "the internal CA certificate cert-manager issues from")
		}
		if s.IssuerCAKeyPEM == "" && s.IssuerCAKeyPath == "" {
			add("issuerCAKeyPath", "the internal CA private key")
		}
	}
	return out
}

func (s Spec) Validate() error {
	if missing := s.Missing(); len(missing) > 0 {
		names := make([]string, len(missing))
		for i, f := range missing {
			names[i] = f.Name
		}
		return fmt.Errorf("missing %s", strings.Join(names, ", "))
	}
	if !environmentRE.MatchString(s.Environment) {
		return fmt.Errorf("environment must be a DNS-safe name (lowercase letters, numbers and hyphens)")
	}
	if IsSSHRepository(s.TargetRepo) && strings.TrimSpace(s.RepoSSHPrivateKey) == "" {
		return fmt.Errorf("an SSH target repository requires --repo-key so ArgoCD can clone it")
	}
	if !strings.Contains(s.Domain, ".") || strings.ContainsAny(s.Domain, " /:") {
		return fmt.Errorf("domain must be a hostname such as bud.example.com")
	}
	if s.IngressClass == "" {
		return fmt.Errorf("ingress class is required when it cannot be detected from the cluster")
	}
	if !strings.Contains(s.AdminEmail, "@") {
		return fmt.Errorf("a valid initial administrator email is required")
	}
	if s.TrustedCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(s.TrustedCAPEM)) {
			return fmt.Errorf("CA bundle does not contain a valid PEM certificate")
		}
	}
	switch s.TLS {
	case TLSInternalCA:
		pair, err := tls.X509KeyPair([]byte(s.IssuerCACertPEM), []byte(s.IssuerCAKeyPEM))
		if err != nil {
			return fmt.Errorf("internal CA requires a matching PEM certificate and private key: %w", err)
		}
		certificate, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || !certificate.IsCA {
			return fmt.Errorf("internal CA certificate must have CA=true")
		}
	case TLSACMEDNS01, TLSACMEHTTP01, TLSSelfSigned, TLSExternal:
	default:
		return fmt.Errorf("TLS mode must be acme-dns01, acme-http01, self-signed, internal-ca or external")
	}
	return nil
}

// IsSSHRepository reports whether a repository is cloned over SSH, which needs
// a deploy key for ArgoCD.
func IsSSHRepository(repository string) bool {
	return strings.HasPrefix(repository, "ssh://") || strings.HasPrefix(repository, "git@")
}

// RepositoryURL strips embedded HTTP credentials and the .git suffix before a
// repository is written to manifests or terminal output.
func RepositoryURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" {
		u.User = nil
		return strings.TrimSuffix(u.String(), ".git")
	}
	return raw
}
