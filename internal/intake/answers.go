// Package intake models what the operator is asked before any check runs.
// FRD-020 §7/D6: readiness is meaningless against an unstated target, so
// thresholds are DERIVED from these answers rather than guessed by a fixed
// small/standard/production profile.
package intake

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// TLSMethod decides whether inbound :80 is a blocker.
type TLSMethod string

const (
	TLSACMEHTTP01 TLSMethod = "acme-http01"
	TLSACMEDNS01  TLSMethod = "acme-dns01"
	TLSProvided   TLSMethod = "provided"
	TLSNone       TLSMethod = "none"
)

// Answers is the operator's statement of intent. Every threshold that is not a
// physical constant traces back to a field here.
type Answers struct {
	Domain         string    `yaml:"domain"`
	WildcardDNS    bool      `yaml:"wildcardDns"`
	TLS            TLSMethod `yaml:"tls"`
	CABundle       string    `yaml:"caBundle,omitempty"`
	ModelStorageGi int       `yaml:"modelStorageGi"`
	ModelCount     int       `yaml:"modelCount"`
	Deployments    int       `yaml:"concurrentDeployments"`
	GPU            bool      `yaml:"gpu"`
	RetentionDays  int       `yaml:"observabilityRetentionDays"`
	InClusterData  bool      `yaml:"inClusterDataStores"`
	UseArgoCD      bool      `yaml:"useArgoCd"`
	ConfigRepo     string    `yaml:"configRepo"`
	RegistryUser   string    `yaml:"registryUser,omitempty"`
	RegistryPass   string    `yaml:"registryPassword,omitempty"`
	OpenSandbox    bool      `yaml:"openSandbox"`
}

// Defaults are deliberately modest: a POC-shaped install that a reviewer can
// see is a starting point rather than a recommendation.
func Defaults() Answers {
	return Answers{
		TLS: TLSACMEHTTP01, ModelStorageGi: 200, ModelCount: 5, Deployments: 3,
		RetentionDays: 30, InClusterData: true, UseArgoCD: true,
	}
}

func Load(path string) (Answers, error) {
	a := Defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return a, err
	}
	if err := yaml.Unmarshal(b, &a); err != nil {
		return a, err
	}
	return a, a.Validate()
}

func (a Answers) Save(path string) error {
	b, err := yaml.Marshal(a)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (a Answers) Validate() error {
	if a.Domain == "" {
		return fmt.Errorf("domain is required: it determines every hostname the stack publishes")
	}
	if a.ModelStorageGi <= 0 {
		return fmt.Errorf("modelStorageGi must be positive")
	}
	return nil
}

// Hostnames are the names the chart publishes under the root domain. Per-host
// overrides in values are applied by the config group when --values is given;
// this is the default shape.
func (a Answers) Hostnames() []string {
	if a.Domain == "" {
		return nil
	}
	subs := []string{
		"admin", "app", "gateway", "playground", "customer",
		"ask", "notify", "api.novu", "ws.novu", "mcpgateway", "s3", "auth",
	}
	out := make([]string, 0, len(subs))
	for _, s := range subs {
		out = append(out, s+"."+strings.TrimPrefix(a.Domain, "."))
	}
	return out
}

// StorageComponent is one addend of the storage requirement. The requirement is
// returned as its parts, not as a bare number, because "needs 957 GiB" that the
// operator cannot decompose is a number they cannot argue with or correct.
type StorageComponent struct {
	Label    string
	Gi       int
	Estimate bool // true when the figure is inferred rather than measured
}

// RequiredStorageBreakdown returns the components of the storage requirement in
// the order they are worth reading.
func (a Answers) RequiredStorageBreakdown(profile Profile) []StorageComponent {
	out := []StorageComponent{
		{Label: "model weights", Gi: a.ModelStorageGi},
		{Label: "platform claims", Gi: profile.BaseStorageGi},
	}
	if a.InClusterData {
		out = append(out, StorageComponent{Label: "in-cluster data stores", Gi: profile.DataStoreStorageGi})
		if days := a.RetentionDays * profile.ClickHouseGiPerDay; days > 0 {
			out = append(out, StorageComponent{
				Label:    fmt.Sprintf("traces and metrics (%dd retention)", a.RetentionDays),
				Gi:       days,
				Estimate: true,
			})
		}
	}
	return out
}

// RequiredStorageGi is the total the cluster must be able to provision.
func (a Answers) RequiredStorageGi(profile Profile) int {
	total := 0
	for _, c := range a.RequiredStorageBreakdown(profile) {
		total += c.Gi
	}
	return total
}

// ExplainStorage renders the breakdown as arithmetic the operator can check.
func (a Answers) ExplainStorage(profile Profile) string {
	parts := []string{}
	for _, c := range a.RequiredStorageBreakdown(profile) {
		label := c.Label
		if c.Estimate {
			label += ", estimated"
		}
		parts = append(parts, fmt.Sprintf("%d GiB %s", c.Gi, label))
	}
	return strings.Join(parts, " + ")
}

// RequiredImageFsGi is a physical floor, not an intake answer: it comes from
// measured image sizes and carries a deliberate buffer (FRD-020 §5.6).
func (a Answers) RequiredImageFsGi(profile Profile) int { return profile.ImageFsGi }
