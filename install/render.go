package install

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/install/appset"
	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/install/gitops"
	"github.com/BudEcosystem/budctl/install/spec"
	"github.com/BudEcosystem/budctl/internal/sops"
	"gopkg.in/yaml.v3"
)

// RenderedComponent is one component's final configuration.
type RenderedComponent struct {
	Component components.Component
	// Values is what is committed in plaintext: the shared layers, the
	// environment's values and the operator's overrides, merged.
	Values map[string]any
	// Secrets is what is committed SOPS-encrypted. Nil when the component has
	// none.
	Secrets map[string]any
	// ValueFiles is the list the ApplicationSet hands Helm, in order.
	ValueFiles []string
}

type Bundle struct {
	Artifacts        []gitops.File
	Components       []RenderedComponent
	ApplicationSet   []byte
	RootApplication  []byte
	RecoveryKey      []byte
	RecoveryFileName string
	AdminPassword    string
	AgeRecipient     string
	// BootstrapValues exists only in memory. It combines the generated ArgoCD
	// public values and plaintext SOPS identity so the first ArgoCD release can
	// decrypt the same files that are committed for its steady-state upgrade.
	BootstrapValues map[string]any
}

// Render builds an environment from the component table. For each enabled
// component the shared layers, the values derived from the Spec and the
// operator's overrides are merged into one values file, and its credentials
// into one SOPS file; the ApplicationSet lists exactly those files.
//
// Generated credentials are passed in rather than created, so a corrected or
// resumed run keeps every service password. SOPS ciphertext is freshly
// randomized each time.
func Render(s spec.Spec, generated spec.GeneratedSecrets) (Bundle, error) {
	s.Normalize()
	if err := s.Validate(); err != nil {
		return Bundle{}, err
	}
	if generated.AgeIdentity == "" || generated.AgeRecipient == "" || generated.AdminPassword == "" || len(generated.Values) == 0 {
		return Bundle{}, fmt.Errorf("cached generated credentials are incomplete")
	}
	if err := checkOverrides(s); err != nil {
		return Bundle{}, err
	}
	recipients := append([]string{generated.AgeRecipient}, s.AgeRecipients...)
	encrypter := sops.New()
	env := s.Environment

	bundle := Bundle{
		RecoveryKey:      []byte("# created by budctl; keep outside Git\n" + generated.AgeIdentity + "\n"),
		RecoveryFileName: "budctl-" + env + ".agekey",
		AdminPassword:    generated.AdminPassword,
		AgeRecipient:     generated.AgeRecipient,
	}
	var elements []appset.Element
	for _, c := range components.Enabled(s) {
		public, err := c.Base(s)
		if err != nil {
			return Bundle{}, err
		}
		if c.Values != nil {
			public = components.Merge(public, c.Values(s))
		}
		if over := s.Values[c.Name]; over != nil {
			public = components.Merge(public, over)
		}
		var secret map[string]any
		if c.Secrets != nil {
			secret = c.Secrets(s, generated)
		}
		if over := s.SecretValues[c.Name]; over != nil {
			secret = components.Merge(secret, over)
		}

		valueFiles := append([]string(nil), c.ChartValueFiles...)
		if len(public) > 0 {
			path := "values/" + c.Name + "/values." + env + ".yaml"
			data, err := marshalValues(c.Name, env, public)
			if err != nil {
				return Bundle{}, fmt.Errorf("encode %s: %w", path, err)
			}
			bundle.Artifacts = append(bundle.Artifacts, gitops.File{Path: path, Data: data})
			valueFiles = append(valueFiles, "$values/"+path)
		}
		if secret != nil {
			path := "values/" + c.Name + "/secrets." + env + ".yaml"
			plain, err := yaml.Marshal(secret)
			if err != nil {
				return Bundle{}, fmt.Errorf("encode %s: %w", path, err)
			}
			encrypted, err := encrypter.EncryptYAML(plain, recipients)
			if err != nil {
				return Bundle{}, fmt.Errorf("encrypt %s: %w", path, err)
			}
			bundle.Artifacts = append(bundle.Artifacts, gitops.File{Path: path, Data: encrypted, Sensitive: true})
			valueFiles = append(valueFiles, "$values/"+path)
		}

		elements = append(elements, appset.Element{
			Name:           c.Name,
			Namespace:      c.Namespace,
			GitPath:        c.Source.GitPath,
			GitRepoURL:     c.Source.GitRepoURL,
			GitRevision:    c.Source.GitRevision,
			RepoURL:        c.Source.RepoURL,
			Chart:          c.Source.Chart,
			TargetRevision: c.Source.Version,
			ValueFiles:     valueFiles,
		})
		bundle.Components = append(bundle.Components, RenderedComponent{
			Component: c, Values: public, Secrets: secret, ValueFiles: valueFiles,
		})
		if c.Name == "argocd" {
			bundle.BootstrapValues = components.Merge(public, secret)
		}
	}

	repo := spec.RepositoryURL(s.TargetRepo)
	var err error
	if bundle.ApplicationSet, err = appset.Marshal(appset.New(env, repo, s.PushBranch, elements)); err != nil {
		return Bundle{}, fmt.Errorf("encode ApplicationSet: %w", err)
	}
	if bundle.RootApplication, err = appset.Marshal(appset.Root(env, repo, s.PushBranch)); err != nil {
		return Bundle{}, fmt.Errorf("encode root Application: %w", err)
	}
	bundle.Artifacts = append(bundle.Artifacts,
		gitops.File{Path: "appsets/" + env + ".yaml", Data: bundle.ApplicationSet},
		gitops.File{Path: "apps/" + env + ".yaml", Data: bundle.RootApplication},
	)
	sort.Slice(bundle.Artifacts, func(i, j int) bool { return bundle.Artifacts[i].Path < bundle.Artifacts[j].Path })
	return bundle, nil
}

// checkOverrides rejects an override for a component that does not exist or
// is not part of this installation, which would otherwise be silently unused.
func checkOverrides(s spec.Spec) error {
	for _, name := range s.SkipComponents {
		if _, ok := components.Lookup(name); !ok {
			return fmt.Errorf("--skip-component: unknown component %q (components: %s)", name, strings.Join(components.Names(), ", "))
		}
		if name == "argocd" {
			return fmt.Errorf("--skip-component: argocd cannot be skipped; every other component is installed through it")
		}
	}
	for _, set := range []map[string]map[string]any{s.Values, s.SecretValues} {
		for name := range set {
			c, ok := components.Lookup(name)
			if !ok {
				return fmt.Errorf("unknown component %q (components: %s)", name, strings.Join(components.Names(), ", "))
			}
			if !c.IsEnabled(s) {
				return fmt.Errorf("component %q is not part of this installation (TLS %s, Bud Studio %v)", name, s.TLS, s.BudStudio)
			}
		}
	}
	return nil
}

// valuesHeader opens every committed values file, so whoever finds it in the
// repository knows where it came from and how to change it.
const valuesHeader = `# ──────────────────────────────────────────────────────────────────────
#  %s values for environment %q
#  Generated by budctl install. Do not edit: the next install rewrites it.
#
#  Merged in order, each layer overriding the one before:
#    1. budctl's shared defaults for %s
#    2. values derived from the install flags
#    3. --values and --set overrides
#
#  Helm reads this file after the chart's own defaults. To change a
#  value, re-run budctl install with --set or --values.
# ──────────────────────────────────────────────────────────────────────

`

func marshalValues(component, environment string, values map[string]any) ([]byte, error) {
	var out bytes.Buffer
	fmt.Fprintf(&out, valuesHeader, component, environment, component)
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(values); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
