package install

import (
	"fmt"
	"os"
	"strings"

	"github.com/BudEcosystem/budctl/install/components"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/strvals"
)

// Overrides are the operator's per-component values as given on the command
// line. Every key starts with a component name, which routes it:
// keycloak.ingress.className=nginx sets ingress.className in keycloak's values.
type Overrides struct {
	// ValueFiles are component=path pairs (--values).
	ValueFiles   []string
	Values       []string // --set
	StringValues []string // --set-string
	FileValues   []string // --set-file
	JSONValues   []string // --set-json
	// SecretValues use --set syntax and land in the component's SOPS file.
	SecretValues []string // --set-secret
}

// Empty reports whether no override was given.
func (o Overrides) Empty() bool {
	return len(o.ValueFiles)+len(o.Values)+len(o.StringValues)+len(o.FileValues)+len(o.JSONValues)+len(o.SecretValues) == 0
}

// Resolve parses the overrides into per-component values and secrets.
// Precedence follows Helm: values files first, then --set-json, --set,
// --set-string and --set-file, each later one winning.
func (o Overrides) Resolve() (values, secrets map[string]map[string]any, err error) {
	merged := map[string]any{}
	for _, entry := range o.ValueFiles {
		name, path, ok := strings.Cut(entry, "=")
		if !ok || name == "" || path == "" {
			return nil, nil, fmt.Errorf("--values %q: expected <component>=<file>", entry)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("--values %s: %w", entry, err)
		}
		layer := map[string]any{}
		if err := yaml.Unmarshal(body, &layer); err != nil {
			return nil, nil, fmt.Errorf("--values %s: %w", entry, err)
		}
		merged = components.Merge(merged, map[string]any{name: layer})
	}
	for _, v := range o.JSONValues {
		if err := strvals.ParseJSON(v, merged); err != nil {
			return nil, nil, fmt.Errorf("--set-json %s: %w", v, err)
		}
	}
	for _, v := range o.Values {
		if err := strvals.ParseInto(v, merged); err != nil {
			return nil, nil, fmt.Errorf("--set %s: %w", v, err)
		}
	}
	for _, v := range o.StringValues {
		if err := strvals.ParseIntoString(v, merged); err != nil {
			return nil, nil, fmt.Errorf("--set-string %s: %w", v, err)
		}
	}
	for _, v := range o.FileValues {
		reader := func(rs []rune) (any, error) {
			body, err := os.ReadFile(string(rs))
			return string(body), err
		}
		if err := strvals.ParseIntoFile(v, merged, reader); err != nil {
			return nil, nil, fmt.Errorf("--set-file %s: %w", v, err)
		}
	}
	if values, err = route(merged, "--set"); err != nil {
		return nil, nil, err
	}

	secretMap := map[string]any{}
	for _, v := range o.SecretValues {
		if err := strvals.ParseInto(v, secretMap); err != nil {
			// The value is a secret: report the key only.
			key, _, _ := strings.Cut(v, "=")
			return nil, nil, fmt.Errorf("--set-secret %s: %w", key, err)
		}
	}
	if secrets, err = route(secretMap, "--set-secret"); err != nil {
		return nil, nil, err
	}
	return values, secrets, nil
}

// route splits a merged override tree by its top-level key, the component.
func route(tree map[string]any, flag string) (map[string]map[string]any, error) {
	if len(tree) == 0 {
		return nil, nil
	}
	out := map[string]map[string]any{}
	for name, value := range tree {
		if _, ok := components.Lookup(name); !ok {
			return nil, fmt.Errorf("%s: unknown component %q (components: %s)", flag, name, strings.Join(components.Names(), ", "))
		}
		m, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s %s: a key must name a component and then a value inside it, as in keycloak.ingress.className=nginx", flag, name)
		}
		out[name] = m
	}
	return out, nil
}
