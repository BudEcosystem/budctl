package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/install/gitops"
	"github.com/BudEcosystem/budctl/internal/sops"
	"gopkg.in/yaml.v3"
)

// CommittedComponent is one component's configuration as it is committed in
// the GitOps repository.
type CommittedComponent struct {
	Name   string
	Values map[string]any
	// Secrets is the decrypted SOPS file, when decryption was asked for and
	// possible. HasSecrets says whether the component has one at all.
	Secrets    map[string]any
	HasSecrets bool
}

// ReadCommitted clones the repository and reads every component's committed
// values for the environment. With decrypt set, SOPS files are decrypted with
// whatever age identity SOPS finds (SOPS_AGE_KEY or SOPS_AGE_KEY_FILE).
func ReadCommitted(ctx context.Context, repository, branch, environment string, decrypt bool) ([]CommittedComponent, error) {
	dir, err := os.MkdirTemp("", "budctl-values-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	repo := filepath.Join(dir, "repository")
	if err := gitops.Clone(ctx, repository, branch, repo); err != nil {
		return nil, err
	}
	var out []CommittedComponent
	for _, c := range components.All {
		base := filepath.Join(repo, "values", c.Name)
		valuesPath := filepath.Join(base, "values."+environment+".yaml")
		secretsPath := filepath.Join(base, "secrets."+environment+".yaml")
		cc := CommittedComponent{Name: c.Name}
		found := false
		if body, err := os.ReadFile(valuesPath); err == nil {
			found = true
			if err := yaml.Unmarshal(body, &cc.Values); err != nil {
				return nil, fmt.Errorf("%s: %w", valuesPath, err)
			}
		}
		if _, err := os.Stat(secretsPath); err == nil {
			found, cc.HasSecrets = true, true
			if decrypt {
				cc.Secrets, err = sops.New().Decrypt(secretsPath)
				if err != nil {
					return nil, err
				}
			}
		}
		if found {
			out = append(out, cc)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the repository has no values for environment %q on branch %s", environment, branch)
	}
	return out, nil
}
