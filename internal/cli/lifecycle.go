package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BudEcosystem/budctl/install"
	"github.com/BudEcosystem/budctl/install/components"
	"github.com/BudEcosystem/budctl/status"
	"github.com/BudEcosystem/budctl/sysdump"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newUninstallCommand() *cobra.Command {
	var environment string
	var yes bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove an environment's components from the cluster",
		Long: `Remove an environment's components from the cluster, in the reverse of the
order install synced them. ArgoCD prunes each component's resources before its
Application is deleted.

ArgoCD itself is kept running (remove it with: helm uninstall argocd -n argocd).
The GitOps repository, the namespaces and any PersistentVolumeClaims the
stateful components left behind are not touched.`,
		Example:     "  budctl uninstall --environment production --yes",
		Args:        cobra.NoArgs,
		Annotations: needsCluster("required"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := clusterFrom(cmd.Context())
			if err != nil {
				return err
			}
			if environment == "" {
				r, err := status.Collect(cmd.Context(), client, "")
				if err != nil {
					return err
				}
				if len(r.Environments) != 1 {
					var names []string
					for _, e := range r.Environments {
						names = append(names, e.Name)
					}
					return fmt.Errorf("--environment is required: this cluster has %s", strings.Join(names, ", "))
				}
				environment = r.Environments[0].Name
			}
			if !yes {
				return fmt.Errorf("uninstall deletes environment %q's components from cluster %s; re-run with --yes", environment, client.Context)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Uninstalling environment %s from %s\n", environment, client.Context)
			err = install.Uninstall(cmd.Context(), client, environment, timeout, func(s string) { fmt.Fprintln(out, "  →", s) })
			if err != nil {
				return fmt.Errorf("uninstall: %w", err)
			}
			fmt.Fprintln(out, "Done. ArgoCD is still running; remove it with: helm uninstall argocd -n argocd")
			return nil
		},
	}
	cmd.Flags().StringVar(&environment, "environment", "", "the environment to remove (default: the only one installed)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the removal")
	cmd.Flags().DurationVar(&timeout, "wait-duration", 10*time.Minute, "how long to wait for each component to be pruned")
	return cmd
}

func newSysdumpCommand() *cobra.Command {
	var output string
	var namespaces []string
	var tail int64
	cmd := &cobra.Command{
		Use:   "sysdump",
		Short: "Collect ArgoCD state, pods, events and logs into a zip for debugging",
		Long: `Collect what is needed to debug an installation into one zip: the ArgoCD
Applications and ApplicationSets, the nodes, and the pods, events and recent
container logs of every namespace the platform deploys into. Secrets are never
collected.`,
		Args:        cobra.NoArgs,
		Annotations: needsCluster("required"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := clusterFrom(cmd.Context())
			if err != nil {
				return err
			}
			if output == "" {
				output = "budctl-sysdump-" + time.Now().Format("20060102-150405") + ".zip"
			}
			f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			err = sysdump.Collect(cmd.Context(), client, sysdump.Options{
				Namespaces: namespaces,
				TailLines:  tail,
				Step:       func(s string) { fmt.Fprintln(out, "  →", s) },
			}, f)
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				_ = os.Remove(output)
				return fmt.Errorf("sysdump: %w", err)
			}
			abs, _ := filepath.Abs(output)
			fmt.Fprintln(out, "sysdump written to", abs)
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output-file", "", "zip to write (default: budctl-sysdump-<time>.zip)")
	cmd.Flags().StringSliceVar(&namespaces, "namespaces", nil, "namespaces to collect (default: argocd and every component's)")
	cmd.Flags().Int64Var(&tail, "tail", 500, "log lines to keep per container")
	return cmd
}

func newValuesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "values",
		Short: "Inspect an environment's committed configuration",
	}
	cmd.AddCommand(newValuesViewCommand())
	return cmd
}

func newValuesViewCommand() *cobra.Command {
	var repo, branch, environment, component, recoveryKey, statePath string
	var showSecrets bool
	cmd := &cobra.Command{
		Use:   "view",
		Short: "Print each component's values as committed in the GitOps repository",
		Long: `Clone the GitOps repository and print each component's values for an
environment, as committed. The repository, branch and environment default to
those of the last install run.

With --show-secrets the SOPS files are decrypted too, with the recovery key of
the last run, --recovery-key, or SOPS_AGE_KEY / SOPS_AGE_KEY_FILE.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if statePath == "" {
				var err error
				if statePath, err = install.DefaultStatePath(); err != nil {
					return err
				}
			}
			if state, found, err := install.LoadState(statePath); err == nil && found {
				repo = firstSet(repo, state.Spec.TargetRepo)
				branch = firstSet(branch, state.Spec.PushBranch)
				environment = firstSet(environment, state.Spec.Environment)
				recoveryKey = firstSet(recoveryKey, state.RecoveryPath)
			}
			branch = firstSet(branch, "main")
			if repo == "" || environment == "" {
				return errors.New("values view needs --repo and --environment (there is no previous install run to take them from)")
			}
			if component != "" {
				if _, ok := components.Lookup(component); !ok {
					return fmt.Errorf("unknown component %q (components: %s)", component, strings.Join(components.Names(), ", "))
				}
			}
			// SOPS reads every identity it is given, so the recovery key is added to
			// the operator's own rather than replacing them.
			if showSecrets && recoveryKey != "" {
				key, err := os.ReadFile(recoveryKey)
				if err != nil {
					return fmt.Errorf("--show-secrets: %w", err)
				}
				os.Setenv("SOPS_AGE_KEY", strings.TrimSpace(os.Getenv("SOPS_AGE_KEY")+"\n"+string(key)))
			}
			committed, err := install.ReadCommitted(cmd.Context(), repo, branch, environment, showSecrets)
			if err != nil {
				return fmt.Errorf("values view: %w", err)
			}
			out := cmd.OutOrStdout()
			for _, c := range committed {
				if component != "" && c.Name != component {
					continue
				}
				fmt.Fprintf(out, "# %s · values/%s/values.%s.yaml\n", c.Name, c.Name, environment)
				merged := c.Values
				switch {
				case c.HasSecrets && showSecrets:
					merged = components.Merge(c.Values, c.Secrets)
				case c.HasSecrets:
					fmt.Fprintf(out, "# secrets.%s.yaml is encrypted (--show-secrets decrypts it)\n", environment)
				}
				body, err := yaml.Marshal(merged)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%s---\n", body)
			}
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&repo, "repo", "", "GitOps repository (default: the last install's)")
	fs.StringVar(&branch, "branch", "", "branch (default: the last install's, else main)")
	fs.StringVar(&environment, "environment", "", "environment (default: the last install's)")
	fs.StringVar(&component, "component", "", "print only this component")
	fs.BoolVar(&showSecrets, "show-secrets", false, "decrypt and include the SOPS-encrypted values")
	fs.StringVar(&recoveryKey, "recovery-key", "", "age identity for --show-secrets (default: the last install's)")
	fs.StringVar(&statePath, "state", "", "installer resume-state path to take defaults from")
	return cmd
}

func firstSet(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
