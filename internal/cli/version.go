package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/internal/intake"
	"github.com/BudEcosystem/budctl/k8s"
	"github.com/BudEcosystem/budctl/status"
	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	var clientOnly bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show the budctl version, and what is deployed when a cluster is reachable",
		Args:  cobra.NoArgs,
		// Optional: an unreachable cluster still prints the client version.
		Annotations: needsCluster("optional"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprint(out, clientVersionText())
			if clientOnly {
				return nil
			}
			client, err := clusterFrom(cmd.Context())
			if err != nil {
				fmt.Fprintf(out, "cluster: not reachable (%v)\n", err)
				return nil
			}
			printClusterVersions(cmd, out, client)
			return nil
		},
	}
	cmd.Flags().BoolVar(&clientOnly, "client", false, "print only the budctl version, without contacting a cluster")
	return cmd
}

func printClusterVersions(cmd *cobra.Command, out io.Writer, client *k8s.Client) {
	server, err := client.ServerVersion()
	if err != nil {
		fmt.Fprintf(out, "cluster %s: not reachable (%v)\n", client.Context, err)
		return
	}
	fmt.Fprintf(out, "cluster %s: Kubernetes %s\n", client.Context, server.GitVersion)
	r, err := status.Collect(cmd.Context(), client, "")
	switch {
	case errors.Is(err, status.ErrNoArgoCD), errors.Is(err, status.ErrNotInstalled):
		fmt.Fprintln(out, "  no Bud environment installed")
		return
	case err != nil:
		fmt.Fprintf(out, "  installed versions unknown: %v\n", err)
		return
	}
	for _, e := range r.Environments {
		versions := map[string]string{}
		for _, a := range e.Applications {
			v := orDash(a.Revision)
			if a.Sync != "Synced" {
				v += " (not synced)"
			}
			versions[a.Component] = v
		}
		fmt.Fprintf(out, "  environment %s: bud chart %s, argocd chart %s\n", e.Name, orDash(versions["bud"]), orDash(versions["argocd"]))
	}
}

func clientVersionText() string {
	p, _ := intake.LoadProfile()
	return fmt.Sprintf("budctl %s (%s)\ncheck catalogue %s\n", defaults.Version, defaults.Commit, p.CatalogVersion)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
