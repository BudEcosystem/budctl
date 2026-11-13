package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/BudEcosystem/budctl/internal/probes"
	"github.com/spf13/cobra"
)

func newCleanupCommand() *cobra.Command {
	return &cobra.Command{
		Use:         "cleanup",
		Short:       "Remove probe namespaces left by an interrupted run",
		Args:        cobra.NoArgs,
		Annotations: needsCluster("required"),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cleanup(cmd.Context())
		},
	}
}

func cleanup(ctx context.Context) error {
	kube, err := clusterFrom(ctx)
	if err != nil {
		return err
	}
	removed := 0
	for _, ns := range kube.List(ctx, "namespaces", "") {
		name := ns.Name()
		if ns.Labels()[probes.ManagedByKey] == probes.ManagedByValue || strings.HasPrefix(name, probes.NamePrefix) {
			r := probes.NewRunner(kube, name, "", false)
			_ = r.Ensure(ctx)
			r.Cleanup()
			fmt.Printf("removed probe namespace %s\n", name)
			removed++
		}
	}
	if removed == 0 {
		fmt.Println("nothing to clean up")
	}
	return nil
}
