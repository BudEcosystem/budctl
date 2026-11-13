// Package cli is budctl's command layer: the cobra tree, flag binding and
// everything that talks to the terminal. Business logic belongs in the
// packages it calls.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BudEcosystem/budctl/defaults"
	"github.com/BudEcosystem/budctl/k8s"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// globalFlags are the flags every command accepts.
type globalFlags struct {
	kubeconfig  string
	kubecontext string
}

const rootLong = `budctl — precheck and install Bud

check needs a target to check against: at least --domain, or an answers file.
Readiness is meaningless against an unstated target: "is 200 GiB enough?" has
no answer until someone says how many models they intend to hold.

budctl with no command runs check.

EXIT CODES
  0 READY    1 NOT READY    2 risks under --strict    3 budctl could not run`

// NewDefaultCommand returns the budctl command tree, reading its arguments
// from os.Args.
func NewDefaultCommand() *cobra.Command {
	root := newRootCommand()
	root.SetArgs(normalizeArgs(root, os.Args[1:]))
	return root
}

func newRootCommand() *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:     "budctl",
		Short:   "Precheck and install Bud",
		Long:    rootLong,
		Version: defaults.Version,
		// Errors and exit codes are reported once, by ExitCode.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return connect(cmd, g)
		},
	}
	root.SetVersionTemplate(clientVersionText())
	wrapFlagHelp(root)
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return fmt.Errorf("%w\n  run '%s --help' for usage", err, cmd.CommandPath())
	})
	root.PersistentFlags().StringVar(&g.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: the usual discovery)")
	root.PersistentFlags().StringVar(&g.kubecontext, "context", "", "kube context to use")
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colour (also NO_COLOR)")
	root.AddCommand(
		newCheckCommand(g),
		newInstallCommand(g),
		newCleanupCommand(),
		newStatusCommand(),
		newUninstallCommand(),
		newSysdumpCommand(),
		newValuesCommand(),
		newCmdrefCommand(),
		newVersionCommand(),
	)
	return root
}

// kubeAnnotation declares whether a command uses the cluster: "required" stops
// the run when no client can be built, "optional" hands the error to the
// command. A command without it never builds a client, so help, completion and
// version --client work with no kubeconfig at all.
const kubeAnnotation = "budctl/kube"

func needsCluster(how string) map[string]string { return map[string]string{kubeAnnotation: how} }

type clusterKey struct{}

type cluster struct {
	client *k8s.Client
	err    error
}

// connect builds the Kubernetes client once for the whole run and puts it in
// the command's context.
func connect(cmd *cobra.Command, g *globalFlags) error {
	how := cmd.Annotations[kubeAnnotation]
	if how == "" {
		return nil
	}
	client, err := k8s.NewClient(g.kubeconfig, g.kubecontext)
	if err != nil && how == "required" {
		return fmt.Errorf("cannot reach the cluster: %w", err)
	}
	cmd.SetContext(context.WithValue(cmd.Context(), clusterKey{}, &cluster{client, err}))
	return nil
}

// clusterFrom returns the client connect built, or why there is none.
func clusterFrom(ctx context.Context) (*k8s.Client, error) {
	c, _ := ctx.Value(clusterKey{}).(*cluster)
	if c == nil {
		return nil, errors.New("no cluster connection was made for this command")
	}
	return c.client, c.err
}

// normalizeArgs keeps command lines written for the Go flag package working.
// That package accepted -flag as well as --flag, while pflag reads -flag as a
// run of shorthands, so a single-dash long flag is rewritten to two dashes. A
// command line that names no command still runs check, as it always has.
func normalizeArgs(root *cobra.Command, args []string) []string {
	long := map[string]bool{"help": true, "version": true}
	commands := map[string]bool{"help": true, "completion": true}
	var collect func(*cobra.Command)
	collect = func(c *cobra.Command) {
		for _, fs := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
			fs.VisitAll(func(f *pflag.Flag) { long[f.Name] = true })
		}
		for _, sub := range c.Commands() {
			commands[sub.Name()] = true
			collect(sub)
		}
	}
	collect(root)

	out := make([]string, 0, len(args)+1)
	for i, a := range args {
		if a == "--" {
			out = append(out, args[i:]...)
			break
		}
		if len(a) > 2 && a[0] == '-' && a[1] != '-' {
			if name, _, _ := strings.Cut(a[1:], "="); long[name] {
				a = "-" + a
			}
		}
		out = append(out, a)
	}

	// A leading word that is not a command is left for cobra to reject.
	if len(out) > 0 && !strings.HasPrefix(out[0], "-") {
		return out
	}
	for _, a := range out {
		if commands[a] || a == "-h" || a == "--help" || a == "-v" || a == "--version" {
			return out
		}
	}
	return append([]string{"check"}, out...)
}

// multiFlag is a repeatable flag that also splits on commas.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Type() string   { return "string" }
func (m *multiFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

// intakeFlags are the answers both check and install ask for.
type intakeFlags struct {
	caBundle       string
	domain         string
	tls            string
	modelStorageGi int
	modelCount     int
	deployments    int
	gpu            bool
	repo           string
	repoKey        string
	registryUser   string
	registryPass   string
}

func (f *intakeFlags) register(fs *pflag.FlagSet) {
	fs.StringVar(&f.caBundle, "ca-bundle", "", "PEM file of extra roots to trust when verifying served certificates (an internal CA)")
	// Intake — FRD-020 §7. These are asked, not guessed.
	fs.StringVar(&f.domain, "domain", "", "root domain the stack will publish under (required)")
	fs.StringVar(&f.tls, "tls", "", "TLS mode: acme-dns01 | acme-http01 | self-signed | internal-ca | external")
	fs.IntVar(&f.modelStorageGi, "model-storage-gi", 0, "GiB of model weight storage to provision for")
	fs.IntVar(&f.modelCount, "models", 0, "roughly how many models will be held")
	fs.IntVar(&f.deployments, "deployments", 0, "expected concurrent model deployments")
	fs.BoolVar(&f.gpu, "gpu", false, "GPU deployments are expected")
	fs.StringVar(&f.repo, "repo", "", "the GitOps repository ArgoCD reads and install pushes to (https://, ssh:// or git@host:org/repo)")
	fs.StringVar(&f.repoKey, "repo-key", "", "SSH deploy-key file ArgoCD clones an ssh:// or git@ repository with")
	fs.StringVar(&f.registryUser, "registry-user", "", "registry.bud.studio robot account (or BUD_REGISTRY_USER)")
	fs.StringVar(&f.registryPass, "registry-password", "", "registry.bud.studio token (or BUD_REGISTRY_PASSWORD)")
}
