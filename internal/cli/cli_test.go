package cli

import (
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/BudEcosystem/budctl/check"
	"github.com/spf13/cobra"
)

// parse runs flag parsing for the command the arguments select, without
// running it.
func parse(t *testing.T, args ...string) (*cobra.Command, error) {
	t.Helper()
	root := newRootCommand()
	cmd, rest, err := root.Find(normalizeArgs(root, args))
	if err != nil {
		return nil, err
	}
	return cmd, cmd.ParseFlags(rest)
}

func TestParseInstallFlags(t *testing.T) {
	g := &globalFlags{}
	p := &installParams{globalFlags: g}
	cmd := &cobra.Command{}
	p.register(cmd.Flags())
	err := cmd.ParseFlags([]string{"--repo", "https://example.com/config.git", "--environment", "prod", "--tls", "internal-ca", "--ca-bundle", "/tmp/trust.pem", "--issuer-ca-cert", "/tmp/issuer.crt", "--issuer-ca-key", "/tmp/issuer.key", "--bud-studio", "--state", "/tmp/budctl-state", "--fresh", "--dry-run"})
	if err != nil {
		t.Fatal(err)
	}
	if p.repo == "" || p.environment != "prod" || p.tls != "internal-ca" || p.caBundle != "/tmp/trust.pem" || p.issuerCACert != "/tmp/issuer.crt" || p.issuerCAKey != "/tmp/issuer.key" || !p.budStudio || p.statePath != "/tmp/budctl-state" || !p.fresh || p.dryRun != "plan" {
		t.Fatalf("install flags not retained: %+v", p)
	}
	for _, name := range []string{"repo", "environment", "tls", "ca-bundle", "issuer-ca-cert", "issuer-ca-key", "bud-studio", "state", "fresh", "dry-run"} {
		if !p.isSet(name) {
			t.Errorf("explicit flag %q was not tracked", name)
		}
	}
	if p.isSet("domain") {
		t.Error("an omitted flag was reported as set")
	}
}

// check takes every install flag (TestCheckParsesAnInstallCommandLine); the
// reverse, and intake flags on other commands, are still rejected.
func TestParseRejectsFlagsFromAnotherCommand(t *testing.T) {
	if _, err := parse(t, "install", "--external-datastores"); err == nil {
		t.Fatal("install accepted a check-only flag")
	}
	if _, err := parse(t, "cleanup", "--domain", "x"); err == nil {
		t.Fatal("cleanup accepted an intake flag")
	}
}

func TestNormalizeArgs(t *testing.T) {
	root := newRootCommand()
	cases := []struct{ in, want []string }{
		{nil, []string{"check"}},
		{[]string{"--domain", "x"}, []string{"check", "--domain", "x"}},
		{[]string{"-domain=x", "-gpu"}, []string{"check", "--domain=x", "--gpu"}},
		{[]string{"--context", "kind", "install"}, []string{"--context", "kind", "install"}},
		{[]string{"install", "-yes"}, []string{"install", "--yes"}},
		{[]string{"check", "-o", "json"}, []string{"check", "-o", "json"}},
		{[]string{"check", "-ojson"}, []string{"check", "-ojson"}},
		{[]string{"-help"}, []string{"--help"}},
		{[]string{"-version"}, []string{"--version"}},
		{[]string{"-v"}, []string{"-v"}},
		{[]string{"completion", "bash"}, []string{"completion", "bash"}},
		{[]string{"bogus"}, []string{"bogus"}},
		{[]string{"check", "--", "-domain"}, []string{"check", "--", "-domain"}},
	}
	for _, c := range cases {
		if got := normalizeArgs(root, c.in); !slices.Equal(got, c.want) {
			t.Errorf("normalizeArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultsToCheck(t *testing.T) {
	cmd, err := parse(t, "-domain", "bud.example.com", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Name() != "check" {
		t.Fatalf("no command ran %q, want check", cmd.Name())
	}
	if got, _ := cmd.Flags().GetString("domain"); got != "bud.example.com" {
		t.Fatalf("--domain = %q", got)
	}
}

func TestExitCodes(t *testing.T) {
	if got := ExitCode(nil); got != 0 {
		t.Errorf("nil → %d", got)
	}
	if got := ExitCode(exitCode(2)); got != 2 {
		t.Errorf("ExitError{2} → %d", got)
	}
	// A bad flag or unknown command is "budctl could not run".
	for _, args := range [][]string{{"bogus"}, {"check", "--bud-studio"}, {"check", "--egress-from", "moon"}} {
		root := newRootCommand()
		root.SetArgs(normalizeArgs(root, args))
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		if got := ExitCode(root.Execute()); got != 3 {
			t.Errorf("%q → %d, want 3", args, got)
		}
	}
}

func TestHelpIsGenerated(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"check", "--help"}, {"install", "--help"}} {
		root := newRootCommand()
		var out strings.Builder
		root.SetArgs(normalizeArgs(root, args))
		root.SetOut(&out)
		if err := root.Execute(); err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		if !strings.Contains(out.String(), "Usage:") {
			t.Errorf("%q printed no usage:\n%s", args, out.String())
		}
	}
}

func TestVerdictExitCodes(t *testing.T) {
	cases := []struct {
		verdict check.Verdict
		strict  bool
		want    int
	}{
		{check.Ready, false, 0},
		{check.Ready, true, 0},
		{check.ReadyWithRisks, false, 0},
		{check.ReadyWithRisks, true, 2},
		{check.NotReady, false, 1},
		{check.NotReady, true, 1},
	}
	for _, c := range cases {
		if got := verdictExitCode(c.verdict, c.strict); got != c.want {
			t.Errorf("verdictExitCode(%s, strict=%v) = %d, want %d", c.verdict, c.strict, got, c.want)
		}
	}
}

func TestInstallDryRunForms(t *testing.T) {
	for args, want := range map[string]string{
		"--dry-run":           "plan",
		"--dry-run=manifests": "manifests",
	} {
		p := &installParams{globalFlags: &globalFlags{}}
		cmd := &cobra.Command{}
		p.register(cmd.Flags())
		if err := cmd.ParseFlags([]string{args}); err != nil {
			t.Fatal(err)
		}
		if err := p.validate(); err != nil {
			t.Fatal(err)
		}
		if p.dryRun != want {
			t.Errorf("%s → dry-run %q, want %q", args, p.dryRun, want)
		}
	}
	p := &installParams{globalFlags: &globalFlags{}}
	cmd := &cobra.Command{}
	p.register(cmd.Flags())
	_ = cmd.ParseFlags([]string{"--dry-run=everything"})
	if err := p.validate(); err == nil {
		t.Fatal("an unknown --dry-run mode was accepted")
	}
}

// A flags-only install with nothing set must name every flag it needs, at
// once, and change nothing.
func TestInstallListsMissingFlags(t *testing.T) {
	root := newRootCommand()
	var out strings.Builder
	root.SetArgs([]string{"install", "--state", t.TempDir() + "/state.age", "--kubeconfig", "/nonexistent", "--dry-run"})
	root.SetOut(&out)
	root.SetErr(io.Discard)
	err := root.Execute()
	if err == nil {
		t.Fatal("install with no flags succeeded")
	}
	for _, flag := range []string{"--repo", "--domain", "--registry-user", "--admin-email", "--cloudflare-token"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("missing-flags error does not name %s:\n%v", flag, err)
		}
	}
	if ExitCode(err) != 3 {
		t.Errorf("exit code %d, want 3", ExitCode(err))
	}
}

// check and install take the same command line: one --repo, one set of --tls
// modes, and --values as <component>=<file>.
func TestCheckAcceptsInstallFlags(t *testing.T) {
	for mode, want := range map[string]string{
		"self-signed": "provided", "internal-ca": "provided", "external": "provided",
		"acme-dns01": "acme-dns01", "acme-http01": "acme-http01",
	} {
		if got := string(checkTLS(mode)); got != want {
			t.Errorf("--tls %s: check reads %s, want %s", mode, got, want)
		}
	}
	got := budValuesFiles([]string{"bud=a.yaml", "kafka=b.yaml"})
	if strings.Join(got, " ") != "a.yaml" {
		t.Errorf("--values = %v", got)
	}
	for _, name := range []string{"check", "install"} {
		cmd, _, err := newRootCommand().Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Flags().Lookup("repo") == nil {
			t.Errorf("%s has no --repo", name)
		}
		if cmd.Flags().Lookup("repo-key") == nil {
			t.Errorf("%s has no --repo-key", name)
		}
	}
}

// An install command line, pasted after "budctl check", parses.
func TestCheckParsesAnInstallCommandLine(t *testing.T) {
	root := newRootCommand()
	cmd, _, err := root.Find([]string{"check"})
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.ParseFlags([]string{
		"--registry-user", "u", "--registry-password", "p",
		"--repo", "git@github.com:acme/config.git", "--repo-key", "./key",
		"--environment", "e2e", "--domain", "bud.example.com", "--tls", "self-signed",
		"--admin-email", "admin@example.com", "--model-storage-gi", "50",
		"--skip-component", "bud", "--set", "argocd.a.b=1", "--values", "bud=v.yaml",
		"--state", "s.age", "--recovery-key", "k", "--yes", "--dry-run",
	})
	if err != nil {
		t.Fatalf("check rejected an install command line: %v", err)
	}
}
