package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResumeBasesCommitOnExistingMainWhenRemoteHEADIsMissing(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	bare := filepath.Join(root, "target.git")
	seed := filepath.Join(root, "seed")
	mustGit(t, ctx, "", "init", "--bare", bare)
	mustGit(t, ctx, "", "init", "-b", "main", seed)
	marker := filepath.Join(seed, "values", "argocd", "values.budruntime.yaml")
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("global: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appSetTemplate := filepath.Join(seed, applicationSetTemplatePath)
	if err := os.MkdirAll(filepath.Dir(appSetTemplate), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appSetTemplate, []byte("apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata:\n  name: [[ .Environment ]]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, ctx, seed, "add", "--all")
	mustGit(t, ctx, seed, "-c", "user.name=test", "-c", "user.email=test@example.com", "commit", "-m", "seed")
	mustGit(t, ctx, seed, "push", bare, "HEAD:refs/heads/main")

	spec := Defaults()
	spec.Environment = "production"
	spec.TargetRepo = bare
	firstBundle := Bundle{
		AgeRecipient: "age1test",
		Artifacts: []Artifact{
			{Path: "appsets/production.yaml"},
			{Path: "values/bud/values.production.yaml", Data: []byte("domain: old.example.com\n")},
		},
	}
	first, err := PrepareRepository(ctx, spec, firstBundle, filepath.Join(root, "first"), false, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := PushRepository(ctx, first, "main"); err != nil {
		t.Fatal(err)
	}

	secondBundle := firstBundle
	secondBundle.Artifacts = []Artifact{
		{Path: "appsets/production.yaml"},
		{Path: "values/bud/values.production.yaml", Data: []byte("domain: corrected.example.com\n")},
	}
	second, err := PrepareRepository(ctx, spec, secondBundle, filepath.Join(root, "second"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := PushRepository(ctx, second, "main"); err != nil {
		t.Fatalf("resumed push was not a fast-forward: %v", err)
	}
	body := mustGit(t, ctx, "", "--git-dir="+bare, "show", "main:values/bud/values.production.yaml")
	if !strings.Contains(body, "corrected.example.com") {
		t.Fatalf("remote main was not corrected: %s", body)
	}
}

func mustGit(t *testing.T, ctx context.Context, dir string, args ...string) string {
	t.Helper()
	out, err := git(ctx, dir, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

func TestApplicationSetTemplateUsesInstallerValuesAndConditionals(t *testing.T) {
	body := []byte(`apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: [[ .Environment ]]
spec:
  repo: [[ quote .RepoURL ]]
  branch: [[ quote .Branch ]]
  components:
    - opensandbox
[[ if .CAInjection ]]    - kyverno
[[ end ]]
[[ if .BudStudio ]]    - bud-studio
[[ end ]]`)
	data := applicationSetTemplateData{
		Environment: "production",
		RepoURL:     "https://github.com/example/config.git",
		Branch:      "main",
		CAInjection: true,
		BudStudio:   true,
	}
	rendered, err := executeApplicationSetTemplate(body, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name: production", `repo: "https://github.com/example/config.git"`, `branch: "main"`, "- opensandbox", "- kyverno", "- bud-studio"} {
		if !strings.Contains(string(rendered), want) {
			t.Errorf("rendered ApplicationSet does not contain %q:\n%s", want, rendered)
		}
	}
	data.CAInjection = false
	data.BudStudio = false
	rendered, err = executeApplicationSetTemplate(body, data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rendered), "bud-studio") {
		t.Fatal("optional Bud Studio remained in an unselected ApplicationSet")
	}
	if strings.Contains(string(rendered), "kyverno") {
		t.Fatal("self-signed CA injector remained in a non-self-signed ApplicationSet")
	}
}

func TestCopyTemplateBaseExcludesIllustrativeEnvironment(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	for _, rel := range templateBaseFiles {
		full := filepath.Join(source, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("base\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	examples := []string{
		"apps/example.yaml",
		"appsets/example.yaml",
		"values/bud/values.example.yaml",
	}
	for _, rel := range examples {
		full := filepath.Join(source, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("example\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyTemplateBase(source, destination); err != nil {
		t.Fatal(err)
	}
	for _, rel := range templateBaseFiles {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(rel))); err != nil {
			t.Errorf("required base file %s was not copied: %v", rel, err)
		}
	}
	for _, rel := range examples {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Errorf("illustrative file %s was copied into the target", rel)
		}
	}
}
