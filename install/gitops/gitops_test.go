package gitops

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seed creates a bare repository whose main branch holds files.
func seed(t *testing.T, files map[string]string) string {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	bare := filepath.Join(root, "target.git")
	work := filepath.Join(root, "seed")
	mustGit(t, ctx, "", "init", "--bare", bare)
	mustGit(t, ctx, "", "init", "-b", "main", work)
	for path, body := range files {
		full := filepath.Join(work, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if len(files) > 0 {
		mustGit(t, ctx, work, "add", "--all")
		mustGit(t, ctx, work, "-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-m", "seed")
		mustGit(t, ctx, work, "push", bare, "HEAD:refs/heads/main")
	}
	return bare
}

func options(repo string) Options {
	return Options{Repository: repo, Branch: "main", Environment: "production", Recipients: []string{"age1test"}}
}

func TestResumeBasesCommitOnExistingMainWhenRemoteHEADIsMissing(t *testing.T) {
	ctx := context.Background()
	bare := seed(t, map[string]string{MarkerPath: "version: 1\nenvironments: []\n"})
	dir := t.TempDir()

	first, err := Prepare(ctx, options(bare), []File{
		{Path: "values/bud/values.production.yaml", Data: []byte("domain: old.example.com\n")},
	}, filepath.Join(dir, "first"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Push(ctx, first, "main"); err != nil {
		t.Fatal(err)
	}

	opts := options(bare)
	opts.Resume = true
	second, err := Prepare(ctx, opts, []File{
		{Path: "values/bud/values.production.yaml", Data: []byte("domain: corrected.example.com\n")},
	}, filepath.Join(dir, "second"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Push(ctx, second, "main"); err != nil {
		t.Fatalf("resumed push was not a fast-forward: %v", err)
	}
	body := mustGit(t, ctx, "", "--git-dir="+bare, "show", "main:values/bud/values.production.yaml")
	if !strings.Contains(body, "corrected.example.com") {
		t.Fatalf("remote main was not corrected: %s", body)
	}
}

func TestPrepareRefusesToOverwriteWithoutResume(t *testing.T) {
	bare := seed(t, map[string]string{"values/bud/values.production.yaml": "x: 1\n", "appsets/production.yaml": "kind: ApplicationSet\n"})
	_, err := Prepare(context.Background(), options(bare), []File{
		{Path: "values/bud/values.production.yaml", Data: []byte("x: 2\n")},
	}, filepath.Join(t.TempDir(), "repo"))
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("existing environment file was overwritten without resume: %v", err)
	}
}

func TestPrepareRefusesAnUnrelatedRepository(t *testing.T) {
	bare := seed(t, map[string]string{"README.md": "someone else's project\n"})
	_, err := Prepare(context.Background(), options(bare), nil, filepath.Join(t.TempDir(), "repo"))
	if err == nil || !strings.Contains(err.Error(), "not managed by budctl") {
		t.Fatalf("an unrelated repository was accepted: %v", err)
	}
}

func TestPrepareInitialisesAnEmptyRepositoryAndWritesTheMarker(t *testing.T) {
	ctx := context.Background()
	bare := seed(t, nil)
	prepared, err := Prepare(ctx, options(bare), []File{{Path: "apps/production.yaml", Data: []byte("kind: Application\n")}}, filepath.Join(t.TempDir(), "repo"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(prepared.Dir, MarkerPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "- production") {
		t.Fatalf("marker does not list the environment:\n%s", body)
	}
	sops, err := os.ReadFile(filepath.Join(prepared.Dir, ".sops.yaml"))
	if err != nil || !strings.Contains(string(sops), "age1test") {
		t.Fatalf(".sops.yaml does not list the recipient: %v\n%s", err, sops)
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

func TestResumeKeepsSensitiveFilesTheHookCallsUnchanged(t *testing.T) {
	ctx := context.Background()
	bare := seed(t, map[string]string{MarkerPath: "version: 1\n", "values/bud/secrets.production.yaml": "committed ciphertext\n"})
	opts := options(bare)
	opts.Resume = true
	opts.Unchanged = func(path string, committed, generated []byte) bool {
		return string(committed) == "committed ciphertext\n"
	}
	prepared, err := Prepare(ctx, opts, []File{
		{Path: "values/bud/secrets.production.yaml", Data: []byte("fresh ciphertext, same values\n"), Sensitive: true},
	}, filepath.Join(t.TempDir(), "repo"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(prepared.Dir, "values/bud/secrets.production.yaml"))
	if string(body) != "committed ciphertext\n" {
		t.Fatalf("an unchanged secret was rewritten: %q", body)
	}
}
