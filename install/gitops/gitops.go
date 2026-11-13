// Package gitops writes an environment into the operator's GitOps repository:
// clone, write the generated files, keep .sops.yaml and the budctl marker up
// to date, commit, and push. It knows nothing about what the files contain.
package gitops

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// File is one generated file, by repository path.
type File struct {
	Path      string
	Data      []byte
	Sensitive bool
}

// Options describe the environment being written.
type Options struct {
	Repository  string
	Branch      string
	Environment string
	// Recipients are the age recipients .sops.yaml lists for the environment.
	Recipients []string
	// Resume allows the environment's existing files to be overwritten, which
	// is how a corrected or interrupted installation converges.
	Resume bool
	// Unchanged reports whether a regenerated sensitive file says the same as
	// the one already committed. SOPS ciphertext differs on every run, so
	// without it a resume would commit every secret again.
	Unchanged func(path string, committed, generated []byte) bool
}

// Prepared is a local clone with the environment committed.
type Prepared struct {
	Dir      string
	DiffStat string
	Commit   string
}

// MarkerPath is the file that identifies a repository budctl manages.
const MarkerPath = ".budctl.yaml"

const markerVersion = 1

type marker struct {
	Version      int      `yaml:"version"`
	Environments []string `yaml:"environments"`
}

// Prepare clones the repository into dir, which must not exist, and commits
// the environment's files on the branch. The caller owns dir.
func Prepare(ctx context.Context, opts Options, files []File, dir string) (Prepared, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return Prepared{}, fmt.Errorf("git is required for budctl install: %w", err)
	}
	if err := Clone(ctx, opts.Repository, opts.Branch, dir); err != nil {
		return Prepared{}, err
	}
	if err := checkOwnership(ctx, dir); err != nil {
		return Prepared{}, err
	}
	if out, err := git(ctx, dir, "checkout", "-B", opts.Branch); err != nil {
		return Prepared{}, fmt.Errorf("create installation branch: %w\n%s", err, out)
	}
	if err := writeFiles(dir, files, opts.Resume, opts.Unchanged); err != nil {
		return Prepared{}, err
	}
	if err := updateSOPSConfig(dir, opts.Environment, opts.Recipients); err != nil {
		return Prepared{}, err
	}
	if err := updateMarker(dir, opts.Environment); err != nil {
		return Prepared{}, err
	}
	if out, err := git(ctx, dir, "diff", "--check"); err != nil {
		return Prepared{}, fmt.Errorf("generated files fail git diff --check: %w\n%s", err, out)
	}
	stat, _ := git(ctx, dir, "status", "--short")
	if strings.TrimSpace(stat) == "" {
		commit, err := git(ctx, dir, "rev-parse", "HEAD")
		if err != nil {
			return Prepared{}, err
		}
		return Prepared{Dir: dir, Commit: commit, DiffStat: "no configuration changes"}, nil
	}
	if out, err := git(ctx, dir, "add", "--all"); err != nil {
		return Prepared{}, fmt.Errorf("stage generated configuration: %w\n%s", err, out)
	}
	if out, err := git(ctx, dir, "-c", "user.name=budctl", "-c", "user.email=budctl@bud.studio", "commit", "-m", "chore: configure "+opts.Environment+" installation"); err != nil {
		return Prepared{}, fmt.Errorf("commit generated configuration: %w\n%s", err, out)
	}
	commit, err := git(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return Prepared{}, err
	}
	diffStat, _ := git(ctx, dir, "show", "--stat", "--oneline", "--format=%h %s", "HEAD")
	return Prepared{Dir: dir, DiffStat: diffStat, Commit: commit}, nil
}

// Clone clones repository into dir and checks out branch when the remote has
// it. A remote can contain the branch while its symbolic HEAD points
// elsewhere (or nowhere, common for a newly seeded bare repository), so the
// workspace is based on the remote branch explicitly and a resumed push is
// always a fast-forward.
func Clone(ctx context.Context, repository, branch, dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if out, err := git(ctx, "", "clone", repository, dir); err != nil {
		return fmt.Errorf("clone target repository: %w\n%s", err, out)
	}
	remoteRef := "refs/remotes/origin/" + branch
	if _, err := git(ctx, dir, "show-ref", "--verify", "--quiet", remoteRef); err == nil {
		if out, err := git(ctx, dir, "checkout", "-B", branch, "origin/"+branch); err != nil {
			return fmt.Errorf("checkout target branch: %w\n%s", err, out)
		}
	}
	return nil
}

// Push publishes the prepared commit to branch.
func Push(ctx context.Context, prepared Prepared, branch string) error {
	if prepared.Dir == "" || branch == "" {
		return fmt.Errorf("prepared repository and branch are required")
	}
	if out, err := git(ctx, prepared.Dir, "push", "--set-upstream", "origin", "HEAD:refs/heads/"+branch); err != nil {
		return fmt.Errorf("push installation branch: %w\n%s", err, out)
	}
	return nil
}

// checkOwnership refuses a repository budctl does not manage, so an operator
// pointing --repo at the wrong place does not get Bud committed into it. An
// empty repository is initialised from scratch.
func checkOwnership(ctx context.Context, dir string) error {
	if fileExists(filepath.Join(dir, MarkerPath)) {
		return nil
	}
	if info, err := os.Stat(filepath.Join(dir, "appsets")); err == nil && info.IsDir() {
		return nil
	}
	out, err := git(ctx, dir, "ls-files")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}
	return fmt.Errorf("target repository is not empty and is not managed by budctl (no %s or appsets/ directory)", MarkerPath)
}

func writeFiles(root string, files []File, resume bool, unchanged func(string, []byte, []byte) bool) error {
	for _, file := range files {
		path := filepath.Join(root, filepath.FromSlash(file.Path))
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("generated path escapes repository: %s", file.Path)
		}
		if fileExists(path) && !resume {
			return fmt.Errorf("refusing to overwrite existing environment file %s", file.Path)
		}
		if file.Sensitive && unchanged != nil {
			if committed, err := os.ReadFile(path); err == nil && unchanged(file.Path, committed, file.Data) {
				continue
			}
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, file.Data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", file.Path, err)
		}
	}
	return nil
}

func updateMarker(root, environment string) error {
	path := filepath.Join(root, MarkerPath)
	m := marker{}
	if body, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(body, &m); err != nil {
			return fmt.Errorf("parse %s: %w", MarkerPath, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	m.Version = markerVersion
	seen := map[string]bool{environment: true}
	envs := []string{environment}
	for _, e := range m.Environments {
		if !seen[e] {
			seen[e] = true
			envs = append(envs, e)
		}
	}
	sort.Strings(envs)
	m.Environments = envs
	body, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte("# Managed by budctl. Lists the environments installed from this repository.\n"), body...), 0o644)
}

func updateSOPSConfig(root, environment string, recipients []string) error {
	path := filepath.Join(root, ".sops.yaml")
	doc := map[string]any{}
	if body, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(body, &doc); err != nil {
			return fmt.Errorf("parse .sops.yaml: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	age := []any{}
	seen := map[string]bool{}
	for _, recipient := range recipients {
		if recipient = strings.TrimSpace(recipient); recipient != "" && !seen[recipient] {
			seen[recipient] = true
			age = append(age, recipient)
		}
	}
	rule := map[string]any{
		"path_regex": fmt.Sprintf(`.*\.%s\.yaml$`, regexp.QuoteMeta(environment)),
		"key_groups": []any{map[string]any{"age": age}},
	}
	rules := []any{rule}
	if existing, ok := doc["creation_rules"].([]any); ok {
		for _, raw := range existing {
			m, _ := raw.(map[string]any)
			if m != nil && m["path_regex"] == rule["path_regex"] {
				continue
			}
			rules = append(rules, raw)
		}
	}
	doc["creation_rules"] = rules
	body, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode .sops.yaml: %w", err)
	}
	return os.WriteFile(path, body, 0o644)
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// CloneAt clones repository into dir and checks out revision, for reading a
// chart that lives in a Git repository.
func CloneAt(ctx context.Context, repository, revision, dir string) error {
	if out, err := git(ctx, "", "clone", "--quiet", repository, dir); err != nil {
		return fmt.Errorf("clone %s: %w\n%s", repository, err, out)
	}
	if out, err := git(ctx, dir, "checkout", "--quiet", "--detach", revision); err != nil {
		return fmt.Errorf("checkout %s: %w\n%s", revision, err, out)
	}
	return nil
}
