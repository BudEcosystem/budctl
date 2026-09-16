package install

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

type PreparedRepository struct {
	Dir       string
	DiffStat  string
	Commit    string
	PushedRef string
}

// PrepareRepository clones the user's repository into a new directory,
// populates an empty repository from the pinned reference template, and writes
// only this environment's generated files. The caller owns dir and may remove
// it after the cluster has consumed the pushed revision.
func PrepareRepository(ctx context.Context, spec Spec, bundle Bundle, dir string, push, resume bool) (PreparedRepository, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return PreparedRepository{}, fmt.Errorf("git is required for budctl install: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return PreparedRepository{}, err
	}
	if out, err := git(ctx, "", "clone", spec.TargetRepo, dir); err != nil {
		return PreparedRepository{}, fmt.Errorf("clone target repository: %w\n%s", err, out)
	}
	// A remote can contain the requested branch while its symbolic HEAD still
	// points elsewhere (or nowhere, which is common for a newly seeded bare
	// repository). Explicitly base the workspace on that remote branch so a
	// resumed push is always a fast-forward.
	remoteRef := "refs/remotes/origin/" + spec.PushBranch
	if _, err := git(ctx, dir, "show-ref", "--verify", "--quiet", remoteRef); err == nil {
		if out, err := git(ctx, dir, "checkout", "-B", spec.PushBranch, "origin/"+spec.PushBranch); err != nil {
			return PreparedRepository{}, fmt.Errorf("checkout target branch: %w\n%s", err, out)
		}
	}

	hasBase := fileExists(filepath.Join(dir, "values", "argocd", "values.budruntime.yaml"))
	hasAppSetTemplate := fileExists(filepath.Join(dir, applicationSetTemplatePath))
	if !hasBase {
		empty, err := repositoryHasNoFiles(ctx, dir)
		if err != nil {
			return PreparedRepository{}, err
		}
		if !empty {
			return PreparedRepository{}, fmt.Errorf("target repository is not empty and is not a Bud infra repository (values/argocd/values.budruntime.yaml is absent)")
		}
	}
	if !hasBase || !hasAppSetTemplate {
		templateDir, err := os.MkdirTemp("", "budctl-template-")
		if err != nil {
			return PreparedRepository{}, err
		}
		defer os.RemoveAll(templateDir)
		if out, err := git(ctx, "", "clone", "--no-checkout", spec.TemplateRepo, templateDir); err != nil {
			return PreparedRepository{}, fmt.Errorf("clone installation template: %w\n%s", err, out)
		}
		if out, err := git(ctx, templateDir, "checkout", "--detach", spec.TemplateRef); err != nil {
			return PreparedRepository{}, fmt.Errorf("checkout pinned installation template %s: %w\n%s", spec.TemplateRef, err, out)
		}
		if !hasBase {
			if err := copyTemplateBase(templateDir, dir); err != nil {
				return PreparedRepository{}, fmt.Errorf("populate target from template %s: %w", spec.TemplateRef, err)
			}
		} else if err := copyTemplateFile(templateDir, dir, applicationSetTemplatePath); err != nil {
			return PreparedRepository{}, fmt.Errorf("add ApplicationSet template from template %s to existing target: %w", spec.TemplateRef, err)
		}
	}

	if out, err := git(ctx, dir, "checkout", "-B", spec.PushBranch); err != nil {
		return PreparedRepository{}, fmt.Errorf("create installation branch: %w\n%s", err, out)
	}
	hydrated, err := hydrateApplicationSet(dir, spec, bundle)
	if err != nil {
		return PreparedRepository{}, err
	}
	bundle = hydrated
	if err := writeBundle(dir, bundle, resume); err != nil {
		return PreparedRepository{}, err
	}
	if err := updateSOPSConfig(dir, spec.Environment, append([]string{bundle.AgeRecipient}, spec.AgeRecipients...)); err != nil {
		return PreparedRepository{}, err
	}
	if out, err := git(ctx, dir, "diff", "--check"); err != nil {
		return PreparedRepository{}, fmt.Errorf("generated files fail git diff --check: %w\n%s", err, out)
	}
	stat, _ := git(ctx, dir, "status", "--short")
	if strings.TrimSpace(stat) == "" {
		commit, err := git(ctx, dir, "rev-parse", "HEAD")
		if err != nil {
			return PreparedRepository{}, err
		}
		return PreparedRepository{Dir: dir, Commit: strings.TrimSpace(commit), DiffStat: "no configuration changes"}, nil
	}
	if out, err := git(ctx, dir, "add", "--all"); err != nil {
		return PreparedRepository{}, fmt.Errorf("stage generated configuration: %w\n%s", err, out)
	}
	if out, err := git(ctx, dir, "-c", "user.name=budctl", "-c", "user.email=budctl@bud.studio", "commit", "-m", "chore: configure "+spec.Environment+" installation"); err != nil {
		return PreparedRepository{}, fmt.Errorf("commit generated configuration: %w\n%s", err, out)
	}
	commit, err := git(ctx, dir, "rev-parse", "HEAD")
	if err != nil {
		return PreparedRepository{}, err
	}
	diffStat, _ := git(ctx, dir, "show", "--stat", "--oneline", "--format=%h %s", "HEAD")
	prepared := PreparedRepository{Dir: dir, DiffStat: strings.TrimSpace(diffStat), Commit: strings.TrimSpace(commit)}
	if push {
		if out, err := git(ctx, dir, "push", "--set-upstream", "origin", "HEAD:refs/heads/"+spec.PushBranch); err != nil {
			return prepared, fmt.Errorf("push installation branch: %w\n%s", err, out)
		}
		prepared.PushedRef = spec.PushBranch
	}
	return prepared, nil
}

func PushRepository(ctx context.Context, prepared PreparedRepository, branch string) error {
	if prepared.Dir == "" || branch == "" {
		return fmt.Errorf("prepared repository and branch are required")
	}
	if out, err := git(ctx, prepared.Dir, "push", "--set-upstream", "origin", "HEAD:refs/heads/"+branch); err != nil {
		return fmt.Errorf("push installation branch: %w\n%s", err, out)
	}
	return nil
}

func writeBundle(root string, bundle Bundle, resume bool) error {
	for _, artifact := range bundle.Artifacts {
		path := filepath.Join(root, filepath.FromSlash(artifact.Path))
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("generated path escapes repository: %s", artifact.Path)
		}
		if fileExists(path) && !resume {
			return fmt.Errorf("refusing to overwrite existing environment file %s", artifact.Path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, artifact.Data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", artifact.Path, err)
		}
	}
	return nil
}

func WriteRecoveryKey(path string, bundle Bundle) error {
	if path == "" {
		return fmt.Errorf("a recovery key path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create recovery key without overwriting: %w", err)
	}
	if _, err = f.Write(bundle.RecoveryKey); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// EnsureRecoveryKey preserves retryability without silently accepting a
// different key at the same path. An existing matching key is a successful
// resume; any mismatch requires an explicit new path.
func EnsureRecoveryKey(path string, bundle Bundle) error {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return WriteRecoveryKey(path, bundle)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(body, bundle.RecoveryKey) {
		return fmt.Errorf("recovery key %s belongs to a different installation state", path)
	}
	return os.Chmod(path, 0o600)
}

// EnsureCACertificate writes the public self-signed root beside the recovery
// material. A different certificate at the same path is not replaced silently:
// changing a trust anchor should always be an explicit operator decision.
func EnsureCACertificate(path string, certificate []byte) error {
	if path == "" || len(bytes.TrimSpace(certificate)) == 0 {
		return fmt.Errorf("a CA certificate path and certificate are required")
	}
	if body, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(certificate)) {
			return fmt.Errorf("CA certificate %s contains a different trust anchor", path)
		}
		return os.Chmod(path, 0o644)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".budctl-ca-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(certificate); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o644)
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

func repositoryHasNoFiles(ctx context.Context, dir string) (bool, error) {
	out, err := git(ctx, dir, "ls-files")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "", nil
}

const applicationSetTemplatePath = "templates/appset.yaml.tmpl"

var templateBaseFiles = []string{
	applicationSetTemplatePath,
	"values/argocd/values.budruntime.yaml",
	"values/dapr/values.yaml",
	"values/kafka/values.budruntime.yaml",
	"values/mongodb/values.budruntime.yaml",
	"values/cert-manager/values.budruntime.yaml",
	"values/cert-manager/values.selfsigned-ca.yaml",
	"values/kyverno/values.inject-ca.yaml",
	"values/kyverno/values.budruntime.yaml",
	"values/clickhouse/values.budruntime.yaml",
	"values/postgres/values.budruntime.yaml",
	"values/postgres/values.minimal.budruntime.yaml",
	"values/seaweedfs/values.budruntime.yaml",
	"values/valkey/values.yaml",
	"values/valkey/values.minimal.yaml",
	"values/valkey/values.budruntime.yaml",
	"values/keycloak/values.budruntime.yaml",
}

// copyTemplateBase intentionally does not copy sample environments or their
// encrypted credentials. Only files referenced as common layers by the
// generated ApplicationSet are imported into an empty target repository.
func copyTemplateBase(src, dst string) error {
	for _, rel := range templateBaseFiles {
		if err := copyTemplateFile(src, dst, rel); err != nil {
			return err
		}
	}
	return nil
}

func copyTemplateFile(src, dst, rel string) error {
	body, err := os.ReadFile(filepath.Join(src, filepath.FromSlash(rel)))
	if err != nil {
		return fmt.Errorf("read required template file %s: %w", rel, err)
	}
	target := filepath.Join(dst, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, body, 0o644)
}

type applicationSetTemplateData struct {
	Environment    string
	RepoURL        string
	Branch         string
	OpenSandboxRef string
	CertManager    bool
	CertValues     bool
	CertSecrets    bool
	CAInjection    bool
	SelfSigned     bool
	BudStudio      bool
}

func hydrateApplicationSet(root string, spec Spec, bundle Bundle) (Bundle, error) {
	artifactPath := filepath.ToSlash(filepath.Join("appsets", spec.Environment+".yaml"))
	for i := range bundle.Artifacts {
		if bundle.Artifacts[i].Path != artifactPath {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, applicationSetTemplatePath))
		if err != nil {
			return Bundle{}, fmt.Errorf("read ApplicationSet template: %w", err)
		}
		rendered, err := executeApplicationSetTemplate(body, applicationSetTemplateData{
			Environment:    spec.Environment,
			RepoURL:        manifestRepo(spec.TargetRepo),
			Branch:         spec.PushBranch,
			OpenSandboxRef: openSandboxSourceRef,
			CertManager:    spec.TLS != TLSExternal,
			CertValues: spec.TLS == TLSACMEDNS01 || spec.TLS == TLSACMEHTTP01 || spec.TLS == TLSInternalCA ||
				(spec.TLS == TLSSelfSigned && spec.TrustedCAPEM != ""),
			CertSecrets: spec.TLS == TLSACMEDNS01 || spec.TLS == TLSInternalCA,
			CAInjection: spec.TLS == TLSSelfSigned || spec.TLS == TLSInternalCA,
			SelfSigned:  spec.TLS == TLSSelfSigned,
			BudStudio:   spec.BudStudio,
		})
		if err != nil {
			return Bundle{}, err
		}
		bundle.Artifacts[i].Data = rendered
		return bundle, nil
	}
	return Bundle{}, fmt.Errorf("generated bundle is missing %s", artifactPath)
}

func executeApplicationSetTemplate(body []byte, data applicationSetTemplateData) ([]byte, error) {
	tmpl, err := template.New("appset").Delims("[[", "]]").Funcs(template.FuncMap{
		"quote": strconv.Quote,
	}).Option("missingkey=error").Parse(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse ApplicationSet template: %w", err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return nil, fmt.Errorf("render ApplicationSet template: %w", err)
	}
	var parsed any
	if err := yaml.Unmarshal(out.Bytes(), &parsed); err != nil {
		return nil, fmt.Errorf("rendered ApplicationSet template is invalid YAML: %w", err)
	}
	return out.Bytes(), nil
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
