// Package install produces and applies a Bud GitOps installation: it resolves
// the Spec, generates credentials, renders every component's configuration,
// commits it to the operator's repository, and bootstraps ArgoCD.
//
// It never talks to a terminal. Progress goes to an Observer, questions are
// returned as data (MissingError), and the one irreversible decision is a
// Confirm callback or Parameters.Yes.
package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/BudEcosystem/budctl/install/gitops"
	"github.com/BudEcosystem/budctl/install/spec"
	"github.com/BudEcosystem/budctl/internal/sops"
	"github.com/BudEcosystem/budctl/k8s"
	"gopkg.in/yaml.v3"
)

// Phase is one resumable unit of an installation.
type Phase string

const (
	PhaseSelect    Phase = "select"
	PhaseGenerate  Phase = "generate"
	PhaseRender    Phase = "render"
	PhasePrepare   Phase = "prepare"
	PhasePush      Phase = "push"
	PhaseBootstrap Phase = "bootstrap"
	PhaseExportCA  Phase = "export-ca"
	PhaseComplete  Phase = "complete"
)

// Observer receives progress as typed events. A CLI prints them; a TUI can
// render them.
type Observer interface {
	PhaseStarted(Phase)
	Step(Phase, string)
	PhaseFinished(Phase, error)
}

type nopObserver struct{}

func (nopObserver) PhaseStarted(Phase)         {}
func (nopObserver) Step(Phase, string)         {}
func (nopObserver) PhaseFinished(Phase, error) {}

// Parameters are the caller's decisions for one run.
type Parameters struct {
	// StatePath is the encrypted resume state; empty means DefaultStatePath.
	StatePath string
	// Fresh ignores the previous session and starts from the defaults.
	Fresh bool
	// Apply sets the operator's explicit choices on the Spec: the resumed
	// session's, or the defaults. It should set only what the operator chose,
	// so everything else keeps its saved or detected value.
	Apply func(*spec.Spec)
	// RecoveryKeyPath is where the SOPS age identity is kept, outside Git.
	// Empty means the previous session's path, or a file in the working
	// directory.
	RecoveryKeyPath string
	// DryRun stops after Render: nothing is saved, written or pushed.
	DryRun      bool
	NoPush      bool
	NoBootstrap bool
	NoSync      bool
	// Yes accepts both irreversible steps (the push and the cluster
	// installation) without calling Confirm.
	Yes bool
}

// Installer runs an installation.
type Installer struct {
	Params Parameters
	// Client and ClientErr are the cluster connection. Detection is skipped
	// without a client; bootstrapping requires one.
	Client    *k8s.Client
	ClientErr error
	Observer  Observer
	// Confirm is asked before each irreversible step unless Params.Yes is set.
	// Without it, Apply refuses those steps.
	Confirm func(question string) (bool, error)
}

// Plan is a resolved, rendered installation, ready to apply or to show.
type Plan struct {
	Spec      spec.Spec
	Bundle    Bundle
	StatePath string
	// Resumed means a previous session's choices and credentials were reused.
	Resumed bool
	state   State
}

// Result is what Apply did.
type Result struct {
	Commit          string
	DiffStat        string
	RecoveryKeyPath string
	StatePath       string
	CAPath          string
	// LocalRepository is the committed clone, kept only under NoPush.
	LocalRepository string
	// Deferred means the push happened and the cluster installation was
	// declined at its confirmation.
	Deferred bool
}

// MissingError reports the required decisions the Spec still lacks.
type MissingError struct {
	Fields []spec.Field
}

func (e *MissingError) Error() string {
	names := make([]string, len(e.Fields))
	for i, f := range e.Fields {
		names[i] = f.Name
	}
	return "missing " + strings.Join(names, ", ")
}

var (
	// ErrConfirmationRequired is returned when an irreversible step needs
	// confirming and there is neither Params.Yes nor a Confirm callback.
	ErrConfirmationRequired = errors.New("installation pushes to the repository and changes the cluster; it must be confirmed")
	ErrCancelled            = errors.New("cancelled")
)

// The resume state records these names; they are kept from earlier releases.
var persisted = map[Phase]string{
	PhaseSelect: "selected", PhaseGenerate: "generated", PhasePrepare: "prepared",
	PhasePush: "pushed", PhaseComplete: "complete",
}

// Run plans and applies in one call.
func (i *Installer) Run(ctx context.Context) (*Plan, *Result, error) {
	p, err := i.Plan(ctx)
	if err != nil || i.Params.DryRun {
		return p, nil, err
	}
	r, err := i.Apply(ctx, p)
	return p, r, err
}

// Plan runs Select, Generate and Render. Unless DryRun is set, the resolved
// Spec and generated credentials are saved so a later run can resume.
func (i *Installer) Plan(ctx context.Context) (*Plan, error) {
	p := &Plan{}
	if err := i.phase(PhaseSelect, func() error { return i.selectSpec(ctx, p) }); err != nil {
		return nil, err
	}
	if err := i.phase(PhaseGenerate, func() error { return i.generate(p) }); err != nil {
		return nil, err
	}
	err := i.phase(PhaseRender, func() error {
		var err error
		p.Bundle, err = Render(p.Spec, *p.state.Secrets)
		if err != nil {
			return fmt.Errorf("generate configuration: %w", err)
		}
		return nil
	})
	return p, err
}

// Apply runs Prepare, Push, Bootstrap, ExportCA and Complete for a plan.
func (i *Installer) Apply(ctx context.Context, p *Plan) (*Result, error) {
	params := i.Params
	if params.DryRun {
		return nil, errors.New("a dry run cannot be applied")
	}
	if params.NoPush && !params.NoBootstrap {
		return nil, errors.New("--no-push requires --no-bootstrap because ArgoCD cannot consume an unpushed revision")
	}
	// Fail before the push rather than after it: a repository that is pushed
	// and then cannot be bootstrapped leaves the operator half-installed.
	if !params.NoBootstrap && (i.Client == nil || i.ClientErr != nil) {
		return nil, fmt.Errorf("the cluster cannot be reached, so ArgoCD cannot be bootstrapped: %v\n  fix kube access, or pass --no-bootstrap to only push the configuration", i.ClientErr)
	}
	if !params.NoBootstrap {
		if err := i.checkArgoCDRelease(); err != nil {
			return nil, err
		}
	}
	if err := i.confirm("Generate, commit, and push this installation?"); err != nil {
		return nil, err
	}

	r := &Result{StatePath: p.StatePath}
	s := p.Spec
	recoveryPath, err := recoveryKeyPath(params.RecoveryKeyPath, p.state.RecoveryPath, p.Bundle.RecoveryFileName)
	if err != nil {
		return nil, err
	}
	r.RecoveryKeyPath = recoveryPath
	workspace, err := os.MkdirTemp("", "budctl-install-")
	if err != nil {
		return nil, err
	}
	if !params.NoPush {
		defer os.RemoveAll(workspace)
	}

	var prepared gitops.Prepared
	err = i.phase(PhasePrepare, func() error {
		var err error
		prepared, err = gitops.Prepare(ctx, gitops.Options{
			Repository:  s.TargetRepo,
			Branch:      s.PushBranch,
			Environment: s.Environment,
			Recipients:  append([]string{p.Bundle.AgeRecipient}, s.AgeRecipients...),
			Resume:      p.Resumed,
			Unchanged:   sameSecrets(p.state.Secrets.AgeIdentity),
		}, p.Bundle.Artifacts, filepath.Join(workspace, "repository"))
		if err != nil {
			return fmt.Errorf("prepare repository: %w", err)
		}
		r.Commit, r.DiffStat = prepared.Commit, prepared.DiffStat
		if params.NoPush {
			r.LocalRepository = prepared.Dir
		}
		p.state.Commit = prepared.Commit
		p.state.RecoveryPath = recoveryPath
		return i.save(p, PhasePrepare)
	})
	if err != nil {
		return r, err
	}

	// The identity is deliberately persisted before the only irreversible
	// operation (push). If pushing succeeds, the operator is guaranteed to have
	// the key needed to recover and add another recipient later.
	if err := EnsureRecoveryKey(recoveryPath, p.Bundle.RecoveryKey); err != nil {
		return r, fmt.Errorf("save recovery key: %w", err)
	}
	if !params.NoPush {
		err := i.phase(PhasePush, func() error {
			if err := gitops.Push(ctx, prepared, s.PushBranch); err != nil {
				return fmt.Errorf("%w\n  the recovery key was retained at %s", err, recoveryPath)
			}
			return i.save(p, PhasePush)
		})
		if err != nil {
			return r, err
		}
	}

	if !params.NoBootstrap {
		cluster := firstNonEmpty(i.Client.Context, i.Client.Host(), "the configured Kubernetes cluster")
		if err := i.confirm("Git push complete. Start the ArgoCD installation on " + cluster + "?"); err != nil {
			if errors.Is(err, ErrCancelled) {
				r.Deferred = true
				return r, nil
			}
			return r, err
		}
		err := i.phase(PhaseBootstrap, func() error {
			if err := i.bootstrap(ctx, p); err != nil {
				return fmt.Errorf("repository was pushed, but ArgoCD bootstrap failed: %w\n  recovery key: %s", err, recoveryPath)
			}
			return nil
		})
		if err != nil {
			return r, err
		}
		if s.TLS == spec.TLSSelfSigned && !params.NoSync {
			err := i.phase(PhaseExportCA, func() error { return i.exportCA(ctx, p, recoveryPath) })
			if err != nil {
				return r, err
			}
			r.CAPath = p.state.CAPath
		}
	}
	err = i.phase(PhaseComplete, func() error { return i.save(p, PhaseComplete) })
	return r, err
}

func (i *Installer) selectSpec(ctx context.Context, p *Plan) error {
	params := i.Params
	statePath, err := statePath(params.StatePath)
	if err != nil {
		return err
	}
	p.StatePath = statePath
	state, resumed, err := LoadState(statePath)
	if err != nil && !params.Fresh {
		return fmt.Errorf("load resume state: %w\n  use --fresh to start over, or restore %s", err, StateKeyPath(statePath))
	}
	if params.Fresh {
		state, resumed = State{}, false
	}
	apply := func(s *spec.Spec) {
		if params.Apply != nil {
			params.Apply(s)
		}
	}
	s := spec.Defaults()
	if resumed {
		s = state.Spec
	}
	apply(&s)
	// An explicit different environment starts a new session. This prevents
	// the last environment's generated credentials from being reused.
	if resumed && s.Environment != state.Spec.Environment {
		state, resumed = State{}, false
		s = spec.Defaults()
		apply(&s)
	}
	prior := state.Spec

	if i.Client != nil && i.ClientErr == nil {
		DetectDefaults(ctx, i.Client, &s)
	}
	if s.Environment == "" {
		s.Environment = "production"
	}
	s.Normalize()
	if err := s.LoadTLSMaterial(); err != nil {
		return err
	}
	if err := s.LoadRepositoryKey(); err != nil {
		return err
	}
	if resumed && (s.Environment != prior.Environment || spec.RepositoryURL(s.TargetRepo) != spec.RepositoryURL(prior.TargetRepo)) {
		state, resumed = State{}, false
	}
	if s.TLS != spec.TLSSelfSigned {
		state.CAPath = ""
	}
	state.Spec = s
	p.Spec, p.Resumed, p.state = s, resumed, state
	// Saved before validation, so a run that stops on a missing value keeps
	// everything else: the next run supplies only what was missing.
	if err := i.save(p, PhaseSelect); err != nil {
		return err
	}
	if missing := s.Missing(); len(missing) > 0 {
		return &MissingError{Fields: missing}
	}
	return s.Validate()
}

func (i *Installer) generate(p *Plan) error {
	var generated spec.GeneratedSecrets
	if p.state.Secrets != nil {
		generated = *p.state.Secrets
		if err := spec.RepairSecrets(&generated); err != nil {
			return fmt.Errorf("repair cached credentials: %w", err)
		}
	} else {
		var err error
		generated, err = spec.GenerateSecrets(p.Spec.AdminPassword)
		if err != nil {
			return fmt.Errorf("generate credentials: %w", err)
		}
	}
	if p.Spec.AdminPassword != "" {
		generated.AdminPassword = p.Spec.AdminPassword
	}
	p.state.Spec, p.state.Secrets = p.Spec, &generated
	return i.save(p, PhaseGenerate)
}

func (i *Installer) exportCA(ctx context.Context, p *Plan, recoveryPath string) error {
	certificate, err := i.Client.SecretData(ctx, "cert-manager", "selfsigned-ca-root", "tls.crt")
	if err != nil {
		return fmt.Errorf("platform synchronized, but the self-signed root CA could not be exported: %w\n  retrieve cert-manager/selfsigned-ca-root key tls.crt before accessing Bud endpoints", err)
	}
	caPath := p.state.CAPath
	if caPath == "" {
		caPath = filepath.Join(filepath.Dir(recoveryPath), "budctl-"+p.Spec.Environment+"-ca.crt")
	}
	if err := EnsureCACertificate(caPath, certificate); err != nil {
		return fmt.Errorf("save self-signed root CA: %w", err)
	}
	p.state.CAPath = caPath
	return nil
}

func (i *Installer) phase(ph Phase, fn func() error) error {
	obs := i.observer()
	obs.PhaseStarted(ph)
	err := fn()
	obs.PhaseFinished(ph, err)
	return err
}

func (i *Installer) observer() Observer {
	if i.Observer == nil {
		return nopObserver{}
	}
	return i.Observer
}

func (i *Installer) confirm(question string) error {
	if i.Params.Yes {
		return nil
	}
	if i.Confirm == nil {
		return ErrConfirmationRequired
	}
	ok, err := i.Confirm(question)
	if err != nil {
		return err
	}
	if !ok {
		return ErrCancelled
	}
	return nil
}

// save records the session after a phase. A dry run records nothing.
func (i *Installer) save(p *Plan, ph Phase) error {
	if i.Params.DryRun {
		return nil
	}
	name, ok := persisted[ph]
	if !ok {
		return nil
	}
	p.state.Phase = name
	if err := SaveState(p.StatePath, p.state); err != nil {
		return fmt.Errorf("save resume state: %w", err)
	}
	return nil
}

func statePath(given string) (string, error) {
	if given == "" {
		return DefaultStatePath()
	}
	return filepath.Abs(given)
}

func recoveryKeyPath(given, cached, fallback string) (string, error) {
	if given == "" {
		given = firstNonEmpty(cached, fallback)
	}
	return filepath.Abs(given)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

// sameSecrets reports whether two SOPS documents hold the same values for the
// same recipients, so a resumed run can keep the committed ciphertext.
func sameSecrets(identity string) func(string, []byte, []byte) bool {
	return func(_ string, committed, generated []byte) bool {
		dec := sops.New()
		a, errA := dec.DecryptWith(committed, identity)
		b, errB := dec.DecryptWith(generated, identity)
		if errA != nil || errB != nil {
			return false
		}
		delete(a, "sops")
		delete(b, "sops")
		return reflect.DeepEqual(a, b) && reflect.DeepEqual(ageRecipients(committed), ageRecipients(generated))
	}
}

func ageRecipients(document []byte) []string {
	var doc struct {
		SOPS struct {
			Age []struct {
				Recipient string `yaml:"recipient"`
			} `yaml:"age"`
		} `yaml:"sops"`
	}
	if yaml.Unmarshal(document, &doc) != nil {
		return nil
	}
	var out []string
	for _, a := range doc.SOPS.Age {
		out = append(out, a.Recipient)
	}
	sort.Strings(out)
	return out
}
