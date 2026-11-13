# budctl architecture and refactor plan

This document covers:

- how budctl is built today
- how [cilium-cli](https://github.com/cilium/cilium-cli) is built
- how they differ
- a step-by-step plan to bring budctl in line with cilium-cli

The plan has three goals:

1. **Drop the template-based install** in favour of a **key-based** one. budctl
   builds every values layer and the ApplicationSet in Go, and users override
   individual keys with `--set` / `--values`.
2. **Ship a CLI first**, modeled on cilium-cli. The TUI is out of scope for now.
3. **Make the code a UI-free library**, so a TUI can later be built on top of it
   without touching business logic.

> Paths below are relative to this directory. Line numbers in §1 refer to the
> tree at commit `170ac94`, before the refactor.
>
> **Status (2026-11-10):** Steps 0–6 are implemented. §1 describes the code as
> it was; §4 and §6 describe it as it is now, including where it departs from
> the original plan.

---

## 1. Current architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ cmd/budctl  (package main, ~1.1k lines of logic)                     │
│   main.go     run(): hand-rolled dispatch check|install|cleanup|...  │
│   flags.go    one `config` struct (~70 fields) for every command     │
│   install.go  runInstall(): the entire install orchestration         │
├──────────────────────────────────────────────────────────────────────┤
│ internal/tui      Bubble Tea app, called directly from main          │
│ internal/output   table / json / junit renderers                     │
├──────────────────────────────────────────────────────────────────────┤
│ internal/engine   Check contract, registry, group runner, Observer   │
│ internal/checks   14 readiness groups, registered from init()        │
│ internal/install  Spec, render (Go maps), workspace (git + template),│
│                   bootstrap (ArgoCD), state, secrets, prompt (huh)   │
│ internal/intake   Answers + embedded defaults.yaml profile           │
│ internal/probes   probe namespace / pod / PVC runner                 │
├──────────────────────────────────────────────────────────────────────┤
│ internal/adapters Kube (dynamic, unstructured Object), Helm v3,      │
│                   Net, OCI, SOPS                                     │
└──────────────────────────────────────────────────────────────────────┘
```

### 1.1 Command layer
- `cmd/budctl/flags.go:110` `parseFlags`: the first non-flag argument picks
  the command, and one shared `flag` set fills a single `config` struct. Every
  command sees every flag. `usage()` (`flags.go:318`) is maintained by hand.
- `cmd/budctl/main.go:37` `run()` returns exit codes 0–3 directly. The
  `check` path builds `engine.Ctx` inline and chooses between
  `tui.Run` (`main.go:169`) and `engine.Run`.
- `cmd/budctl/install.go:15` `runInstall` is about 280 lines of install
  orchestration inside package `main`:
  - resume state
  - flag→spec mapping (`applyInstallFlags`, `:341`)
  - prompts, secret generation, render
  - clone/commit/push, ArgoCD bootstrap, CA export

  Progress goes out through `fmt.Println`. None of this can be reused by
  another frontend.

### 1.2 Readiness checks: already well-shaped
`internal/engine` already has the right shape for a library:
- `Check`, `Result`, `Severity`, `State` and `Report` are plain data.
- `Run(ctx, c, sel, obs Observer)` (`engine/runner.go:52`) streams results
  through `Observer` (`runner.go:35`), and the TUI consumes them through that
  same interface.
- `GroupOrder` (`engine/registry.go:15`) fixes execution order.

The problem is only placement: it sits under `internal/`, and `main` assembles
`Ctx` by hand.

### 1.3 Install: the template-based pipeline (the part being replaced)

```
 Spec ──► RenderWithSecrets (render.go:48) ──► Bundle{values.<env>, secrets.<env> (SOPS)}
                                                    │   appsets/<env>.yaml = nil placeholder
                                                    ▼
 PrepareRepository (workspace.go:29)
   git clone target
   if no values/argocd/values.budruntime.yaml (workspace.go:50):
       git clone example-bud-foundry-config @ 9b4ac59…  (spec.go:14,18)
       copyTemplateBase → 17 files (workspace.go:284,307)
   hydrateApplicationSet (workspace.go:341)
       text/template with [[ ]] delims over templates/appset.yaml.tmpl (:373)
   write bundle, update .sops.yaml, commit, push
                                                    ▼
 Bootstrap (bootstrap.go:22)
   reads values/argocd/values.budruntime.yaml from the clone (:85)
   helm install argocd, apply root Application, sync children in a
   hard-coded order (bootstrap.go:49)
```

#### What is wrong with it
**1. Three places to keep in sync.**

| Fact | Template repo | budctl | Chart |
|---|---|---|---|
| Component list, namespaces | `appset.yaml.tmpl` | `render.go` file maps, `bootstrap.go:49` sync list | – |
| Chart name and version | `appset.yaml.tmpl` (`targetRevision`) | `bootstrap.go` (argocd only) | `Chart.yaml` |
| Base values (16 files, `values.budruntime.yaml` + variants) | `values/*` | `templateBaseFiles` list | value schema |
| Per-env overlay | – | `render.go` Go maps | value schema |
| Conditional layers (TLS, Studio, CA injection) | `[[ if ]]` blocks | `applicationSetTemplateData` flags (`workspace.go:328`) | – |

Every chart bump touches the template repo, a new `DefaultTemplateRef`, and
often `render.go`. There are also the migration helpers:
- `upgradeCachedTemplateRef` (`install.go:298`)
- `IsMaintainedTemplateRepository` (`spec.go:236`)
- `LegacyTemplateRepo`

They exist only because the template moves independently of the binary.

**2. Go templates nested inside Go templates.** One file is processed by three
template engines:
- budctl's `[[ ]]`
- ArgoCD's ApplicationSet `{{ }}` / `templatePatch`
- the Bud chart's `tpl` over values such as
  `{{ include "bud.ingress.hosts.budadmin" . }}` (`render.go:328`)

The `[[ ]]` delimiters are a workaround, and every new conditional is
whitespace-sensitive YAML inside `[[ if ]]`.

**3. A network dependency at install time**, on a second repository.

### 1.4 UI coupling inside the library
- `internal/install/prompt.go`: `Prompt`/`Confirm` (`:65`, `:152`) import
  `charmbracelet/huh`. It is the only non-TUI package that imports a UI library.
- `Bootstrap` takes a `progress func(string)`. That is the right idea, but it
  is ad hoc.
- `tui.SaveReport` is called from `main` for the non-interactive path, so a
  report-file feature lives inside the TUI package.

---

## 2. cilium-cli reference architecture

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Packaging      cmd/cilium/main.go (15 lines) · Makefile  │
├─────────────────────────────────────────────────────────────┤
│ 2. Command layer  cli/  cobra tree; PersistentPreRunE builds│
│                   k8s.Client once and puts it in cmd ctx    │
│      ▲ api/ Hooks (NopHooks default) for embedders          │
├─────────────────────────────────────────────────────────────┤
│ 3. Domain pkgs    install/ status/ connectivity/ sysdump/   │
│                   hubble/ clustermesh/ encrypt/ …           │
│                   each: Parameters struct + Log/Writer      │
├─────────────────────────────────────────────────────────────┤
│ 4. k8s/           single Client: typed, dynamic, CRD, Helm, │
│                   exec, port-forward, logs                  │
├─────────────────────────────────────────────────────────────┤
│ 5. defaults/ utils/ internal/helm                           │
└─────────────────────────────────────────────────────────────┘
```

Patterns budctl should take from it:

- **Thin `main`.** It calls `cli.NewDefaultCiliumCommand().Execute()` and
  nothing else.
- **cobra command per verb.** Each command binds its flags into a domain
  `Parameters` struct, calls `NewX(client, params)`, then `.Run(ctx)`. `cli/`
  holds no business logic.
- **Global flags with a single client.** `--context`, `--kubeconfig`, `-n`
  (with an env var fallback) and `--as` are set once. Commands that need no
  cluster (`version --client`, `completion`, `help`) skip client creation.
- **Library packages at module root** (not `internal/`), so another module
  can import them. cilium also keeps `cli/` public, plus `api.Hooks`, because
  its enterprise CLI (a separate module) embeds the whole cobra tree and adds
  flags, tests and sysdump tasks without forking. budctl has no such embedder,
  so it takes the root-level libraries but keeps the command layer in
  `internal/cli` and drops `api.Hooks` (§4).
- **Key-based Helm values.** `install`/`upgrade` combine:
  - the chart defaults
  - values the CLI derives from auto-detection (`install/autodetect.go`: EKS,
    AKS, GKE, kube-proxy, datapath)
  - the user's `--values`/`-f`, `--set`, `--set-string`, `--set-file`

  These merge in that order. There is no template repo, because the chart and
  the CLI are the only sources of truth.
- **Dry-run surfaces.** `--dry-run` prints manifests, and
  `--dry-run-helm-values` prints the merged values only.
- **Logging through the domain object** (`k.Log(...)`), with output going to a
  `Writer` passed in from `cli`.
- **Version stamped into `defaults.CLIVersion`** through `-ldflags`.

---

## 3. Differences and how to resolve each

| Area | budctl today | cilium-cli | Target for budctl |
|---|---|---|---|
| Command framework | `flag` + manual dispatch (`flags.go`, `main.go`) | cobra | cobra, one file per command in `internal/cli/` |
| Flag scope | one `config` with ~70 fields shared by all commands | per-command flags into `Parameters` | per-command `check.Parameters`, `install.Parameters`, … |
| Exit codes | `run()` returns 0–3 | error → `os.Exit(1)` | keep the documented 0–3: commands return `*cli.ExitError{Code}` and `main` maps it |
| Library visibility | everything under `internal/` | root-level packages | root-level `check/ install/ k8s/ status/ output/ defaults/`; the command layer (`internal/cli`) and helpers stay in `internal/` |
| Kubernetes client | `adapters.Kube` (dynamic + unstructured) | `k8s.Client` (typed + dynamic) | move to `k8s.Client`; keep the dynamic `Object` helpers checks rely on, add typed clientsets as needed |
| Client creation | per command, in `main` | once in `PersistentPreRunE` | once in root `PersistentPreRunE`. `check` must still tolerate an unreachable cluster, so keep the error in `Ctx` and do not abort |
| Install model | template repo clone + Go maps + `[[ ]]` AppSet template | chart defaults + autodetect + `--set` | **key-based**: component table in Go → values files + typed AppSet, `--set comp.key=val` overrides (§5) |
| Install orchestration | `runInstall` in `main` | `install.K8sInstaller` methods | `install.Installer.Run(ctx)` with explicit phases |
| Prompts | `install.Prompt` (huh) inside the lib | none | `internal/cli/prompt.go` only. The lib exposes `Spec`, `Validate`, `DetectDefaults`, and the caller fills gaps |
| Progress | `fmt.Println` in main, `progress func` in Bootstrap | `Log` + `Writer` | `Logger` interface + typed `Observer` events (§4.1) |
| Report files | `tui.SaveReport` | n/a | `output.Save` |
| Version | `main.Version` ldflag | `defaults.CLIVersion` | `defaults.Version`, `defaults.Commit` |
| Helm | v3 | v4 | stay on v3 for now; record it as a follow-up, unrelated to this refactor |
| Resume state + SOPS + age | budctl-only | – | keep as is, moved under `install/` |
| Readiness checks | `engine` + `checks` | `connectivity/check` + `builder` | keep budctl's engine design (it already matches the pattern); move it to `check/` |

---

## 4. Target layout

This is the layout as implemented (Steps 0–6).

```
cmd/budctl/main.go       cli.NewDefaultCommand().ExecuteContext(ctx); cli.ExitCode(err) → os.Exit

internal/cli/            cobra only. No business logic, the only package allowed to
  root.go                touch stdin/stdout/terminal. Global flags --kubeconfig and
  check.go               --context; PersistentPreRunE builds k8s.Client once for
  install.go             commands annotated budctl/kube=required|optional and puts
  status.go              it in cmd.Context(). Nothing prompts: every input is a flag.
  lifecycle.go           uninstall, sysdump, values view
  cleanup.go
  version.go
  cmdref.go              hidden: regenerates docs/cmdref
  exit.go                ExitError{Code int}, ExitCode(err)

defaults/                Version, Commit (ldflags), ArgoCD chart ref/version and
                         namespace, sync timeouts, default branch/ingress/capacity

k8s/                     Client  ← internal/adapters/kube.go, Object, NodeStats,
                         plus fresh (uncached) ArgoCD reads, finalizers, delete

check/                   ← internal/engine  (Check, Result, Report, Run, Observer,
                           Selection, Ctx)
check/checks/            ← internal/checks  (one file per group, init() register)

install/                 Installer (Plan → Apply), Phase, Observer, Parameters,
                         Render, Overrides, State, DetectDefaults, Uninstall
install/spec/            Spec, TLS modes, Missing(), Validate(), GeneratedSecrets.
                         A leaf, so components can use it without an import cycle
install/components/      the component table (§5.1) + base/ (embedded shared layers)
install/appset/          typed ApplicationSet/Application builders (struct → YAML)
install/gitops/          clone, write files, .sops.yaml, .budctl.yaml marker,
                         commit, push

status/                  ArgoCD Application sync/health per environment, Wait
sysdump/                 zip of ArgoCD state, nodes, pods, events, logs
output/                  table/json/junit + Save/Markdown

internal/helm            ← adapters/helm.go + helm_getter.go   (helm.Client)
internal/sops            ← adapters/sops.go                    (sops.Client)
internal/net             ← adapters/net.go                     (net.Client)
internal/oci             ← adapters/oci.go, Credential         (oci.Client)
internal/probes, internal/intake                               (unchanged content)
internal/lint            repository-wide architecture tests (§4.1 rule 1)

internal/tui/            FROZEN: compiles and is tested, imported by no command.
                         Rebuilt later on check.Observer + install.Observer.
```

`adapters` became five packages, and each type is named `Client` with a `New`
constructor (`net.Client` rather than `net.Net`). The Helm REST getter moved to
`internal/helm`, since only Helm uses it.

The command layer lives in `internal/cli`, not at the root. Its only importers
(`cmd/budctl`, and later a TUI) are in this module. It is also the package
that changes most often (flags, exit codes), so it should not be a public API.
The libraries below it stay public, so other code can still drive budctl
without the CLI. If an external binary ever needs to embed the command tree,
promote `internal/cli` → `cli/` and add cilium-style `api.Hooks` then. Going
from internal to public breaks no importers. Going the other way would.

### 4.1 Rules that keep the library TUI-ready
1. **No terminal I/O below `internal/cli`.** Library packages never read
   `os.Stdin`, never import a terminal library, and never print to
   `os.Stdout`. Output goes to an `io.Writer` or Observer the caller passes in.
   `internal/lint` enforces it: it fails on `fmt.Print*`, `os.Stdout`,
   `os.Stdin`, `charmbracelet/*` or `golang.org/x/term` outside `cmd/`,
   `internal/cli/` and `internal/tui/`.
2. **Typed events.** Long-running operations report through an interface,
   not strings:
   ```go
   // check
   type Observer interface { CheckStarted(*Check); CheckFinished(Result) }

   // install
   type Observer interface {
       PhaseStarted(Phase)
       Step(Phase, string)
       PhaseFinished(Phase, error)
   }
   ```
   The CLI implements these as line-printers. A future TUI implements them as
   Bubble Tea messages, as `internal/tui/app.go:146` already does for checks.
3. **Questions are data, not calls.** The library exposes `spec.Spec`,
   `Spec.Validate()`, `DetectDefaults(ctx, client, *Spec)` and
   `Spec.Missing() []Field`. `Installer.Plan` returns a `*MissingError`
   listing every unset field. The CLI maps each field to its flag and prints
   them all in one error; a TUI would build a form from the same list.
4. **Confirmation is a callback.** `Installer.Confirm func(question string) (bool, error)`
   can be injected. Without it, `Apply` refuses the irreversible steps (push,
   cluster installation) unless `Parameters.Yes` is set. The CLI injects none,
   so `install` needs `--yes`.
5. **Phases are resumable units.** Each phase does its work, saves state, then
   emits `PhaseFinished`. `Plan` (Select, Generate, Render) and `Apply`
   (Prepare, Push, Bootstrap, ExportCA, Complete) are separate calls, so a
   frontend can show the plan before anything irreversible happens.

---

## 5. Key-based install design

### 5.1 One component table
Today the component list exists in three places: `render.go`,
`appset.yaml.tmpl`, and `bootstrap.go:49`. It becomes a single table:

```go
// install/components
type Component struct {
    Name      string                       // "keycloak"
    Namespace string                       // "keycloak"
    Source    Source                       // HelmChart{Repo, Chart, Version} | Git{Repo, Rev, Path}
    ChartValueFiles []string               // files that live INSIDE the chart, e.g. "example.minimal.yaml"
    Enabled   func(Spec) bool              // TLS/Studio/CA-injection conditions
    Base      func(Spec) map[string]any    // ← ported values.budruntime.yaml (+ minimal/selfsigned/inject-ca)
    Values    func(Spec) map[string]any    // ← render.go keycloakValues(), budValues(), …
    Secrets   func(Spec, GeneratedSecrets) map[string]any // ← render.go *Secrets()
    SyncWave  int                          // replaces the bootstrap.go order list
}

var All = []Component{ argocd, certManager, kyverno, dapr, kafka, mongodb,
    clickhouse, postgres, seaweedfs, valkey, keycloak, opensandbox, bud, budStudio }
```

The full table, taken from the pinned template (`templates/appset.yaml.tmpl` at `9b4ac59`):

| Component | Namespace | Source | Version | Chart-internal files | Base layers to port | Enabled when |
|---|---|---|---|---|---|---|
| argocd | argocd | registry.bud.studio/charts/argocd | 0.1.1 | – | `argocd/values.budruntime.yaml` | always |
| dapr | dapr-system | dapr.github.io/helm-charts/dapr | 1.17.5 | – | `dapr/values.yaml` | always |
| kafka | kafka | bud charts/kafka | 0.1.1 | `example.minimal.yaml` | `kafka/values.budruntime.yaml` | always |
| mongodb | mongodb | bud charts/mongodb | 0.1.1 | `example.minimal.yaml` | `mongodb/values.budruntime.yaml` | always |
| cert-manager | cert-manager | bud charts/cert-manager | 0.1.3 | – | `values.budruntime.yaml`, `values.selfsigned-ca.yaml` (self-signed only) | TLS ≠ external |
| kyverno | kyverno | bud charts/kyverno | 0.0.2 | – | `values.inject-ca.yaml`, `values.budruntime.yaml` | TLS ∈ {self-signed, internal-ca} |
| clickhouse | clickhouse | bud charts/clickhouse | 0.1.1 | `example.minimal.yaml` | `clickhouse/values.budruntime.yaml` | always |
| postgres | postgres | bud charts/postgres | 0.1.1 | `example.minimal.yaml` | `values.budruntime.yaml`, `values.minimal.budruntime.yaml` | always |
| seaweedfs | seaweedfs | bud charts/seaweedfs | 0.1.1 | `example.minimal.yaml` | `seaweedfs/values.budruntime.yaml` | always |
| valkey | valkey | registry-1.docker.io/cloudpirates/valkey | 0.21.4 | – | `values.yaml`, `values.minimal.yaml`, `values.budruntime.yaml` | always |
| keycloak | keycloak | bud charts/keycloak | 0.2.1 | – | `keycloak/values.budruntime.yaml` (176 lines, the largest) | always |
| bud | bud | bud charts/bud | 1.2.8 | – | – (env overlay only) | always |
| opensandbox | opensandbox-system | git bud-runtime `infra/charts/opensandbox` @ `openSandboxSourceRef` | – | – | – | always |
| bud-studio | bud-studio | bud charts/budagent | 0.3.6 | – | – | `--bud-studio` |

Everything this table drives:
- the public values files, `values/<c>/values.<env>.yaml`. Base and env layers
  are **merged in Go** into one file per component.
- the SOPS files, `values/<c>/secrets.<env>.yaml`
- the ApplicationSet `list` generator elements and each element's `valueFiles`
- the ArgoCD bootstrap values: `argocd.Base` + `argocd.Values` +
  `argocd.Secrets` merged in memory. This replaces `bootstrapValues` reading
  the clone (`bootstrap.go:85`).
- the child sync order, sorted by `SyncWave`

Adding or bumping a component is now **one edit, in one place, in the
binary**.

### 5.2 Value precedence (matches cilium)

```
component.Base(spec)            ← what values.budruntime.yaml used to be
  ⊕ component.Values(spec)      ← per-env overlay derived from Spec (domain, TLS, ingress…)
  ⊕ autodetect                  ← DetectDefaults: StorageClass, IngressClass, OpenShift, apps domain
  ⊕ --values <comp>=file.yaml   ← user files, repeatable
  ⊕ --set <comp>.<key>=<val>    ← also --set-string, --set-file, --set-json
```

- Parse with Helm's `pkg/cli/values.Options` and `pkg/strvals`, which are
  already in the dependency tree through Helm v3. Split on the first path
  segment to route a key to a component: `--set keycloak.ingress.className=nginx`.
  An unknown component is an error that lists the valid names.
- Secrets use the same mechanism, but write to the SOPS file:
  `--set-secret bud.appApiToken=…`. They are never printed by
  `--dry-run-values` unless `--show-secrets` is given.
- The merged result is what gets committed, so the GitOps repo stays readable
  and diff-able. Users can still hand-edit it afterwards, and ArgoCD consumes
  it unchanged.

### 5.3 Typed ApplicationSet, so there are no nested templates
`install/appset` defines Go structs for `ApplicationSet`, `Application`,
generator elements and `templatePatch`. They are emitted with `yaml.Marshal`:

- budctl never runs `text/template`. `[[ ]]`, `applicationSetTemplateData`,
  `hydrateApplicationSet` and `executeApplicationSetTemplate` are deleted.
- ArgoCD's `{{.name}}` / `{{- .valueFiles | toYaml | nindent 12 }}` and the
  Bud chart's `{{ include "bud.ingress..." }}` are ordinary Go string
  literals. The marshaller quotes them, and they reach their real consumers
  untouched.
- The `templatePatch` block (helm-vs-git source switch) stays as one constant
  string, because it belongs to ArgoCD's template engine.
- Each element carries `valueFiles = ChartValueFiles + ["$values/values/<c>/values.<env>.yaml", "$values/values/<c>/secrets.<env>.yaml"?]`.
  Conditional layers disappear because the conditions are applied while merging.
- `renderBootstrap` (`templates.go:5`), the root `Application`, becomes a
  builder in the same package.

### 5.4 What is removed
- `Spec.TemplateRepo`, `Spec.TemplateRef`, `DefaultTemplateRepo`,
  `DefaultTemplateRef`, `LegacyTemplateRepo`, `IsMaintainedTemplateRepository`
  (`spec.go`)
- `--template-repo`, `--template-ref`, `upgradeCachedTemplateRef`
  (`install.go:298`)
- `templateBaseFiles`, `copyTemplateBase`, `copyTemplateFile`, the template
  clone in `PrepareRepository`, `hydrateApplicationSet`,
  `executeApplicationSetTemplate` (`workspace.go`)
- `bootstrapValues` reading from disk (`bootstrap.go:85`), and the
  hard-coded `applications` list (`bootstrap.go:49`)

### 5.5 Compatibility
- **Repo detection.** Today a repo counts as "Bud-owned" if it contains
  `values/argocd/values.budruntime.yaml`. budctl now writes a
  `.budctl.yaml` marker (`{version, environments: [...]}`) and accepts either
  the marker or an existing `appsets/` directory. An empty repo is still
  initialised from scratch.
- **Old repos.** Base files left behind by earlier versions stay in place but
  are no longer referenced by the new AppSet. `budctl install` prints a
  one-line notice listing them. Deletion is left to the user.
- **Old resume state.** Unknown `templateRepo`/`templateRef` YAML fields are
  ignored on load, and generated secrets are reused as before.
- **Flags.** `--plan` is replaced by `--dry-run`, and the documented exit codes
  are unchanged.

### 5.6 New install surfaces
- `budctl install --dry-run`: the plan summary plus the file list, with no
  side effects. It is today's `--plan`.
- `budctl install --dry-run-values [--component bud]`: merged values per
  component as YAML. This is the key-based equivalent of cilium's
  `--dry-run-helm-values`.
- `budctl install --dry-run=manifests`: the generated AppSet and root
  Application.

---

## 6. Step-by-step PLAN

Each step is one PR, `go test ./...` and `go vet ./...` stay green, and
behaviour is unchanged unless the step says otherwise.

### Step 0: safety net (golden tests)
- [x] Golden test of the install output for a matrix of
  `TLS ∈ {acme-dns01, acme-http01, self-signed, internal-ca, external}` ×
  `BudStudio ∈ {on, off}` × `OpenShift ∈ {on, off}` (20 cases,
  `install/golden_test.go`). It uses a fixed age identity, fixed
  `GeneratedSecrets` and a fixed test CA, and records per case:
  - `<case>.artifacts.yaml`: every generated file, secrets decrypted. It was
    recorded against the AppSet hydrated from a vendored copy of the template
    at `9b4ac59`, then regenerated in Step 4, when the layout changed.
  - `<case>.effective.yaml`: per component, the AppSet's `valueFiles` merged
    in order (chart-internal files listed, not merged), plus the AppSet
    template, the root Application and the ArgoCD bootstrap values. This is
    the parity target.
- [x] Golden test of `check` table, JSON and JUnit output for three synthetic
  clusters (healthy vanilla, broken vanilla, healthy OpenShift), limited to the
  groups that make no network call (`check/checks/golden_test.go`). The
  verdict → exit code mapping is unit-tested (`verdictExitCode`).
- Rewrite with `go test ./install ./check/checks -run Golden -update`.

### Step 1: cobra skeleton
- [x] Add `internal/cli/` with `root.go` and the global flags `--kubeconfig` and
  `--context`. `-o/--output` and `--no-color` are registered on `check` only,
  because no other command uses them. `-n/--namespace` is deferred until a
  command has a namespace for it to mean (today there are only
  `--probe-namespace` and `--argocd-namespace`, both on `check`).
- [x] Add `check`, `install`, `cleanup`, `version` and `completion` commands that
  bind the same flags as today. Each command registers only the flags it uses,
  so `cleanup` now rejects the intake flags it used to ignore.
- [x] Split `config` into per-command parameter structs (`checkParams`,
  `installParams`, with the shared `intakeFlags`). `applyAnswerFlags` and
  `applyInstallFlags` move with them.
- [x] Add `cli.ExitError{Code}`. `main.go` becomes
  `cli.NewDefaultCommand().ExecuteContext(ctx)` + `cli.ExitCode(err)`.
- [x] Keep `budctl` with no command = `budctl check` for compatibility, and keep
  the Go-flag spelling `-flag` working by rewriting it to `--flag`
  (`normalizeArgs`).
- [x] Pulled forward from Step 3: `check` no longer opens the TUI, even on a
  terminal. It always prints the plain report, and a missing domain fails
  with exit 3, as a non-terminal run did before. `--no-tui`, `--tui`,
  `--theme` and `--no-prompt` are removed (pre-release: no deprecated
  aliases). The report writer moved to `output.Save` /
  `output.Markdown` so that `check --save` does not import `tui`.
- Exit criteria: `budctl --help` and `budctl check --help` are generated by
  cobra, and the Step 0 goldens (landed after this step) pass. Also covered by
  `internal/cli/cli_test.go` (arg
  normalization, flag scoping, exit codes, generated help).

### Step 2: lift the library out of `internal/`
- [x] `internal/adapters` → `k8s/` (`k8s.Client`, `k8s.Object`, `k8s.NodeStats`)
  plus `internal/net`, `internal/oci`, `internal/helm` (with the REST getter)
  and `internal/sops`, each with a `Client` type and `New`.
- [x] `internal/engine` → `check/`, and `internal/checks` → `check/checks/`.
  The `init()` registration and the failure-coverage gate are unchanged.
- [x] `internal/output` → `output/`. Colour detection (it inspects stdout)
  moved to `internal/cli`.
- [x] `defaults/` with `Version` and `Commit`; `release.sh` stamps
  `-X github.com/BudEcosystem/budctl/defaults.Version=…`.
- [x] Root `PersistentPreRunE` builds the client once for commands annotated
  `budctl/kube`. `check` and `install` take it as optional (the error becomes
  a finding, or a reason not to bootstrap); `status`, `cleanup`, `uninstall`
  and `sysdump` require it.
- Exit criteria met: the Step 0 goldens passed unchanged.

### Step 3: separate UI from the library
Changed from the original plan: **install is flags-only**. Nothing prompts, so
there is no `internal/cli/prompt.go` and `huh` is no longer linked into the
binary (only the frozen TUI uses it).
- [x] `install.Prompt`/`Confirm` deleted; `install` no longer imports `huh`.
  `DetectDefaults` stays in `install/detect.go`.
- [x] `install.Installer{Params, Client, ClientErr, Observer, Confirm}` with
  `Plan(ctx)` (Select → Generate → Render) and `Apply(ctx, plan)` (Prepare →
  Push → Bootstrap → ExportCA → Complete), and `Run` for both. State is saved
  under the names already persisted (`selected/generated/prepared/pushed/complete`).
  The Spec is saved before validation, so a run that stops on a missing flag
  keeps everything else.
- [x] `internal/cli/install.go` binds flags, calls `Plan`, prints the plan,
  calls `Apply`, prints the summary. A `*MissingError` is printed as every
  missing flag at once.
- [x] `Bootstrap`'s `progress func(string)` became `Observer.Step`.
- [x] Detach `tui/` (done in Step 1).
- [x] `internal/lint` enforces §4.1 rule 1.
- Behaviour changes, deliberate:
  - `install` needs `--yes` to push or touch the cluster; without it the plan
    is printed and nothing changes (exit 3). There is no interactive confirm.
  - An unreachable cluster now fails **before** the push when bootstrap would
    run, instead of after it. `--no-bootstrap` still pushes without a cluster.
  - `--no-prompt` is removed; install never prompts.

### Step 4: key-based install
- [x] `install/components` holds the table from §5.1. Deviation: the base
  layers are **embedded verbatim as YAML** (`install/components/base/`, the 16
  files from `9b4ac59`) and selected per Spec by `BaseFiles`, instead of being
  hand-ported to Go maps. They stay diffable against the template, and are
  still built into the binary. `render.go`'s `*Values`/`*Secrets` functions
  moved to `install/components/values.go`.
- [x] `Spec` and `GeneratedSecrets` moved to the leaf `install/spec` so the
  subpackages can use them without an import cycle.
- [x] `install/appset` builds the AppSet and root Application as structs.
  `templates.go` and every `text/template` path are gone.
- [x] `install.Render` iterates the table: Base ⊕ Values ⊕ overrides into one
  `values.<env>.yaml` per component, credentials ⊕ `--set-secret` into one
  `secrets.<env>.yaml`, and the AppSet elements from the same data.
- [x] Bootstrap uses the ArgoCD values from memory and syncs children by
  `SyncWave` from the table.
- [x] `--values <comp>=file`, `--set`, `--set-string`, `--set-file`,
  `--set-json`, `--set-secret`, parsed with Helm's `strvals` in Helm's order and
  routed by component. They are stored in the encrypted resume state
  (`Spec.Values`/`SecretValues`), so a resumed run keeps them.
- [x] Template code removed (§5.4); `--template-repo`/`--template-ref` are
  removed. `.budctl.yaml` marker written; a repository
  is accepted when it has the marker, `appsets/`, template-era files, or is
  empty. Template-era files are listed after install, and flagged when they
  differ from the embedded defaults (hand edits that no longer apply).
- [x] **Parity test.** All 20 `effective.yaml` goldens are byte-identical to
  the ones recorded from the template-based installer. No differences needed
  justifying.
- [x] Unit tests for override routing and precedence, unknown and disabled
  components, `--set-secret` encryption, and `{{ include … }}` / ArgoCD
  template expressions surviving unchanged.
- Exit criteria met: no template repository is contacted, and a chart bump is
  one `Version` field in `install/components/components.go`.

### Step 5: cilium-style command additions
- [x] `budctl install --dry-run` (plan plus file list), `--dry-run=manifests`,
  `--dry-run-values [--component c] [--show-secrets]`. A dry run saves no state.
- [x] Added after e2e testing: `budctl install --dry-run=render [--component c]
  [--render-dir d]` pulls every component's chart and templates it client-side
  with the exact values ArgoCD will pass (chart files, values, secrets, in
  `valueFiles` order). It is `helm template` for the whole platform, with no
  cluster changes, and is the fast way to test a values change.
- [x] `budctl status [--environment] [--wait] [--wait-duration] [-o json]` in
  `status/`: the root Application and each environment's Applications (found
  by ApplicationSet owner reference). Exit 0 all Synced and Healthy, 1 not (or
  `--wait` timed out), 3 cannot read the cluster or no ArgoCD.
- [x] `budctl version`: client version, Kubernetes version, and each
  environment's Bud and ArgoCD chart versions; `--client` skips the cluster.
- [x] `budctl uninstall --environment E --yes` (`install.Uninstall`): deletes
  the root Application and the ApplicationSet (orphaning), then prunes each
  component's Application in reverse wave order through ArgoCD's resources
  finalizer, waiting for each. The `argocd` Application is released without
  pruning, so ArgoCD keeps running; the repository is untouched.
- [x] `budctl sysdump`: zip of ArgoCD Applications/ApplicationSets, nodes, and
  each platform namespace's pods, events and container log tails. No secrets.
- [x] `budctl values view`: clones the repository and prints each component's
  committed values; `--show-secrets` decrypts with the recovery key. Defaults
  come from the last install's resume state.

### Step 6: docs
- [x] `README.md` rewritten for the cobra commands, flags-only install,
  `--set`/`--values`, `--dry-run*`, status and uninstall.
- [x] `budctl cmdref` (hidden) regenerates `docs/cmdref/` with
  `cobra/doc.GenMarkdownTree`.

### Step 7: TUI on top of the library (out of scope, for later)
- `tui/` depends only on `check`, `install`, `status`, `output` and `k8s`.
- It runs `check.Run(ctx, c, sel, tuiObserver)`, as today, and
  `install.Installer{Observer: tuiObserver, Confirm: tuiConfirm}.Run(ctx)`.
- Forms are built from `Spec.Missing()` plus `DetectDefaults`. No install
  logic is duplicated in the UI.
- The cobra command opens it with an `--interactive`/`-i` flag, or with a
  separate `budctl ui` command.

---

## 7. Risks and open items
- **Porting base layers.** Resolved: the 16 base files are embedded verbatim,
  and the Step 0 parity test passed with no differences.
- **Chart-internal value files.** `example.minimal.yaml` is referenced
  *inside* the kafka, mongodb, clickhouse, postgres and seaweedfs charts. It
  stays in `ChartValueFiles` and is still resolved by ArgoCD, not merged by
  budctl, so one implicit cross-repo dependency remains on purpose.
- **Repos created by earlier versions** may contain hand-edits to
  `values.budruntime.yaml`. The new AppSet stops reading those files, so
  `install` has to warn when they differ from the ported defaults.
- **Helm v3 vs cilium's v4.** This is independent of the refactor. Do not
  combine the two upgrades.
- **Exit codes and `--output json`** are part of the CI contract in
  `README.md`. The goldens from Step 0 guard them throughout.
- **CI failure-coverage gate** (`.github/workflows`, `check/checks` tests).
  Update package paths in Step 2 without weakening the gate.

### Flags shared by check and install (2026-11-11)
- One name per setting in both commands: `--repo` (was `--config-repo` on
  check), `--repo-key` (was `--repo-ssh-key`), one `--tls` set
  (`acme-dns01 | acme-http01 | self-signed | internal-ca | external`; check
  reads the non-ACME modes as a provided certificate), `--values
  <component>=<file>` (check uses `bud=`), and a global `--no-color`.
- check accepts every install flag, hidden and ignored when it has no use
  for it, so an install command line can be checked unchanged.
- Pre-release, so no deprecated aliases: the old names are removed.
