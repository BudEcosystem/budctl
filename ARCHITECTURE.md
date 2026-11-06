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

> Paths below are relative to this directory. Line numbers refer to the tree at
> commit `170ac94`.

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

```
cmd/budctl/main.go       cli.NewDefaultCommand().Execute(); ExitError → os.Exit(code)

internal/cli/            cobra only. No business logic, the only package allowed to
  root.go                touch stdin/stdout/terminal. Global flags --kubeconfig,
  check.go               --context, -n/--namespace, --no-color, -o/--output.
  install.go             PersistentPreRunE builds k8s.Client → cmd.Context().
  status.go
  cleanup.go
  version.go
  prompt.go              huh forms (moved from internal/install/prompt.go)
  exit.go                ExitError{Code int}

defaults/                Version, Commit (ldflags), ArgoCD chart ref/version,
                         namespaces, timeouts, default branch/ingress/model Gi

k8s/                     Client  ← internal/adapters/kube.go + helm_getter.go
                         (Object helpers stay, as k8s.Object)

check/                   ← internal/engine  (Check, Result, Report, Run, Observer,
                           Selection, Ctx, Parameters)
check/checks/            ← internal/checks  (one file per group, init() register)

install/                 Parameters, Installer, phases, State, GeneratedSecrets, Spec
install/components/      the component table (§5.1): single source of truth
install/appset/          typed ApplicationSet/Application builders (struct → YAML)
install/gitops/          clone, write bundle, .sops.yaml, commit, push
                         (← workspace.go minus everything template-related)

status/                  NEW: ArgoCD Application sync/health per component, --wait
output/                  table/json/junit + Save (← internal/output, tui.SaveReport)

internal/helm            ← adapters/helm.go
internal/sops            ← adapters/sops.go
internal/net, internal/oci, internal/probes, internal/intake   (unchanged content)

tui/                     FROZEN: kept compiling, not wired into any command.
                         Rebuilt later on check.Observer + install.Observer.
```

The command layer lives in `internal/cli`, not at the root. Its only importers
(`cmd/budctl`, and later a TUI) are in this module. It is also the package
that changes most often (flags, prompts, exit codes), so it should not be a
public API. The libraries below it stay public, so other code can still drive
budctl without the CLI. If an external binary ever needs to embed the command
tree, promote `internal/cli` → `cli/` and add cilium-style `api.Hooks` then.
Going from internal to public breaks no importers. Going the other way would.

### 4.1 Rules that keep the library TUI-ready
1. **No terminal I/O below `internal/cli`.** Library packages never read
   `os.Stdin`, never call `term.IsTerminal`, and never print to `os.Stdout`.
   Output goes to an `io.Writer`/`Logger` the caller passes in. A
   `go vet`-style test greps for `fmt.Print`, `os.Stdout` and `charmbracelet`
   outside `internal/cli/` and `tui/`.
2. **Typed events.** Long-running operations report through an interface,
   not strings:
   ```go
   // check (exists today as engine.Observer)
   type Observer interface { CheckStarted(*Check); CheckFinished(Result) }

   // install (new)
   type Observer interface {
       PhaseStarted(Phase)
       Step(Phase, string)
       PhaseFinished(Phase, error)
   }
   ```
   The CLI implements these as line-printers. A future TUI implements them as
   Bubble Tea messages, as `internal/tui/app.go:146` already does for checks.
3. **Questions are data, not calls.** The library exposes `Spec`,
   `Spec.Validate()`, `DetectDefaults(ctx, client, *Spec)` and a
   `Spec.Missing() []Field` list. Each frontend decides how to ask:
   - `internal/cli/prompt.go` with huh
   - flags with `--no-prompt`
   - TUI forms later
4. **Confirmation is a callback.** `Installer.Confirm func(question string) (bool, error)`
   is injected. Without it, `Run` refuses irreversible phases unless
   `Parameters.Yes` is set.
5. **Phases are resumable units.** Each phase loads state, does its work,
   saves state, then emits `PhaseFinished`. A UI can render, retry or skip
   them without knowing what they do inside.

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
- **Flags.** `--plan` becomes a hidden alias of `--dry-run`, and the documented
  exit codes are unchanged.

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
- [ ] Golden test of the **current** install output for a matrix of
  `TLS ∈ {acme-dns01, acme-http01, self-signed, internal-ca, external}` ×
  `BudStudio ∈ {on, off}` × `OpenShift ∈ {on, off}`. It records:
  - every bundle artifact (decrypted secrets, using a fixed age identity and
    fixed `GeneratedSecrets`)
  - the AppSet hydrated from a vendored copy of the template at `9b4ac59`
- [ ] For each case, also record the **effective values per component**: chart
  files skipped, template base layers + env overlay merged in list order. This
  is the parity target for Step 4.
- [ ] Golden test of `check` table and JSON output and exit codes against the
  existing fake-kube harness (`internal/checks/harness_test.go`).

### Step 1: cobra skeleton
- [ ] Add `internal/cli/` with `root.go` and the global flags `--kubeconfig`, `--context`,
  `-n`, `--no-color` and `-o/--output`.
- [ ] Add `check`, `install`, `cleanup`, `version` and `completion` commands that
  bind the same flags as today. Each command registers only the flags it uses.
- [ ] Split `config` into per-command parameter structs. `applyAnswerFlags` and
  `applyInstallFlags` move with them.
- [ ] Add `cli.ExitError{Code}`. `main.go` becomes
  `cli.NewDefaultCommand().Execute()` + code mapping, about 15 lines.
- [ ] Keep `budctl` with no args = `budctl check` for compatibility.
- Exit criteria: the Step 0 goldens pass, and `budctl --help` and `budctl check --help`
  are generated by cobra.

### Step 2: lift the library out of `internal/`
- [ ] `internal/adapters/kube.go` and `helm_getter.go` → `k8s/` (`k8s.Client`, `k8s.Object`).
- [ ] `internal/engine` → `check/`, and `internal/checks` → `check/checks/`.
  Keep the `init()` registration. Keep the CI failure-coverage gate.
- [ ] `internal/output` → `output/`, and move `tui.SaveReport` → `output.Save`.
- [ ] Add `defaults/` with `Version` and `Commit`, and update the `release.sh`
  ldflags to `-X github.com/BudEcosystem/budctl/defaults.Version=…`.
- [ ] Root `PersistentPreRunE` builds the client once. On failure it stores
  the error for `check` (the toolchain check reports it), and fails fast for
  `install`/`status`.
- Exit criteria: no behaviour change, and the goldens pass.

### Step 3: separate UI from the library
- [ ] Move `install.Prompt`/`Confirm` → `internal/cli/prompt.go`. `internal/install`
  no longer imports `huh`.
- [ ] Add `install.Installer{Params, Client, Log, Observer, Confirm}` and
  `Run(ctx)` with phases:
  `Select → Generate → Render → Prepare → Push → Bootstrap → ExportCA → Complete`.
  Save state after each phase, using the same names already persisted
  (`selected/generated/prepared/pushed/complete`).
- [ ] Move the body of `runInstall` into those phases.
  `internal/cli/install.go` shrinks to: bind flags, resolve the spec, prompt if
  interactive, `Installer.Run`, print the summary.
- [ ] Replace `Bootstrap`'s `progress func(string)` with `Observer.Step`.
- [ ] Detach `tui/`: no command imports it. Keep it compiling, either behind a
  `//go:build tui` tag or with a single `tui_test.go` build check.
- [ ] Add a lint test: no `fmt.Print*`, `os.Stdout`, `os.Stdin` or
  `charmbracelet/*` imports outside `internal/cli/` and `tui/`.
- Exit criteria: goldens pass, and `budctl install --plan --no-prompt …` output
  is byte-identical.

### Step 4: key-based install
- [ ] Add `install/components` with the table from §5.1. Port each template base
  file at `9b4ac59` into its component's `Base(spec)`, and move each
  `render.go` `*Values` / `*Secrets` function into its component.
- [ ] Add `install/appset` with typed builders for the AppSet and root
  Application. Delete `templates.go`.
- [ ] `RenderWithSecrets` iterates the table:
  - merge Base ⊕ Values ⊕ overrides
  - emit `values.<env>.yaml` and `secrets.<env>.yaml`
  - build the AppSet from the same data
- [ ] `Bootstrap` takes the ArgoCD values from the table in memory and syncs
  children by `SyncWave`.
- [ ] Add `--values <comp>=file`, `--set`, `--set-string`, `--set-file`, `--set-json`,
  and `--set-secret` to `install`, parsed with Helm `values.Options`/`strvals`,
  routed by component prefix.
- [ ] Delete the template code paths listed in §5.4. Add the `.budctl.yaml`
  marker and old-repo detection (§5.5).
- [ ] **Parity test.** For every matrix case, the merged values per component
  equal the Step 0 effective values. Differences are allowed only where they
  are listed and justified in the test.
- [ ] Unit tests for override routing, precedence, an unknown component, and
  a `{{ include … }}` value surviving round-trip unchanged.
- Exit criteria: installs work with no network access to the template repo,
  and a chart bump is a one-line change in `install/components`.

### Step 5: cilium-style command additions
- [ ] `budctl install --dry-run`, `--dry-run-values`, `--dry-run=manifests`
  (§5.6), with `--plan` kept as a hidden alias.
- [ ] `budctl status [--wait] [--wait-duration]` reports each component's
  ArgoCD Application sync and health, plus the root Application. It lives in
  `status/` and supports `-o json`.
- [ ] `budctl version`: the client version, plus the deployed Bud chart and
  ArgoCD versions when a cluster is reachable. `--client` skips the cluster.
- [ ] Follow-ups, each its own PR: `budctl uninstall` (delete root
  Application, wait for prune), `budctl sysdump` (collect ArgoCD app status,
  pod logs and events into a zip, like cilium's `sysdump/`), and
  `budctl values view` (print committed merged values for an environment).

### Step 6: docs
- [ ] Rewrite `README.md` usage for the cobra commands, `--set` examples, and
  `--dry-run`.
- [ ] Generate a command reference (`budctl cmdref` → `docs/cmdref/`) the way
  cilium does with `cmdref.NewCmd`.

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
- **Porting base layers by hand.** The 16 template base values files total
  about 750 lines of YAML. The Step 0 parity test is what makes the port safe. Do
  not skip it.
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
- **CI failure-coverage gate** (`.github/workflows`, `internal/checks` tests).
  Update package paths in Step 2 without weakening the gate.
