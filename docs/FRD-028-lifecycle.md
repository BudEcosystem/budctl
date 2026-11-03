# FRD-028: budctl — Install Lifecycle (install, status, upgrade, repair, uninstall)

**Status**: Draft for review
**Date**: 2026-11-03
**Owner**: Infra
**Surfaces touched**: this repository (CLI, TUI, engine);
[bud-runtime](https://github.com/BudEcosystem/bud-runtime) `infra/charts/**`, `infra/appsets/**`, `infra/values/**`
(a release manifest and a few fixes, §13) and `docs/developer-docs/installation.mdx`;
[example-bud-foundry-config](https://github.com/BudEcosystem/example-bud-foundry-config) (the template repo)
**Builds on**: [FRD-020](https://github.com/BudEcosystem/bud-runtime/blob/main/specs/020-cluster-readiness-installer/FRD.md)
(in bud-runtime). Readiness (Phase 1) is implemented. This FRD
replaces FRD-020 §10 ("Phase 2 — guided install, outline") and goes further, to cover day 2.

---

## 1. Summary

`budctl` can tell an operator whether a cluster is ready (`budctl check`, FRD-020). It can also take them through a
first GitOps install (`budctl install`), and it can pick that install up again after a failure. Once Bud is
running, it does nothing more. The operator is back to `kubectl get applications -n argocd`, hand edits to
`targetRevision` and the "Upgrading" section of the docs, which is five lines long.

This FRD sets out where `budctl` should end up. That is one tool covering the whole life of an installation:

| Command | Question it answers |
|---|---|
| `budctl check` | Can this cluster host Bud? *(FRD-020, built)* |
| `budctl install` | Get me from an empty cluster to a working, verified Bud: quick, custom, or repair |
| `budctl status` | Is my installation healthy, and if not, what is wrong and what fixes it? |
| `budctl upgrade` | What changes if I move to version N, and can I do it safely and undo it? |
| `budctl repair` | My installation drifted or a step failed. Put it back without losing data or credentials |
| `budctl uninstall` | Remove Bud cleanly, and say exactly what happens to the data |
| `budctl self-update` | Keep the tool itself current |

Every command shares one interaction model (§5). It shows a **plan**, writes nothing until you confirm it, then
applies the plan in checkpointed steps and verifies the result. The model comes from the reference designs that
came with this FRD (start/preflight/components/config/install/done, the status table and the upgrade plan with its
changelog). Those mock-ups show a single-host developer runtime. §5.4 maps each element onto what Bud actually is:
a Kubernetes platform delivered through Argo CD from a Git repository the customer owns.

No single release delivers all of this. §12 splits it into phases. Each phase ships something usable and leaves the
seams the next one needs.

### The governing rules

> **1. Git is the source of truth. `budctl` writes desired state to Git and reads actual state from the cluster.**
> The only changes it makes to the cluster directly are the ones Git cannot make: the first Helm install of Argo CD,
> asking Argo CD to sync, and removing what an uninstall removes. A change made any other way is drift that the
> next sync silently undoes.

> **2. Nothing changes until the operator confirms a plan.** The plan lists every commit, every cluster action and
> every file outside Git. `--plan` prints it and exits. `--yes` confirms it without asking.

> **3. Every step can be resumed.** An interrupted run continues from its last checkpoint, reuses the credentials it
> generated, and never asks a question it has already had answered.

---

## 2. Where we are (budctl 0.4.x, as built)

| Area | State |
|---|---|
| `check` | 90 checks across 14 groups (Appendix A), intake-driven thresholds, probes, TUI + `json`/`junit`, exit codes (FRD-020). Per-check re-run and copy-remedy are not built. |
| `install` | A `huh` form in sections: GitOps target, private-repo access, network/TLS (five modes), capacity, registry/admin, Bud Studio. It detects the default StorageClass, the ingress class and the OpenShift apps domain, generates every internal secret, and renders values and an ApplicationSet from the pinned template (`DefaultTemplateRef`). It encrypts with SOPS/age, then commits and pushes. It Helm-installs Argo CD (`oci://registry.bud.studio/charts/argocd` 0.1.1) and syncs children in dependency order, with a live progress view. |
| Resume | Encrypted state is kept per installation under `budctl/installs/`, keyed by environment and repository. Phases recorded: `selected → generated → prepared → pushed → complete`. Re-runs never re-seed operator-owned template files unless `--force-template` is given. |
| Flags | `--plan`, `--yes`, `--no-push`, `--no-bootstrap`, `--no-sync`, `--state`, `--fresh`, `--force-template`. |
| `cleanup`, `version` | Built. |
| **Not built** | Quick vs custom paths; preflight run inside install; a plan screen; post-install verification; diagnosis of a stuck Application; `status`; `upgrade` (including FRD-020's unbuilt `check --upgrade`); `repair`; `uninstall`; self-update; release signing; air-gapped mirroring; any marker on the cluster recording what was installed. |

The full as-built reference is in the appendices. **Appendix A** lists every prerequisite check (90 in 14 groups),
with probes, intake, floors and the network inventory. **Appendix B** describes the install procedure step by step.

`install` and `check` are separate programs today. They have separate forms, separate question sets
(`intake.Answers` and `install.Spec` overlap) and separate visual shells. The first job of this FRD is to merge them
(§6.3).

---

## 3. Goals and non-goals

### Goals

- **G1 — Two-minute decisions, not two-hour discoveries.** Anything that will fail must fail in preflight or plan,
  before a commit. That covers readiness blockers, repository access, a decrypt-key mismatch and an incompatible
  upgrade.
- **G2 — Quick install asks four questions.** Those are repository, domain, registry credentials and admin email.
  Everything else is detected or given a stated default, and the plan shows which is which.
- **G3 — Custom install exposes every supported decision and nothing unsupported.** Components, TLS, storage,
  datastores, sizing and GitOps details are all available. Each option shows what it costs and what depends on it.
- **G4 — "Done" means verified.** An install or upgrade finishes only after a smoke pass (§7.8). Argo CD saying
  `Healthy` is not enough.
- **G5 — A failure names its cause and its fix.** A stuck Application is matched to the readiness check or known
  pitfall that explains it (§7.7).
- **G6 — Upgrades are previewed, staged and reversible.** The operator sees the changelog, the plan, the image pull
  size and the expected downtime, and gets a rollback path with its limits stated (§9).
- **G7 — Headless parity.** Every TUI screen has a plain or JSON equivalent, and every command runs in CI with
  `--no-prompt --yes`.
- **G8 — One binary, still.** No `kubectl`, `helm`, `sops`, `age` or `argocd` binary on the host (FRD-020 D1).

### Non-goals

- **NG1** — Provisioning Kubernetes, nodes, a CNI or a storage backend. `budctl` reports on them. `nix/` and the
  cloud provider install them.
- **NG2** — Replacing Argo CD. `budctl` drives and reads Argo CD and never applies chart manifests itself (rule 1).
- **NG3** — Continuous monitoring or alerting. `status` is a point-in-time view. SigNoz and Argo CD notifications
  remain the monitoring path.
- **NG4** — Managing the remote client clusters that Bud onboards (`client-*.yaml` appsets, budcluster onboarding,
  HAMi/NFD). That belongs to budcluster and FRD-024.
- **NG5** — Database-level backup and restore tooling. `budctl` checks that backups are configured and reports their
  state (§11). The operators (CNPG barman, clickhouse-backup, Velero) do the work.

---

## 4. Users and scenarios

| # | Who | Scenario | Path |
|---|---|---|---|
| S1 | Field engineer, POC | Empty k3s or EKS cluster, wants Bud up this afternoon | `install` → **Quick** |
| S2 | Customer platform team | Production: internal CA, existing StorageClass, external Postgres, private Git, change review | `install` → **Custom**, `--plan` reviewed in a PR, then `--yes` |
| S3 | Operator, day 2 | "Users say login is slow, is anything down?" | `status` |
| S4 | Operator | A new Bud release is out | `upgrade` → plan → apply → verify; `upgrade --rollback` if needed |
| S5 | Operator | Install died at "sync clickhouse" because the node ran out of disk | fix, then `install` again: it resumes |
| S6 | Operator | Someone edited values by hand, an app is OutOfSync, a secret was deleted | `repair` |
| S7 | Air-gapped customer | No internet from the cluster or the jump host | `mirror`, then `install --registry-mirror` (§10) |
| S8 | CI pipeline | Nightly verification of a staging install | `status --output json`, exit code |
| S9 | Operator | POC is over | `uninstall` |

---

## 5. Interaction model (all commands)

### 5.1 The shell

Every interactive command draws the same frame on the terminal's alternate screen. The screen is restored on exit,
and a short tail summary stays in scrollback:

```
 ▟▙ bud foundry · install                              budctl 0.6.0  darwin/arm64
 ──────────────────────────────────────────────────────────────────────────────
 ● start   ○ preflight   ○ components   ○ config   ○ plan   ○ install   ○ verify
 ──────────────────────────────────────────────────────────────────────────────
   <body>
 ──────────────────────────────────────────────────────────────────────────────
 ↑↓ move   enter select   space toggle   ? help   q quit
```

- **Header**: product, command, budctl version, platform. When known, it also shows the **target**: kube context,
  environment and repository. "Which cluster am I about to change?" must never be a question.
- **Stepper**: the command's phases. Done steps are filled, the current one is highlighted and later ones are
  dimmed. A failed step is marked `✗`, with the colour as a second signal only (FRD-020 §8.3).
- **Footer**: the keys that work on the current screen. No others.
- **Back**: `esc` returns to the previous step until the plan is confirmed. After that, the run can be stopped
  (`ctrl-c` finishes the current atomic action, saves a checkpoint and exits) but not reversed.

### 5.2 Plan before apply

Every mutating command ends its input phase on a **Plan** screen like this:

```
 Plan                                              target: prod-eks · production
 [✓] commit 23 files to git@github.com:acme/bud-config.git (main)   +1,204 −0
 [✓] install Argo CD 0.1.1 (Helm, namespace argocd)
 [✓] sync 12 Applications in dependency order                ~15–25 min
 [ ] sync Bud Studio                                          optional
 ─ outside Git ─────────────────────────────────────────────────────────────────
     recovery key → ~/.config/budctl/installs/production-3fa2.agekey   (0600)
     root CA      → ~/.config/budctl/installs/production-3fa2-ca.pem
 ⚠  storage.rwx RISK: no ReadWriteMany class; budmodel shares a RWO claim
```

Items that can be skipped have checkboxes. Required items cannot be unticked, and the screen says why. Each line
also has a headless form. `--plan --output json` emits the same list, so a team can review a plan in a pull request
before anyone applies it.

### 5.3 Headless parity and exit codes

| Code | install / upgrade / repair / uninstall | status | check |
|---:|---|---|---|
| 0 | done and verified | healthy | ready |
| 1 | failed (state saved, resumable) | degraded | not ready |
| 2 | done with risks (`--strict`) | warnings (`--strict`) | ready with risks (`--strict`) |
| 3 | could not run (input, access, version) | could not read | could not run |
| 4 | stopped by operator, checkpoint saved | — | — |

`--output table|json`, `--no-prompt`, `--yes`, `--plan` and `NO_COLOR` all behave the same on every command.
Each run writes a log under `budctl/logs/<install-id>/<timestamp>-<command>.log`, with secrets redacted. On failure,
the error message gives the log's path.

### 5.4 Mapping the reference designs to Bud

The mock-ups describe a local developer runtime ("sets up the CLI, a local runtime and your shell completions",
`/usr/local/bin`, `containerd`, ports). This table maps each element to its Bud equivalent:

| Mock-up element | Bud equivalent |
|---|---|
| Quick / Custom / Repair on the start screen | Same three, plus **Continue \<session\>** when a resumable session exists (§7.1) |
| "Est. 1–2 min · 583 MB · needs sudo" | "Est. 15–25 min · ~20 GiB images per node · commits to \<repo\> · needs cluster-admin" (figures from the release manifest, §8) |
| "Nothing is written to disk until you confirm" | Nothing is committed, pushed or applied until you confirm. Local session state is written from the first answer, because that is what makes resume possible, and the start screen says so |
| Status: service / version / state / port / uptime / health | Component / version / sync / health / age / detail, from Argo CD Applications, workloads and operator CRs (§8.2) |
| Status "runtime" tab | **Cluster** tab: nodes, storage, GPU, ingress, certificates |
| "cli 0.4.1 · 0.5.0 available" | Both **budctl** and the **platform** release, each with "newer available" when known (§9.6) |
| Upgrade changelog: added / changed / removed | From the release manifest (§8), with `breaking` and `action required` as extra kinds |
| Plan items like "migrate gateway config v1 → v2, backup kept" | Values migrations, written to Git as their own commit so a revert undoes them (§9.3) |
| "restart running services · ~8s downtime" | Per-component disruption from the manifest (`none` / `rolling` / `brief` / `outage`) |
| "pins gateway v1, stays on 0.4.1 until you migrate" | An operator-owned file conflicts with the upgrade: three-way merge preview, or that component is held back (§9.4) |
| "Rollback stays available for 14 days" | `budctl upgrade --rollback`, valid while the previous release's charts and images are still pullable and no forward-only migration is pending (§9.5) |

---

## 6. Install — shared foundations

### 6.1 Phases and checkpoints

```
start → preflight → components → config → plan → install → verify → done
                                                  │
                        ┌─────────────────────────┴─────────────────────────────┐
                        render → commit → push → argocd → bootstrap → sync[app]…
```

Each checkpoint is recorded in session state (it extends today's `Phase`):

`selected → preflighted → generated → prepared → pushed → argocd-installed → bootstrapped → synced:<app> → verified → complete`

When the operator resumes, budctl re-validates the last checkpoint. It confirms that the commit is still at the head
of the branch and that Argo CD is still installed, then continues from the step after it. If a checkpoint no longer
holds, for example because someone force-pushed, that step is redone. Nothing is assumed.

### 6.2 Installation identity

Three records identify an installation. Every command looks for all three:

1. **Local session** (exists): encrypted state plus its age key, keyed by `environment + repository`.
2. **Git**: the environment's files in the config repo (`appsets/<env>.yaml`, `values/**/*.<env>.yaml`,
   `secrets.<env>.yaml`).
3. **Cluster marker** (new): a ConfigMap `bud-installation` in the `argocd` namespace. It is rendered into Git so
   Argo CD applies it (rule 1) and records `environment`, `repository`, `platformVersion`, `releaseManifest`
   digest, `budctlVersion`, `installedAt` and `lastUpgradeAt`. With the marker, `status` and `upgrade` work from
   a machine that has no local session: they read the kube context, find the marker and clone the repo.

### 6.3 One question model

`intake.Answers` (check) and `install.Spec` (install) merge into a single versioned **InstallSpec**:

- Install runs preflight from its own answers, so nothing is asked twice.
- `--answers file.yaml` works for both commands. `budctl install --plan --save-answers` writes one.
- Every field records where its value came from: `asked`, `detected`, `default` or `flag`. The plan and the
  config screen show this (G2).

### 6.4 Preflight inside install

The install's preflight step runs the FRD-020 engine (catalogue: Appendix A), scoped to the chosen components and
answers:

- **BLOCK** stops at the preflight screen. Each blocker has a remedy, and `r` re-runs it after the fix.
- **RISK** must be acknowledged. Each acknowledged risk is listed on the plan. `--strict` turns risks into blocks.
- `--skip-preflight` exists, is shown in red on the plan, and is recorded in the cluster marker.
- Install-specific checks are added to this step:
  - repository write access from the workstation (exists: `CheckRepositoryAccess`)
  - repository read access from inside the cluster: the Argo CD repo-server's view (exists as `argocd.config-repo-reachable`)
  - that the environment does not already exist in the repo under a different installation
  - for a resumed session, that the age recipients in `.sops.yaml` still match the saved key

---

## 7. Install — the flow

### 7.1 Start

```
 Bud Foundry installs the Bud platform onto this cluster through GitOps.
 It writes configuration to your Git repository, then Argo CD applies it.
 Nothing is committed or applied until you confirm the plan.

 ▸ Continue production @ acme/bud-config   stopped at: sync clickhouse · 2h ago
   Quick install        recommended defaults, four questions
   Custom install       choose components, TLS, storage, datastores, sizing
   Repair / reinstall   keeps your repository, credentials and data

 target  prod-eks (EKS 1.31 · 4 nodes) · Est. 15–25 min · needs cluster-admin
```

- **Continue** appears only when a resumable session matches the current context. Choosing it goes straight to
  the step after the checkpoint.
- If the cluster already carries a `bud-installation` marker, the start screen leads with **Repair** and
  **Upgrade**. **Quick** and **Custom** are refused, with a message saying which installation is already present.

### 7.2 Quick install

It asks only for the target repository, root domain, registry credentials and admin email. The repository's SSH
deploy key is asked for only when the repository is private and SSH. Everything else is decided as below, and the
plan shows each decision:

| Decision | Quick default | Detected from |
|---|---|---|
| Environment name | `production` | — |
| Platform | OpenShift path if `route.openshift.io` exists | API discovery |
| Domain | Pre-filled with `*.apps.<cluster>` on OpenShift | `ingresses.config.openshift.io/cluster` |
| Ingress class | Default IngressClass, else the only one, else Traefik (installed) | IngressClass list |
| StorageClass | The default class, if `check` proved it provisions | `storage.default-class`, `storage.provision` |
| TLS | ACME HTTP-01 if `domains.inbound-80` passes from outside; else self-signed CA, with a warning | `domains.*` |
| Components | Required set + OpenSandbox; Bud Studio off | §7.4 |
| Datastores | In-cluster, minimal profile (single instance each) | — |
| Sizing | Derived from node capacity: `minimal` below 3 schedulable nodes, else `standard` | `nodes.*` |
| Model storage | 300 GiB, capped to what the StorageClass can provision | `storage.capacity` |
| Push branch | `main` | — |

If a detection is ambiguous (two default classes, or no ingress controller), Quick asks that one question rather
than guessing.

### 7.3 Custom install

These pages follow the stepper. Each one shows **consequence lines** that update as you type (FRD-020 §7 pattern):

1. **GitOps target**: repository, branch, environment, deploy key, extra age recipients, template ref (advanced).
2. **Components** (§7.4): a toggle list. Required items are locked and show why. Optional items show their
   resource cost and what they depend on. Turning on an item turns on what it needs, and the screen says so.
3. **Network & TLS**: domain, per-host overrides (`global.ingress.hosts.*`), ingress class, TLS mode (ACME
   HTTP-01, ACME DNS-01/Cloudflare, self-signed CA, existing internal CA, external termination), extra CA bundle.
4. **Storage & capacity**: StorageClass (global and per datastore), model storage, models, concurrent deployments,
   GPU expected, observability retention.
5. **Datastores**: for Postgres, ClickHouse, Kafka, MongoDB, Valkey and S3, choose in-cluster or external. For an
   external store, give its endpoint and credentials and choose a reachability probe (`externaldatastores.*`).
6. **Sizing**: `minimal` (single replica, the `example.minimal.yaml` profiles) / `standard` / `ha` (3-instance
   Postgres, Kafka, ClickHouse, MongoDB). Each shows the summed requests against cluster capacity.
7. **Access**: admin email and password (generated if blank), registry credentials, Keycloak realm settings
   (advanced).

`--answers` pre-fills every page. `--no-prompt` with a complete answers file skips them all.

### 7.4 Component catalogue

The component list comes from the release manifest (§8), not from code. budctl knows the kinds of components but not
which ones exist. This table is the catalogue for platform 1.3.0, taken from `infra/appsets` and the bud chart:

| Component | Kind | Default | Depends on | Notes |
|---|---|---|---|---|
| argocd | required | on | — | Helm-bootstrapped, then managed by itself |
| cert-manager (+ trust-manager) | required unless TLS = external | on | — | |
| kyverno | conditional | on for self-signed / internal CA | cert-manager | Injects the CA bundle; pods need a restart after first sync (§13) |
| dapr | required | on | — | namespace `dapr-system` |
| postgres (CNPG) | required, or external | in-cluster | — | Also holds seaweedfs filer metadata |
| clickhouse (Altinity) | required, or external | in-cluster | — | DB name must be `metrics` |
| kafka (Strimzi) | required, or external | in-cluster | — | |
| mongodb (Percona) | required, or external | in-cluster | — | Used by Novu |
| valkey | required, or external | in-cluster | — | Index allocation checked by `config.valkey-indexes` |
| seaweedfs | required, or external S3 | in-cluster | postgres | Bucket quota must match `storage.budmodelRegistry` |
| keycloak | required | on | postgres | `auth.<domain>` |
| opensandbox | optional | on | — | CN-region images (FRD-020 Q2) |
| bud | required | on | all of the above | ~21 microservices, toggled inside the chart |
| bud-studio | optional | off | bud | chart `budagent` |
| budeval | optional (in bud) | off | bud | `microservices.budeval.enabled` |
| prometheus / otel collector | optional (in bud) | on | clickhouse | |
| openebs | optional add-on | off | — | Only when the cluster has no usable StorageClass |
| signoz, velero, harbor | optional add-ons | off | — | Velero is required for §11 backup checks |

Turning off a required component is not possible. Switching a datastore to **external** is the supported
alternative.

### 7.5 Plan

As in §5.2, the plan shows:

- the diffstat of the generated commit, and the sensitive file count, which are encrypted
- every Application, in sync order, with its chart version
- files written outside Git
- acknowledged risks
- an estimate, from manifest-recorded pull sizes and typical sync times
- `d` opens the full rendered diff (secrets shown as `ENC[…]`)

### 7.6 Apply and watch

Apply follows the existing order: render, commit, push, Helm-install Argo CD, sync bootstrap, then sync children in
dependency order (`argocd → cert-manager → kyverno → dapr → kafka → mongodb → clickhouse → postgres → seaweedfs →
valkey → keycloak → opensandbox → bud → bud-studio`). Two things change:

- **Per-Application detail.** Each row shows sync, health and age. `enter` expands to show the Application's
  conditions, the failing resources and their latest events.
- **Expected Degraded is labelled, not hidden.** The CRD race on first sync is marked as `settling` while the
  Application is within its settle window. The window comes from the release manifest, per component. Past the
  window, the row becomes `stuck` and diagnosis starts (§7.7).

Timeouts are per Application, also from the manifest. budctl never waits on one global timeout.

### 7.7 Diagnose

When an Application is stuck or fails, budctl reads the Application's resources and events and matches them to a
cause:

| Signal | Likely cause | Re-run / remedy |
|---|---|---|
| `ImagePullBackOff`, `ErrImagePull` | Registry auth, missing tag, egress | `registry.auth`, `registry.tags`, `registry.from-cluster` |
| PVC `Pending` | StorageClass cannot provision / no capacity | `storage.provision`, `storage.capacity` |
| Pod `Pending`, `Insufficient cpu/memory` | Capacity | `nodes.capacity`, `nodes.largest-pod` |
| `Evicted`, `DiskPressure` | Image filesystem | `nodes.imagefs` |
| Certificate not Ready, Challenge pending | DNS / port 80 / DNS-01 token | `domains.*`, `egress.acme` |
| `Error decrypting` in repo-server | age key mismatch | Compare `.sops.yaml` recipients with Argo CD's `helm-secrets-private-age-keys` |
| `CrashLoopBackOff` with auth errors to a datastore | Credentials differ across secrets files | `repair --secrets` (§7.10) |
| Apply rejected: object exists without Helm ownership | Leftover from an earlier install | `config.dry-run`, `components.appset-conflicts` |
| Pods `1/1` where `2/2` is expected | Dapr injector was not ready when pods started | Restart the affected deployments (offered as an action) |

Diagnosis shows the evidence and the remedy, and offers `r` to retry the sync once the operator has fixed the cause.
It never changes the configuration on its own.

### 7.8 Verify (smoke pass)

Install is `complete` only when every one of these passes. Each is a check in a new `verify` group, so `status` can
run the same checks:

- every Application is `Synced` and `Healthy`
- every workload that should have a Dapr sidecar has it (`2/2`)
- every Certificate is `Ready` and the served certificate chains to the expected issuer
- each public host returns its health endpoint over HTTPS from the operator's vantage point: `admin.`, `app.`,
  `gateway.` (`/health`), `auth.` (realm discovery), `s3.`
- the default-cluster onboarding Job (`registerDefaultCluster`) has completed
- the admin user can obtain a token from Keycloak, using generated credentials held in memory only
- operator CRs report ready: CNPG `Cluster`, Strimzi `Kafka`, ClickHouse `CHI`, `PerconaServerMongoDB`, `Keycloak`

### 7.9 Done

```
 ✓ Bud 1.3.0 is installed and verified                       production · 21 min

   console      https://admin.bud.example.com
   gateway      https://gateway.bud.example.com
   admin        admin@example.com · password shown once below — store it now
   recovery     ~/.config/budctl/installs/production-3fa2.agekey   back this up
   root CA      ~/.config/budctl/installs/production-3fa2-ca.pem   import into clients

   next   budctl status · budctl upgrade --check · docs.budecosystem.com/…
```

The admin password appears on this screen only and is never written in plaintext. This matches current behaviour.

### 7.10 Repair / reinstall

Repair rebuilds the installation from saved state and Git, without regenerating anything that already exists.

- **Re-render**: regenerate the per-environment files from the saved spec, show the diff against Git, then commit
  and sync. This restores files someone edited by hand, and the operator can choose which files to keep.
- **Re-sync**: sync every Application that is OutOfSync or Degraded, in dependency order, then verify.
- **Secrets**: check that the credentials shared across secrets files agree, for example the Postgres user in
  `postgres` and in `bud`. If any differ, re-render from the saved generated secrets. Rotating secrets is a separate,
  explicit action (`repair --rotate <name>`, later phase).
- **Argo CD**: reinstall or repair the Helm release, the repository credential and the SOPS key secret.
- **Lost local state**: recover from Git plus the recovery key (`--recovery-key`). Values that were only ever local
  (the admin password) are reported as unrecoverable, with how to reset each one.

Repair never deletes PVCs, namespaces or data.

---

## 8. Release manifest (the enabler for upgrade and status)

Today a "version of Bud" is spread across three places: the pinned template SHA (`DefaultTemplateRef`), each
appset element's `targetRevision`, and image tags in values. Nothing ties these together. This FRD introduces a
**release manifest**: one signed document per platform release.

```yaml
apiVersion: budctl.bud.studio/v1
kind: Release
version: 1.4.0
releasedAt: 2026-11-20
minBudctl: 0.7.0
upgradeFrom: [">=1.3.0 <1.4.0"]          # supported direct sources
template: { repo: …/example-bud-foundry-config.git, ref: <sha> }
components:
  - name: bud
    chart: { repo: oci://registry.bud.studio/charts, name: bud, version: 1.4.0 }
    images: [ registry.bud.studio/runtime/budapp:1.4.0, … ]   # with compressed sizes
    disruption: rolling                     # none | rolling | brief | outage
    settle: 10m
    timeout: 20m
  - name: postgres
    chart: { …, version: 0.1.2 }
    disruption: brief
    …
migrations:                                 # values changes, applied as their own commit
  - id: 1.4.0-gateway-routes-v2
    files: ["values/bud/values.<env>.yaml"]
    kind: jsonpatch | script
changelog:
  - { kind: added,    text: "…" }
  - { kind: changed,  text: "…", component: bud }
  - { kind: removed,  text: "…" }
  - { kind: breaking, text: "…", action: "…" }
```

- **Source**: written by the bud-runtime release pipeline and published as an OCI artifact at
  `registry.bud.studio/releases/bud:<version>`, signed with cosign. It is also attached to the GitHub release.
- **Embedded copy**: each budctl build embeds the manifest of the latest release it was tested against. This
  replaces `DefaultTemplateRef`, so an air-gapped host can still install.
- **Uses**: install (component catalogue, sync order, timeouts, estimates), status (expected versions), upgrade
  (diff, changelog, migrations, disruption), mirror (image and chart list), check (`registry.tags` against the
  manifest instead of the rendered chart).

---

## 9. Upgrade

`budctl upgrade [--to <version>] [--check] [--plan] [--rollback]`

Stepper: `plan → preflight → apply → verify → done`.

### 9.1 Plan

```
 Upgrade  1.3.0 → 1.4.0
 Released 4 days ago · 6.2 GiB new images · your values are migrated, never overwritten

 added      budctl watch — follow a sync from the CLI
 changed    gateway routes move to the v2 config schema
 breaking   kafka 0.1.1 → 0.2.0 needs a broker rolling restart
 removed    budeval legacy dataset path

 Plan
 ▸ [✓] upgrade budctl to 0.7.0         required by 1.4.0 (minBudctl)
   [✓] migrate values: gateway v2      1 file · own commit · reversible
   [✓] bump 9 charts                   bud 1.3.0→1.4.0, postgres 0.1.1→0.1.2, …
   [✓] pre-pull images                 6.2 GiB on 4 nodes · optional
   [✓] sync in dependency order        bud rolling · postgres ~30s write pause
 ⚠  values/bud/values.budruntime.yaml was edited locally — 2 conflicts, review with m
    Rollback available while 1.3.0 images stay pullable: budctl upgrade --rollback
```

- `upgrade --check` gives a one-line answer ("1.4.0 available, 3 breaking items") and is cheap enough to run
  from cron.
- `d` shows the full changelog. `m` opens the merge preview (§9.4).
- When there is no direct path, the plan shows the hops (1.2.5 → 1.3.0 → 1.4.0) and runs them one at a time.

### 9.2 Upgrade preflight (`check --upgrade`)

This mode runs the FRD-020 engine with the upgrade-only checks that its IMPLEMENTATION_PLAN lists as unbuilt:

- the installed release matches the marker; flag Applications that are OutOfSync before the upgrade starts
- existing PVCs whose size or class no longer matches the new chart's claims
- the ApplicationSet-installed components (Dapr, cert-manager, Traefik CRDs) are present and healthy: required for
  an upgrade, though not for an install (FRD-020 §3.1)
- every image and chart in the target manifest resolves (`registry.tags` against the manifest)
- `nodes.imagefs` has room for the new images in addition to the old ones
- the target release's requirements, such as a newer minimum Kubernetes version
- backups: a recent successful Postgres backup exists, or the operator acknowledges that none does (§11)
- `config.dry-run` against the target values

### 9.3 Apply

1. **Self-update** budctl if `minBudctl` requires it (§9.6), then re-exec with the same session.
2. **Migration commit**: apply values migrations to the environment files. This is one commit per migration, each
   with a clear message.
3. **Version commit**: bump each `targetRevision`, update image tags where values pin them, and update the marker's
   `platformVersion`.
4. **Push**, then **sync** in dependency order, using the same watch, settle and diagnose as install (§7.6–7.7).
5. **Verify** (§7.8). After that, the marker's `lastUpgradeAt` is set.

Every step is a checkpoint. An interrupted upgrade resumes the same way an install does.

### 9.4 Operator-owned files

`values.budruntime.yaml` and `templates/appset.yaml.tmpl` are seeded once and belong to the operator from then on
(current behaviour). To upgrade them, budctl records the template ref used at seed time. It does a three-way merge
between the old template, the operator's file and the new template:

- **Clean merge**: shown in the plan and committed.
- **Conflict**: the operator resolves it in the merge preview (`m`), or holds that component at its current
  version. The plan states which component is held back and why.
- `--force-template` still replaces the files outright, and the plan says so in red.

### 9.5 Rollback

`budctl upgrade --rollback` reverts the version commit (and optionally the migration commits), then syncs and
verifies. Its limits are stated in the plan, not discovered later:

- Database migrations run forward-only at service start (`safe_migrate.py`), and services tolerate a schema that is
  ahead of them (`ALLOW_SCHEMA_AHEAD`). Rolling back the application is therefore supported. The schema is not
  rolled back.
- Operator-chart rollbacks (CNPG, Strimzi, and so on) are allowed only where the manifest marks the pair
  `reversible`.
- Rollback needs the previous release's images and charts. Registry tags are immutable, so this holds unless a
  mirror pruned them.

### 9.6 budctl self-update

- `budctl self-update [--to <v>]` downloads the release, verifies `SHA256SUMS` and the cosign signature, and
  replaces the binary atomically. Signing is a prerequisite that is not built yet (FRD-020 WS-7).
- When a check is allowed, `status` and `install` show a notice like "budctl 0.7.0 available". The check runs once
  a day at most, `BUDCTL_NO_UPDATE_CHECK=1` disables it, and it is never made on an air-gapped host.

---

## 10. Air-gapped installs

- `budctl mirror --to <registry> [--release <v>]` copies every image and chart in the release manifest to a private
  registry. It runs from a machine with access to both registries. `mirror --to-dir` produces an OCI layout for
  transfer by disk.
- `install --registry-mirror <registry>` rewrites image and chart references in the generated values, and `check`
  then judges the mirror instead of upstream.
- Known blocker, to fix in infra (§13): the Argo CD chart's init container downloads sops, age, helm-secrets,
  kubectl and vals from GitHub at runtime. That download must be replaced by a pre-built repo-server image.

---

## 11. Status

`budctl status [--watch] [--output json]`

It is read-only by default. Tabs: **overview · components · services · cluster**.

```
 Overview                                   production · acme/bud-config · refreshed 2s ago
 platform   1.3.0 · 1.4.0 available (3 breaking)      budctl 0.6.0
 argocd     12/12 Synced · 11 Healthy · 1 Progressing
 endpoints  admin ✓  app ✓  gateway ✓ 41ms  auth ✓  s3 ✓
 certs      7/7 Ready · earliest expiry 61 days
 backups    postgres ✓ 6h ago · clickhouse ✓ 6h ago · velero — not configured

 Components
   component     version   sync      health        age      detail
 ▸ bud           1.3.0     Synced    Healthy       6d 04h   21/21 services ready
   postgres      0.1.1     Synced    Healthy       6d 04h   3/3 instances · primary pg-1
   clickhouse    0.1.1     Synced    Progressing   00m 40s  1 replica restarting
   keycloak      0.2.1     OutOfSync Healthy       6d 04h   values changed in Git, not synced

 ⚠ clickhouse-0 restarted 3 times in the last hour — OOMKilled. enter for details
 ↑↓ select  enter details  l logs  s sync  r refresh  u upgrade  q quit
```

- **components**: one row per Argo CD Application. Expected version comes from the marker and manifest, actual
  version from the Application.
- **services**: the bud microservices, with ready/desired replicas, restarts in the last hour, sidecar presence and
  the health endpoint.
- **cluster**: the FRD-020 read-only checks for capacity, imagefs, storage, GPU and certificates. They run on
  demand, without probes.
- **Actions**:
  - `l` opens logs (follow mode, previous container on a crash).
  - `s` asks Argo CD to sync the selected Application. It needs confirmation, and it is the only change `status`
    can make. Rule 1 permits it.
  - `u` starts `upgrade`.
- **Warnings** are ranked: data at risk, then user-facing outage, then degraded, then informational. Each warning
  has its diagnosis (§7.7) one key away.
- **Headless**: `status --output json` returns the same model. Exit codes are in §5.3. `--strict` treats warnings
  as failures.
- **Backups**: reads CNPG `ScheduledBackup`/`Backup`, the clickhouse-backup status and Velero `Backup` objects. It
  never triggers a backup.

---

## 12. Uninstall

`budctl uninstall [--keep-data | --purge] [--keep-git]`

- **Plan**: lists every Application, namespace and PVC, plus each PV's reclaim policy. Data is grouped by store, with
  sizes.
- **Default `--keep-data`**: delete Applications in reverse dependency order and keep PVCs and namespaces that
  hold data. The plan states the cost: storage keeps being billed.
- **`--purge`**: also delete namespaces and PVCs. The operator must type the environment name to confirm.
- **Git**: by default, removes the environment's files in one commit. `--keep-git` leaves them. The repository
  itself is never deleted.
- **Argo CD**: uninstalled last, and only if no other environment uses it.
- **Local session**: archived, not deleted. The recovery key stays.

---

## 13. Infra changes this FRD depends on

These items come from the infra survey. Each one causes a failure or surprise during install or upgrade that budctl
can only work around:

| # | Change | Why |
|---|---|---|
| I1 | Release pipeline writes and signs the release manifest (§8) | Upgrade, status and mirror all depend on it |
| I2 | Argo CD repo-server image with sops/age/helm-secrets/kubectl/vals baked in | Init container downloads from GitHub, which breaks air-gapped installs |
| I3 | Sync waves (or explicit dependencies) on operator CRDs vs their CRs | Removes the first-sync Degraded window instead of explaining it |
| I4 | Kyverno CA injection ordered before bud starts, or bud restarted by a hook | "Restart bud after kyverno syncs" is a manual step today |
| I5 | Fix version drift between docs and appsets (dapr 1.18.4 vs 1.17.5; kyverno, seaweedfs) and the missing `values/dapr/values.yaml` | The manifest must be the one truth |
| I6 | Health endpoints listed per service in the manifest (or a chart annotation) | `verify` and `status` should not hard-code paths |
| I7 | Mirror OpenSandbox's CN-region images to `registry.bud.studio` (FRD-020 Q2) | Egress blocker for most customers |
| I8 | Add the `bud-installation` marker to the template repo | §6.2 |

---

## 14. Roadmap

Each phase ships on its own and is accepted on a live cluster (k3s and one OpenShift) before the next starts.

| Phase | Scope | Accepted when |
|---|---|---|
| **P0** (0.4.x, done) | `check`, resumable `install`, `cleanup` | — |
| **P1 — Install shell** | Unified TUI shell (§5.1); merged InstallSpec (§6.3); start screen with Continue/Quick/Custom/Repair (§7.1); Quick path (§7.2); preflight inside install (§6.4); plan screen (§5.2); extended checkpoints (§6.1); `verify` group and Done screen (§7.8–7.9); run logs | A Quick install on an empty k3s cluster asks four questions and ends verified; killing the run at each checkpoint and re-running finishes without re-asking |
| **P2 — Status & diagnose** | Cluster marker (I8, §6.2); `status` overview + components + services (§11); diagnosis table (§7.7) used by both install and status; per-check re-run in `check` | `status` from a second machine with no session finds the install; each diagnosis row has a fixture-driven negative test (FRD-020 §4.1) |
| **P3 — Custom install** | Component catalogue and toggles (§7.4); external datastores; sizing profiles; per-host overrides | An install with external Postgres + internal CA + Bud Studio passes verify |
| **P4 — Release manifest & upgrade** | I1, I5; manifest embedded in budctl in place of `DefaultTemplateRef`; `check --upgrade`; `upgrade` plan/apply/verify; three-way merge of operator files; `--rollback`; signing + `self-update` | 1.3.0 → next release upgrade on a live install with one deliberately edited operator file; rollback restores a verified 1.3.0 |
| **P5 — Repair & uninstall** | `repair` modes (§7.10); `uninstall` (§12) | Hand-deleted secret and a hand-edited values file both restored by `repair`; `uninstall --keep-data` then `install` reattaches the data |
| **P6 — Air-gap & day-2 extras** | I2, I7; `mirror`; `--registry-mirror`; backup status in `status`; `support-bundle` (redacted logs, reports, Application states) | Full install with cluster egress blocked except the mirror |

---

## 15. Decisions

**D1 — Extend budctl; do not build a second tool.** The engine, adapters, probes and TUI are proven (FRD-020
status), and diagnosis reuses readiness checks directly.

**D2 — Writes go to Git, not the cluster.** This includes the installation marker and values migrations. The
exceptions are the Argo CD bootstrap, sync requests and uninstall deletions. Anything else would be reverted by the
next sync, or would make Git stop describing the cluster.

**D3 — A "version" is a release manifest, not a template SHA.** The template pin answers "which files", not "which
platform". Upgrade needs the latter.

**D4 — Quick install detects, then shows its work.** Every non-asked decision appears in the plan with its source,
so "quick" never means "opaque".

**D5 — Rollback is promised only where it is true.** Forward-only schema migrations make application rollback safe
and schema rollback impossible. The plan says so.

**D6 — `status` is read-only except for sync.** Restarting, scaling and editing are changes that belong in Git or in
`repair`. A sync only asks Argo CD to apply what Git already says.

---

## 16. Open questions

| # | Question |
|---|---|
| Q1 | Where does the release manifest live long-term: an OCI artifact in `registry.bud.studio`, a file in the template repo, or both? (Proposed: OCI, signed, with an embedded fallback.) |
| Q2 | Should `budctl` manage several environments in one repo and one Argo CD (stage + prod)? Today an installation is environment + repo; uninstall and Argo CD ownership need a rule. |
| Q3 | Is the minimal (single-instance) datastore profile acceptable as the Quick default for anything beyond a POC, or should Quick refuse to produce a "production" environment name with it? |
| Q4 | Who owns values migrations — the service team that changes a values schema, or Infra at release time? A migration with no owner is a release blocker. |
| Q5 | Should `status` read the Bud API (budapp) for application-level health, such as registered clusters and deployments, or stay at the Kubernetes/Argo CD layer? (Proposed: K8s layer in P2, Bud API later, behind admin credentials.) |
| Q6 | Upgrade's backup gate: is "no recent backup" a block or an acknowledged risk? |

---

## Appendix A — Prerequisite check catalogue (as built, budctl 0.4.x)

This is the reference for every check `budctl check` runs today, and for what the install preflight (§6.4) reuses.
It is taken from the code (`internal/checks/*.go`, `internal/intake/defaults.yaml`). Where it differs from
FRD-020 §5, the code is right. **90 checks in 14 groups.**

### A.1 How the checks run

- **Order.** Groups run in this order, which is also the order they are reported in:
  `platform → toolchain → config → cluster → argocd → registry → charts → nodes → storage → components →
  domains → egress → gpu → external-datastores`.
  `config` runs third because `config.render` produces the rendered manifest that the registry, charts and storage
  checks read. Within a group, checks run concurrently.
- **Levels.**
  - **BLOCK**: the sync will fail.
  - **RISK**: the install succeeds but a named capability is degraded.
  - **INFO**: context only.
  - **SKIP**: did not apply or could not run. A SKIP is never counted as a pass.
  The verdict is the worst level seen: `READY`, `READY WITH RISKS` or `NOT READY`. Exit codes are in §5.3.
- **"Max level" in the tables below** is the severity a check is registered with. Many checks downgrade
  themselves for a weaker finding. The *When* column says when that happens.
- **Every check has a negative test.** A check that cannot be driven to BLOCK or RISK against a fixture does not
  merge (FRD-020 §4.1).
- **Thresholds come from the intake answers (A.3).** `defaults.yaml` supplies only the floors an operator cannot
  reasonably be asked for (A.4). A rendered chart (`--values`) overrides both.

### A.2 Probes — what `check` creates in the cluster

All probe objects go in one namespace, `budctl-readiness-<8 hex>`, labelled `app.kubernetes.io/managed-by=budctl`.
The suffix is derived from the kube context, so a re-run reuses the same namespace. Cleanup runs on exit, on
SIGINT/SIGTERM and on SIGPIPE. `budctl cleanup` sweeps any leftovers, and `--keep` retains the namespace for
debugging. `--no-probe` turns every probe check into a SKIP.

| Probe check | Creates | Proves |
|---|---|---|
| `registry.from-cluster` | 1 Pod | Nodes can reach the registry and the credentials are accepted |
| `storage.provision` | 1 × 1 GiB PVC + consumer Pod per candidate class | The provisioner binds (a consumer is needed for `WaitForFirstConsumer`) |
| `egress.*` | 1 Pod (`curlimages/curl:8.11.1`, `--probe-image`) | Outbound reachability from where workloads run |
| `argocd.repo-server-egress` | 1 Pod | The Argo CD init container's tool downloads succeed |
| `gpu.operator-functional` | 1 Pod requesting `nvidia.com/gpu: 1` (`debian:trixie-slim`, `--gpu-probe-image`) | Driver, device plugin and RuntimeClass deliver a device. No CUDA image is pulled |

### A.3 Intake: what `check` asks, and what each answer drives

| Page | Question | Drives |
|---|---|---|
| 1 · Where Bud will live | Root domain | `domains.*`. Pre-filled with `*.apps.<cluster>` on OpenShift |
| | How TLS certificates are obtained | Whether `domains.inbound-80` and `egress.acme` block |
| | Internal CA bundle (optional) | Trust used for `domains.tls` |
| 2 · What it needs to hold | Data stores: in-cluster / external | `nodes.count` quorum, `external-datastores` run or SKIP, storage total |
| | Model storage (GiB), how many models | `storage.capacity`, model-registry claim |
| | Observability retention (days) | ClickHouse size, an estimate at 1 GiB/day |
| 3 · What it will run | Concurrent deployments, GPU expected | `nodes.capacity`, `gpu.*` run or SKIP, `gpu.capacity` |
| 4 · Where ArgoCD reads configuration | Config repository URL | `argocd.config-repo-reachable`, `egress.ssh` |
| 5 · Registry access | `registry.bud.studio` username/token (optional) | `registry.auth`, `registry.tags` run or SKIP |
| 6 · Your configuration | Values file, chart directory, SOPS secrets file | `config.*`, and the rendered images and claims other groups read |
| 7 · Ready to check | Probe from inside the cluster? | Probes on or off |

Answers can be saved (`--save-answers`) and replayed (`--answers`). Flags pre-fill the form.

### A.4 Embedded floors (`defaults.yaml`, catalogue `2026-09-15.1`)

| Floor | Value | Why |
|---|---|---|
| `imageFsGi` | 80 GiB per node | ~55 GiB of images at 1.2.8 plus a deliberate buffer |
| `baseStorageGi` | 58 GiB | budmodelAddDir 20 + budappStaticDir 20 + budcache 10 + prometheus 8 (budeval's 32 GiB excluded) |
| `dataStoreStorageGi` | 269 GiB | Every in-cluster store at chart defaults × replicas |
| `clickHouseGiPerDay` | 1 GiB | An estimate, labelled as one wherever it is used |
| `minNodes` / `minNodesWithAddons` | 1 / 3 | Kafka `min.insync.replicas=2`, Keeper quorum 3, CNPG 3 instances |
| `baseCpuCores` / `baseMemoryGi` | 6 cores / 33 GiB | Summed platform requests |
| `largestPodMemoryGi` / `largestPodCpuCores` | 6 GiB / 1 core | semantic-router |
| `minKubernetes` / `minOpenShift` | 1.25 / 4.12 | |
| `hfThroughputMBs` | 5 MB/s | Opt-in `egress.hf-throughput` |
| `clockSkewWarnSeconds` / `FailSeconds` | 30 s / 120 s | Keycloak `exp`, budevent 300 s HMAC window, S3 SigV4 |

### A.5 The catalogue

#### `platform` (3)

| Check | Verifies | Max level / when |
|---|---|---|
| `platform.distribution` | OpenShift if `route.openshift.io` and `security.openshift.io` are served; otherwise vanilla, k3s, EKS, AKS or GKE from node labels and the version string. Every later group branches on this | INFO |
| `platform.openshift-version` | OpenShift ≥ 4.12, read from the newest `Completed` history entry (not the last attempted one) | BLOCK |
| `platform.cluster-proxy` | OpenShift `proxy.config.openshift.io/cluster`. Recorded against every egress result | INFO |

#### `toolchain` (4) — the operator's machine

| Check | Verifies | Max level / when |
|---|---|---|
| `toolchain.kubeconfig` | A context resolves and the API server answers, including through an `exec` credential plugin | BLOCK |
| `toolchain.exec-plugin` | The binary an `exec` plugin names (`aws`, `gcloud`, `az`) exists. The only host dependency budctl cannot absorb | BLOCK |
| `toolchain.clock` | Workstation clock within 30 s of a public reference | RISK |
| `toolchain.age-identity` | An age identity is available. Only runs when `--secrets` names a SOPS file | BLOCK (conditional) |

#### `config` (7) — the values that will be handed to Argo CD (needs `--values` / `--secrets`)

| Check | Verifies | Max level / when |
|---|---|---|
| `config.render` | `helm template` succeeds with the supplied values, which is where the chart's own guards fire. Helm runs as a library, not the CLI | BLOCK |
| `config.dry-run` | A server-side dry run is accepted. Catches objects that exist without Helm ownership | BLOCK |
| `config.required-values` | Values with no safe default are present: budevent AES key (exactly 32 bytes), RSA keypair, `registerDefaultCluster.token` | BLOCK |
| `config.fail-closed` | `realtimeGrantSecret`, `widgetInternalToken`, `resolveInternalToken`. A blank value silently disables a feature, and the check names which one | RISK |
| `config.public-defaults` | Credentials still set to the publicly known chart value (`appApiToken`, budcache keys, Novu key, `PASSWORD_SALT`, `SUPER_USER_PASSWORD`) | RISK |
| `config.placeholders` | `<change_me>`, `getmefrombud` | BLOCK for registry credentials, otherwise RISK |
| `config.valkey-indexes` | No two logical uses share a Valkey DB index | BLOCK |

#### `cluster` (5) — API surface and permissions

| Check | Verifies | Max level / when |
|---|---|---|
| `cluster.version` | Server ≥ 1.25 | BLOCK |
| `cluster.api-groups` | `apps/v1`, `batch/v1`, `networking.k8s.io/v1`, `autoscaling/v2`, `storage.k8s.io/v1`, `discovery.k8s.io/v1`, `rbac.authorization.k8s.io/v1`, `apiextensions.k8s.io/v1` are served | BLOCK |
| `cluster.server-side-apply` | The API server accepts SSA, which the ApplicationSets use | BLOCK |
| `cluster.installer-rbac` | The operator's identity can create namespaces, CRDs, ClusterRoles and ClusterRoleBindings | BLOCK |
| `cluster.admission-policy` | Vanilla: no restricted PodSecurity default and no enforcing Kyverno/Gatekeeper policy that would deny the stack's pods. OpenShift: the installer may grant an SCC | RISK |

#### `argocd` (8) — Argo CD's absence is never a blocker

| Check | Verifies | Max level / when |
|---|---|---|
| `argocd.installed` | Whether Argo CD is present, and which mode the group ran in | INFO |
| `argocd.chart-repo-reachable` | `oci://registry.bud.studio/charts` answers, and the bud chart resolves at the target version when credentials are given | BLOCK |
| `argocd.config-repo-reachable` | The config repo answers: HTTPS `info/refs?service=git-upload-pack`, or an SSH handshake on port 22 | BLOCK |
| `argocd.healthy` | *If installed:* application-controller, repo-server and applicationset-controller are Available | RISK |
| `argocd.version` | *If installed:* supports multi-source Applications with `$values` | RISK |
| `argocd.chart-repo-credential` | *If installed:* an OCI `repository` Secret exists with `enableOCI: "true"` | RISK |
| `argocd.rbac` | *If installed:* the controller's ServiceAccount can create namespaces, CRDs and cluster RBAC | RISK |
| `argocd.repo-server-egress` | *Probe, if installed from `infra/charts/argocd`:* the `download-tools` init container can fetch sops, vals, helm-secrets, age, curl and kubectl from GitHub and `dl.k8s.io` | RISK |

#### `registry` (8) — metadata requests only; no image layer is ever pulled

| Check | Verifies | Max level / when |
|---|---|---|
| `registry.reachable` | Each registry in the inventory (A.6) answers `/v2/` with 200 or 401 (401 still proves DNS, routing and TLS) | BLOCK for required hosts, RISK for conditional ones |
| `registry.tls` | Chain validates and has not expired. Surfaces corporate MITM proxies | BLOCK |
| `registry.from-cluster` | *Probe:* the same reachability test, run from a pod | BLOCK |
| `registry.auth` | `registry.bud.studio` credentials are accepted. **SKIP** when none are supplied | BLOCK when supplied and rejected |
| `registry.tags` | Every distinct `image:tag` in the render resolves to a manifest. Needs credentials and `--values` | BLOCK |
| `registry.pinned-tags` | No `:latest`, `:nightly` or untagged image | RISK |
| `registry.hami-scheduler` | The kube-scheduler image HAMi will use, with its tag computed from the cluster's own version | BLOCK on GPU clusters, SKIP otherwise |
| `registry.upstream-defaults` | Renders the charts in scope, collects every image host, and diffs them against the inventory. A host in the render but not the inventory means an upstream default moved | RISK |

#### `charts` (4) — Helm repositories

| Check | Verifies | Max level / when |
|---|---|---|
| `charts.oci` | `oci://registry.bud.studio/charts` resolves bud, keycloak and the addon charts at their pinned versions | BLOCK |
| `charts.classic` | `index.yaml` is reachable for each classic repo in scope (A.6) | BLOCK for repos in scope |
| `charts.runtime` | NFD, HAMi and NVIDIA NGC repos, which budcluster pulls at cluster onboarding | RISK |
| `charts.aibrix` | Aibrix release manifests on GitHub, including the redirect to the release-asset CDN | RISK |

#### `nodes` (11) — fleet shape and disk

| Check | Verifies | Max level / when |
|---|---|---|
| `nodes.ready` | Nodes are Ready and not cordoned | BLOCK if none is schedulable |
| `nodes.count` | ≥ 1 schedulable node, and ≥ 3 when data stores are in-cluster | BLOCK below 1, RISK below 3 |
| `nodes.architecture` | amd64 (images are published for `linux/amd64` only) | BLOCK |
| `nodes.tolerations` | At least one node is schedulable without a toleration (no chart declares any) | BLOCK |
| `nodes.capacity` | Allocatable minus committed requests covers the requirement derived from intake | BLOCK |
| `nodes.largest-pod` | The largest single pod (6 GiB / 1 core) fits on one node | BLOCK |
| `nodes.imagefs` | Per node, kubelet `imageFs.availableBytes` ≥ 80 GiB | BLOCK |
| `nodes.eviction-pressure` | No node is already under its `imagefs.available` eviction threshold | RISK |
| `nodes.pod-slots` | Committed plus expected pods stay under `max-pods` | RISK |
| `nodes.accelerators` | GPU/HPU inventory (CPU-only is supported) | INFO |
| `nodes.control-plane-label` | ≥ 1 node labelled `bud.studio/control-plane=true`, the preferred-affinity target | RISK |

#### `storage` (9) — provisioner-agnostic

| Check | Verifies | Max level / when |
|---|---|---|
| `storage.default-class` | A default StorageClass exists whenever a claim leaves `storageClassName` empty | BLOCK if any claim relies on it, otherwise RISK |
| `storage.named-classes` | Every class named in the answers or values exists | BLOCK |
| `storage.csi-healthy` | The CSI driver pods behind each class are Running | BLOCK |
| `storage.expansion` | `allowVolumeExpansion` on the classes backing the model registry and ClickHouse | RISK |
| `storage.capacity` | Provisionable capacity ≥ the requirement, from `CSIStorageCapacity`, OpenEBS `DiskPool` or node ephemeral capacity. Also counts how many segments can take the largest claim | BLOCK if known to be short, RISK if it cannot be verified |
| `storage.host-prereqs` | Host prerequisites implied by class parameters (`volgroup`, `fsType`), confirmed through per-node `CSIStorageCapacity` where the driver publishes it | RISK |
| `storage.shared-rwo` | A RWO claim mounted by several workloads, which pins them all to one node (for example `bud-models-registry`) | RISK |
| `storage.rwx` | A RWX claim on a class that serves one node at a time. An unrecognised driver is SKIPped | BLOCK |
| `storage.provision` | *Probe:* a 1 GiB PVC with a consumer reaches `Bound` for each candidate class | BLOCK |

#### `components` (4) — the only cluster components Bud requires but does not install

| Check | Verifies | Max level / when |
|---|---|---|
| `components.dns` | CoreDNS / kube-dns pods are healthy and resolving | BLOCK |
| `components.ingress` | A working ingress path. Vanilla: an IngressClass whose controller has ready endpoints. OpenShift: the Ingress Operator with a default IngressController | BLOCK when proved broken, RISK when it cannot be confirmed |
| `components.metrics-server` | `metrics.k8s.io` is Available. Every HPA depends on it | BLOCK |
| `components.appset-conflicts` | For any appset component already present (FRD-020 §3.1), flags version or ownership conflicts. Checks conflicts only, never that the component is present | INFO (conflicts reported as RISK) |

#### `domains` (6) — hosts: `admin. app. gateway. playground. customer. ask. notify. api.novu. ws.novu. mcpgateway. s3. auth.`

| Check | Verifies | Max level / when |
|---|---|---|
| `domains.resolve` | Every hostname resolves | BLOCK |
| `domains.wildcard` | A `*.<root>` record is detected | INFO |
| `domains.points-at-ingress` | Each host resolves to the ingress controller's external address. INFO, not PASS, when only private addresses are advertised | RISK |
| `domains.inbound-80` | Port 80 reaches the ingress from outside (needed for ACME HTTP-01). The result records the vantage point | BLOCK for HTTP-01 |
| `domains.inbound-443` | Port 443 reaches the ingress | RISK |
| `domains.tls` | Any certificate already served: chain (with `--ca-bundle`), expiry > 14 days, SAN coverage. Reports the exact x509 cause | RISK |

#### `egress` (8) — *probe*, from a pod by default (`--egress-from workstation|cluster|both`)

| Check | Verifies | Max level / when |
|---|---|---|
| `egress.install` | Every `when: install` endpoint in A.6 | BLOCK |
| `egress.acme` | Let's Encrypt ACME directory, when TLS is ACME | BLOCK |
| `egress.ssh` | `github.com:22` (port 22, not 443) for `ssh://` config repos | BLOCK (conditional) |
| `egress.runtime` | Runtime endpoints: Hugging Face API and `hf.co` CDN, BudConnect, the GitHub release CDN, NFD and Aibrix | RISK, naming the feature affected |
| `egress.optional` | Optional chart repos, PyPI, inference providers | INFO |
| `egress.proxy` | `HTTP_PROXY` / `NO_PROXY` in effect on nodes | INFO |
| `egress.clock-nodes` | Node clock skew, sampled from the probe pod | RISK, BLOCK beyond 120 s |
| `egress.hf-throughput` | Opt-in (`--hf-throughput`): samples a few MB from Hugging Face and reports MB/s | RISK below 5 MB/s |

#### `gpu` (6) — SKIPs entirely when there are no GPU nodes

| Check | Verifies | Max level / when |
|---|---|---|
| `gpu.nodes` | Nodes advertising `nvidia.com/gpu`, `habana.ai/gaudi` or `amd.com/gpu` in **allocatable** | INFO |
| `gpu.device-plugin` | The vendor device-plugin DaemonSet is Ready on every GPU node | BLOCK |
| `gpu.runtime-class` | The `nvidia` RuntimeClass exists when needed | BLOCK |
| `gpu.operator-functional` | *Probe:* a pod requesting one GPU schedules, starts and sees its device. Failures are reported by stage: Pending, failed to start, or started without the device | BLOCK |
| `gpu.sharing` | HAMi or MIG configuration and the effective GPU count | INFO |
| `gpu.capacity` | Allocatable GPUs against the intake answer | RISK |

#### `external-datastores` (7) — only when stores are external; SKIP when the appset installs them

Each check runs DNS, TCP from a pod (the only vantage that counts) and TLS where it applies. It also lists the
databases, buckets and topics that must already exist, because the umbrella chart creates none of them.
Credentials and schema privileges are not checked.

| Check | Max level |
|---|---|
| `externaldatastores.postgres` | BLOCK |
| `externaldatastores.clickhouse` | BLOCK |
| `externaldatastores.valkey` | BLOCK |
| `externaldatastores.kafka` | BLOCK |
| `externaldatastores.mongodb` | RISK (only Novu, the notifications service, uses it) |
| `externaldatastores.s3` | BLOCK |
| `externaldatastores.keycloak` | BLOCK |

### A.6 Network inventory (embedded)

**Image registries**

| Host | Pulled by | Requirement |
|---|---|---|
| `registry.bud.studio` | Every first-party image, and the OCI charts | required |
| `docker.io` | Aibrix (`budstudio/*`), HAMi, ClickHouse, Percona MongoDB, SeaweedFS, curl, alpine, otel-collector | required |
| `quay.io` | Keycloak, Argo CD, Prometheus; the cert-manager and Strimzi OCI charts | required |
| `ghcr.io` | Dapr, CloudNativePG, OpenTelemetry operator, valkey-operator, budecosystem scaler | required |
| `registry.k8s.io` | prometheus-adapter, NFD, kube-state-metrics, CSI sidecars, HAMi kube-scheduler | required |
| `ecr-public.aws.com` | Argo CD's bundled Redis, HAProxy in HA mode | required |
| `reg.kyverno.io` | Kyverno (five images) | required when Kyverno is installed |
| `nvcr.io` | NVIDIA GPU operator, dcgm-exporter | conditional: GPU |
| `sandbox-registry.cn-zhangjiakou.cr.aliyuncs.com` | OpenSandbox controller, server, egress, image-committer | conditional: OpenSandbox |
| `mirror.gcr.io`, `docker.redpanda.com` | Harbor trivy DB, SigNoz Redpanda (both disabled today) | dormant (INFO) |

**HTTP endpoints**

| When | Endpoints |
|---|---|
| install | `registry.bud.studio`, `registry-1.docker.io`, `quay.io`, `ghcr.io`, `registry.k8s.io`, `ecr-public.aws.com` (all `/v2/`); `dapr.github.io/helm-charts` |
| acme | `acme-v02.api.letsencrypt.org` |
| runtime | NFD charts; Aibrix release manifests on GitHub; `objects.githubusercontent.com` (where every GitHub release download redirects); `budconnect.bud.studio`; `huggingface.co`; `hf.co` (rotating `cdn-lfs*`) |
| optional | `reg.kyverno.io`; prometheus-community, bitnami, CloudNativePG, Altinity, Percona, SeaweedFS, OpenEBS, OpenTelemetry, Argo, SigNoz, HAMi and NVIDIA NGC chart repos (most are bundled in the published OCI charts and fetched only when building from source); `pypi.org` |

**TCP endpoints**

| When | Endpoint | Note |
|---|---|---|
| install | `github.com:22` | Argo CD's SSH git source. A 443-only egress policy breaks it |

---

## Appendix B — Install procedure (as built, budctl 0.4.x)

This is exactly what `budctl install` does today, step by step, taken from `cmd/budctl/install.go` and
`internal/install/*.go`. §6–§7 describe how this procedure is meant to change. The step numbers here are the
reference to compare against.

### B.1 Session

1. **Choose a session.** An explicit `--state <file>` is used as given. Otherwise budctl moves any legacy
   single-state file into `budctl/installs/` and lists the saved sessions. One session is resumed automatically. When
   there are several, the interactive run asks which to continue, and a non-interactive run must pass `--state` or
   `--fresh`.
2. **New installation or the saved one?** If `--environment` is set to a different value, or the form later changes
   the environment or repository, budctl starts a new installation. It does this so credentials are never
   inherited across installations.
3. **Build the spec.** Start from the defaults: branch `main`, TLS `acme-dns01`, 300 GiB model storage, 5 models,
   3 deployments, the pinned template repo and ref. On a resume, the saved spec is used instead. Flags are
   applied on top. If the saved template ref is the old default, it is upgraded to the current pin unless
   `--template-ref` is set.

### B.2 Detect and ask

4. **Detect from the cluster** (when it is reachable):
   - The environment name, from the kube context.
   - OpenShift: if `route.openshift.io/v1` is served, ingress class `openshift-default` and the domain from
     `ingresses.config.openshift.io/cluster`.
   - Otherwise the ingress class: the default IngressClass, else the only one, else `traefik`.
   - The StorageClass: the default one (GA or beta annotation), else the only one.
   - If nothing names the environment, it defaults to `production`.
5. **Form** (interactive, unless `--no-prompt`):
   1. GitOps target: repository, environment, push branch.
   2. Private repository: a notice that Argo CD cannot read it, then a deploy key for SSH repositories.
   3. Network & TLS: domain, ingress class, TLS strategy (`acme-dns01` with Cloudflare, `acme-http01`,
      `self-signed`, `internal-ca`, `external`). Depending on the strategy, it also asks for a Cloudflare token, an
      extra CA bundle, or an issuing CA certificate and key.
   4. Capacity: StorageClass, model storage, expected models, concurrent deployments, GPU.
   5. Registry and admin: `registry.bud.studio` user and token, admin email and password (generated when left blank),
      extra age recipients.
   6. Bud Studio: whether to enable it, and its model.
6. **Load files**: the TLS material (CA bundle, issuer certificate and key) and the repository SSH key.
   Checkpoint **`selected`** is saved after each, unless `--plan` is set.
7. **Validate.**
   - The environment is DNS-safe.
   - A repository is given, and an SSH repository has a deploy key.
   - The domain is a hostname.
   - An ingress class and a StorageClass are set.
   - Registry credentials and a valid admin email are present.
   - The TLS material matches the chosen mode.
8. **Repository access.** Confirm that the repository is readable with the credentials Argo CD will use. If this
   fails, a full install stops. Runs with `--plan` or `--no-bootstrap` only get a warning.

### B.3 Generate and plan

9. **Secrets.** These are reused from saved state when it has them. Otherwise budctl generates:
   - An age identity for SOPS.
   - An admin password, unless one was given.
   - A password-protected RSA-2048 keypair.
   - A 32-byte hex AES key.
   - A 32-character budevent key.
   - 32-byte random tokens for: `postgres-bud`, `postgres-keycloak`, `postgres-seaweedfs`, `clickhouse`, `kafka`,
     `mongodb`, `valkey`, `s3-access`, `s3-secret`, `keycloak-admin`, `keycloak-budadmin`, `keycloak-budcustomer`,
     `keycloak-budplayground`, `keycloak-mcpgateway`, `keycloak-budapp-admin`, `app-api`, `oidc-mcpgateway`,
     `novu-encryption`, `novu-admin`, `jwt`, `session`, `password-salt`, `notify-store`, `notify-jwt`, `mcp-basic`,
     `mcp-jwt`, `mcp-encryption`, `dapr-symmetric`, `dapr-asymmetric`, `cluster-token`, `opensandbox-api`.

   Secrets saved by an older budctl are repaired to the shape the charts now require; for example, the budevent key
   must be exactly 32 characters. Checkpoint **`generated`**.
10. **Render** the bundle. Sensitive files are SOPS-encrypted to the age recipient plus any extra recipients:
    - `apps/<env>.yaml`: the bootstrap Application.
    - `appsets/<env>.yaml`: hydrated later from `templates/appset.yaml.tmpl`.
    - `values/{argocd,bud,keycloak,seaweedfs}/values.<env>.yaml`, plus `cert-manager` (depending on TLS mode) and
      `bud-studio` (if enabled).
    - `values/{argocd,bud,keycloak,postgres,clickhouse,kafka,mongodb,seaweedfs,valkey,opensandbox}/secrets.<env>.yaml`,
      plus `cert-manager` and `bud-studio` where they apply. All encrypted.
11. **Print the plan**: environment, target and branch, template and ref, domain, TLS, ingress and storage, components
    (OpenSandbox always on, Bud Studio optional), state path, whether this is a resume, and which actions will run.
    With `--plan`, budctl stops here and exits 0, having written nothing.
12. **Check the flags and confirm.** `--no-push` requires `--no-bootstrap`. A non-interactive run requires `--yes`.
    Otherwise budctl asks: *"Generate, commit, and push this installation?"*

### B.4 Repository

13. **Clone** the target repository into a temporary workspace (using the deploy key over SSH when one is set), then
    check out the push branch if it already exists.
14. **Seed from the template.**
    - An empty repository gets the template contents at the pinned ref.
    - A non-empty repository without `values/argocd/values.budruntime.yaml` is refused.
    - An existing Bud repository keeps its operator-owned files, and only gets `templates/appset.yaml.tmpl` if that
      file is missing.
    - `--force-template` re-copies the shared files.
15. **Write** the generated files, hydrate the ApplicationSet from the template, and add the environment's rule
    (with all recipients) to `.sops.yaml`.
16. **Commit** as `budctl <budctl@bud.studio>` with the message `chore: configure <env> installation`. This is
    skipped when there are no changes, and `git diff --check` must pass first. The diffstat is printed.
    Checkpoint **`prepared`**, which records the commit.
17. **Save the recovery key** (the age identity, `0600`) *before* the push, because the push is the first step that
    cannot be undone.
18. **Push** `HEAD:refs/heads/<branch>`, unless `--no-push`. Checkpoint **`pushed`**.

### B.5 Cluster

19. **Confirm** (unless `--yes`): *"Git push complete. Start the ArgoCD installation on \<context\>?"* Declining
    exits 0 with the session saved. An unreachable cluster exits 3, telling the operator to re-run once access is
    fixed.
20. **Install Argo CD.** budctl Helm-installs or upgrades `oci://registry.bud.studio/charts/argocd` 0.1.1 as release
    `argocd` in namespace `argocd`, with values from `values/argocd/values.budruntime.yaml` merged with the generated
    values. The install is staged: the first pass leaves out AppProjects until their CRDs exist.
21. **Create the platform Applications.** budctl applies the bootstrap Application and syncs it, with a 10-minute
    timeout.
22. **Sync each child Application** in dependency order, with a 20-minute timeout each. This is skipped with
    `--no-sync`. The order:
    1. `argocd`: hands the Helm release over to Argo CD.
    2. `cert-manager`, unless TLS is external.
    3. `kyverno`, for self-signed or internal-CA TLS.
    4. `dapr`, `kafka`, `mongodb`, `clickhouse`, `postgres`, `seaweedfs`, `valkey`, `keycloak`, `opensandbox`, `bud`.
    5. `bud-studio`, if enabled.

    The list is narrowed to what the ApplicationSet actually declares. Any element budctl doesn't recognise is synced
    last.
23. **Export the CA** (self-signed TLS only): read `cert-manager/selfsigned-ca-root` `tls.crt` and save it next to
    the recovery key.
24. Checkpoint **`complete`**. Print the state path, CA path, local repository (when kept) and the admin password
    (once, never written in plaintext), and say whether children were synced.

### B.6 Flags that change the procedure

| Flag | Effect |
|---|---|
| `--plan` | Stop after step 11. Nothing is written |
| `--yes` | Skip the confirmations at steps 12 and 19 |
| `--no-push` | Commit locally and keep the workspace. Requires `--no-bootstrap` |
| `--no-bootstrap` | Stop after step 18 |
| `--no-sync` | Stop after step 21. Children wait for an explicit sync |
| `--state` / `--fresh` | Choose a session / start a new one |
| `--force-template` | Re-copy the shared template files at step 14 |
| `--template-repo` / `--template-ref` | Override the template source |
| `--recovery-key` | Where to write the age identity |

### B.7 Gaps against the target (cross-reference)

| As built | Target |
|---|---|
| Readiness checks never run inside install | §6.4: preflight inside install |
| `check` and `install` ask overlapping questions in separate forms | §6.3: one InstallSpec |
| The plan is a printed summary | §5.2: interactive plan with toggles and `--output json` |
| A fixed 20-minute timeout per Application, and a failure stops the run | §7.6–7.7: per-component settle windows and timeouts, plus diagnosis |
| Done means every Application synced | §7.8: smoke pass |
| No marker on the cluster | §6.2: `bud-installation` ConfigMap |
| Checkpoints are `selected`, `generated`, `prepared`, `pushed`, `complete` | §6.1: per-Application and verify checkpoints |
