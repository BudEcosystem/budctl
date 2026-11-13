# budctl

`budctl` checks whether a Kubernetes or OpenShift cluster is ready for
[Bud](https://budecosystem.com/) and installs Bud through GitOps.

It ships as a single binary with Kubernetes, Helm, SOPS, and age support built
in. You do not need to install `kubectl`, `helm`, `sops`, or `age` separately.
Every command is driven by flags; nothing prompts.

## Install

macOS and Linux binaries are available for amd64 and arm64.

```sh
curl -fsSL https://raw.githubusercontent.com/BudEcosystem/budctl/main/install.sh | sh
```

The installer verifies the release checksum and installs to `/usr/local/bin`,
falling back to `~/.local/bin` when needed.

To pin a version or choose an install directory:

```sh
curl -fsSL https://raw.githubusercontent.com/BudEcosystem/budctl/main/install.sh \
  | BUDCTL_VERSION=0.4.0 BUDCTL_INSTALL_DIR="$HOME/.local/bin" sh
```

You can also download a binary and `SHA256SUMS` directly from
[GitHub Releases](https://github.com/BudEcosystem/budctl/releases).

## Requirements

- A Kubernetes or OpenShift cluster and working kubeconfig
- Network access from the cluster to the registries and chart repositories used
  by Bud
- `git` and access to the target GitOps repository when using `budctl install`

If your kubeconfig uses an external credential helper such as `aws`, `gcloud`,
or `az`, that helper must also be available.

## Commands

| Command | What it does |
| --- | --- |
| `budctl check` | Readiness checks against a sized target (the default command) |
| `budctl install` | Generate the configuration, commit it to a GitOps repository, bootstrap ArgoCD |
| `budctl status` | Each component's ArgoCD sync and health; `--wait` blocks until converged |
| `budctl values view` | Each component's committed values for an environment |
| `budctl uninstall` | Remove an environment's components, in reverse order |
| `budctl sysdump` | Zip of ArgoCD state, pods, events and logs for debugging |
| `budctl cleanup` | Remove probe namespaces an interrupted `check` left behind |
| `budctl version` | The budctl version, and what is deployed when a cluster is reachable |

`--kubeconfig` and `--context` work on every command. The full reference, with
every flag, is in [docs/cmdref](docs/cmdref/budctl.md).

## Check a cluster

```sh
budctl check --domain bud.example.com --model-storage-gi 600 --models 12
```

`check` needs a target to check against: at least `--domain`, or an answers file
(`--answers readiness.yaml`). Use `--no-probe` for a read-only check that creates
nothing in the cluster, and `--only`/`--skip` to select groups or checks.

For CI, select a machine-readable format:

```sh
budctl check --answers readiness.yaml --output json --strict
```

| Code | Meaning |
| ---: | --- |
| `0` | Ready |
| `1` | Not ready |
| `2` | Risks found with `--strict` |
| `3` | `budctl` could not run |

## Install Bud

Preview first. `--dry-run` resolves everything, detects what it can from the
cluster (OpenShift, the default StorageClass and IngressClass), and prints the
plan and every file it would commit, without changing anything:

```sh
export BUD_REGISTRY_PASSWORD=...
budctl install --dry-run \
  --repo https://github.com/acme/bud-config.git \
  --environment production \
  --domain bud.example.com \
  --tls self-signed \
  --registry-user robot \
  --admin-email admin@example.com
```

Then run the same command with `--yes` instead of `--dry-run`. Pushing to the
repository and installing onto the cluster are both irreversible, so without
`--yes` install prints the plan and stops. A run that is missing a value lists
every flag it still needs.

The installer:

1. Clones the target repository (an empty one, or one budctl already manages).
2. Writes one values file and one SOPS-encrypted secrets file per component,
   plus the ApplicationSet and its root Application, and commits them.
3. Pushes to `main` (or `--branch`).
4. Installs or upgrades ArgoCD and syncs each component in dependency order.

Use `--no-bootstrap` to only push, `--no-sync` to bootstrap ArgoCD without
syncing the components, and `--no-push --no-bootstrap` for a local commit only.
`--skip-component <name>` leaves a component out (for a staged or partial install).
OpenSandbox is installed by default; Bud Studio (`--bud-studio`) is the only
optional add-on. TLS modes are `acme-dns01` (the default, needs a Cloudflare
token), `acme-http01`, `self-signed`, `internal-ca` and `external`.

### Override chart values

Every component's configuration is built into budctl. Change any value with
Helm-style flags, routed by the component name:

```sh
budctl install --yes \
  --set keycloak.ingress.className=nginx \
  --set-string bud.storage.budmodelRegistry.size=500Gi \
  --values bud=bud-overrides.yaml \
  --set-secret bud.appApiToken="$TOKEN"
```

`--set`, `--set-string`, `--set-file` and `--set-json` behave as in Helm and win
over `--values <component>=<file>`. `--set-secret` values are committed
SOPS-encrypted. Overrides are saved with the installation, so a later run keeps
them unless new ones are given.

Inspect the result before or after committing:

```sh
budctl install --dry-run-values --component keycloak   # what Helm will receive
budctl install --dry-run=manifests                     # the ApplicationSet and root Application
budctl install --dry-run=render --render-dir out        # every chart templated, like helm template
budctl values view --component keycloak                # what is committed
```

### Watch and manage an installation

```sh
budctl status --wait --wait-duration 30m
budctl uninstall --environment production --yes
```

`uninstall` prunes each component through ArgoCD and keeps ArgoCD itself
running; it does not change the GitOps repository.

## Secrets and recovery

Secrets are SOPS-encrypted before they are written to the GitOps repository.
The generated age recovery key is stored outside Git with `0600` permissions.

Installer progress, choices and overrides are saved in an encrypted local state
file, so a failed or interrupted installation resumes without regenerating
credentials, and a later run needs only the flags that change. To continue on
another machine, securely copy both the state file and its adjacent `.agekey`
file, then pass the state file with `--state`.

Keep the recovery key and installer state in a secure password manager or
secrets system. Losing both means encrypted values in Git cannot be recovered.

## Development

```sh
go test ./...
go build -o budctl ./cmd/budctl
go run ./cmd/budctl cmdref   # regenerate docs/cmdref after changing flags
```

The architecture and the refactor plan are in [ARCHITECTURE.md](ARCHITECTURE.md).
Release builds are produced with `./release.sh` and published when a matching
`v*` tag is pushed. See [LICENSE](LICENSE) and
[THIRD_PARTY.md](THIRD_PARTY.md) for licensing information.
