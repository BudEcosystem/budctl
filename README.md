# budctl

`budctl` checks whether a Kubernetes or OpenShift cluster is ready for
[Bud](https://budecosystem.com/) and guides you through a GitOps installation.

It ships as a single binary with Kubernetes, Helm, SOPS, and age support built
in. You do not need to install `kubectl`, `helm`, `sops`, or `age` separately.

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

## Quick start

First, check whether the cluster is ready:

```sh
budctl check
```

Then start the guided GitOps installation:

```sh
budctl install
```

Both commands open an interactive form. Existing cluster settings such as the
default StorageClass and ingress configuration are detected when possible.

The installer will:

1. Clone your target GitOps repository and prepare the selected environment.
2. Generate configuration and SOPS-encrypted secrets.
3. Commit and push the configuration to `main` by default.
4. Ask for confirmation before changing the cluster.
5. Install or upgrade ArgoCD and synchronize Bud in dependency order.

OpenSandbox is installed by default. Bud Studio is the only optional add-on.
Traefik is used when no ingress class can be detected; OpenShift uses its native
ingress path.

For the complete platform prerequisites, see the
[Bud installation guide](https://docs.budecosystem.com/developer-docs/installation).

## Preview an installation

Use `--plan` to validate the configuration without cloning, writing, pushing,
or changing the cluster. Set `BUD_REGISTRY_PASSWORD` in your environment before
running this non-interactive example:

```sh
budctl install --plan --no-prompt \
  --repo https://github.com/acme/bud-config.git \
  --environment production \
  --domain bud.example.com \
  --ingress-class traefik \
  --storage-class standard \
  --tls self-signed \
  --registry-user robot \
  --registry-password "$BUD_REGISTRY_PASSWORD" \
  --admin-email admin@example.com
```

Run `budctl help` to see all supported options, including TLS modes, private
repository access, registry credentials, additional age recipients, and Bud
Studio configuration.

## Automated readiness checks

For CI or other non-interactive environments, provide saved answers and select
a machine-readable output format:

```sh
budctl check --answers readiness.yaml --output json --strict
```

Exit codes are:

| Code | Meaning |
| ---: | --- |
| `0` | Ready |
| `1` | Not ready |
| `2` | Risks found with `--strict` |
| `3` | `budctl` could not run |

Use `--no-probe` for a read-only check. If an interrupted run leaves probe
resources behind, remove them with `budctl cleanup`.

## Secrets and recovery

Secrets are SOPS-encrypted before they are written to the GitOps repository.
The generated age recovery key is stored outside Git with `0600` permissions.

Installer progress is saved in an encrypted local state file so a failed or
interrupted installation can be resumed without regenerating credentials. To
continue on another machine, securely copy both the state file and its adjacent
`.agekey` file, then pass the state file with `--state`.

Keep the recovery key and installer state in a secure password manager or
secrets system. Losing both means encrypted values in Git cannot be recovered.

## Development

```sh
go test ./...
go build -o budctl ./cmd/budctl
```

Release builds are produced with `./release.sh` and published when a matching
`v*` tag is pushed. See [LICENSE](LICENSE) and
[THIRD_PARTY.md](THIRD_PARTY.md) for licensing information.
