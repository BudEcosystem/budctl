# budctl — is this cluster fit to host Bud?

Run this **before** applying the ApplicationSets. It answers one question: would
the install succeed, in *this* cluster, on *this* network, against *these*
answers? Design: FRD-020 (internal).

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/BudEcosystem/budctl/main/install.sh | sh
```

The script checks the published SHA-256 before it installs anything. It puts
`budctl` in `/usr/local/bin`, or `~/.local/bin` when that is not writable; set
`BUDCTL_INSTALL_DIR` to choose, `BUDCTL_VERSION` to pin, and `BUDCTL_BASE_URL`
to install from an internal mirror. Or take the binary for your platform from
[Releases](https://github.com/BudEcosystem/budctl/releases), check it against
`SHA256SUMS`, and `gunzip` it — the tool needs no installer to work.

Nothing else has to be present: budctl carries client-go, Helm, SOPS and age as
libraries, so no `kubectl`, `helm`, `sops` or `age` binary is required. All it
needs is a kubeconfig with a reachable API server.

## Use

```sh
budctl check
```

That is the whole command. On a terminal it opens a **guided, paged form** and
asks for everything it needs — you should never have to read `--help` to
discover that model storage is a question at all. There are seven short pages:

1. **Where Bud will live** — root domain, how TLS certificates are obtained, and
   the internal CA bundle when you supply your own certificate
2. **What it needs to hold** — in-cluster or external data stores, model storage,
   model count, observability retention
3. **What it will run** — concurrent deployments, GPU, OpenSandbox
4. **How it is delivered** — ArgoCD, and its config repository (required under ArgoCD)
5. **Registry access** — optional; the token is never echoed or saved
6. **Your configuration** — optional values file, chart directory, SOPS secrets
7. **Ready to check** — probe from inside the cluster, or read-only

Under each field is the *consequence* of the value, recomputed as you type, so
you see what the number will be checked against rather than just the number:

```
  Model storage (GiB)
  300 GiB model weights + 58 GiB platform claims + 269 GiB in-cluster data stores
  + 30 GiB traces and metrics (30d retention), estimated = 657 GiB the cluster
  must be able to provision.
  > 300
```

Questions the answers make irrelevant are not asked — no config repo when
ArgoCD is off. On OpenShift the `*.apps` wildcard the cluster already owns is
offered as the domain default.

Flags **pre-fill** the form rather than replacing it; `--no-prompt` skips it once
every answer is supplied, and a non-terminal (a pipe, CI) never prompts at all:

```bash
budctl check --domain bud.example.com --model-storage-gi 600 --models 12
budctl check --answers readiness.yaml --output json --strict   # CI
```

`--save-answers readiness.yaml` records what you answered so a re-run after
remediation asks nothing again.

## What you get back

While it runs, a progress card shows the check in flight, `N of M checks`, and
blockers and risks as they are found, with a row per group.

It then lands on a **summary**, not on a wall of checks:

```
╭──────────────╮ ╭──────────╮ ╭────────╮ ╭────────╮ ╭──────────────╮
│  NOT READY   │ │    4     │ │   9    │ │   50   │ │      19      │
│   verdict    │ │ blocking │ │ risks  │ │ passed │ │ not verified │
╰──────────────╯ ╰──────────╯ ╰────────╯ ╰────────╯ ╰──────────────╯

BLOCKING — the install will fail (4)
╭──────────────────────────────────────────────────────────────────╮
│ ✗ nodes.imagefs                                                  │
│ 4 nodes are below the 80 GiB image-filesystem floor              │
│   worker-0  ██████████░░░░░░  46.7 GiB / 80.0 GiB                │
│   worker-2  ███████░░░░░░░░░  33.0 GiB / 80.0 GiB                │
│ → grow the image filesystem to at least 80 GiB free per node     │
╰──────────────────────────────────────────────────────────────────╯
↓ 74 more below    ↓/j down • v expand not-verified • d browse all checks • s save report • q quit
```

A root cause comes first when there is one (an unreachable cluster explains
every skip below it). Blockers are cards with their fix; measured shortfalls
are drawn as bars against what is needed. Risks follow, then what was **not
verified**, grouped by reason — press `v` to list every check id.

`d` opens **browse**: tabs for All / Blocking / Risks / Not verified / Passed
(`tab` or `1`–`5`), `/` to search, and the selected check's full record — gauges,
fix, evidence, and what the check *does not prove*. At 100 columns or wider the
list and the record sit side by side; narrower, `enter` opens a record and `esc`
closes it.

`s` saves, and quitting asks whether to save first. **Save writes two files**: a
`.json` for a pipeline and a `.md` for the person who has to fix something. The
Markdown leads with *what the cluster was checked against* — domain, model
storage, TLS method, GPU — because a verdict without its target cannot be
interpreted by whoever receives it. Credentials are never written to either
file.

Colours follow the terminal's background. `--theme dark` or `--theme light`
forces one when detection guesses wrong (some terminals over SSH or tmux do not
answer the query); every text colour holds WCAG 4.5:1 contrast on common dark
and light backgrounds. `--no-color` or `NO_COLOR` turns colour off.

Exit codes: `0` READY · `1` NOT READY · `2` risks under `--strict` · `3` budctl
could not run.

## What it needs on the host

A kubeconfig. That is all.

`budctl` carries `client-go`, Helm's templating engine, SOPS and age as
*libraries*, so there is **no `kubectl`, `helm`, `sops` or `age` binary** to
install. The single exception is an `exec` credential plugin (`aws`, `gcloud`,
`az`) when your kubeconfig uses one — `toolchain.exec-plugin` checks for it,
because that is the one dependency the tool genuinely cannot absorb.

## The governing rule

**Only what must already be true for the sync to succeed is a prerequisite.**

Twenty components — Dapr, cert-manager, OpenEBS, Kyverno, every database
operator — are installed by the ApplicationSets. Requiring them would be
requiring that the installer has already run. Three things are not installed by
anything: an ingress path, metrics-server, and cluster DNS.

It also never pulls an image layer or a model weight. Registry access is proven
from manifest metadata, which is a few kilobytes.

## Intake, not a fixed profile

"Is 200 GiB enough?" has no answer until someone says how many models they
intend to hold, so the flow asks and derives every threshold from the answers:
domain, TLS method, model storage, model count, concurrent deployments, GPU or
CPU, retention, in-cluster or external data stores, ArgoCD and its config repo,
OpenSandbox, optional registry credentials, an optional values file, and whether
to probe from inside the cluster.

Registry credentials are **optional** — the robot account is normally issued
after readiness passes, so reachability is proven without them (a `401` from
`/v2/` is a pass: it proves DNS, routing, TLS and a live registry). The
credentialed checks then SKIP *with a stated reason*, never silently pass.

## Certificates you supply yourself

budctl never asks for your certificate or its key. It inspects what is actually
served: it opens a TLS connection to every hostname the install publishes and
reads the certificate off the wire, checking that

- the chain **verifies**, against this host's trust store,
- it has more than **14 days** left, and
- its SANs **cover every published name** — `*.bud.example.com` matches
  `admin.bud.example.com` but not `api.novu.bud.example.com`, which is the trap
  a wildcard hides.

Before the install nothing is serving those names yet, so the check SKIPs and
says so; a controller's own placeholder (nginx's "Fake Certificate", OpenShift's
router certificate) is reported as INFO. Neither is a pass.

**An internal CA needs its root.** A certificate signed by your own CA cannot be
told apart from a misissued one unless budctl holds the root, so pass it:

```bash
budctl check --tls provided --ca-bundle /etc/pki/internal-root.pem
```

The guided form asks for the same file once you answer that you provide the
certificate. Without it, the finding is a RISK naming the actual x509 cause
(`certificate signed by unknown authority`, not a generic "did not verify"), and
the fix says to pass the root rather than to reissue from a public CA. The
bundle is added to this host's trust store for the run — it is not sent
anywhere, and the cluster's own trust is a separate matter: every client that
talks to the stack, browsers and in-cluster callers alike, must trust that root
too.

## Kubernetes and OpenShift

The `platform` group runs first and everything branches on it. On OpenShift the
ingress path is the Ingress Operator rather than an IngressClass, admission is
SCC rather than PodSecurity, egress is read from
`proxy.config.openshift.io/cluster`, and the `*.apps` wildcard is offered for the
domain answers. A vanilla-only sub-check is never reported as PASS on OpenShift,
or the reverse — it is skipped with a reason.

## Probes

Four things cannot be answered read-only: whether nodes can reach the
registries, whether a StorageClass actually binds, whether egress works from
where the workloads run, and whether the GPU stack delivers a device. Those run
in one labelled namespace that is deleted on the way out — on interrupt, and on
a closed output pipe (`budctl check | head`), which kills a Go program outright
unless it says otherwise. `--no-probe` is read-only; `budctl cleanup` sweeps leftovers from a
killed run.

The GPU probe requests `nvidia.com/gpu: 1` on a **slim Debian image**, not a
CUDA image: asserting the injected device node is present proves allocation,
device-plugin injection and the runtime-hook chain for megabytes instead of
gigabytes. It is not busybox because HAMi preloads its vGPU library into every
GPU container, and that library needs glibc's `libdl.so.2`; point
`--gpu-probe-image` at a mirror of any glibc image on an air-gapped cluster.

## SKIP is never a pass

"We did not look" and "we looked and it was fine" are different facts. Skips are
counted separately, listed separately, and every one carries a reason.

## Build and share

```bash
cd budctl
VERSION=0.2.0 ./release.sh
```

To cut a release, bump `VERSION` in `install.sh` to the version you are about to
publish, commit it, and push the matching tag:

```bash
git tag v0.3.1 && git push origin v0.3.1
```

CI refuses a tag that disagrees with the pin, so the published installer can
never point at a release other than the one it shipped with. It then runs the
suite, regenerates `THIRD_PARTY.md`, builds all four platforms, checks that the
linux binary actually starts and reports its own version, and publishes.

Produces one static binary per platform in `dist/`, each with a `.gz` and a
`SHA256SUMS`. Measured at 0.2.0:

| artifact | raw | gzipped |
|---|---|---|
| `budctl-linux-amd64` | 86M | 26M |
| `budctl-linux-arm64` | 81M | 23M |
| `budctl-darwin-arm64` | 83M | 24M |
| `budctl-darwin-amd64` | 89M | 26M |

`CGO_ENABLED=0`, so the result is genuinely static — verified by running
`budctl-linux-amd64` inside an `alpine` container with no kubectl, helm, sops,
age, python or go present.

Hand over the binary and the checksum:

```bash
scp dist/budctl-linux-amd64 dist/SHA256SUMS jump-host:
ssh jump-host 'sha256sum -c SHA256SUMS --ignore-missing && chmod +x budctl-linux-amd64'
```

Air-gapped is the same hand-off: the tool needs no network **to run**. The
network it tests is the cluster's, and `--egress-from cluster` (the default) runs
those probes from inside.

### macOS

`budctl-darwin-arm64` (Apple Silicon) and `budctl-darwin-amd64` (Intel) both
build and produce valid Mach-O binaries. Two caveats, neither cosmetic:

**Gatekeeper.** The binaries are unsigned and unnotarised. Copied with `scp` or
`curl` they run normally; downloaded through a **browser** they carry a
quarantine attribute and macOS refuses them with "cannot be opened because the
developer cannot be verified". Clear it:

```bash
xattr -d com.apple.quarantine budctl-darwin-arm64
```

**DNS resolution differs from the rest of the system.** Cross-compiled Darwin
builds are necessarily `CGO_ENABLED=0`, so Go uses its own resolver rather than
libc's. That resolver reads `/etc/resolv.conf` and does **not** honour macOS
per-domain resolvers configured through `scutil` — the split-DNS a corporate VPN
installs. So on a VPN, `domains.resolve` can disagree with what `dig` or Safari
see on the same machine.

This matters because DNS is something budctl checks rather than merely uses. Two
ways round it, in order of preference:

1. Trust the cluster's answer, not the laptop's — `domains.*` already labels its
   vantage point, and the probes run from inside the cluster where the workloads
   will actually resolve.
2. Build on the Mac itself, where cgo is available and the system resolver is
   used:
   ```bash
   CGO_ENABLED=1 go build -o budctl ./cmd/budctl
   ```

A darwin build has been run on a Mac against a live cluster. Only one Mac has
run it, so treat the other architecture as compiled-and-format-verified.

Not yet built (FRD-020 WS-7): a CI release job, signatures, and the
self-extracting `install.sh` wrapper. `release.sh` is the manual equivalent.

## Development

```bash
go build ./cmd/budctl
go test ./...          # includes the failure-coverage gate
```

The gate is the point of the test suite: **every check must have a test that
drives it to BLOCK or RISK.** A check that cannot fail converts an unknown into
a false assurance. `TestMain` fails the build when one has neither a negative
test nor a written-down exemption in `probeOnly`.

Checks are driven against a synthetic cluster (`harness_test.go`), because a
single real cluster can only ever be one thing at a time — it is vanilla or
OpenShift, tainted or not, short of disk or not.

## Layout

```
cmd/budctl/          CLI entry point and flags
internal/engine/     the check contract, registry and runner (no UI imports)
internal/adapters/   client-go, Helm, OCI registry, SOPS, network — all libraries
internal/checks/     one file per group, registered in init()
internal/probes/     the only code that writes to the cluster
internal/intake/     the answers, and the embedded floors (defaults.yaml)
internal/output/     table, json, junit
internal/tui/        Bubble Tea view over the same engine.Report (intake, run, summary, browse)
```

Adding a check: register it in the relevant group file, give it a severity, a
remedy that says what to *do*, and a negative test — the gate will fail the
build without one.
