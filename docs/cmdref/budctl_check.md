## budctl check

Run the readiness checks (default)

### Synopsis

Run the readiness checks against the cluster and the inputs an install will use.

check accepts every install flag, so an install command line can be checked
unchanged before it is run; the flags only install acts on are ignored.

```
budctl check [flags]
```

### Examples

```
  # check against a sized target
  budctl check --domain bud.example.com --model-storage-gi 600 --models 12

  # read-only, nothing created in the cluster
  budctl check --domain bud.example.com --no-probe

  # also validate the values you will hand to ArgoCD
  budctl check --domain bud.example.com --chart infra/charts/bud \
      --values bud=infra/values/bud/values.prod.yaml

  # CI gate
  budctl check --answers readiness.yaml --output json --strict
```

### Options

```
      --answers string             read intake answers from a file
      --argocd-namespace string    namespace ArgoCD is (or will be) installed in (default "argocd")
      --ca-bundle string           PEM file of extra roots to trust when verifying served certificates (an internal CA)
      --chart string               path to the bud chart, enabling the config group
      --check-timeout duration     per-check timeout (default 1m30s)
      --deployments int            expected concurrent model deployments
      --domain string              root domain the stack will publish under (required)
      --egress-from string         where egress is tested: cluster | workstation | both (default "cluster")
      --external-datastores        data stores are managed externally, not installed in-cluster
      --gpu                        GPU deployments are expected
      --gpu-probe-image string     image for the GPU probe (a slim glibc image, deliberately not a CUDA image) (default "debian:trixie-slim")
  -h, --help                       help for check
      --hf-throughput              sample Hugging Face download throughput
      --json string                also write the full report to this file
      --keep                       keep the probe namespace for debugging
      --model-storage-gi int       GiB of model weight storage to provision for
      --models int                 roughly how many models will be held
      --net-timeout duration       per-network-probe timeout (default 15s)
      --no-probe                   read-only: create nothing in the cluster
      --only string                run only these groups or check ids, repeatable
  -o, --output string              table | json | junit (default "table")
      --probe-image string         image for network probes (default "curlimages/curl:8.10.1")
      --probe-namespace string     namespace for probe objects
      --registry-password string   registry.bud.studio token (or BUD_REGISTRY_PASSWORD)
      --registry-user string       registry.bud.studio robot account (or BUD_REGISTRY_USER)
      --repo string                the GitOps repository ArgoCD reads and install pushes to (https://, ssh:// or git@host:org/repo)
      --repo-key string            SSH deploy-key file ArgoCD clones an ssh:// or git@ repository with
      --retention-days int         observability retention, sizes ClickHouse
      --save                       write the report as .json and .md (the same files the TUI 's' key writes)
      --save-answers string        write the resolved answers to a file for re-runs
      --secrets string             SOPS-encrypted values file
      --skip string                skip these groups or check ids, repeatable
      --strict                     exit non-zero on risks as well as blockers
      --tls string                 TLS mode: acme-dns01 | acme-http01 | self-signed | internal-ca | external
      --values string              values file for one component, as <component>=<file>; repeatable (check validates bud's against --chart)
      --verbose                    show detail and evidence for passing checks too
```

### Options inherited from parent commands

```
      --context string      kube context to use
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl](budctl.md)	 - Precheck and install Bud

