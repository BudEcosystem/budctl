## budctl install

Prepare, push and bootstrap a GitOps installation

### Synopsis

Generate the Bud configuration for an environment, commit it to a GitOps
repository, and bootstrap ArgoCD on the cluster to sync it.

Everything is set with flags; nothing is asked. A run that is missing a value
lists every flag it still needs. The choices of the last run, and the
credentials it generated, are kept in an encrypted resume state, so a later run
needs only the flags that change.

Pushing and installing onto the cluster are both irreversible, so they need
--yes. Without it, install prints the plan and stops.

```
budctl install [flags]
```

### Examples

```
  # preview: the plan and every file it would commit, with no side effects
  budctl install --dry-run --repo https://github.com/acme/bud-config.git \
      --environment production --domain bud.example.com --tls self-signed \
      --registry-user robot --registry-password token --admin-email admin@example.com

  # install: push the configuration and bootstrap ArgoCD
  budctl install --repo https://github.com/acme/bud-config.git --environment production \
      --domain bud.example.com --tls self-signed --registry-user robot \
      --registry-password token --admin-email admin@example.com --yes

  # resume or correct the last run: only the flags that change are needed
  budctl install --admin-email ops@example.com --yes

  # override any chart value, routed by component name
  budctl install --set keycloak.ingress.className=nginx --values bud=bud-overrides.yaml --yes

  # show the merged values Helm will receive
  budctl install --dry-run-values --component bud
```

### Options

```
      --admin-email string           initial Bud administrator email
      --admin-password string        initial administrator password (generated when omitted)
      --age-recipient string         additional age recipient, repeatable
      --branch string                branch to create or update in the target repository (default: main)
      --bud-studio                   install the optional Bud Studio add-on
      --ca-bundle string             PEM file of extra roots to trust when verifying served certificates (an internal CA)
      --cloudflare-token string      Cloudflare API token for ACME DNS-01 (or CLOUDFLARE_API_TOKEN)
      --component string             with --dry-run-values or --dry-run=render, only this component
      --deployments int              expected concurrent model deployments
      --domain string                root domain the stack will publish under (required)
      --dry-run string[="plan"]      show what would happen and change nothing: plan (the summary and every file), manifests (the ApplicationSet and root Application) or render (every chart templated with its final values, like helm template)
      --dry-run-values               print the merged values each component's chart receives, and change nothing
      --environment string           DNS-safe environment name (default: derived from the kube context, else production)
      --fresh                        ignore the previous installer state and start with defaults
      --gpu                          GPU deployments are expected
  -h, --help                         help for install
      --ingress-class string         Kubernetes IngressClass (detected when possible; default: traefik)
      --issuer-ca-cert string        PEM certificate for an existing internal issuing CA
      --issuer-ca-key string         PEM private key for an existing internal issuing CA
      --model-storage-gi int         GiB of model weight storage to provision for
      --models int                   roughly how many models will be held
      --no-bootstrap                 do not install ArgoCD or apply its root Application
      --no-push                      create a local committed workspace without pushing (requires --no-bootstrap)
      --no-sync                      bootstrap ArgoCD and the ApplicationSet but leave child Applications unsynced
      --recovery-key string          path outside Git for the generated SOPS age identity
      --registry-password string     registry.bud.studio token (or BUD_REGISTRY_PASSWORD)
      --registry-user string         registry.bud.studio robot account (or BUD_REGISTRY_USER)
      --render-dir string            with --dry-run=render, write one <component>.yaml per component here instead of to stdout
      --repo string                  the GitOps repository ArgoCD reads and install pushes to (https://, ssh:// or git@host:org/repo)
      --repo-key string              SSH deploy-key file ArgoCD clones an ssh:// or git@ repository with
      --set stringArray              set a value, as <component>.<key>=<value>; repeatable
      --set-file stringArray         like --set, but the value is read from a file
      --set-json stringArray         like --set, but the value is JSON
      --set-secret stringArray       like --set, but the value is committed SOPS-encrypted
      --set-string stringArray       like --set, but the value is always a string
      --show-secrets                 with --dry-run-values, also print the values that are committed encrypted
      --skip-component stringArray   leave a component out of the installation, for a staged or partial install; repeatable
      --state string                 encrypted installer resume-state path
      --storage-class string         Kubernetes StorageClass (detected when possible)
      --studio-model string          model used by Bud Studio
      --tls string                   TLS mode: acme-dns01 | acme-http01 | self-signed | internal-ca | external
      --values stringArray           values file for one component, as <component>=<file>; repeatable (check validates bud's against --chart)
      --yes                          accept both the Git push and the cluster installation
```

### Options inherited from parent commands

```
      --context string      kube context to use
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl](budctl.md)	 - Precheck and install Bud

