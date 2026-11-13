## budctl uninstall

Remove an environment's components from the cluster

### Synopsis

Remove an environment's components from the cluster, in the reverse of the
order install synced them. ArgoCD prunes each component's resources before its
Application is deleted.

ArgoCD itself is kept running (remove it with: helm uninstall argocd -n argocd).
The GitOps repository, the namespaces and any PersistentVolumeClaims the
stateful components left behind are not touched.

```
budctl uninstall [flags]
```

### Examples

```
  budctl uninstall --environment production --yes
```

### Options

```
      --environment string       the environment to remove (default: the only one installed)
  -h, --help                     help for uninstall
      --wait-duration duration   how long to wait for each component to be pruned (default 10m0s)
      --yes                      confirm the removal
```

### Options inherited from parent commands

```
      --context string      kube context to use
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl](budctl.md)	 - Precheck and install Bud

