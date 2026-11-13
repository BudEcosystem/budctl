## budctl sysdump

Collect ArgoCD state, pods, events and logs into a zip for debugging

### Synopsis

Collect what is needed to debug an installation into one zip: the ArgoCD
Applications and ApplicationSets, the nodes, and the pods, events and recent
container logs of every namespace the platform deploys into. Secrets are never
collected.

```
budctl sysdump [flags]
```

### Options

```
  -h, --help                 help for sysdump
      --namespaces strings   namespaces to collect (default: argocd and every component's)
      --output-file string   zip to write (default: budctl-sysdump-<time>.zip)
      --tail int             log lines to keep per container (default 500)
```

### Options inherited from parent commands

```
      --context string      kube context to use
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl](budctl.md)	 - Precheck and install Bud

