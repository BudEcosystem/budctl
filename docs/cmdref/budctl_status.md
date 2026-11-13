## budctl status

Show each component's ArgoCD sync and health

### Synopsis

Show how an installed environment is doing, as ArgoCD sees it: the root
Application, and each component's Application, synced or not, healthy or not.

Exit code 0 means every Application is Synced and Healthy, 1 means at least one
is not (or --wait timed out), and 3 means budctl could not read the cluster.

```
budctl status [flags]
```

### Examples

```
  budctl status
  budctl status --environment production --wait --wait-duration 30m
  budctl status -o json
```

### Options

```
      --environment string       the environment to show (default: every environment)
  -h, --help                     help for status
  -o, --output string            table | json (default "table")
      --wait                     wait until every Application is Synced and Healthy
      --wait-duration duration   how long --wait waits (default 15m0s)
```

### Options inherited from parent commands

```
      --context string      kube context to use
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl](budctl.md)	 - Precheck and install Bud

