## budctl

Precheck and install Bud

### Synopsis

budctl — precheck and install Bud

check needs a target to check against: at least --domain, or an answers file.
Readiness is meaningless against an unstated target: "is 200 GiB enough?" has
no answer until someone says how many models they intend to hold.

budctl with no command runs check.

EXIT CODES
  0 READY    1 NOT READY    2 risks under --strict    3 budctl could not run

### Options

```
      --context string      kube context to use
  -h, --help                help for budctl
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl check](budctl_check.md)	 - Run the readiness checks (default)
* [budctl cleanup](budctl_cleanup.md)	 - Remove probe namespaces left by an interrupted run
* [budctl completion](budctl_completion.md)	 - Generate the autocompletion script for the specified shell
* [budctl install](budctl_install.md)	 - Prepare, push and bootstrap a GitOps installation
* [budctl status](budctl_status.md)	 - Show each component's ArgoCD sync and health
* [budctl sysdump](budctl_sysdump.md)	 - Collect ArgoCD state, pods, events and logs into a zip for debugging
* [budctl uninstall](budctl_uninstall.md)	 - Remove an environment's components from the cluster
* [budctl values](budctl_values.md)	 - Inspect an environment's committed configuration
* [budctl version](budctl_version.md)	 - Show the budctl version, and what is deployed when a cluster is reachable

