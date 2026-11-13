## budctl values view

Print each component's values as committed in the GitOps repository

### Synopsis

Clone the GitOps repository and print each component's values for an
environment, as committed. The repository, branch and environment default to
those of the last install run.

With --show-secrets the SOPS files are decrypted too, with the recovery key of
the last run, --recovery-key, or SOPS_AGE_KEY / SOPS_AGE_KEY_FILE.

```
budctl values view [flags]
```

### Options

```
      --branch string         branch (default: the last install's, else main)
      --component string      print only this component
      --environment string    environment (default: the last install's)
  -h, --help                  help for view
      --recovery-key string   age identity for --show-secrets (default: the last install's)
      --repo string           GitOps repository (default: the last install's)
      --show-secrets          decrypt and include the SOPS-encrypted values
      --state string          installer resume-state path to take defaults from
```

### Options inherited from parent commands

```
      --context string      kube context to use
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl values](budctl_values.md)	 - Inspect an environment's committed configuration

