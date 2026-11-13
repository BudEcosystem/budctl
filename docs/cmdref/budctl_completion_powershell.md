## budctl completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	budctl completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
budctl completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
      --context string      kube context to use
      --kubeconfig string   path to kubeconfig (default: the usual discovery)
      --no-color            disable colour (also NO_COLOR)
```

### SEE ALSO

* [budctl completion](budctl_completion.md)	 - Generate the autocompletion script for the specified shell

