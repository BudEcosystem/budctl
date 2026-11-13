## budctl completion fish

Generate the autocompletion script for fish

### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	budctl completion fish | source

To load completions for every new session, execute once:

	budctl completion fish > ~/.config/fish/completions/budctl.fish

You will need to start a new shell for this setup to take effect.


```
budctl completion fish [flags]
```

### Options

```
  -h, --help              help for fish
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

