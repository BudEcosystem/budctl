## budctl completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(budctl completion zsh)

To load completions for every new session, execute once:

#### Linux:

	budctl completion zsh > "${fpath[1]}/_budctl"

#### macOS:

	budctl completion zsh > $(brew --prefix)/share/zsh/site-functions/_budctl

You will need to start a new shell for this setup to take effect.


```
budctl completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
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

