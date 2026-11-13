## budctl completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(budctl completion bash)

To load completions for every new session, execute once:

#### Linux:

	budctl completion bash > /etc/bash_completion.d/budctl

#### macOS:

	budctl completion bash > $(brew --prefix)/etc/bash_completion.d/budctl

You will need to start a new shell for this setup to take effect.


```
budctl completion bash
```

### Options

```
  -h, --help              help for bash
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

