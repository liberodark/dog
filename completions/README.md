# Shell Completions

Shell completions are generated dynamically.

## Generating Completions

```bash
# Bash
dog --completions bash > dog.bash

# Zsh
dog --completions zsh > _dog

# Fish
dog --completions fish > dog.fish

# PowerShell
dog --completions powershell > _dog.ps1

# Elvish
dog --completions elvish > dog.elv
```

## Installing Completions

### Bash
```bash
dog --completions bash > ~/.local/share/bash-completion/completions/dog
# Or system-wide:
sudo dog --completions bash > /etc/bash_completion.d/dog
```

### Zsh
```bash
dog --completions zsh > ~/.zfunc/_dog
# Make sure ~/.zfunc is in your fpath (add to ~/.zshrc):
# fpath=(~/.zfunc $fpath)
# autoload -Uz compinit && compinit
```

### Fish
```bash
dog --completions fish > ~/.config/fish/completions/dog.fish
```

### PowerShell
```powershell
dog --completions powershell >> $PROFILE
```
