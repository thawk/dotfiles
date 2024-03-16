#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "fzf"

echo "[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh" >> "$(create_plugin_file env.zsh)"
echo "[ -f ~/.fzf.bash ] && source ~/.fzf.bash" >> "$(create_plugin_file env.bash)"
