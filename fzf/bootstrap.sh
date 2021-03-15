#!/bin/sh

conf_dir="${DOTFILES_LOCAL}/fzf"
mkdir -p "${conf_dir}"
rm -f "${conf_dir}"/*

echo "[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh" >> "${conf_dir}/"env.zsh
echo "[ -f ~/.fzf.bash ] && source ~/.fzf.bash" >> "${conf_dir}/"env.bash
