#!/bin/sh

env_file="${DOTFILES_LOCAL}/taskwarrior/env.zsh"
mkdir -p "$(dirname "$env_file")"
rm "$(dirname "$env_file")"/*
: > "${env_file}"

if [ -f /usr/local/share/taskwarrior/scripts/zsh/_task ]; then
    echo "fpath=(\$fpath /usr/local/share/taskwarrior/scripts/zsh)" >> "${env_file}"
elif [ -f /usr/local/share/doc/task/scripts/zsh/_task ]; then
    echo "fpath=(\$fpath /usr/local/share/doc/task/scripts/zsh)" >> "${env_file}"
elif [ -f /usr/share/doc/task/scripts/zsh/_task ]; then
    echo "fpath=(\$fpath /usr/share/doc/task/scripts/zsh)" >> "${env_file}"
fi
