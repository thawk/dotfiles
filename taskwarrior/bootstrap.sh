#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "taskwarrior"
completion_file="$(create_plugin_file completion.sh)"

if [ -f /usr/local/share/taskwarrior/scripts/zsh/_task ]; then
    echo "fpath=(\$fpath /usr/local/share/taskwarrior/scripts/zsh)" >> "${completion_file}"
elif [ -f /usr/local/share/doc/task/scripts/zsh/_task ]; then
    echo "fpath=(\$fpath /usr/local/share/doc/task/scripts/zsh)" >> "${completion_file}"
elif [ -f /usr/share/doc/task/scripts/zsh/_task ]; then
    echo "fpath=(\$fpath /usr/share/doc/task/scripts/zsh)" >> "${completion_file}"
fi
