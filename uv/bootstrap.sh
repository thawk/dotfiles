#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "uv"
completion_file="$(create_plugin_file completion.zsh)"
echo "$(uv generate-shell-completion zsh)" >>"${completion_file}"
