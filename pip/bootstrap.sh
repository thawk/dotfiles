#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "pip"
path_file="$(create_plugin_file path.sh)"

#Not work at macos

pip_bin="$(python -m site --user-base)/bin"
# shellcheck disable=SC2016
printf 'if [[ ":$PATH:" != *":%s:"* ]]; then export PATH="%s:$PATH"; fi\n' "${pip_bin}" "${pip_bin}" >> "${path_file}"

