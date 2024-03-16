#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "pip"
path_file="$(create_plugin_file path.sh)"

#Not work at macos

echo "export PATH=$(python -m site --user-base)/bin:\${PATH}" >> "${path_file}"

