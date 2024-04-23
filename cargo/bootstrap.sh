#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "cargo"
env_file="$(create_plugin_file env.sh)"

# shellcheck disable=SC2016
echo '[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"' >> "${env_file}"

