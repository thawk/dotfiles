#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "gem"
path_file="$(create_plugin_file path.sh)"

gem_bin="$(ruby -rrubygems -e "puts Gem.user_dir")/bin"
# shellcheck disable=SC2016
printf 'if [[ ":$PATH:" != *":%s:"* ]]; then export PATH="$PATH:%s"; fi\n' "${gem_bin}" "${gem_bin}" >> "${path_file}"
