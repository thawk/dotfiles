#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "gem"
path_file="$(create_plugin_file path.sh)"

echo "export PATH=\${PATH}:$(ruby -rrubygems -e "puts Gem.user_dir")/bin" >> "${path_file}"
