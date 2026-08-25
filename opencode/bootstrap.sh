#!/usr/bin/env bash

if [[ -x "$HOME/.opencode/bin/opencode" ]]; then
  source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
  init_plugin "opencode"
  path_file="$(create_plugin_file path.sh)"

  echo "export PATH=$HOME/.opencode/bin:\${PATH}" >>"${path_file}"
fi
