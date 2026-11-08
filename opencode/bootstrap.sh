#!/usr/bin/env bash

if [[ -x "$HOME/.opencode/bin/opencode" ]]; then
  source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
  init_plugin "opencode"
  path_file="$(create_plugin_file path.sh)"

  # shellcheck disable=SC2016
  echo 'if [[ ":$PATH:" != *":$HOME/.opencode/bin:"* ]]; then export PATH="$HOME/.opencode/bin:$PATH"; fi' >>"${path_file}"
fi
