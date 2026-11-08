#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "uv"
completion_file="$(create_plugin_file completion.zsh)"
echo "$(uv generate-shell-completion zsh)" >>"${completion_file}"

# 写入pip源
source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/logging.sh"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/uv"
UV_CONFIG_FILE="$CONFIG_DIR/uv.toml"

if [[ ! -f "$UV_CONFIG_FILE" ]] || ! grep '\[\[index\]\]' "$UV_CONFIG_FILE" &>/dev/null; then
  info "        Updating python index for uv in ${UV_CONFIG_FILE}"

  cat <<'EOF' >>"$UV_CONFIG_FILE"
[[index]]
url="https://mirrors.aliyun.com/pypi/simple"
default=true
EOF
else
  debug "        Python index for uv has already exists in ${UV_CONFIG_FILE}"
fi
