#!/bin/sh

conf_dir="${DOTFILES_LOCAL}/haskell"
mkdir -p "${conf_dir}"
rm "${conf_dir}"/*

echo '[[ -f "$HOME/.ghcup/env" ]] && source "$HOME/.ghcup/env"' >> "${conf_dir}/env.sh"

