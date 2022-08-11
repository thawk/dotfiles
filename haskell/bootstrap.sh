#!/bin/sh

conf_dir="${DOTFILES_LOCAL}/haskell"
mkdir -p "${conf_dir}"
rm -f "${conf_dir}"/*

# shellcheck disable=SC2016
echo '[[ -f "$HOME/.ghcup/env" ]] && source "$HOME/.ghcup/env"' >> "${conf_dir}/env.sh"

