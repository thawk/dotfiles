#!/bin/bash

DEST_FILE=${1:-spacevim-$(date +%Y%m%d).tar.bz2}

if [[ -n "$XDG_CONFIG_HOME" ]]; then
    SPACEVIM_D_DIR="${XDG_CONFIG_HOME#$HOME/}/SpaceVim.d"
else
    SPACEVIM_D_DIR=".SpaceVim.d"
fi

files=("${SPACEVIM_D_DIR}" .SpaceVim .cache/vimfiles )
[[ -d "$HOME/.config/coc" ]] && files=( "${files[@]}" .config/coc )

tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .git --exclude ".cache/*.so" --exclude "*/node_modules/*" "${files[@]}"
