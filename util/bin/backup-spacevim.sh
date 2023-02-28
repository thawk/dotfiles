#!/bin/bash

DEST_FILE=${1:-spacevim-$(date +%Y%m%d).tar.bz2}

files=(.SpaceVim.d .SpaceVim .cache/vimfiles )
[[ -d "$HOME/.config/coc" ]] && files=( "${files[@]}" .config/coc )

tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .git --exclude ".cache/*.so" --exclude "*/node_modules/*" "${files[@]}"
