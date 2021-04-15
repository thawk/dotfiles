#!/bin/bash

DEST_FILE=${1:-spacevim-$(date +%Y%m%d).tar.bz2}

dirs=(.SpaceVim.d .SpaceVim .cache/vimfiles )
[[ -d "$HOME/.config/coc" ]] && dirs=( "${dirs[@]}" .config/coc )
tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .git --exclude "*.so" "${dirs[@]}"
