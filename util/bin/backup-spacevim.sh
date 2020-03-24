#!/bin/sh

DEST_FILE=${1:-spacevim.tar.bz2}

tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .git --exclude "*.so" .SpaceVim.d .SpaceVim .cache/vimfiles .config/coc
