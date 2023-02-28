#!/bin/sh

DEST_FILE=${1:-dotfiles-$(date +%Y%m%d).tar.bz2}

files=( .dotfiles )
files=( "${files[@]}" .tmux/plugins )
files=( "${files[@]}" .zi )

CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache}"
CACHE_HOME="${CACHE_HOME#$HOME/}"
if [[ -d "${CACHE_HOME}/gitstatus" ]]; then
    # gitstatus
    files=( "${files[@]}" "${CACHE_HOME}/gitstatus" )
fi

tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .taskrc.symlink --exclude .gitconfig.local.symlink --exclude .git --exclude "*.so" "${files[@]}"
