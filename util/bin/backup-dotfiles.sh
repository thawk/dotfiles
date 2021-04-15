#!/bin/sh

DEST_FILE=${1:-dotfiles-$(date +%Y%m%d).tar.bz2}

tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .taskrc.symlink --exclude .gitconfig.local.symlink --exclude .git --exclude "*.so" .dotfiles .tmux/plugins .zinit .cache/gitstatus
