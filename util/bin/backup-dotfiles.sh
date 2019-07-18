#!/bin/sh

DEST_FILE=${1:-dotfiles.tar.bz2}

tar -C "$HOME" -cjvf "${DEST_FILE}" --exclude .taskrc.symlink --exclude .gitconfig.local.symlink --exclude .git --exclude "*.so" .dotfiles .tmux/plugins .zplugin
