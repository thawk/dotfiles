#!/bin/sh

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

ln -sf "${SCRIPT_DIR}/.tmux.conf" ~/
ln -sf "${SCRIPT_DIR}/.screenrc" ~/
ln -sf "${SCRIPT_DIR}/.dir_colors" ~/
ln -sf "${SCRIPT_DIR}/.inputrc" ~/
ln -sf "${SCRIPT_DIR}/.mime.types" ~/
ln -sf "${SCRIPT_DIR}/.bashrc" ~/
ln -sf "${SCRIPT_DIR}/.ctags" ~/
ln -sf "${SCRIPT_DIR}/.bash_profile" ~/
[ -e ~/libexec ] || ln -sf "${SCRIPT_DIR}/libexec" ~/

