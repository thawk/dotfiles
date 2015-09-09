#!/bin/sh

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

if [ -x git ]
then
    git config --global core.autocrlf false
    git config --global core.eol lf
fi

ln -sf "${SCRIPT_DIR}/.tmux.conf" ~/
ln -sf "${SCRIPT_DIR}/.screenrc" ~/
ln -sf "${SCRIPT_DIR}/.dir_colors" ~/
ln -sf "${SCRIPT_DIR}/.inputrc" ~/
ln -sf "${SCRIPT_DIR}/.mime.types" ~/
ln -sf "${SCRIPT_DIR}/.bashrc" ~/
ln -sf "${SCRIPT_DIR}/.ctags" ~/
ln -sf "${SCRIPT_DIR}/.minttyrc" ~/
ln -sf "${SCRIPT_DIR}/.bash_profile" ~/
ln -sf "${SCRIPT_DIR}/.bash_completion" ~/

[ -e ~/.bash_completion.d ] || mkdir ~/.bash_completion.d
for i in "${SCRIPT_DIR}/.bash_completion.d/"*
do
    ln -sf "$i" ~/.bash_completion.d/
done

[ -e ~/libexec ] || ln -sf "${SCRIPT_DIR}/libexec" ~/
[ -e ~/bin ] || mkdir ~/bin
for i in "${SCRIPT_DIR}/bin/"*
do
    ln -sf "$i" ~/bin/
done
