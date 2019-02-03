#!/bin/sh

mkdir -p "${DOTFILES_LOCAL}/pipenv"
rm "${DOTFILES_LOCAL}/pipenv"/*

PIPENV_SHELL=bash pipenv --completion > "${DOTFILES_LOCAL}/pipenv/completion.bash"
PIPENV_SHELL=zsh pipenv --completion > "${DOTFILES_LOCAL}/pipenv/completion.zsh"

