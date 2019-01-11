#!/usr/bin/env bash

source "${DOTFILES_ROOT}/logging.sh"
DRY_RUN=$1

if ! [ -f $DOTFILES_LOCAL/.taskrc.symlink ]
then
    info 'setup taskrc'

    if [ "${DRY_RUN}" = 'yes' ]
    then
        echo .taskrc.symlink
    else
        mkdir -p "$DOTFILES_LOCAL"
        cp $DOTFILES_ROOT/taskwarrior/.taskrc.symlink.example $DOTFILES_LOCAL/.taskrc.symlink
    fi

    success 'taskrc'
fi

