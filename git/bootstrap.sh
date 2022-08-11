#!/usr/bin/env bash

source "${DOTFILES_ROOT}/logging.sh"
DRY_RUN=$1

if ! [ -f "$DOTFILES_LOCAL/.gitconfig.local.symlink" ]
then
    info 'setup gitconfig'

    git_credential='cache'
    if [[ "$OSTYPE" == "darwin"* ]]
    then
        git_credential='osxkeychain'
    fi

    user ' - What is your github author name?'
    read -r -e git_authorname
    user ' - What is your github author email?'
    read -r -e git_authoremail

    if [ "${DRY_RUN}" = 'yes' ]
    then
        echo .gitconfig.local.symlink
        sed -e "s/AUTHORNAME/$git_authorname/g" -e "s/AUTHOREMAIL/$git_authoremail/g" -e "s/GIT_CREDENTIAL_HELPER/$git_credential/g" "$DOTFILES_ROOT/git/.gitconfig.local.symlink.example"
    else
        mkdir -p "$DOTFILES_LOCAL"
        sed -e "s/AUTHORNAME/$git_authorname/g" -e "s/AUTHOREMAIL/$git_authoremail/g" -e "s/GIT_CREDENTIAL_HELPER/$git_credential/g" "$DOTFILES_ROOT/git/.gitconfig.local.symlink.example" > "$DOTFILES_LOCAL/.gitconfig.local.symlink"
    fi

    success 'gitconfig'
fi
