#!/bin/sh

env_file="${DOTFILES_LOCAL}/pet/completion.zsh"
mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*
: > "${env_file}"

GOPATH=$(env GOPATH= GOROOT= go env GOPATH)

if [ -d "${GOPATH}/src/github.com/knqyf263/pet/misc/completions/zsh" ]
then
    echo "fpath=(\$fpath \"${GOPATH}/src/github.com/knqyf263/pet/misc/completions/zsh\")" >> "${env_file}"
fi
