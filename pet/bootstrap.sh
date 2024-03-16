#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "pet"
completion_file="$(create_plugin_file completion.sh)"

if type go &> /dev/null; then
    GOPATH=$(env GOPATH= GOROOT= go env GOPATH)

    if [ -d "${GOPATH}/src/github.com/knqyf263/pet/misc/completions/zsh" ]
    then
        echo "fpath=(\$fpath \"${GOPATH}/src/github.com/knqyf263/pet/misc/completions/zsh\")" >> "${completion_file}"
    fi
fi
