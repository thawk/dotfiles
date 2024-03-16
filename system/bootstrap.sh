#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "system"
path_file="$(create_plugin_file path.sh)"
alias_file="$(create_plugin_file alias.sh)"

if [[ -d ~/bin ]]; then
    echo "export PATH=~/bin:\$PATH" >> "${path_file}"
fi

if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "freebsd"* ]]
then
    echo "alias ls='ls -G'" >> "${alias_file}"
    echo "type gmake &> /dev/null && alias make=gmake" >> "${alias_file}"
else
    echo "alias ls='ls --color=auto'" >> "${alias_file}"
fi

echo "alias ll='ls -l'" >> "${alias_file}"

if [[ "$OSTYPE" = "cygwin" ]]
then
    echo "alias cyg='apt-cyg mirror http://mirrors.163.com/cygwin/'" >> "${alias_file}"
    echo "alias cyp='apt-cyg mirror http://mirrors.kernel.org/sources.redhat.com/cygwinports/'" >> "${alias_file}"
fi

