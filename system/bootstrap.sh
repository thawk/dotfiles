#!/usr/bin/env bash

env_file="${DOTFILES_LOCAL}/system/env.sh"
mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*
: > "${env_file}"

if [[ -d ~/bin ]]; then
    echo "export PATH=~/bin:\$PATH" >> "${env_file}"
fi

if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "freebsd"* ]]
then
    echo "alias ls='ls -G'" >> "${env_file}"
    echo "type gmake &> /dev/null && alias make=gmake" >> "${env_file}"
else
    echo "alias ls='ls --color=auto'" >> "${env_file}"
fi

echo "alias ll='ls -l'" >> "${env_file}"

if [[ "$OSTYPE" = "cygwin" ]]
then
    echo "alias cyg='apt-cyg mirror http://mirrors.163.com/cygwin/'" >> "${env_file}"
    echo "alias cyp='apt-cyg mirror http://mirrors.kernel.org/sources.redhat.com/cygwinports/'" >> "${env_file}"
fi

