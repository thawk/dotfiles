#!/bin/sh

env_file="${DOTFILES_LOCAL}/system/env.sh"
mkdir -p "$(dirname "$env_file")"
rm "$(dirname "$env_file")"/*
: > "${env_file}"

if [ -d ~/bin ]; then
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

# 如果有vim则用vim。否则用vi。在有vim时，如果没有vi，将vi定义为vim的alias
if type nvim &> /dev/null ; then
    echo "export EDITOR='nvim'" >> "${env_file}"

    # 在MacOS下，使用neovim代替vim
    [[ "$OSTYPE" == "darwin"* ]] && echo "alias vim=nvim" >> "${env_file}"

    type vi &> /dev/null || echo "alias vi=nvim" >> "${env_file}"
elif type vim &> /dev/null ; then
    echo "export EDITOR='vim'" >> "${env_file}"
    type vi &> /dev/null || echo "alias vi=vim" >> "${env_file}"
elif type vi &> /dev/null ; then
    echo "export EDITOR='vi'" >> "${env_file}"
fi
