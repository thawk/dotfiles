#!/usr/bin/env bash

env_file="${DOTFILES_LOCAL}/system/env.sh"
editor_file="${DOTFILES_LOCAL}/system/editor.sh"
mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*
: > "${env_file}"
: > "${editor_file}"

if [ -d /usr/local/sbin ]; then
    case ":${PATH:-}:" in
        *:/usr/local/sbin:*) ;;
        *) echo "export PATH=/usr/local/sbin:\$PATH" >> "${env_file}" ;;
    esac
fi

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
    echo "export EDITOR='nvim'" >> "${editor_file}"
    # echo "export MANPAGER=\"nvim +'set ft=man' -\"" >> "${env_file}"

    # 在MacOS下，使用neovim代替vim
    if ! type vim &> /dev/null || [[ "$OSTYPE" == "darwin"* ]] ; then
        echo "alias vim=nvim" >> "${editor_file}"
    fi

    type vi &> /dev/null || echo "alias vi=nvim" >> "${editor_file}"

    # vimu不使用vim配置，适合打开大文件
    echo "alias vimu=nvim -u /dev/null" >> "${editor_file}"
elif type vim &> /dev/null ; then
    echo "export EDITOR='vim'" >> "${editor_file}"
    # echo "export MANPAGER=\"vim +'set ft=man' -\"" >> "${env_file}"
    type vi &> /dev/null || echo "alias vi=vim" >> "${editor_file}"

    # vimu不使用vim配置，适合打开大文件
    echo "alias vimu=vim -u /dev/null" >> "${editor_file}"
elif type vi &> /dev/null ; then
    echo "export EDITOR='vi'" >> "${editor_file}"
fi

