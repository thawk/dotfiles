#!/usr/bin/env bash
# Time: 2022-04-08 22:12:02

env_file="${DOTFILES_LOCAL}/homebrew/env.sh"
path_file="${DOTFILES_LOCAL}/homebrew/path.sh"

mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*
# : > "${env_file}"

shellenv="brew shellenv"
homebrew_prefix=

if test -d ~/.linuxbrew ; then
    shellenv="~/.linuxbrew/bin/brew shellenv"
    homebrew_prefix=~/.linuxbrew
fi

if test -d /home/linuxbrew/.linuxbrew ; then
    shellenv="/home/linuxbrew/.linuxbrew/bin/brew shellenv"
    homebrew_prefix=/home/linuxbrew/.linuxbrew
fi

eval "$shellenv" | grep -v "\bPATH=" > "${env_file}"
eval "$shellenv" | grep "\bPATH=" > "${path_file}"

test -n "$homebrew_prefix" && test -x $homebrew_prefix/bin/curl && echo "export HOMEBREW_CURL_PATH=$homebrew_prefix/bin/curl" >> "${env_file}"
