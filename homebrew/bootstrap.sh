#!/usr/bin/env bash
# Time: 2022-04-08 22:12:02

env_file="${DOTFILES_LOCAL}/homebrew/env.sh"
top_file="${DOTFILES_LOCAL}/homebrew/top_sh.sh"

mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*
# : > "${env_file}"

shellenv="brew shellenv"

if test -d ~/.linuxbrew ; then
    shellenv="$HOME/.linuxbrew/bin/brew shellenv"
fi

if test -d /home/linuxbrew/.linuxbrew ; then
    shellenv="/home/linuxbrew/.linuxbrew/bin/brew shellenv"
fi

eval "$shellenv" | grep -v "\bPATH=" > "${env_file}"
eval "$shellenv" | grep "\bPATH=" > "${top_file}"

