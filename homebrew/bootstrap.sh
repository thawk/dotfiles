#!/usr/bin/env bash
# Time: 2022-04-08 22:12:02

env_file="${DOTFILES_LOCAL}/homebrew/env.sh"
path_file="${DOTFILES_LOCAL}/homebrew/path.sh"

mkdir -p "$(dirname "$env_file")"
rm -f "$(dirname "$env_file")"/*
# : > "${env_file}"

brew shellenv | grep -v "\bPATH=" > "${env_file}"
brew shellenv | grep "\bPATH=" > "${path_file}"
