#!/usr/bin/env bash
# Time: 2022-04-08 22:12:02

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "homebrew"
env_file="$(create_plugin_file env.sh)"
top_file="$(create_plugin_file top_sh.sh)"

shellenv="brew shellenv"

if test -d ~/.linuxbrew ; then
    shellenv="$HOME/.linuxbrew/bin/brew shellenv"
fi

if test -d /home/linuxbrew/.linuxbrew ; then
    shellenv="/home/linuxbrew/.linuxbrew/bin/brew shellenv"
fi

eval "$shellenv" | grep -v "\bPATH=" > "${env_file}"

brew_path_line="$(eval "$shellenv" | grep "\bPATH=")"
if [ -n "${brew_path_line}" ]; then
    brew_bin="${brew_path_line#*PATH=\"}"
    brew_bin="${brew_bin%%:*}"
    # shellcheck disable=SC2016
    printf 'if [[ ":$PATH:" != *":%s:"* ]]; then %s fi\n' "${brew_bin}" "${brew_path_line}" > "${top_file}"
fi

