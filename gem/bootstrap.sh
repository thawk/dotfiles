#!/bin/sh

env_file="${DOTFILES_LOCAL}/gem/path.sh"
mkdir -p "$(dirname "$env_file")"
rm "$(dirname "$env_file")"/*
: > "${env_file}"

echo "export PATH=\${PATH}:$(ruby -rrubygems -e "puts Gem.user_dir")/bin" >> "${env_file}"
