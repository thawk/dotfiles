#!/bin/sh

env_file="${DOTFILES_LOCAL}/pip/path.sh"
mkdir -p "$(dirname "$env_file")"
rm "$(dirname "$env_file")"/*
: > "${env_file}"

#Not work at macos

#echo "export PATH=\${PATH}:$(python -m site --user-base)/bin" >> "${env_file}"

#if [ -n "$(python -c 'import site; print(site.USER_SITE)')" ]
#then
#    echo "export PYTHONPATH=$(python -c "import site; print(site.USER_SITE)"):\${PYTHONPATH:+:\${PYTHONPATH}}" >> "${env_file}"
#fi
