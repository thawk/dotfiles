#!/bin/bash

PATH=$HOME/.pyenv/bin:$PATH

conf_dir="${DOTFILES_LOCAL}/pyenv"
mkdir -p "${conf_dir}"
rm -f "${conf_dir}"/*

env_file="${conf_dir}/env.sh"
: > "${env_file}"

path_file="${conf_dir}/path.sh"
: > "${path_file}"

# shellcheck disable=SC2016
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> "${env_file}"
# shellcheck disable=SC2016
echo 'export PATH="$HOME/.pyenv/bin:$PATH"' >> "${path_file}"

pyenv init --path >> "${path_file}"

# set path to suppress the warning prompt of pyenv init -
eval "$(pyenv init --path)"

pyenv init - bash > "${conf_dir}/init.bash"
pyenv virtualenv-init - bash > "${conf_dir}/virtualenv-init.bash"

pyenv init - zsh > "${conf_dir}/init.zsh"
pyenv virtualenv-init - zsh > "${conf_dir}/virtualenv-init.zsh"

echo "export PYENV_VIRTUALENV_DISABLE_PROMPT=1" >> "${env_file}"

# setup neovim pyenv
if [[ -x "$HOME/.pyenv/versions/neovim2/bin/python" ]]; then
    # shellcheck disable=SC2016
    echo 'export PYTHON_HOST_PROG="$HOME/.pyenv/versions/neovim2/bin/python"' >> "${env_file}"
fi

if [[ -x "$HOME/.pyenv/versions/neovim3/bin/python" ]]; then
    # shellcheck disable=SC2016
    echo 'export PYTHON3_HOST_PROG="$HOME/.pyenv/versions/neovim3/bin/python"' >> "${env_file}"
fi

