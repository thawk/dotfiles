#!/bin/bash

conf_dir="${DOTFILES_LOCAL}/pyenv"
mkdir -p "${conf_dir}"
rm -f "${conf_dir}"/*

env_file="${conf_dir}/env.sh"
: > "${env_file}"

echo "export PATH=\"$HOME/.pyenv/bin:\$PATH\"" >> "${env_file}"
echo "export PYENV_VIRTUALENV_DISABLE_PROMPT=1" >> "${env_file}"

#eval "$(pyenv init -)"
#eval "$(pyenv virtualenv-init -)"

# setup neovim pyenv
if [[ -x "$HOME/.pyenv/versions/neovim2/bin/python" ]]; then
    echo "export PYTHON_HOST_PROG=\"$HOME/.pyenv/versions/neovim2/bin/python\"" >> "${env_file}"
fi

if [[ -x "$HOME/.pyenv/versions/neovim3/bin/python" ]]; then
    echo "export PYTHON3_HOST_PROG=\"$HOME/.pyenv/versions/neovim3/bin/python\"" >> "${env_file}"
fi

PATH=$HOME/.pyenv/bin:$PATH

pyenv init - bash > "${conf_dir}/init.bash"
pyenv virtualenv-init - bash > "${conf_dir}/virtualenv-init.bash"

pyenv init - zsh > "${conf_dir}/init.zsh"
pyenv virtualenv-init - zsh > "${conf_dir}/virtualenv-init.zsh"

