#!/bin/sh

env_file="${DOTFILES_LOCAL}/pyenv/env.sh"
mkdir -p "$(dirname "$env_file")"
rm "$(dirname "$env_file")"/*
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

pyenv init - bash > "${DOTFILES_LOCAL}/pyenv/init.bash"
pyenv virtualenv-init - bash > "${DOTFILES_LOCAL}/pyenv/virtualenv-init.bash"

pyenv init - zsh > "${DOTFILES_LOCAL}/pyenv/init.zsh"
pyenv virtualenv-init - zsh > "${DOTFILES_LOCAL}/pyenv/virtualenv-init.zsh"

