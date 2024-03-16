#!/usr/bin/env bash
# Time: 2024-03-16 11:46:25
source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"

init_plugin python
env_file="$(create_plugin_file env.sh)"

## pyenv related
PATH="$HOME/.pyenv/bin:$PATH"

venv_root=$HOME/venv
pyenv_root=
if type pyenv &> /dev/null; then
    pyenv_root="$(pyenv root)"
fi

# setup neovim pyenv
if [[ -x "${pyenv_root}/versions/neovim2/bin/python" ]]; then
    # shellcheck disable=SC2016
    echo "export PYTHON_HOST_PROG='${pyenv_root}/versions/neovim2/bin/python'" >> "${env_file}"
fi

if [[ -x "${pyenv_root}/versions/neovim3/bin/python" ]]; then
    # shellcheck disable=SC2016
    echo "export PYTHON3_HOST_PROG='${pyenv_root}/versions/neovim3/bin/python'" >> "${env_file}"
elif [[ -x "${venv_root}/neovim3/bin/activate" ]]; then
    # if pyenv not found, but a venv named neovim3 found, use it
    echo "export VIRTUAL_ENV='${venv_root}/neovim3'" >> "${env_file}"
fi

