#!/bin/bash
source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"

init_plugin pyenv
conf_dir="$(get_config_dir)"
env_file="$(create_plugin_file env.sh)"
path_file="$(create_plugin_file path.sh)"

PATH=$HOME/.pyenv/bin:$PATH

# shellcheck disable=SC2016
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> "${env_file}"
# shellcheck disable=SC2016
echo 'export PATH="$HOME/.pyenv/bin:$PATH"' >> "${path_file}"

pyenv init --path >> "${path_file}"

# set path to suppress the warning prompt of pyenv init -
eval "$(pyenv init --path)"

pyenv init - bash > "$(create_plugin_file init.bash)"
pyenv virtualenv-init - bash > "$(create_plugin_file virtualenv-init.bash)"

pyenv init - zsh > "$(create_plugin_file init.zsh)"
pyenv virtualenv-init - zsh > "$(create_plugin_file virtualenv-init.zsh)"

echo "export PYENV_VIRTUALENV_DISABLE_PROMPT=1" >> "${env_file}"

