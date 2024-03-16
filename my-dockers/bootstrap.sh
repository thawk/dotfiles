#!/usr/bin/env bash

source "${DOTFILES_ROOT}/util.sh"

plug_name=my-dockers
init_plugin ${plug_name}
func_file="$(create_plugin_file functions.sh)"

for script in "${DOTFILES_ROOT}/${plug_name}/scripts/"*; do
    cmd="${script##*/}"
    # For every scripts in scripts/, if command not exists then create a function to start docker
    if ! type "${cmd}" &> /dev/null; then
        (
            echo "${cmd}() {"
            cat "${script}"
            echo "}"
            echo ""
        ) >> "${func_file}"
    fi
done

