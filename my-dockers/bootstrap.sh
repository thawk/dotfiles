#!/usr/bin/env bash

source "${DOTFILES_ROOT}/util.sh"

plug_name=my-dockers
conf_path="$(init_local_config "${plug_name}")"
func_file="${conf_path}/functions.sh"

for script in "${DOTFILES_ROOT}/${plug_name}/scripts/"*; do
    cmd="${script##*/}"
    # For every scripts in scripts/, if command not exists then create a function to start docker
    if ! type "${cmd}" &> /dev/null; then
        echo "${cmd}() {" >> "${func_file}"
        cat "${script}" >> "${func_file}"
        echo "}" >> "${func_file}"
        echo "" >> "${func_file}"
    fi
done

