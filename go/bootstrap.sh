#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "go"
env_file="$(create_plugin_file env.sh)"
path_file="$(create_plugin_file path.sh)"

# Reset environment to correctly handle golang upgrade
export GOPATH=
export GOROOT=

go_path=$(go env GOPATH)
go_root=$(go env GOROOT)

if [ -z "${go_path}" ]; then
    echo "export GOPATH=${go_path}" >> "${env_file}"
else
    echo "export GOPATH=${HOME}/go" >> "${env_file}"
fi

echo "export GOROOT=${go_root}" >> "${env_file}"

if [ -d "${go_root}/bin" ]
then
    echo "export PATH=\$PATH:${go_root}/bin" >> "${path_file}"
fi

if [ "${go_path}" != "${go_root}" ] && [ -d "${go_path}/bin" ]
then
    echo "export PATH=\$PATH:${go_path}/bin" >> "${path_file}"
fi
