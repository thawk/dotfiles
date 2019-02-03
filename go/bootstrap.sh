#!/bin/sh

env_file="${DOTFILES_LOCAL}/go/path.sh"
mkdir -p "$(dirname "$env_file")"
rm "$(dirname "$env_file")"/*
: > "${env_file}"

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
    echo "export PATH=\$PATH:${go_root}/bin" >> "${env_file}"
fi

if [ "${go_path}" != "${go_root}" ] && [ -d "${go_path}/bin" ]
then
    echo "export PATH=\$PATH:${go_path}/bin" >> "${env_file}"
fi
