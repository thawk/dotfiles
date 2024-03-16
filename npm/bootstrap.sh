#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "npm"
env_file="$(create_plugin_file env.sh)"

NPM_ROOT="$(npm root -g)"
if [ -d "${NPM_ROOT}" ]
then
    echo "export NODE_PATH=${NPM_ROOT}" >> "${env_file}"
fi
