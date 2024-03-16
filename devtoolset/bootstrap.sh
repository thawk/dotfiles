#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "devtoolset"
env_file="$(create_plugin_file env.sh)"

echo 'for d in $(ls -d /opt/rh/llvm-toolset-* | sort -Vr); do
    if [[ -e "$d/enable" ]]; then
        . "$d/enable"
        break
    fi
done' >> "${env_file}"

echo 'for d in $(ls -d /opt/rh/devtoolset-* | sort -Vr); do
    if [[ -e "$d/enable" ]]; then
        . "$d/enable"
        break
    fi
done' >> "${env_file}"
