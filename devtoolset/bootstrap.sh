#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "devtoolset"
env_file="$(create_plugin_file env.sh)"

for n in llvm-toolset- devtoolset- rh-nodejs; do
    if ls /opt/rh | grep "^${n}" >& /dev/null; then
        for d in $(ls -d /opt/rh/${n}* | sort -Vr); do
            if [[ -e "$d/enable" ]]; then
                echo ". '$d/enable'" >> "${env_file}"
                break
            fi
        done
    fi
done
