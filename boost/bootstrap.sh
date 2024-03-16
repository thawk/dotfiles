#!/usr/bin/env bash

source "$(dirname "$(dirname "${BASH_SOURCE[0]}")")/util.sh"
init_plugin "boost"
env_file="$(create_plugin_file env.sh)"

ROOTS=("$HOME/workspace/cs/lib/cppf/common/3rd/" "$HOME/workspace/")

for i in $(seq 0 $((${#ROOTS[*]} - 1)))
do
    root="${ROOTS[$i]}"
    if [ ! -d "${root}" ]
    then
        continue
    fi

    boost_root=$(find "$root" -maxdepth 1 -type d -name "boost_*" | sort -r | head -n 1)
    if [ -d "${boost_root}" ]
    then
        echo "export BOOST_ROOT=\"${boost_root}\"" >> "${env_file}"
        echo "export GTAGSLIBPATH=\"\${GTAGSLIBPATH:+\${GTAGSLIBPATH}:}${boost_root}\"" >> "${env_file}"

        break
    fi
done

