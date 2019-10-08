#!/usr/bin/env bash

ROOTS=("$HOME/workspace/cs/lib/cppf/common/3rd/" "$HOME/workspace/")

env_file="${DOTFILES_LOCAL}/boost/env.sh"
mkdir -p "$(dirname "${env_file}")"
rm "$(dirname "$env_file")"/*
: > "${env_file}"

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

