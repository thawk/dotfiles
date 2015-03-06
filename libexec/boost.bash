#!/bin/sh

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
        export BOOST_ROOT=${boost_root}
        if [ -n "${GTAGSLIBPATH}" ]
        then
            export GTAGSLIBPATH=${boost_root}
        else
            export GTAGSLIBPATH=${GTAGSLIBPATH}:${boost_root}
        fi
        return 0
    fi
done

return 1
