#!/usr/bin/env sh

if [[ "${OSTYPE}" == "linux-gnu" ]] && \
    grep "Microsoft\|WSL" /proc/sys/kernel/osrelease > /dev/null ; then

    if type socat > /dev/null ; then
        true
    else
        echo "socat is required!" 1>&2
        false
    fi
fi

