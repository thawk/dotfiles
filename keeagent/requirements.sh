#!/usr/bin/env sh

[[ "${OSTYPE}" == "linux-gnu" ]] && \
    grep "Microsoft\|WSL" /proc/sys/kernel/osrelease > /dev/null && \
    type socat > /dev/null
