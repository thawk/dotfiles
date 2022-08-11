#!/usr/bin/env bash

[[ "${OSTYPE}" == "linux-gnu" ]] && \
    grep "Microsoft\|WSL" /proc/sys/kernel/osrelease > /dev/null

