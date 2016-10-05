#!/usr/bin/env sh

# only needed for WSL
if ! [ "$(uname -s)" = "Linux" ] || ! grep "Microsoft\|WSL" /proc/sys/kernel/osrelease > /dev/null
then
    exit 0
fi

# If MSYSGIT socket in keeagent is set as c:\Users/foo/Documents/ssh_auth_msysgit
SSH_AUTH_KEEAGENT_SOCK=/mnt/c/Users/$USER/keepass.sock

# Don't overwrite SSH_AUTH_SOCK
if [ -n "${SSH_AUTH_SOCK}" ]
then
    unset SSH_AUTH_KEEAGENT_SOCK
    exit 0
fi

# export SSH_AUTH_SOCK even SSH_AUTH_KEEAGENT_SOCK does not exist.
# this allow SSH_KEEAGENT work when keeagent is started.
export SSH_AUTH_SOCK="/tmp/keeagent.sock"

if [ -e "$SSH_AUTH_KEEAGENT_SOCK" ]
then
    SSH_AUTH_KEEAGENT_PORT=`sed -r 's/!<socket >([0-9]*\b).*/\1/' ${SSH_AUTH_KEEAGENT_SOCK}`

    SSH_AUTH_LOCK_FILE=/var/lock/keeagent.lock

    # remove sock file if only sock exists, and lock file is not exists.
    if [ ! -e "${SSH_AUTH_LOCK_FILE}" ]
    then
        [ -e "${SSH_AUTH_SOCK}" ] && rm "${SSH_AUTH_SOCK}"

        (socat -L"${SSH_AUTH_LOCK_FILE}" UNIX-LISTEN:"${SSH_AUTH_SOCK}",mode=0600,fork,shut-down TCP:127.0.0.1:${SSH_AUTH_KEEAGENT_PORT},connect-timeout=2 </dev/null >/dev/null 2>/dev/null &) &
    fi

    unset SSH_AUTH_LOCK_FILE
fi
