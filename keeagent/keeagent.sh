#!/usr/bin/env sh

# If MSYSGIT socket in keeagent is set as c:\Users/foo/Documents/ssh_auth_msysgit
SSH_AUTH_KEEAGENT_SOCK=/mnt/c/Users/$USER/keepass.sock

if [ -e "$SSH_AUTH_KEEAGENT_SOCK" ]
then
    SSH_AUTH_KEEAGENT_PORT=`sed -r 's/!<socket >([0-9]*\b).*/\1/' ${SSH_AUTH_KEEAGENT_SOCK}`

    #use socket filename structure similar to ssh-agent
    #ssh_auth_tmpdir=`mktemp --tmpdir --directory keeagent-ssh.XXXXXXXXXX`
    #export SSH_AUTH_SOCK="${ssh_auth_tmpdir}/agent.$$"
    export SSH_AUTH_SOCK="/tmp/keeagent.sock"

    (socat -L/var/lock/keeagent.lock UNIX-LISTEN:${SSH_AUTH_SOCK},mode=0600,fork,shut-down TCP:127.0.0.1:${SSH_AUTH_KEEAGENT_PORT},connect-timeout=2 </dev/null >/dev/null 2>/dev/null &) &
fi
