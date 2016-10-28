#!/usr/bin/env sh

EchoUsage()
{
    echo "
Usage: $(basename "$0") [options]

  Options:
      -h [ --help ]            show this screen
      -f [ --force ]           force execution
" >&2
}

TEMP=$(getopt -o h,f --long help,force -- "$@")

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; return 1 ; fi

# Note the quotes around `$TEMP': they are essential!
eval set -- "$TEMP"

force=

while true ; do
    case "$1" in
        -h|--help)
            EchoUsage
            return 1
            ;;
        -f|--force)
            force=yes
            shift 1
            break
            ;;
        --)
            shift 1
            break
            ;;
        *) 
            echo "Unknown parameter '$1'!"
            return 1
            ;;
    esac
done

# only needed for WSL
if ! [ "$(uname -s)" = "Linux" ] || ! grep "Microsoft\|WSL" /proc/sys/kernel/osrelease > /dev/null
then
    return 0
fi

# If MSYSGIT socket in keeagent is set as c:\Users/foo/Documents/ssh_auth_msysgit
SSH_AUTH_KEEAGENT_SOCK=/mnt/c/Users/$USER/keepass.sock

# Don't overwrite SSH_AUTH_SOCK
if [ "${force}" != "yes" ] && [ -n "${SSH_AUTH_SOCK}" ] && [ -e "${SSH_AUTH_SOCK}" ]
then
    unset SSH_AUTH_KEEAGENT_SOCK
    return 0
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
    unset SSH_AUTH_KEEAGENT_PORT
fi

unset SSH_AUTH_KEEAGENT_SOCK
