#!/bin/bash
# Usage: wsl-ssh-agent-forward [ -k | -r ]
# Options:
#    -k    Kill the current process (if exists) and do not restart it.
#    -r    Kill the current process (if exists) and restart it.
# Default operation is to start a process only if it does not exist.
#
# Robustness notes:
#   - Detection checks that the socket FILE actually exists ([ -S ]), not just
#     that socat is still listening in `ss` (a deleted/unlinked socket file
#     would otherwise leave the forwarder broken forever).
#   - A flock serializes concurrent invocations (multiple terminals / tmux
#     panes sourcing stage2 at the same time), avoiding rm/start races.

export SSH_AUTH_SOCK=$HOME/.ssh/agent.sock
LOCK_FILE="${TMPDIR:-/tmp}/wsl-ssh-agent-forwarder.lock"

if ! type socat > /dev/null ; then
    echo "wsl: socat is required!" 1>&2
    exit 1
fi

# Print pids of socat processes listening on $SSH_AUTH_SOCK (one per line).
socat_pids() {
    ss -ap 2>/dev/null | grep "$SSH_AUTH_SOCK" | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p'
}

kill_pids() {
    while read -r p; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done < <(printf '%s\n' "$1")
}

start_forwarder() {
    pkill -x npiperelay.exe 2>/dev/null
    rm -f "$SSH_AUTH_SOCK"
    # 9>&- : socat must not inherit the lock fd, otherwise it holds the lock forever
    ( setsid socat UNIX-LISTEN:"$SSH_AUTH_SOCK",fork EXEC:"$DOTFILES_ROOT/wsl/npiperelay.exe -ei -s //./pipe/openssh-ssh-agent",nofork 9>&- & ) >"${TMPDIR:-/tmp}/wsl-ssh-agent-forwarder.log" 2>&1
    for _ in 1 2 3 4 5; do
        [ -S "$SSH_AUTH_SOCK" ] && break
        sleep 0.2
    done
    if [ -S "$SSH_AUTH_SOCK" ]; then
        echo "wsl-ssh-agent: started ($SSH_AUTH_SOCK)"
    else
        echo "wsl-ssh-agent: FAILED to create $SSH_AUTH_SOCK, see ${TMPDIR:-/tmp}/wsl-ssh-agent-forwarder.log" 1>&2
    fi
}

# Acquire an exclusive lock so concurrent startups don't race each other.
owner=true
have_flock=false
if type flock > /dev/null 2>&1; then
    have_flock=true
    if ! exec 9>"$LOCK_FILE"; then
        have_flock=false
    fi
fi
if [ "$have_flock" = true ]; then
    flock -n 9 2>/dev/null && owner=true || owner=false
fi

if [ "$owner" = true ]; then
    pids=$(socat_pids)
    if [ "$1" = "-k" ] || [ "$1" = "-r" ]; then
        kill_pids "$pids"
        if [ "$1" = "-k" ]; then
            rm -f "$SSH_AUTH_SOCK"
            exit 0
        fi
        start_forwarder
    elif [ -z "$pids" ] || [ ! -S "$SSH_AUTH_SOCK" ]; then
        kill_pids "$pids"
        start_forwarder
    fi
else
    # Another shell owns the lock; wait for the socket to appear.
    waited=0
    while [ ! -S "$SSH_AUTH_SOCK" ] && [ "$waited" -lt 20 ]; do
        sleep 0.1
        waited=$((waited+1))
    done
    [ -S "$SSH_AUTH_SOCK" ] || echo "wsl-ssh-agent: another instance is starting but socket not ready yet" 1>&2
fi
