# tmux相关命令
function pattach() {
    if [[ $1 == "" ]]; then
        PERCOL=percol
    else
        PERCOL="percol --query $1"
    fi

    sessions="$(tmux ls)" || return

    session=$(echo "$sessions" | eval "$PERCOL" | cut -d : -f 1)
    if [[ -n "$session" ]]; then
        tmux att -t "$session"
    fi
}


