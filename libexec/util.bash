# 进入与当前tmux session名称一致的目录
cdd() {
    if type tmux &> /dev/null
    then
        cd "$(tmux display-message -p '#S')"
    fi
}
