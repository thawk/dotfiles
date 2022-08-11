url() {
    tmux capture-pane -pJS - \
        | grep -oE '\b(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]' \
        | fzf-tmux --multi --tac --exit-0 \
        | while read -r url; do open "$url"; done
}
