dcc() {
    local prompt="Colorscheme> "
    local filter="percol --prompt='${prompt}' --query='$*'"
    if type fzf &> /dev/null; then
        filter="fzf --prompt='${prompt}' --query='$*'"
    elif type peco &> /dev/null ; then
        filter="peco --prompt='${prompt}' --query='$*'"
    fi

    dynamic-colors list |
    eval "$filter" |
    head -n 1 |
    sed -e 's/^\*//' |
    xargs dynamic-colors switch
}
