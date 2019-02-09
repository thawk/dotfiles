dcc() {
    if type peco &> /dev/null ; then
        dynamic-colors list |
        peco   --prompt='Colorscheme> ' --query="$1" |
        head -n 1 |
        sed -e 's/^\*//' |
        xargs dynamic-colors switch
    elif type percol &> /dev/null ; then
        dynamic-colors list |
        percol --prompt='Colorscheme> ' --query="$1" |
        head -n 1 |
        sed -e 's/^\*//' |
        xargs dynamic-colors switch
    fi
}
