if type peco &> /dev/null ; then
    alias dcc="dynamic-colors list | peco   --prompt='Colorscheme> ' | head -n 1 | xargs dynamic-colors switch"
elif type percol &> /dev/null ; then
    alias dcc="dynamic-colors list | percol --prompt='Colorscheme> ' | head -n 1 | xargs dynamic-colors switch"
fi
