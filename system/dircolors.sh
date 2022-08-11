if [ -x /usr/bin/dircolors ]; then
    if test -r ~/.dir_colors
    then
        eval "$(dircolors -b ~/.dir_colors)"
    else
        eval "$(dircolors -b)"
    fi
fi
