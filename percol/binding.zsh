if which percol &> /dev/null; then
    function _percol_select_history() {
        local tac
        (which gtac &> /dev/null) && tac="gtac" || { (which tac &> /dev/null) && tac="tac" || { tac="tail -r" } }
        BUFFER=$(fc -l -n 1 | eval $tac | percol --query "$LBUFFER")
        CURSOR=$#BUFFER         # move cursor
        zle -R -c               # refresh
    }

    zle -N _percol_select_history
    bindkey '^R' _percol_select_history
fi
