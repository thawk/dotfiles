if [[ "$DOTFILES_THEME" == "solarized" ]]
then
    if [ -n "$ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE" ]
    then
        # if use zsh_autosuggestions，change the highlight color
        # so it will be visible under solarized
        export ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=blue'
    fi

    zstyle ":history-search-multi-word" highlight-color
    if [ $? -ne 2 ]
    then
        # if use history-search-multi-word，change the highlight color
        # so it will be visible under solarized
        zstyle ":history-search-multi-word" highlight-color "fg=white,bg=blue"
    fi
fi
